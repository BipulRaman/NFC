//! Tamper seals: an ECDSA P-256 signature over a card's content and unique ID, stored as an extra
//! NDEF record. Any change to the content, or copying it to another card, breaks the seal.
//!
//! The format is shared with the Android app (`data/Seal.kt`):
//! record = external type `nfcstudio.dev:seal`, payload = `0x01 ‖ public key (33, compressed) ‖ r ‖ s`.
//! Signed bytes = `"NFCSTUDIO-SEAL-v1\0" ‖ len(uid) ‖ uid ‖ for each other record:
//! tnf ‖ u32 len(type) ‖ type ‖ u32 len(id) ‖ id ‖ u32 len(payload) ‖ payload` (big-endian).

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, VerifyingKey};
pub use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

pub const SEAL_TYPE: &[u8] = b"nfcstudio.dev:seal";
const TNF_EXTERNAL: u8 = 4;
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"NFCSTUDIO-SEAL-v1\0";

/// An NDEF record exactly as stored, so signatures cover the real bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRecord {
    pub tnf: u8,
    pub rtype: Vec<u8>,
    pub id: Vec<u8>,
    pub payload: Vec<u8>,
}

impl RawRecord {
    pub fn is_seal(&self) -> bool {
        self.tnf == TNF_EXTERNAL && self.rtype == SEAL_TYPE
    }

    pub fn is_empty_record(&self) -> bool {
        self.tnf == 0
    }
}

pub fn decode_raw(data: &[u8]) -> Result<Vec<RawRecord>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    let take = |i: &mut usize, n: usize| -> Result<std::ops::Range<usize>, String> {
        if *i + n > data.len() {
            return Err("Truncated NDEF record".into());
        }
        *i += n;
        Ok(*i - n..*i)
    };
    while i < data.len() {
        let hdr = data[take(&mut i, 1)?.start];
        let type_len = data[take(&mut i, 1)?.start] as usize;
        let payload_len = if hdr & 0x10 != 0 {
            data[take(&mut i, 1)?.start] as usize
        } else {
            let r = take(&mut i, 4)?;
            u32::from_be_bytes(data[r].try_into().unwrap()) as usize
        };
        let id_len = if hdr & 0x08 != 0 { data[take(&mut i, 1)?.start] as usize } else { 0 };
        let rtype = data[take(&mut i, type_len)?].to_vec();
        let id = data[take(&mut i, id_len)?].to_vec();
        let payload = data[take(&mut i, payload_len)?].to_vec();
        out.push(RawRecord { tnf: hdr & 0x07, rtype, id, payload });
        if hdr & 0x40 != 0 {
            break;
        }
    }
    Ok(out)
}

pub fn encode_raw(records: &[RawRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let mut hdr = r.tnf & 0x07;
        if i == 0 {
            hdr |= 0x80;
        }
        if i == records.len() - 1 {
            hdr |= 0x40;
        }
        let short = r.payload.len() < 256;
        if short {
            hdr |= 0x10;
        }
        if !r.id.is_empty() {
            hdr |= 0x08;
        }
        out.push(hdr);
        out.push(r.rtype.len() as u8);
        if short {
            out.push(r.payload.len() as u8);
        } else {
            out.extend_from_slice(&(r.payload.len() as u32).to_be_bytes());
        }
        if !r.id.is_empty() {
            out.push(r.id.len() as u8);
        }
        out.extend_from_slice(&r.rtype);
        out.extend_from_slice(&r.id);
        out.extend_from_slice(&r.payload);
    }
    out
}

/// Puts ISO 15693 UIDs (sent least significant byte first by some readers) in one canonical order.
pub fn normalize_uid(uid: &[u8]) -> Vec<u8> {
    if uid.len() == 8 && uid[7] == 0xE0 {
        uid.iter().rev().copied().collect()
    } else {
        uid.to_vec()
    }
}

/// Cards whose ID changes on every tap (random IDs start with 0x08) can't be sealed.
pub fn uid_is_stable(uid: &[u8]) -> bool {
    !uid.is_empty() && !(uid.len() == 4 && uid[0] == 0x08)
}

pub fn signed_bytes(uid: &[u8], records: &[RawRecord]) -> Vec<u8> {
    let uid = normalize_uid(uid);
    let mut c = DOMAIN.to_vec();
    c.push(uid.len() as u8);
    c.extend_from_slice(&uid);
    for r in records {
        c.push(r.tnf);
        for part in [&r.rtype, &r.id, &r.payload] {
            c.extend_from_slice(&(part.len() as u32).to_be_bytes());
            c.extend_from_slice(part);
        }
    }
    c
}

/// Bytes a seal record adds to the NDEF message.
pub const SEAL_RECORD_SIZE: usize = 3 + SEAL_TYPE.len() + 1 + 33 + 64;

pub fn seal_record(key: &SigningKey, uid: &[u8], records: &[RawRecord]) -> RawRecord {
    let sig: Signature = key.sign(&signed_bytes(uid, records));
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut payload = vec![VERSION];
    payload.extend_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
    payload.extend_from_slice(&sig.to_bytes());
    RawRecord { tnf: TNF_EXTERNAL, rtype: SEAL_TYPE.to_vec(), id: Vec::new(), payload }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealStatus {
    None,
    /// The content and card ID match the signature made by this key.
    Valid { key: Vec<u8> },
    /// The content was changed, or copied from another card, after sealing.
    Broken,
}

/// Splits `records` into content and seal and checks the seal against `uid`.
pub fn verify(uid: &[u8], records: &[RawRecord]) -> (SealStatus, Vec<RawRecord>) {
    let content: Vec<RawRecord> = records.iter().filter(|r| !r.is_seal()).cloned().collect();
    let Some(seal) = records.iter().rev().find(|r| r.is_seal()) else {
        return (SealStatus::None, content);
    };
    let ok = (|| {
        let p = &seal.payload;
        if p.len() != 1 + 33 + 64 || p[0] != VERSION {
            return None;
        }
        let key = VerifyingKey::from_sec1_bytes(&p[1..34]).ok()?;
        let sig = Signature::from_slice(&p[34..]).ok()?;
        key.verify(&signed_bytes(uid, &content), &sig).ok()?;
        Some(p[1..34].to_vec())
    })();
    match ok {
        Some(key) => (SealStatus::Valid { key }, content),
        None => (SealStatus::Broken, content),
    }
}

/// A short, human-comparable ID for a sealing key, e.g. `3F2A-91C4-0B7E`.
pub fn fingerprint(public_key: &[u8]) -> String {
    let h = Sha256::digest(public_key);
    format!("{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}", h[0], h[1], h[2], h[3], h[4], h[5])
}

pub fn public_key(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

pub fn generate_key() -> SigningKey {
    SigningKey::random(&mut rand_core::OsRng)
}

pub fn key_from_bytes(bytes: &[u8]) -> Option<SigningKey> {
    SigningKey::from_slice(bytes).ok()
}

pub fn key_to_bytes(key: &SigningKey) -> Vec<u8> {
    key.to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        crate::apdu::parse_hex(s).unwrap()
    }

    fn sample() -> Vec<RawRecord> {
        vec![
            RawRecord { tnf: 1, rtype: b"T".to_vec(), id: vec![], payload: b"\x02enHello".to_vec() },
            RawRecord { tnf: 1, rtype: b"U".to_vec(), id: vec![], payload: b"\x04example.com".to_vec() },
        ]
    }

    const UID: &str = "04A1B2C3D4E5F6";

    #[test]
    fn matches_shared_vector() {
        let canon = signed_bytes(&hex(UID), &sample());
        assert_eq!(
            crate::apdu::to_hex(&canon).replace(' ', "").to_lowercase(),
            "4e464353545544494f2d5345414c2d7631000704a1b2c3d4e5f6010000000154000000000000000802656e48656c6c6f\
             010000000155000000000000000c046578616d706c652e636f6d"
        );
        // Signed by an independent implementation (Python `cryptography`).
        let mut payload = vec![1];
        payload.extend(hex("02bd7c73b88b2e9b4ceda62022b2da8be13193a5b56edc26e7df7842e24cd0b5eb"));
        payload.extend(hex(
            "c9ee6e3f1d48913f65ce340ebde16eb3bb0e121edc693949148adc7402d61060\
             2f7a9d99f5f68f51c5310d80fb9e7297614083cdbf97a1e73e50922ef318979d",
        ));
        let mut recs = sample();
        recs.push(RawRecord { tnf: 4, rtype: SEAL_TYPE.to_vec(), id: vec![], payload });
        assert!(matches!(verify(&hex(UID), &recs).0, SealStatus::Valid { .. }));
    }

    #[test]
    fn detects_changes_and_copies() {
        let key = generate_key();
        let uid = hex(UID);
        let mut recs = sample();
        recs.push(seal_record(&key, &uid, &sample()));
        assert_eq!(recs.last().unwrap().byte_len(), SEAL_RECORD_SIZE);
        let (status, content) = verify(&uid, &recs);
        assert_eq!(status, SealStatus::Valid { key: public_key(&key) });
        assert_eq!(content, sample());

        let msg = encode_raw(&recs);
        assert_eq!(decode_raw(&msg).unwrap(), recs);

        let mut changed = recs.clone();
        changed[0].payload = b"\x02enHellO".to_vec();
        assert_eq!(verify(&uid, &changed).0, SealStatus::Broken);
        assert_eq!(verify(&hex("04A1B2C3D4E5F7"), &recs).0, SealStatus::Broken, "copied to another card");
        assert_eq!(verify(&uid, &sample()).0, SealStatus::None);
    }

    #[test]
    fn uid_rules() {
        assert_eq!(normalize_uid(&hex("0102030405060FE0")), hex("E00F060504030201"));
        assert_eq!(normalize_uid(&hex("E00F060504030201")), hex("E00F060504030201"));
        assert!(!uid_is_stable(&hex("08AABBCC")));
        assert!(uid_is_stable(&hex(UID)));
        assert_eq!(fingerprint(&[1, 2, 3]).len(), 14);
    }

    impl RawRecord {
        fn byte_len(&self) -> usize {
            encode_raw(std::slice::from_ref(self)).len()
        }
    }
}
