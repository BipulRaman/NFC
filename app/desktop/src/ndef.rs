//! Minimal NDEF codec (NFC Forum Type 2 TLV + Text/URI well-known records).

const URI_PREFIXES: [&str; 36] = [
    "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
    "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://",
    "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:",
    "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://",
    "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
    "urn:nfc:",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    Text { lang: String, text: String },
    Uri(String),
    Other { tnf: u8, rtype: Vec<u8>, payload: Vec<u8> },
}

impl std::fmt::Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Record::Text { lang, text } => write!(f, "Text [{lang}]: {text}"),
            Record::Uri(u) => write!(f, "URI: {u}"),
            Record::Other { tnf, rtype, payload } => write!(
                f,
                "TNF {tnf}, type '{}', {} byte payload: {}",
                String::from_utf8_lossy(rtype),
                payload.len(),
                crate::apdu::to_hex(payload)
            ),
        }
    }
}

pub fn text_record(text: &str, lang: &str) -> Record {
    Record::Text { lang: lang.to_string(), text: text.to_string() }
}

pub fn uri_record(uri: &str) -> Record {
    Record::Uri(uri.to_string())
}

fn record_parts(r: &Record) -> (u8, Vec<u8>, Vec<u8>) {
    match r {
        Record::Text { lang, text } => {
            let mut p = vec![lang.len() as u8 & 0x3F];
            p.extend_from_slice(lang.as_bytes());
            p.extend_from_slice(text.as_bytes());
            (0x01, b"T".to_vec(), p)
        }
        Record::Uri(uri) => {
            // Longest matching prefix wins (index 0 = no prefix).
            let (code, prefix) = URI_PREFIXES
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(_, p)| uri.starts_with(**p))
                .max_by_key(|(_, p)| p.len())
                .map(|(i, p)| (i as u8, *p))
                .unwrap_or((0, ""));
            let mut p = vec![code];
            p.extend_from_slice(uri[prefix.len()..].as_bytes());
            (0x01, b"U".to_vec(), p)
        }
        Record::Other { tnf, rtype, payload } => (*tnf, rtype.clone(), payload.clone()),
    }
}

/// Encodes records into an NDEF message.
pub fn encode_message(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, r) in records.iter().enumerate() {
        let (tnf, rtype, payload) = record_parts(r);
        let mut hdr = tnf & 0x07;
        if i == 0 {
            hdr |= 0x80; // MB
        }
        if i == records.len() - 1 {
            hdr |= 0x40; // ME
        }
        let short = payload.len() < 256;
        if short {
            hdr |= 0x10; // SR
        }
        out.push(hdr);
        out.push(rtype.len() as u8);
        if short {
            out.push(payload.len() as u8);
        } else {
            out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        out.extend_from_slice(&rtype);
        out.extend_from_slice(&payload);
    }
    out
}

/// Decodes an NDEF message into records.
pub fn decode_message(data: &[u8]) -> Result<Vec<Record>, String> {
    let mut recs = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let hdr = data[i];
        let tnf = hdr & 0x07;
        let short = hdr & 0x10 != 0;
        let has_id = hdr & 0x08 != 0;
        i += 1;
        let need = |i: usize, n: usize| {
            if i + n > data.len() { Err("Truncated NDEF record".to_string()) } else { Ok(()) }
        };
        need(i, 1)?;
        let type_len = data[i] as usize;
        i += 1;
        let payload_len = if short {
            need(i, 1)?;
            i += 1;
            data[i - 1] as usize
        } else {
            need(i, 4)?;
            i += 4;
            u32::from_be_bytes([data[i - 4], data[i - 3], data[i - 2], data[i - 1]]) as usize
        };
        let id_len = if has_id {
            need(i, 1)?;
            i += 1;
            data[i - 1] as usize
        } else {
            0
        };
        need(i, type_len + id_len + payload_len)?;
        let rtype = data[i..i + type_len].to_vec();
        i += type_len + id_len;
        let payload = data[i..i + payload_len].to_vec();
        i += payload_len;

        let rec = match (tnf, rtype.as_slice()) {
            (0x01, b"T") if !payload.is_empty() => {
                let lang_len = (payload[0] & 0x3F) as usize;
                let lang_end = (1 + lang_len).min(payload.len());
                Record::Text {
                    lang: String::from_utf8_lossy(&payload[1..lang_end]).into_owned(),
                    text: String::from_utf8_lossy(&payload[lang_end..]).into_owned(),
                }
            }
            (0x01, b"U") if !payload.is_empty() => {
                let prefix = URI_PREFIXES.get(payload[0] as usize).copied().unwrap_or("");
                Record::Uri(format!("{prefix}{}", String::from_utf8_lossy(&payload[1..])))
            }
            _ => Record::Other { tnf, rtype, payload },
        };
        recs.push(rec);
        if hdr & 0x40 != 0 {
            break;
        }
    }
    Ok(recs)
}

/// Wraps an NDEF message in a Type 2 tag TLV (0x03) followed by a terminator TLV (0xFE).
pub fn wrap_tlv(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0x03];
    if message.len() < 0xFF {
        out.push(message.len() as u8);
    } else {
        out.push(0xFF);
        out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(message);
    out.push(0xFE);
    out
}

/// Finds the NDEF message TLV in Type 2 tag user memory.
pub fn find_ndef_tlv(mem: &[u8]) -> Result<Vec<u8>, String> {
    let mut i = 0;
    while i < mem.len() {
        let t = mem[i];
        match t {
            0x00 => {
                i += 1;
                continue;
            }
            0xFE => break,
            _ => {}
        }
        if i + 1 >= mem.len() {
            break;
        }
        let (len, hdr) = if mem[i + 1] == 0xFF {
            if i + 3 >= mem.len() {
                break;
            }
            (u16::from_be_bytes([mem[i + 2], mem[i + 3]]) as usize, 4)
        } else {
            (mem[i + 1] as usize, 2)
        };
        let start = i + hdr;
        if t == 0x03 {
            if start + len > mem.len() {
                return Err("NDEF TLV extends past read memory".into());
            }
            return Ok(mem[start..start + len].to_vec());
        }
        i = start + len;
    }
    Err("No NDEF message TLV found".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_round_trip_with_prefix_compression() {
        let msg = encode_message(&[uri_record("https://www.rust-lang.org")]);
        assert_eq!(msg[..5], [0xD1, 0x01, 0x0E, b'U', 0x02]);
        assert_eq!(decode_message(&msg).unwrap(), vec![uri_record("https://www.rust-lang.org")]);
    }

    #[test]
    fn multi_record_round_trip_through_tlv() {
        let recs = vec![text_record("Hello NFC", "en"), uri_record("tel:+123")];
        let mem = wrap_tlv(&encode_message(&recs));
        let mut padded = vec![0x00];
        padded.extend(mem);
        padded.extend([0u8; 8]);
        let msg = find_ndef_tlv(&padded).unwrap();
        assert_eq!(decode_message(&msg).unwrap(), recs);
    }

    #[test]
    fn long_payload_uses_long_record() {
        let text = "x".repeat(300);
        let msg = encode_message(&[text_record(&text, "en")]);
        assert_eq!(msg[0] & 0x10, 0);
        assert_eq!(decode_message(&msg).unwrap(), vec![text_record(&text, "en")]);
        let tlv = wrap_tlv(&msg);
        assert_eq!(tlv[1], 0xFF);
        assert_eq!(find_ndef_tlv(&tlv).unwrap(), msg);
    }
}
