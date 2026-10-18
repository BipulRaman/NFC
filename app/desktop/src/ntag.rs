//! Hardware write protection for NTAG213/215/216 and MIFARE Ultralight EV1 (NFC Forum Type 2):
//! a 32-bit write password (with an optional wrong-attempt limit) and permanent locking.
//!
//! Uses raw tag commands (GET_VERSION, READ, WRITE, PWD_AUTH) through any [`Raw`] channel.
//! The password derivation is shared with the Android app (`nfc/Type2.kt`).

use crate::tag::Transport;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

pub trait Raw {
    /// Sends one raw frame. WRITE and PWD_AUTH NAKs must be returned as `Err`.
    fn raw(&mut self, frame: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    Ntag213,
    Ntag215,
    Ntag216,
    UltralightEv1Small,
    UltralightEv1Large,
}

impl Model {
    pub fn name(self) -> &'static str {
        match self {
            Model::Ntag213 => "NTAG213",
            Model::Ntag215 => "NTAG215",
            Model::Ntag216 => "NTAG216",
            Model::UltralightEv1Small => "MIFARE Ultralight EV1 (48 bytes)",
            Model::UltralightEv1Large => "MIFARE Ultralight EV1 (128 bytes)",
        }
    }

    /// Page of CFG0; CFG1, PWD and PACK follow it.
    pub fn cfg_page(self) -> u8 {
        match self {
            Model::Ntag213 => 0x29,
            Model::Ntag215 => 0x83,
            Model::Ntag216 => 0xE3,
            Model::UltralightEv1Small => 0x10,
            Model::UltralightEv1Large => 0x25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Anyone can change the card.
    Open,
    /// Changes need the password. `limited`: the card freezes after repeated wrong passwords.
    Password { limited: bool },
    /// Read-only forever.
    Locked,
}

pub const ATTEMPT_LIMIT: u8 = 7;
const PROTECT_FROM: u8 = 4;
pub const WRONG_PASSWORD: &str = "Wrong card password.";

/// Card password → (PWD, PACK). The UID salt makes the same password different on every card.
pub fn derive(password: &str, uid: &[u8]) -> ([u8; 4], [u8; 2]) {
    let mut salt = b"NFCStudio-PWD".to_vec();
    salt.extend_from_slice(uid);
    let mut out = [0u8; 6];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 10_000, &mut out);
    ([out[0], out[1], out[2], out[3]], [out[4], out[5]])
}

pub fn identify(t: &mut impl Raw) -> Option<Model> {
    let v = t.raw(&[0x60]).ok()?;
    if v.len() < 8 || v[1] != 0x04 {
        return None;
    }
    match (v[2], v[6]) {
        (0x04, 0x0F) => Some(Model::Ntag213),
        (0x04, 0x11) => Some(Model::Ntag215),
        (0x04, 0x13) => Some(Model::Ntag216),
        (0x03, 0x0B) => Some(Model::UltralightEv1Small),
        (0x03, 0x0E) => Some(Model::UltralightEv1Large),
        _ => None,
    }
}

fn read4(t: &mut impl Raw, page: u8) -> Result<[u8; 16], String> {
    let d = t.raw(&[0x30, page])?;
    d.get(..16).and_then(|s| s.try_into().ok()).ok_or_else(|| "The card returned too little data.".into())
}

fn write(t: &mut impl Raw, page: u8, data: [u8; 4]) -> Result<(), String> {
    t.raw(&[0xA2, page, data[0], data[1], data[2], data[3]])
        .map(|_| ())
        .map_err(|_| format!("The card refused the change (page {page})."))
}

pub fn status(t: &mut impl Raw, model: Model) -> Result<Status, String> {
    let head = read4(t, 0)?;
    let cfg = read4(t, model.cfg_page())?;
    let cc_read_only = head[15] & 0x0F == 0x0F;
    let static_locked = head[10] == 0xFF && head[11] == 0xFF;
    let auth0 = cfg[3];
    let authlim = cfg[4] & 0x07;
    Ok(if cc_read_only && static_locked {
        Status::Locked
    } else if auth0 <= model.cfg_page() + 3 {
        Status::Password { limited: authlim != 0 }
    } else {
        Status::Open
    })
}

/// Proves the password for this session so protected pages can be written.
pub fn authenticate(t: &mut impl Raw, password: &str, uid: &[u8]) -> Result<(), String> {
    let (pwd, pack) = derive(password, uid);
    let r = t.raw(&[0x1B, pwd[0], pwd[1], pwd[2], pwd[3]]).map_err(|_| WRONG_PASSWORD.to_string())?;
    if r.len() < 2 || r[..2] != pack {
        // A genuine chip answers with the PACK we stored; anything else is suspicious.
        return Err("The card answered the password check incorrectly. It may be counterfeit.".into());
    }
    Ok(())
}

fn configure(t: &mut impl Raw, model: Model, auth0: u8, authlim: u8) -> Result<(), String> {
    let cfg = model.cfg_page();
    let cur = read4(t, cfg)?;
    // CFG1 first: once AUTH0 is set, the config pages themselves are protected.
    write(t, cfg + 1, [(cur[4] & 0x78) | (authlim & 0x07), cur[5], cur[6], cur[7]])?;
    write(t, cfg, [cur[0], cur[1], cur[2], auth0])
}

/// Sets or changes the write password. `current` is required when the card already has one.
pub fn set_password(
    t: &mut impl Raw,
    model: Model,
    uid: &[u8],
    new_password: &str,
    limit_attempts: bool,
    current: Option<&str>,
) -> Result<(), String> {
    match status(t, model)? {
        Status::Locked => return Err("This card is locked permanently.".into()),
        Status::Password { .. } => authenticate(t, current.ok_or(WRONG_PASSWORD)?, uid)?,
        Status::Open => {}
    }
    let (pwd, pack) = derive(new_password, uid);
    write(t, model.cfg_page() + 2, pwd)?;
    write(t, model.cfg_page() + 3, [pack[0], pack[1], 0, 0])?;
    configure(t, model, PROTECT_FROM, if limit_attempts { ATTEMPT_LIMIT } else { 0 })?;
    authenticate(t, new_password, uid).map_err(|_| "The password was set but couldn't be confirmed. Try again.".into())
}

pub fn remove_password(t: &mut impl Raw, model: Model, uid: &[u8], current: &str) -> Result<(), String> {
    authenticate(t, current, uid)?;
    configure(t, model, 0xFF, 0)?;
    write(t, model.cfg_page() + 2, [0xFF; 4])?;
    write(t, model.cfg_page() + 3, [0; 4])
}

/// Makes the card read-only forever: static lock bits and the read-only CC flag cover pages 3–15;
/// the rest is protected by a random password nobody knows, frozen after one wrong guess.
pub fn lock_forever(t: &mut impl Raw, model: Option<Model>, uid: &[u8], current: Option<&str>) -> Result<(), String> {
    let head = read4(t, 0)?;
    let user_bytes = head[14] as usize * 8;
    if model.is_none() && 16 + user_bytes > 64 {
        return Err("This tag type can't be locked permanently here.".into());
    }
    if let Some(m) = model {
        if let Status::Password { .. } = status(t, m)? {
            authenticate(t, current.ok_or(WRONG_PASSWORD)?, uid)?;
        }
        let mut secret = [0u8; 6];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
        write(t, m.cfg_page() + 2, [secret[0], secret[1], secret[2], secret[3]])?;
        write(t, m.cfg_page() + 3, [secret[4], secret[5], 0, 0])?;
        configure(t, m, PROTECT_FROM, 1)?;
    }
    write(t, 3, [head[12], head[13], head[14], head[15] | 0x0F])?;
    write(t, 2, [head[8], head[9], 0xFF, 0xFF])
}

/// Lets the PC/SC pseudo-APDU NDEF code in [`crate::tag`] run over a raw channel (after
/// [`authenticate`], in the same session).
pub struct RawTransport<'a, R: Raw>(pub &'a mut R);

impl<R: Raw> Transport for RawTransport<'_, R> {
    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let ok = |mut d: Vec<u8>| {
            d.extend_from_slice(&[0x90, 0x00]);
            Ok(d)
        };
        match cmd {
            [0xFF, 0xB0, 0x00, page, _] => match read4(self.0, *page) {
                Ok(d) => ok(d.to_vec()),
                Err(_) => Ok(vec![0x63, 0x00]),
            },
            [0xFF, 0xD6, 0x00, page, 4, a, b, c, d] => match write(self.0, *page, [*a, *b, *c, *d]) {
                Ok(()) => ok(Vec::new()),
                Err(_) => Ok(vec![0x63, 0x00]),
            },
            _ => Ok(vec![0x6D, 0x00]),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ndef::text_record;
    use crate::tag::{self, ReadOutcome, Tech};

    /// An NTAG215 that enforces static locks, AUTH0, AUTHLIM and the read-only CC.
    pub struct FakeNtag {
        pub mem: Vec<u8>,
        authed: bool,
        failures: u8,
        frozen: bool,
    }

    impl FakeNtag {
        pub fn new() -> Self {
            let mut mem = vec![0u8; 135 * 4];
            mem[..9].copy_from_slice(&[0x04, 0xA1, 0xB2, 0x5F, 0xC3, 0xD4, 0xE5, 0xF6, 0x41]);
            mem[12..16].copy_from_slice(&[0xE1, 0x10, 0x3E, 0x00]);
            mem[16..20].copy_from_slice(&[0x03, 0x00, 0xFE, 0x00]);
            let cfg = 0x83 * 4;
            mem[cfg..cfg + 4].copy_from_slice(&[0x04, 0x00, 0x00, 0xFF]);
            mem[cfg + 8..cfg + 12].copy_from_slice(&[0xFF; 4]);
            Self { mem, authed: false, failures: 0, frozen: false }
        }

        pub fn uid(&self) -> Vec<u8> {
            [&self.mem[..3], &self.mem[4..8]].concat()
        }

        /// Removing the card from the field ends the authenticated session.
        pub fn reset(&mut self) {
            self.authed = false;
        }

        fn cfg(&self, i: usize) -> u8 {
            self.mem[0x83 * 4 + i]
        }

        fn writable(&self, page: usize) -> bool {
            let lock = u16::from_le_bytes([self.mem[10], self.mem[11]]);
            match page {
                0..=1 => false,
                2 => true,
                3..=15 => lock & (1 << page) == 0,
                _ => page < 135,
            }
        }
    }

    impl Raw for FakeNtag {
        fn raw(&mut self, f: &[u8]) -> Result<Vec<u8>, String> {
            match f[0] {
                0x60 => Ok(vec![0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03]),
                0x30 => {
                    let p = f[1] as usize * 4;
                    let mut d: Vec<u8> = (p..p + 16).map(|i| self.mem.get(i).copied().unwrap_or(0)).collect();
                    for (k, i) in (p..p + 16).enumerate() {
                        if (0x85 * 4..0x87 * 4).contains(&i) {
                            d[k] = 0; // PWD and PACK read as zero
                        }
                    }
                    Ok(d)
                }
                0xA2 => {
                    let page = f[1] as usize;
                    let auth0 = self.cfg(3) as usize;
                    if !self.writable(page) || (page >= auth0 && !self.authed) {
                        return Err("NAK".into());
                    }
                    let p = page * 4;
                    match page {
                        2 => {
                            self.mem[p + 2] |= f[4];
                            self.mem[p + 3] |= f[5];
                        }
                        3 => (0..4).for_each(|i| self.mem[p + i] |= f[2 + i]),
                        _ => self.mem[p..p + 4].copy_from_slice(&f[2..6]),
                    }
                    Ok(vec![0x0A])
                }
                0x1B => {
                    let limit = self.cfg(4) & 0x07;
                    let pwd = &self.mem[0x85 * 4..0x85 * 4 + 4];
                    if !self.frozen && f[1..5] == *pwd {
                        self.failures = 0;
                        self.authed = true;
                        return Ok(self.mem[0x86 * 4..0x86 * 4 + 2].to_vec());
                    }
                    self.failures += 1;
                    if limit != 0 && self.failures >= limit {
                        self.frozen = true;
                    }
                    Err("NAK".into())
                }
                _ => Err("unsupported".into()),
            }
        }
    }

    fn write_text(t: &mut FakeNtag, text: &str) -> Result<(), String> {
        tag::write(&mut RawTransport(t), Tech::Type2, &[text_record(text, "en")])
    }

    fn read_text(t: &mut FakeNtag) -> String {
        match tag::read(&mut RawTransport(t), Tech::Type2).unwrap() {
            ReadOutcome::Ndef(c) => c.records.first().map(|r| r.summary()).unwrap_or_default(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn derivation_matches_shared_vector() {
        let uid = crate::apdu::parse_hex("04A1B2C3D4E5F6").unwrap();
        let (pwd, pack) = derive("correct horse", &uid);
        assert_eq!([pwd.as_slice(), &pack].concat(), crate::apdu::parse_hex("fffcc6c0aef8").unwrap());
    }

    #[test]
    fn password_blocks_changes_until_authenticated() {
        let mut t = FakeNtag::new();
        let uid = t.uid();
        assert_eq!(identify(&mut t), Some(Model::Ntag215));
        assert_eq!(status(&mut t, Model::Ntag215).unwrap(), Status::Open);
        write_text(&mut t, "original").unwrap();

        set_password(&mut t, Model::Ntag215, &uid, "s3cret", true, None).unwrap();
        t.reset();
        assert_eq!(status(&mut t, Model::Ntag215).unwrap(), Status::Password { limited: true });
        assert!(write_text(&mut t, "tampered").is_err(), "writes need the password");
        assert_eq!(read_text(&mut t), "original", "still readable");

        assert_eq!(authenticate(&mut t, "wrong", &uid).unwrap_err(), WRONG_PASSWORD);
        authenticate(&mut t, "s3cret", &uid).unwrap();
        write_text(&mut t, "updated").unwrap();
        t.reset();
        assert_eq!(read_text(&mut t), "updated");

        assert!(set_password(&mut t, Model::Ntag215, &uid, "new", false, Some("bad")).is_err());
        set_password(&mut t, Model::Ntag215, &uid, "new", false, Some("s3cret")).unwrap();
        t.reset();
        assert_eq!(status(&mut t, Model::Ntag215).unwrap(), Status::Password { limited: false });
        remove_password(&mut t, Model::Ntag215, &uid, "new").unwrap();
        t.reset();
        assert_eq!(status(&mut t, Model::Ntag215).unwrap(), Status::Open);
        write_text(&mut t, "free again").unwrap();
    }

    #[test]
    fn attempt_limit_freezes_the_card() {
        let mut t = FakeNtag::new();
        let uid = t.uid();
        set_password(&mut t, Model::Ntag215, &uid, "pin", true, None).unwrap();
        for _ in 0..ATTEMPT_LIMIT {
            assert!(authenticate(&mut t, "guess", &uid).is_err());
        }
        assert!(authenticate(&mut t, "pin", &uid).is_err(), "frozen even with the right password");
    }

    #[test]
    fn lock_forever_is_permanent() {
        let mut t = FakeNtag::new();
        let uid = t.uid();
        write_text(&mut t, "final").unwrap();
        set_password(&mut t, Model::Ntag215, &uid, "pw", false, None).unwrap();
        t.reset();
        assert!(lock_forever(&mut t, Some(Model::Ntag215), &uid, Some("nope")).is_err());
        lock_forever(&mut t, Some(Model::Ntag215), &uid, Some("pw")).unwrap();
        t.reset();
        assert_eq!(status(&mut t, Model::Ntag215).unwrap(), Status::Locked);
        assert!(authenticate(&mut t, "pw", &uid).is_err());
        assert!(write_text(&mut t, "changed").is_err());
        assert_eq!(read_text(&mut t), "final");
        match tag::read(&mut RawTransport(&mut t), Tech::Type2).unwrap() {
            ReadOutcome::Ndef(c) => assert!(!c.writable),
            other => panic!("{other:?}"),
        }
    }
}
