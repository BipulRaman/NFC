//! Thin wrapper around PC/SC (WinSCard on Windows, pcsc-lite on Linux/macOS).

use pcsc::{
    Attribute, Card, Context, Disposition, Protocols, ReaderState, Scope, ShareMode, State, MAX_BUFFER_SIZE,
};
use std::ffi::CString;
use std::time::Duration;

use crate::apdu;
use crate::tag::Tech;

pub struct Reader {
    ctx: Context,
    card: Option<Card>,
}

#[derive(Default, Clone)]
pub struct CardInfo {
    pub reader: String,
    pub atr: Vec<u8>,
    pub uid: Option<Vec<u8>>,
    pub kind: CardKind,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum CardKind {
    #[default]
    Unknown,
    MifareClassic1K,
    MifareClassic4K,
    MifareMini,
    Ultralight,
    UltralightC,
    Topaz,
    Felica,
    Iso14443_4,
    /// ISO 15693 / NFC-V "vicinity" RFID tags such as NXP ICODE, TI Tag-it and ST LRI.
    Iso15693,
    /// HID iCLASS (PicoPass) access badges; data is encrypted.
    IClass,
}

impl CardKind {
    pub fn label(self) -> &'static str {
        match self {
            CardKind::Unknown => "Unknown",
            CardKind::MifareClassic1K => "MIFARE Classic 1K",
            CardKind::MifareClassic4K => "MIFARE Classic 4K",
            CardKind::MifareMini => "MIFARE Mini",
            CardKind::Ultralight => "MIFARE Ultralight / NTAG",
            CardKind::UltralightC => "MIFARE Ultralight C",
            CardKind::Topaz => "Topaz / Jewel",
            CardKind::Felica => "FeliCa",
            CardKind::Iso14443_4 => "ISO 14443-4 (smart card / DESFire / EMV)",
            CardKind::Iso15693 => "ISO 15693 (NFC-V / ICODE / Tag-it)",
            CardKind::IClass => "HID iCLASS",
        }
    }

    /// A plain-language name for the card type.
    pub fn friendly_name(self) -> &'static str {
        match self {
            CardKind::MifareClassic1K | CardKind::MifareClassic4K | CardKind::MifareMini => "MIFARE Classic card",
            CardKind::Ultralight | CardKind::UltralightC => "NFC tag",
            CardKind::Iso14443_4 => "Smart card",
            CardKind::Topaz => "Topaz NFC tag",
            CardKind::Felica => "FeliCa card",
            CardKind::Iso15693 => "RFID tag",
            CardKind::IClass => "HID iCLASS badge",
            CardKind::Unknown => "Smart card",
        }
    }

    /// What this kind of card is commonly used for.
    pub fn description(self) -> &'static str {
        match self {
            CardKind::MifareClassic1K | CardKind::MifareClassic4K | CardKind::MifareMini => {
                "Common for access badges, hotel keys, transit and blank white cards."
            }
            CardKind::Ultralight | CardKind::UltralightC => "NTAG / Ultralight: used in stickers, key fobs, wristbands and smart posters.",
            CardKind::Iso14443_4 => "Bank, ID, transit or high-security cards, or a phone acting as a tag.",
            CardKind::Iso15693 => {
                "ISO 15693 (NFC-V) RFID tag: used for library books, laundry, ski passes, inventory and asset labels."
            }
            CardKind::IClass => "An HID iCLASS access badge. Its data is encrypted, so only its ID can be shown.",
            CardKind::Topaz | CardKind::Felica => "This card type can be identified but not read or written here.",
            CardKind::Unknown => "A chip card such as a bank card, ID or employee badge, or an unrecognised tag.",
        }
    }

    /// The technologies to try, in order, for reading this card's contents.
    pub fn techs(self) -> Vec<Tech> {
        match self {
            CardKind::MifareClassic1K | CardKind::MifareClassic4K => vec![Tech::Classic { sectors: 16 }],
            CardKind::MifareMini => vec![Tech::Classic { sectors: 5 }],
            CardKind::Ultralight | CardKind::UltralightC => vec![Tech::Type2],
            CardKind::Iso14443_4 => vec![Tech::Type4],
            CardKind::Iso15693 => vec![Tech::Type5],
            CardKind::Unknown => vec![Tech::Type2, Tech::Type4],
            CardKind::Topaz | CardKind::Felica | CardKind::IClass => Vec::new(),
        }
    }

    pub fn is_classic(self) -> bool {
        matches!(self, CardKind::MifareClassic1K | CardKind::MifareClassic4K | CardKind::MifareMini)
    }

    pub fn is_type2(self) -> bool {
        matches!(self, CardKind::Ultralight | CardKind::UltralightC)
    }
}

/// Identifies a contactless card from the PC/SC Part 3 storage-card ATR.
pub fn detect_kind(atr: &[u8]) -> CardKind {
    const RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x06];
    if atr.len() >= 15 && atr[0] == 0x3B && atr[7..12] == RID {
        // Byte 12 is the card standard (SS), bytes 13-14 the card name (NN).
        return match u16::from_be_bytes([atr[13], atr[14]]) {
            0x0001 => CardKind::MifareClassic1K,
            0x0002 => CardKind::MifareClassic4K,
            0x0026 => CardKind::MifareMini,
            0x0003 => CardKind::Ultralight,
            0x003A => CardKind::UltralightC,
            0xF004 => CardKind::Topaz,
            0xF011 | 0xF012 => CardKind::Felica,
            0x0017..=0x0020 => CardKind::IClass,
            _ => match atr[12] {
                0x09..=0x0C => CardKind::Iso15693,
                0x11 => CardKind::Felica,
                _ => CardKind::Unknown,
            },
        };
    }
    if atr.len() >= 4 && atr[0] == 0x3B && atr[1] & 0xF0 == 0x80 {
        return CardKind::Iso14443_4;
    }
    CardKind::Unknown
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RawMode {
    Transparent,
    Acr122,
}

/// Finds a BER-TLV value with a one-byte tag in a PC/SC transparent-session response.
fn tlv_find(data: &[u8], tag: u8) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 1 < data.len() {
        let t = data[i];
        let (len, hdr) = match data[i + 1] {
            0x81 if i + 2 < data.len() => (data[i + 2] as usize, 3),
            0x82 if i + 3 < data.len() => (u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize, 4),
            n => (n as usize, 2),
        };
        let start = i + hdr;
        let end = (start + len).min(data.len());
        if t == tag {
            return Some(data[start..end].to_vec());
        }
        i = end;
    }
    None
}

/// The generic status TLV (C0) reports success as `00 90 00`; it's absent on some readers.
fn transparent_ok(body: &[u8]) -> bool {
    tlv_find(body, 0xC0).is_none_or(|s| s.len() >= 3 && s[0] == 0x00 && s[1..3] == [0x90, 0x00])
}

/// TPM-backed virtual smart cards (e.g. Windows Hello for Business) always report a card but
/// aren't physical readers.
fn is_virtual_reader(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("windows hello") || lower.contains("virtual smart card")
}

impl Reader {
    pub fn new() -> Result<Self, String> {
        let ctx = Context::establish(Scope::User).map_err(|e| format!("PC/SC unavailable: {e}"))?;
        Ok(Self { ctx, card: None })
    }

    pub fn list_readers(&self) -> Result<Vec<String>, String> {
        match self.ctx.list_readers_owned() {
            Ok(r) => Ok(r
                .into_iter()
                .map(|c| c.to_string_lossy().into_owned())
                .filter(|name| !is_virtual_reader(name))
                .collect()),
            Err(pcsc::Error::NoReadersAvailable) => Ok(Vec::new()),
            Err(e) => Err(format!("Failed to list readers: {e}")),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.card.is_some()
    }

    /// Checks whether a card is on `reader` without connecting to it.
    pub fn card_present(&self, reader: &str) -> Result<bool, String> {
        let name = CString::new(reader).map_err(|e| e.to_string())?;
        let mut states = [ReaderState::new(name, State::UNAWARE)];
        match self.ctx.get_status_change(Duration::ZERO, &mut states) {
            Ok(()) | Err(pcsc::Error::Timeout) => Ok(states[0].event_state().contains(State::PRESENT)),
            Err(e) => Err(format!("Reader status: {e}")),
        }
    }

    /// Resets the card's radio session, e.g. after a failed MIFARE Classic authentication.
    pub fn reactivate(&mut self) -> Result<(), String> {
        let card = self.card.as_mut().ok_or("Not connected to a card")?;
        card.reconnect(ShareMode::Shared, Protocols::ANY, Disposition::ResetCard)
            .map_err(|e| format!("Reactivate failed: {e}"))
    }

    /// Opens a channel for raw card commands (needed for NTAG passwords), if the reader has one:
    /// a PC/SC 2.01 transparent session, or the ACR122U's PN532 pass-through.
    pub fn raw_begin(&mut self) -> Option<RawMode> {
        if let Ok(r) = self.transmit(&[0xFF, 0xC2, 0x00, 0x00, 0x02, 0x81, 0x00, 0x00]) {
            if r.ends_with(&[0x90, 0x00]) && transparent_ok(&r[..r.len() - 2]) {
                return Some(RawMode::Transparent);
            }
        }
        if let Ok(r) = self.transmit(&[0xFF, 0x00, 0x00, 0x00, 0x03, 0xD4, 0x42, 0x60]) {
            if r.len() >= 5 && r[0] == 0xD5 && r[1] == 0x43 {
                return Some(RawMode::Acr122);
            }
        }
        None
    }

    pub fn raw_end(&mut self, mode: RawMode) {
        if mode == RawMode::Transparent {
            let _ = self.transmit(&[0xFF, 0xC2, 0x00, 0x00, 0x02, 0x82, 0x00, 0x00]);
        }
    }

    /// Sends a raw frame (CRC added by the reader) and returns the card's answer.
    pub fn raw(&mut self, mode: RawMode, frame: &[u8]) -> Result<Vec<u8>, String> {
        let data = match mode {
            RawMode::Transparent => {
                let mut cmd = vec![0xFF, 0xC2, 0x00, 0x01, (frame.len() + 2) as u8, 0x95, frame.len() as u8];
                cmd.extend_from_slice(frame);
                cmd.push(0x00);
                let r = self.transmit(&cmd)?;
                let body = apdu::expect_ok(&r)?;
                if !transparent_ok(&body) {
                    return Err("No answer from the card".into());
                }
                tlv_find(&body, 0x97).unwrap_or_default()
            }
            RawMode::Acr122 => {
                let mut cmd = vec![0xFF, 0x00, 0x00, 0x00, (frame.len() + 2) as u8, 0xD4, 0x42];
                cmd.extend_from_slice(frame);
                let r = self.transmit(&cmd)?;
                let body = apdu::expect_ok(&r)?;
                if body.len() < 3 || body[..2] != [0xD5, 0x43] || body[2] != 0x00 {
                    return Err("No answer from the card".into());
                }
                body[3..].to_vec()
            }
        };
        // WRITE and PWD_AUTH answer with a 4-bit ACK (0xA); anything else is a NAK.
        if matches!(frame.first(), Some(0xA2 | 0x1B)) && data.len() == 1 && data[0] & 0x0F != 0x0A {
            return Err("The card refused the command".into());
        }
        Ok(data)
    }

    pub fn connect(&mut self, reader: &str) -> Result<CardInfo, String> {
        self.disconnect();
        let name = CString::new(reader).map_err(|e| e.to_string())?;
        let card = self
            .ctx
            .connect(&name, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| match e {
                pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard => {
                    "No card present on the reader".to_string()
                }
                e => format!("Connect failed: {e}"),
            })?;
        let atr = card.get_attribute_owned(Attribute::AtrString).unwrap_or_default();
        self.card = Some(card);
        let uid = self.transmit(&apdu::get_uid()).ok().and_then(|r| apdu::expect_ok(&r).ok());
        Ok(CardInfo { reader: reader.to_string(), kind: detect_kind(&atr), atr, uid })
    }

    pub fn disconnect(&mut self) {
        if let Some(card) = self.card.take() {
            let _ = card.disconnect(Disposition::LeaveCard);
        }
    }

    pub fn transmit(&self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let card = self.card.as_ref().ok_or("Not connected to a card")?;
        let mut buf = [0u8; MAX_BUFFER_SIZE];
        card.transmit(cmd, &mut buf)
            .map(|r| r.to_vec())
            .map_err(|e| format!("Transmit failed: {e}"))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_storage_cards_from_atr() {
        let classic = apdu::parse_hex("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A").unwrap();
        assert_eq!(detect_kind(&classic), CardKind::MifareClassic1K);
        let ntag = apdu::parse_hex("3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00 68").unwrap();
        assert_eq!(detect_kind(&ntag), CardKind::Ultralight);
        let desfire = apdu::parse_hex("3B 81 80 01 80 80").unwrap();
        assert_eq!(detect_kind(&desfire), CardKind::Iso14443_4);
        let icode = apdu::parse_hex("3B 8F 80 01 80 4F 0C A0 00 00 03 06 0B 00 14 00 00 00 00 77").unwrap();
        assert_eq!(detect_kind(&icode), CardKind::Iso15693);
        let tagit = apdu::parse_hex("3B 8F 80 01 80 4F 0C A0 00 00 03 06 0B 00 12 00 00 00 00 71").unwrap();
        assert_eq!(detect_kind(&tagit), CardKind::Iso15693);
        let iclass = apdu::parse_hex("3B 8F 80 01 80 4F 0C A0 00 00 03 06 0B 00 17 00 00 00 00 74").unwrap();
        assert_eq!(detect_kind(&iclass), CardKind::IClass);
    }

    #[test]
    fn parses_transparent_session_responses() {
        let body = apdu::parse_hex("C0 03 00 90 00 92 01 00 96 02 00 00 97 02 AB CD").unwrap();
        assert!(transparent_ok(&body));
        assert_eq!(tlv_find(&body, 0x97), Some(vec![0xAB, 0xCD]));
        assert!(!transparent_ok(&apdu::parse_hex("C0 03 01 64 01").unwrap()));
        assert!(transparent_ok(&[]));
    }
}
