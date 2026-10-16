//! Thin wrapper around PC/SC (WinSCard on Windows, pcsc-lite on Linux/macOS).

use pcsc::{Attribute, Card, Context, Disposition, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use std::ffi::CString;

use crate::apdu;

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
        return match u16::from_be_bytes([atr[13], atr[14]]) {
            0x0001 => CardKind::MifareClassic1K,
            0x0002 => CardKind::MifareClassic4K,
            0x0026 => CardKind::MifareMini,
            0x0003 => CardKind::Ultralight,
            0x003A => CardKind::UltralightC,
            0xF004 => CardKind::Topaz,
            0xF011 | 0xF012 => CardKind::Felica,
            _ => CardKind::Unknown,
        };
    }
    if atr.len() >= 4 && atr[0] == 0x3B && atr[1] & 0xF0 == 0x80 {
        return CardKind::Iso14443_4;
    }
    CardKind::Unknown
}

impl Reader {
    pub fn new() -> Result<Self, String> {
        let ctx = Context::establish(Scope::User).map_err(|e| format!("PC/SC unavailable: {e}"))?;
        Ok(Self { ctx, card: None })
    }

    pub fn list_readers(&self) -> Result<Vec<String>, String> {
        match self.ctx.list_readers_owned() {
            Ok(r) => Ok(r.into_iter().map(|c| c.to_string_lossy().into_owned()).collect()),
            Err(pcsc::Error::NoReadersAvailable) => Ok(Vec::new()),
            Err(e) => Err(format!("Failed to list readers: {e}")),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.card.is_some()
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
    }
}
