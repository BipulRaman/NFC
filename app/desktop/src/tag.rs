//! Friendly "what's on this card" reading and writing for common NFC cards.
//!
//! Works over any [`Transport`] that sends PC/SC pseudo-APDUs, so it can be tested without a reader.

use crate::apdu::{self, KeyType};
use crate::ndef::{self, Record, TlvScan};

pub trait Transport {
    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String>;

    /// Re-activates the card; MIFARE Classic cards stop answering after a failed authentication.
    fn reactivate(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn send_ok(&mut self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        let resp = self.transmit(cmd)?;
        apdu::expect_ok(&resp)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tech {
    /// NFC Forum Type 2: NTAG21x and MIFARE Ultralight stickers, fobs and wristbands.
    Type2,
    /// NFC Forum Type 4: DESFire / NTAG 424 NDEF applications and phones emulating a tag.
    Type4,
    /// MIFARE Classic with the given number of sectors (16 for 1K; only the first 16 are used).
    Classic { sectors: u8 },
    /// NFC Forum Type 5: ISO 15693 / NFC-V RFID tags such as NXP ICODE SLIX.
    Type5,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TagContent {
    pub tech: Tech,
    pub records: Vec<Record>,
    /// Bytes currently used by the stored message.
    pub used: usize,
    /// Bytes available for messages.
    pub capacity: usize,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReadOutcome {
    Ndef(TagContent),
    /// A blank card that isn't set up for messages yet; [`format`] prepares it.
    Blank(Tech),
    /// The card answered but its contents can't be shown; the text explains why.
    Unsupported(String),
}

pub const NFC_KEY_A: [u8; 6] = [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7];
pub const MAD_KEY_A: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
pub const FACTORY_KEY: [u8; 6] = [0xFF; 6];
const NDEF_AID: [u8; 7] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

pub const SECURE_CARD: &str = "This is a secure smart card, such as a bank, ID or transit card. \
     Its data is protected, so there's nothing that can be shown or changed here.";
const DAMAGED: &str = "The data on this card looks damaged. Erasing the card will fix it.";

pub fn read(t: &mut impl Transport, tech: Tech) -> Result<ReadOutcome, String> {
    match tech {
        Tech::Type2 => read_type2(t),
        Tech::Type4 => read_type4(t),
        Tech::Classic { sectors } => read_classic(t, sectors),
        Tech::Type5 => read_type5(t),
    }
}

/// Replaces the card's contents with `records`; an empty slice erases the card.
pub fn write(t: &mut impl Transport, tech: Tech, records: &[Record]) -> Result<(), String> {
    let msg = ndef::encode_message(records);
    match tech {
        Tech::Type2 => write_type2(t, &msg),
        Tech::Type4 => write_type4(t, &msg),
        Tech::Classic { sectors } => write_classic(t, sectors, &msg),
        Tech::Type5 => write_type5(t, &msg),
    }
}

/// Whether a blank card of this technology can be set up here.
pub fn can_format(tech: Tech) -> bool {
    matches!(tech, Tech::Classic { sectors: 16 } | Tech::Type5)
}

/// Sets up a blank card to hold NFC messages.
pub fn format(t: &mut impl Transport, tech: Tech) -> Result<(), String> {
    match tech {
        Tech::Classic { sectors } => format_classic(t, sectors),
        Tech::Type5 => format_type5(t),
        _ => Err("This card type can't be set up here.".into()),
    }
}

/// Bytes `records` will occupy on a card, comparable with [`TagContent::capacity`].
pub fn encoded_size(tech: Tech, records: &[Record]) -> usize {
    let msg = ndef::encode_message(records);
    match tech {
        Tech::Type4 => msg.len(),
        _ => ndef::wrap_tlv(&msg).len() - 1,
    }
}

fn too_big(needed: usize, capacity: usize) -> String {
    format!("That's too much for this card: it needs {needed} bytes but the card only holds {capacity}.")
}

fn empty(tech: Tech, capacity: usize, writable: bool) -> ReadOutcome {
    ReadOutcome::Ndef(TagContent { tech, records: Vec::new(), used: 0, capacity, writable })
}

/// Lays out an NDEF message as a TLV for `capacity` bytes, dropping the terminator if it won't fit.
fn tlv_for(msg: &[u8], capacity: usize, align: usize) -> Result<Vec<u8>, String> {
    let mut bytes = ndef::wrap_tlv(msg);
    let needed = bytes.len() - 1;
    if needed > capacity {
        return Err(too_big(needed, capacity));
    }
    if bytes.len() > capacity {
        bytes.pop();
    }
    while bytes.len() % align != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn scan_memory(mem: &[u8], tech: Tech, capacity: usize, writable: bool) -> Result<Option<ReadOutcome>, String> {
    let view = &mem[..mem.len().min(capacity)];
    match ndef::scan_tlv(view) {
        TlvScan::Found(msg, used) => Ok(Some(ReadOutcome::Ndef(TagContent {
            tech,
            records: ndef::decode_message(&msg).map_err(|_| DAMAGED.to_string())?,
            used,
            capacity,
            writable,
        }))),
        TlvScan::Empty => Ok(Some(empty(tech, capacity, writable))),
        TlvScan::Incomplete if view.len() >= capacity => {
            if view.iter().all(|&b| b == 0) {
                Ok(Some(empty(tech, capacity, writable)))
            } else {
                Err(DAMAGED.into())
            }
        }
        TlvScan::Incomplete => Ok(None),
    }
}

// ---- Type 2 (NTAG / Ultralight) -------------------------------------------

struct Type2Info {
    capacity: usize,
    writable: bool,
}

fn type2_info(head: &[u8]) -> Result<Option<Type2Info>, String> {
    if head.len() < 4 {
        return Err("The tag returned too little data.".into());
    }
    if head[0] != 0xE1 {
        return Ok(None);
    }
    Ok(Some(Type2Info { capacity: head[2] as usize * 8, writable: head[3] & 0x0F == 0 }))
}

fn read_type2(t: &mut impl Transport) -> Result<ReadOutcome, String> {
    let head = t.send_ok(&apdu::read_binary(3, 16))?;
    let Some(info) = type2_info(&head)? else {
        return Ok(ReadOutcome::Unsupported("This tag isn't set up for NFC messages.".into()));
    };
    let mut mem = head[4..].to_vec();
    let mut page: u16 = 7;
    loop {
        if let Some(out) = scan_memory(&mem, Tech::Type2, info.capacity, info.writable)? {
            return Ok(out);
        }
        if page > 255 {
            return Err(DAMAGED.into());
        }
        mem.extend(t.send_ok(&apdu::read_binary(page as u8, 16))?);
        page += 4;
    }
}

fn write_type2(t: &mut impl Transport, msg: &[u8]) -> Result<(), String> {
    let head = t.send_ok(&apdu::read_binary(3, 16))?;
    let Some(info) = type2_info(&head)? else {
        return Err("This tag isn't set up for NFC messages, so it can't be written.".into());
    };
    if !info.writable {
        return Err("This tag is locked (read-only), so it can't be changed.".into());
    }
    let bytes = tlv_for(msg, info.capacity, 4)?;
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let page = 4 + i;
        let page = u8::try_from(page).map_err(|_| too_big(bytes.len(), info.capacity))?;
        t.send_ok(&apdu::update_binary(page, chunk))
            .map_err(|e| format!("Writing stopped part-way (page {page}): {e}"))?;
    }
    Ok(())
}

// ---- Type 4 (ISO-DEP NDEF application) ------------------------------------

struct Type4Info {
    max_read: usize,
    max_write: usize,
    capacity: usize,
    writable: bool,
}

fn open_type4(t: &mut impl Transport) -> Result<Option<Type4Info>, String> {
    if t.send_ok(&apdu::select_aid(&NDEF_AID)).is_err() {
        return Ok(None);
    }
    t.send_ok(&apdu::select_file(0xE103))?;
    let cc = t.send_ok(&apdu::iso_read_binary(0, 15))?;
    if cc.len() < 15 || cc[7] != 0x04 {
        return Err("The card's NFC settings couldn't be understood.".into());
    }
    let word = |i: usize| u16::from_be_bytes([cc[i], cc[i + 1]]) as usize;
    let info = Type4Info {
        max_read: word(3).clamp(1, 0xFF),
        max_write: word(5).clamp(1, 0xFF),
        capacity: word(11).saturating_sub(2),
        writable: cc[14] == 0x00,
    };
    t.send_ok(&apdu::select_file(word(9) as u16))?;
    Ok(Some(info))
}

fn read_type4(t: &mut impl Transport) -> Result<ReadOutcome, String> {
    let Some(info) = open_type4(t)? else {
        return Ok(ReadOutcome::Unsupported(SECURE_CARD.into()));
    };
    let nlen = t.send_ok(&apdu::iso_read_binary(0, 2))?;
    if nlen.len() < 2 {
        return Err(DAMAGED.into());
    }
    let len = u16::from_be_bytes([nlen[0], nlen[1]]) as usize;
    if len > info.capacity {
        return Err(DAMAGED.into());
    }
    let mut msg = Vec::with_capacity(len);
    while msg.len() < len {
        let n = (len - msg.len()).min(info.max_read);
        let chunk = t.send_ok(&apdu::iso_read_binary((2 + msg.len()) as u16, n as u8))?;
        if chunk.is_empty() {
            return Err(DAMAGED.into());
        }
        msg.extend(chunk);
    }
    msg.truncate(len);
    let records = ndef::decode_message(&msg).map_err(|_| DAMAGED.to_string())?;
    Ok(ReadOutcome::Ndef(TagContent {
        tech: Tech::Type4,
        records,
        used: len,
        capacity: info.capacity,
        writable: info.writable,
    }))
}

fn write_type4(t: &mut impl Transport, msg: &[u8]) -> Result<(), String> {
    let Some(info) = open_type4(t)? else {
        return Err("This card has no space for NFC messages.".into());
    };
    if !info.writable {
        return Err("This card is locked (read-only), so it can't be changed.".into());
    }
    if msg.len() > info.capacity {
        return Err(too_big(msg.len(), info.capacity));
    }
    // Clear the length first so a half-finished write never looks valid.
    t.send_ok(&apdu::iso_update_binary(0, &[0, 0]))?;
    for (i, chunk) in msg.chunks(info.max_write).enumerate() {
        let offset = 2 + i * info.max_write;
        t.send_ok(&apdu::iso_update_binary(offset as u16, chunk))
            .map_err(|e| format!("Writing stopped part-way: {e}"))?;
    }
    t.send_ok(&apdu::iso_update_binary(0, &(msg.len() as u16).to_be_bytes()))?;
    Ok(())
}

// ---- Type 5 (ISO 15693 / NFC-V) ------------------------------------------

const FOREIGN_DATA: &str = "This RFID tag holds data in another system's format (for example a library or \
     inventory system), so it isn't shown or changed here. Advanced tools can show its raw memory.";

/// Reader access to an ISO 15693 tag's blocks through PC/SC READ/UPDATE BINARY.
struct Type5Mem {
    /// Le used for reads (4, or 0 for readers that want "whole block").
    le: u8,
    block: usize,
    /// Memory read so far, starting at block 0.
    mem: Vec<u8>,
}

impl Type5Mem {
    fn open(t: &mut impl Transport) -> Result<Self, String> {
        for le in [4u8, 0] {
            if let Ok(d) = t.send_ok(&apdu::read_binary(0, le)) {
                if matches!(d.len(), 4 | 8 | 16 | 32) {
                    return Ok(Self { le, block: d.len(), mem: d });
                }
            }
        }
        Err("Couldn't read this RFID tag's memory with this reader.".into())
    }

    /// Reads the next block; `None` when the tag has no more blocks.
    fn read_next(&mut self, t: &mut impl Transport) -> Result<Option<()>, String> {
        let n = self.mem.len() / self.block;
        let Ok(n) = u8::try_from(n) else { return Ok(None) };
        match t.send_ok(&apdu::read_binary(n, self.le)) {
            Ok(d) if d.len() == self.block => {
                self.mem.extend(d);
                Ok(Some(()))
            }
            _ => Ok(None),
        }
    }

    fn ensure(&mut self, t: &mut impl Transport, len: usize) -> Result<bool, String> {
        while self.mem.len() < len {
            if self.read_next(t)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn write(&self, t: &mut impl Transport, first: usize, data: &[u8]) -> Result<(), String> {
        for (i, chunk) in data.chunks(self.block).enumerate() {
            let block = u8::try_from(first + i).map_err(|_| "The tag is too small for this.".to_string())?;
            let mut buf = chunk.to_vec();
            buf.resize(self.block, 0);
            t.send_ok(&apdu::update_binary(block, &buf))
                .map_err(|e| format!("Writing stopped part-way (block {block}): {e}"))?;
        }
        Ok(())
    }
}

struct Type5Cc {
    len: usize,
    capacity: usize,
    writable: bool,
}

/// Parses the NFC Forum Type 5 capability container (4 or 8 bytes) at the start of memory.
fn type5_cc(mem: &[u8]) -> Option<Type5Cc> {
    if mem.len() < 4 || !matches!(mem[0], 0xE1 | 0xE2) {
        return None;
    }
    let writable = mem[1] & 0x03 == 0;
    if mem[2] != 0 {
        return Some(Type5Cc { len: 4, capacity: (mem[2] as usize * 8).saturating_sub(4), writable });
    }
    if mem.len() < 8 {
        return None;
    }
    let mlen = u16::from_be_bytes([mem[6], mem[7]]) as usize;
    Some(Type5Cc { len: 8, capacity: (mlen * 8).saturating_sub(8), writable })
}

fn read_type5(t: &mut impl Transport) -> Result<ReadOutcome, String> {
    let mut m = Type5Mem::open(t)?;
    m.ensure(t, 8)?;
    let Some(cc) = type5_cc(&m.mem) else {
        return Ok(if m.mem.iter().all(|&b| b == 0) {
            ReadOutcome::Blank(Tech::Type5)
        } else {
            ReadOutcome::Unsupported(FOREIGN_DATA.into())
        });
    };
    loop {
        if m.mem.len() > cc.len {
            if let Some(out) = scan_memory(&m.mem[cc.len..], Tech::Type5, cc.capacity, cc.writable)? {
                return Ok(out);
            }
        }
        if m.read_next(t)?.is_none() {
            // The tag ended before the message did.
            let view = m.mem.get(cc.len..).unwrap_or_default();
            return scan_memory(view, Tech::Type5, view.len(), cc.writable)?.ok_or_else(|| DAMAGED.into());
        }
    }
}

fn write_type5(t: &mut impl Transport, msg: &[u8]) -> Result<(), String> {
    let mut m = Type5Mem::open(t)?;
    m.ensure(t, 8)?;
    let Some(cc) = type5_cc(&m.mem) else {
        return Err("This tag isn't set up for NFC messages yet. Set it up first.".into());
    };
    if !cc.writable {
        return Err("This tag is locked (read-only), so it can't be changed.".into());
    }
    let tlv = tlv_for(msg, cc.capacity, 1)?;
    // The CC may share a block with the start of the message (8-byte blocks).
    let first = cc.len / m.block;
    let mut data = m.mem[first * m.block..cc.len].to_vec();
    data.extend(tlv);
    m.write(t, first, &data)
}

/// Sets up a blank ISO 15693 tag to hold NFC messages (NFC Forum Type 5 layout).
pub fn format_type5(t: &mut impl Transport) -> Result<(), String> {
    let mut m = Type5Mem::open(t)?;
    while m.read_next(t)?.is_some() {}
    if !m.mem.iter().all(|&b| b == 0) {
        return Err("This tag already holds data, so it won't be overwritten.".into());
    }
    let total = m.mem.len();
    if total < 16 {
        return Err("This tag is too small to hold messages.".into());
    }
    let mlen = total / 8;
    let mut data = match u8::try_from(mlen) {
        Ok(n) => vec![0xE1, 0x40, n, 0x00],
        Err(_) => {
            let [hi, lo] = (mlen.min(0xFFFF) as u16).to_be_bytes();
            vec![0xE2, 0x40, 0x00, 0x00, 0x00, 0x00, hi, lo]
        }
    };
    data.extend([0x03, 0x00, 0xFE]);
    m.write(t, 0, &data)
}

// ---- MIFARE Classic (NFC Forum MAD layout) --------------------------------

fn classic_auth(t: &mut impl Transport, block: u8, key: &[u8; 6], kt: KeyType) -> Result<(), String> {
    let r = t
        .send_ok(&apdu::load_key(0, key))
        .and_then(|_| t.send_ok(&apdu::authenticate(block, kt, 0)));
    if r.is_err() {
        let _ = t.reactivate();
    }
    r.map(|_| ())
}

fn classic_capacity(sectors: u8) -> usize {
    (sectors.clamp(2, 16) as usize - 1) * 48
}

fn read_classic(t: &mut impl Transport, sectors: u8) -> Result<ReadOutcome, String> {
    if classic_auth(t, 4, &NFC_KEY_A, KeyType::A).is_err() {
        return Ok(if classic_auth(t, 4, &FACTORY_KEY, KeyType::A).is_ok() {
            ReadOutcome::Blank(Tech::Classic { sectors })
        } else {
            ReadOutcome::Unsupported(
                "This MIFARE Classic card is protected with private keys (for example an office or \
                 transit card), so its contents can't be read here."
                    .into(),
            )
        });
    }
    let tech = Tech::Classic { sectors };
    let capacity = classic_capacity(sectors);
    let mut mem = Vec::new();
    for sector in 1..sectors.min(16) {
        if sector > 1 && classic_auth(t, sector * 4, &NFC_KEY_A, KeyType::A).is_err() {
            break;
        }
        for b in 0..3 {
            mem.extend(t.send_ok(&apdu::read_binary(sector * 4 + b, 16))?);
        }
        if let Some(out) = scan_memory(&mem, tech, capacity, true)? {
            return Ok(out);
        }
    }
    scan_memory(&mem, tech, mem.len(), true)?.ok_or_else(|| DAMAGED.into())
}

fn write_classic(t: &mut impl Transport, sectors: u8, msg: &[u8]) -> Result<(), String> {
    let bytes = tlv_for(msg, classic_capacity(sectors), 16)?;
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let sector = 1 + (i / 3) as u8;
        let block = sector * 4 + (i % 3) as u8;
        if i % 3 == 0 {
            classic_auth(t, block, &FACTORY_KEY, KeyType::B)
                .or_else(|_| classic_auth(t, block, &NFC_KEY_A, KeyType::A))
                .map_err(|_| "This card is write-protected, so it can't be changed.".to_string())?;
        }
        t.send_ok(&apdu::update_binary(block, chunk))
            .map_err(|e| format!("Writing stopped part-way (sector {sector}): {e}"))?;
    }
    Ok(())
}

/// CRC-8 of a MIFARE Application Directory (polynomial 0x1D, preset 0xC7).
fn mad_crc(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xC7;
    for &b in data {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x1D } else { crc << 1 };
        }
    }
    crc
}

fn trailer(key_a: &[u8; 6], access: [u8; 4]) -> Vec<u8> {
    let mut t = key_a.to_vec();
    t.extend_from_slice(&access);
    t.extend_from_slice(&FACTORY_KEY);
    t
}

/// Sets up a blank MIFARE Classic 1K card (factory keys) to hold NFC messages, the same way phones
/// and NXP TagWriter do. Key B stays at the factory value so the card can be reset later.
pub fn format_classic(t: &mut impl Transport, sectors: u8) -> Result<(), String> {
    if sectors != 16 {
        return Err("Only MIFARE Classic 1K cards can be set up here.".into());
    }
    let mut mad = [0u8; 32];
    mad[1] = 0x01;
    for s in 1..16 {
        mad[s * 2] = 0x03;
        mad[s * 2 + 1] = 0xE1;
    }
    mad[0] = mad_crc(&mad[1..]);

    let not_blank = |_| "This card isn't blank (it doesn't use factory keys), so it can't be set up.".to_string();
    classic_auth(t, 0, &FACTORY_KEY, KeyType::A).map_err(not_blank)?;
    t.send_ok(&apdu::update_binary(1, &mad[..16]))?;
    t.send_ok(&apdu::update_binary(2, &mad[16..]))?;
    t.send_ok(&apdu::update_binary(3, &trailer(&MAD_KEY_A, [0x78, 0x77, 0x88, 0xC1])))?;

    for s in 1..16u8 {
        classic_auth(t, s * 4, &FACTORY_KEY, KeyType::A).map_err(not_blank)?;
        let mut first = [0u8; 16];
        if s == 1 {
            first[..3].copy_from_slice(&[0x03, 0x00, 0xFE]);
        }
        t.send_ok(&apdu::update_binary(s * 4, &first))?;
        t.send_ok(&apdu::update_binary(s * 4 + 1, &[0; 16]))?;
        t.send_ok(&apdu::update_binary(s * 4 + 2, &[0; 16]))?;
        t.send_ok(&apdu::update_binary(s * 4 + 3, &trailer(&NFC_KEY_A, [0x7F, 0x07, 0x88, 0x40])))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndef::{text_record, uri_record};

    const OK: [u8; 2] = [0x90, 0x00];
    const FAIL: [u8; 2] = [0x63, 0x00];

    fn ok(mut data: Vec<u8>) -> Result<Vec<u8>, String> {
        data.extend_from_slice(&OK);
        Ok(data)
    }

    /// An NTAG215 with 496 bytes of user memory.
    struct Ntag {
        mem: Vec<u8>,
    }

    impl Ntag {
        fn new() -> Self {
            let mut mem = vec![0u8; 135 * 4];
            mem[12..16].copy_from_slice(&[0xE1, 0x10, 0x3E, 0x00]);
            Self { mem }
        }
    }

    impl Transport for Ntag {
        fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
            let page = c[3] as usize * 4;
            match c[1] {
                0xB0 => ok((page..page + 16).map(|i| self.mem.get(i).copied().unwrap_or(0)).collect()),
                0xD6 if page >= 16 && page + 4 <= self.mem.len() => {
                    self.mem[page..page + 4].copy_from_slice(&c[5..9]);
                    ok(vec![])
                }
                _ => Ok(FAIL.to_vec()),
            }
        }
    }

    #[test]
    fn type2_blank_write_read_erase() {
        let mut tag = Ntag::new();
        let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type2).unwrap() else { panic!() };
        assert_eq!((c.records.len(), c.capacity, c.writable), (0, 496, true));

        let recs = vec![uri_record("https://example.com"), text_record("Hello", "en")];
        write(&mut tag, Tech::Type2, &recs).unwrap();
        let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type2).unwrap() else { panic!() };
        assert_eq!(c.records, recs);
        assert_eq!(c.used, encoded_size(Tech::Type2, &recs));

        write(&mut tag, Tech::Type2, &[]).unwrap();
        let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type2).unwrap() else { panic!() };
        assert!(c.records.is_empty());
    }

    #[test]
    fn type2_rejects_oversized_and_locked() {
        let mut tag = Ntag::new();
        let err = write(&mut tag, Tech::Type2, &[text_record(&"x".repeat(600), "en")]).unwrap_err();
        assert!(err.contains("too much"), "{err}");
        tag.mem[15] = 0x0F;
        assert!(write(&mut tag, Tech::Type2, &[text_record("x", "en")]).unwrap_err().contains("locked"));
    }

    /// A Type 4 tag with a 128-byte NDEF file and small frame limits to exercise chunking.
    struct Type4 {
        app: bool,
        file: u16,
        cc: Vec<u8>,
        ndef: Vec<u8>,
    }

    impl Transport for Type4 {
        fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
            let off = u16::from_be_bytes([c[2], c[3]]) as usize;
            match (c[1], c[2]) {
                (0xA4, 0x04) => {
                    self.app = c[5..12] == NDEF_AID;
                    Ok(if self.app { OK.to_vec() } else { vec![0x6A, 0x82] })
                }
                (0xA4, 0x00) if self.app => {
                    self.file = u16::from_be_bytes([c[5], c[6]]);
                    ok(vec![])
                }
                (0xB0, _) => {
                    let src = if self.file == 0xE103 { &self.cc } else { &self.ndef };
                    ok(src[off..(off + c[4] as usize).min(src.len())].to_vec())
                }
                (0xD6, _) if self.file == 0xE104 => {
                    assert!(c[4] <= 0x10, "chunk larger than MLc");
                    self.ndef[off..off + c[4] as usize].copy_from_slice(&c[5..]);
                    ok(vec![])
                }
                _ => Ok(FAIL.to_vec()),
            }
        }
    }

    #[test]
    fn type4_write_then_read_in_chunks() {
        let cc = vec![0x00, 0x0F, 0x20, 0x00, 0x10, 0x00, 0x10, 0x04, 0x06, 0xE1, 0x04, 0x00, 0x80, 0x00, 0x00];
        let mut tag = Type4 { app: false, file: 0, cc, ndef: vec![0; 0x80] };
        let recs = vec![text_record("A longer message that needs several frames", "en")];
        write(&mut tag, Tech::Type4, &recs).unwrap();
        let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type4).unwrap() else { panic!() };
        assert_eq!((c.records, c.capacity), (recs, 126));
    }

    #[test]
    fn type4_without_ndef_app_is_a_secure_card() {
        struct Bank;
        impl Transport for Bank {
            fn transmit(&mut self, _: &[u8]) -> Result<Vec<u8>, String> {
                Ok(vec![0x6A, 0x82])
            }
        }
        assert_eq!(read(&mut Bank, Tech::Type4).unwrap(), ReadOutcome::Unsupported(SECURE_CARD.into()));
    }

    /// An ISO 15693 tag (e.g. ICODE SLIX: 28 blocks of 4 bytes) behind a PC/SC reader.
    struct Vicinity {
        block: usize,
        mem: Vec<u8>,
    }

    impl Vicinity {
        fn new(block: usize, blocks: usize) -> Self {
            Self { block, mem: vec![0; block * blocks] }
        }
    }

    impl Transport for Vicinity {
        fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
            let start = c[3] as usize * self.block;
            if start + self.block > self.mem.len() {
                return Ok(vec![0x6A, 0x82]);
            }
            match c[1] {
                0xB0 if c[4] as usize == self.block || c[4] == 0 => ok(self.mem[start..start + self.block].to_vec()),
                0xB0 => Ok(vec![0x67, 0x00]),
                0xD6 if c[4] as usize == self.block => {
                    self.mem[start..start + self.block].copy_from_slice(&c[5..]);
                    ok(vec![])
                }
                _ => Ok(FAIL.to_vec()),
            }
        }
    }

    #[test]
    fn type5_blank_format_write_read_erase() {
        for block in [4, 8] {
            let mut tag = Vicinity::new(block, 112 / block);
            assert_eq!(read(&mut tag, Tech::Type5).unwrap(), ReadOutcome::Blank(Tech::Type5));
            assert!(can_format(Tech::Type5));
            format(&mut tag, Tech::Type5).unwrap();
            assert_eq!(tag.mem[..4], [0xE1, 0x40, 0x0E, 0x00]);
            let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type5).unwrap() else { panic!() };
            assert_eq!((c.records.len(), c.capacity, c.writable), (0, 108, true));

            let recs = vec![text_record("Library book #4211", "en"), uri_record("https://example.com/b/4211")];
            write(&mut tag, Tech::Type5, &recs).unwrap();
            assert_eq!(tag.mem[..4], [0xE1, 0x40, 0x0E, 0x00], "CC preserved with {block}-byte blocks");
            let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type5).unwrap() else { panic!() };
            assert_eq!(c.records, recs);

            write(&mut tag, Tech::Type5, &[]).unwrap();
            let ReadOutcome::Ndef(c) = read(&mut tag, Tech::Type5).unwrap() else { panic!() };
            assert!(c.records.is_empty());
        }
    }

    #[test]
    fn type5_protects_foreign_locked_and_oversized() {
        let mut library = Vicinity::new(4, 28);
        library.mem[..6].copy_from_slice(&[0x11, 0x01, 0x31, 0x32, 0x33, 0x34]);
        assert!(matches!(read(&mut library, Tech::Type5).unwrap(), ReadOutcome::Unsupported(_)));
        assert!(format(&mut library, Tech::Type5).unwrap_err().contains("already holds data"));
        assert!(write(&mut library, Tech::Type5, &[text_record("x", "en")]).is_err());

        let mut tag = Vicinity::new(4, 28);
        format(&mut tag, Tech::Type5).unwrap();
        let err = write(&mut tag, Tech::Type5, &[text_record(&"x".repeat(200), "en")]).unwrap_err();
        assert!(err.contains("too much"), "{err}");
        tag.mem[1] = 0x43;
        assert!(write(&mut tag, Tech::Type5, &[text_record("x", "en")]).unwrap_err().contains("locked"));
    }

    /// A MIFARE Classic 1K that enforces keys and, for non-factory sectors, key-B-only writes.
    struct Classic {
        blocks: Vec<[u8; 16]>,
        key: [u8; 6],
        authed: Option<(u8, KeyType)>,
        halted: bool,
    }

    impl Classic {
        fn factory() -> Self {
            let mut blocks = vec![[0u8; 16]; 64];
            for s in 0..16 {
                blocks[s * 4 + 3] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
            }
            Self { blocks, key: [0; 6], authed: None, halted: false }
        }
    }

    impl Transport for Classic {
        fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
            if self.halted {
                return Ok(FAIL.to_vec());
            }
            match c[1] {
                0x82 => {
                    self.key.copy_from_slice(&c[5..11]);
                    ok(vec![])
                }
                0x86 => {
                    let (block, kt) = (c[7], if c[8] == 0x60 { KeyType::A } else { KeyType::B });
                    let t = self.blocks[(block / 4 * 4 + 3) as usize];
                    let expected = if kt == KeyType::A { &t[..6] } else { &t[10..] };
                    if expected == self.key {
                        self.authed = Some((block / 4, kt));
                        ok(vec![])
                    } else {
                        self.authed = None;
                        self.halted = true;
                        Ok(FAIL.to_vec())
                    }
                }
                0xB0 | 0xD6 => {
                    let block = c[3];
                    let Some((sector, kt)) = self.authed.filter(|(s, _)| *s == block / 4) else {
                        return Ok(FAIL.to_vec());
                    };
                    if c[1] == 0xB0 {
                        return ok(self.blocks[block as usize].to_vec());
                    }
                    let access = &self.blocks[(sector * 4 + 3) as usize][6..9];
                    if access != [0xFF, 0x07, 0x80] && kt != KeyType::B {
                        return Ok(FAIL.to_vec());
                    }
                    self.blocks[block as usize].copy_from_slice(&c[5..21]);
                    ok(vec![])
                }
                _ => Ok(FAIL.to_vec()),
            }
        }

        fn reactivate(&mut self) -> Result<(), String> {
            self.halted = false;
            self.authed = None;
            Ok(())
        }
    }

    #[test]
    fn mad_crc_matches_nxp_formatted_cards() {
        let mut mad = vec![0x01];
        for _ in 0..15 {
            mad.extend_from_slice(&[0x03, 0xE1]);
        }
        assert_eq!(mad_crc(&mad), 0x14);
    }

    #[test]
    fn classic_blank_format_write_read() {
        let tech = Tech::Classic { sectors: 16 };
        let mut card = Classic::factory();
        assert_eq!(read(&mut card, tech).unwrap(), ReadOutcome::Blank(tech));

        format_classic(&mut card, 16).unwrap();
        assert_eq!(card.blocks[1][..4], [0x14, 0x01, 0x03, 0xE1]);
        let ReadOutcome::Ndef(c) = read(&mut card, tech).unwrap() else { panic!() };
        assert_eq!((c.records.len(), c.capacity), (0, 720));

        let recs = vec![text_record(&"Classic ".repeat(20), "en"), uri_record("tel:+123")];
        write(&mut card, tech, &recs).unwrap();
        let ReadOutcome::Ndef(c) = read(&mut card, tech).unwrap() else { panic!() };
        assert_eq!(c.records, recs);
    }

    #[test]
    fn classic_with_private_keys_is_reported() {
        let mut card = Classic::factory();
        for s in 0..16 {
            card.blocks[s * 4 + 3][..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        }
        assert!(matches!(read(&mut card, Tech::Classic { sectors: 16 }).unwrap(), ReadOutcome::Unsupported(_)));
        assert!(format_classic(&mut card, 16).unwrap_err().contains("isn't blank"));
    }
}
