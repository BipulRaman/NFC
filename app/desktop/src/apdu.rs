//! APDU helpers: hex parsing/formatting, PC/SC pseudo-APDU builders and status word decoding.

use std::fmt::Write;

/// Parses a hex string, ignoring whitespace, `:` and `-` separators and an optional `0x` prefix.
pub fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .split_whitespace()
        .map(|t| t.trim_start_matches("0x").trim_start_matches("0X"))
        .collect::<String>()
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err("Hex string must have an even number of digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex byte '{}'", &cleaned[i..i + 2]))
        })
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02X}");
    }
    s
}

pub fn to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
        .collect()
}

/// Splits a response into (data, SW1SW2).
pub fn split_sw(resp: &[u8]) -> Result<(&[u8], u16), String> {
    if resp.len() < 2 {
        return Err(format!("Response too short: {}", to_hex(resp)));
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data, u16::from_be_bytes([sw[0], sw[1]])))
}

pub fn describe_sw(sw: u16) -> &'static str {
    match sw {
        0x9000 => "Success",
        0x6300 => "Operation failed (auth/read/write error)",
        0x6281 => "Part of returned data may be corrupted",
        0x6282 => "End of data reached before Le bytes",
        0x6700 => "Wrong length",
        0x6800 => "Function in CLA not supported",
        0x6981 => "Command incompatible with file structure",
        0x6982 => "Security status not satisfied (authenticate first)",
        0x6983 => "Authentication method blocked",
        0x6986 => "Command not allowed",
        0x6A81 => "Function not supported",
        0x6A82 => "File or block not found",
        0x6B00 => "Wrong parameters P1-P2",
        0x6D00 => "Instruction not supported",
        0x6E00 => "Class not supported",
        _ if sw >> 8 == 0x61 => "More data available (GET RESPONSE)",
        _ if sw >> 8 == 0x6C => "Wrong Le; retry with correct length",
        _ => "Unknown status",
    }
}

/// Requires SW 9000 and returns the data portion.
pub fn expect_ok(resp: &[u8]) -> Result<Vec<u8>, String> {
    let (data, sw) = split_sw(resp)?;
    if sw == 0x9000 {
        Ok(data.to_vec())
    } else {
        Err(format!("Card returned {sw:04X}: {}", describe_sw(sw)))
    }
}

// --- PC/SC Part 3 pseudo-APDUs (supported by most contactless readers, e.g. ACR122U/ACR1252U) ---

pub fn get_uid() -> Vec<u8> {
    vec![0xFF, 0xCA, 0x00, 0x00, 0x00]
}

pub fn get_ats() -> Vec<u8> {
    vec![0xFF, 0xCA, 0x01, 0x00, 0x00]
}

/// Loads a 6-byte key into reader volatile key slot `slot`.
pub fn load_key(slot: u8, key: &[u8; 6]) -> Vec<u8> {
    let mut a = vec![0xFF, 0x82, 0x00, slot, 0x06];
    a.extend_from_slice(key);
    a
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyType {
    A,
    B,
}

/// General Authenticate for MIFARE Classic.
pub fn authenticate(block: u8, key_type: KeyType, slot: u8) -> Vec<u8> {
    let kt = match key_type {
        KeyType::A => 0x60,
        KeyType::B => 0x61,
    };
    vec![0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, kt, slot]
}

pub fn read_binary(block: u8, len: u8) -> Vec<u8> {
    vec![0xFF, 0xB0, 0x00, block, len]
}

pub fn update_binary(block: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![0xFF, 0xD6, 0x00, block, data.len() as u8];
    a.extend_from_slice(data);
    a
}

/// Returns true if the MIFARE Classic block is a sector trailer (keys + access bits).
pub fn is_sector_trailer(block: u8) -> bool {
    if block < 128 {
        block % 4 == 3
    } else {
        (block - 128) % 16 == 15
    }
}

// --- ISO 7816-4 commands (sent to the card itself, used by NFC Forum Type 4 tags) ---

pub fn select_aid(aid: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    a.extend_from_slice(aid);
    a.push(0x00);
    a
}

pub fn select_file(fid: u16) -> Vec<u8> {
    let [hi, lo] = fid.to_be_bytes();
    vec![0x00, 0xA4, 0x00, 0x0C, 0x02, hi, lo]
}

pub fn iso_read_binary(offset: u16, len: u8) -> Vec<u8> {
    let [hi, lo] = offset.to_be_bytes();
    vec![0x00, 0xB0, hi, lo, len]
}

pub fn iso_update_binary(offset: u16, data: &[u8]) -> Vec<u8> {
    let [hi, lo] = offset.to_be_bytes();
    let mut a = vec![0x00, 0xD6, hi, lo, data.len() as u8];
    a.extend_from_slice(data);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_various_hex_formats() {
        assert_eq!(parse_hex("FF CA 00 00 00").unwrap(), vec![0xFF, 0xCA, 0, 0, 0]);
        assert_eq!(parse_hex("ffca:0000-00").unwrap(), vec![0xFF, 0xCA, 0, 0, 0]);
        assert_eq!(parse_hex("0xFF 0x01").unwrap(), vec![0xFF, 0x01]);
        assert!(parse_hex("ABC").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn formats_and_splits() {
        assert_eq!(to_hex(&[0x01, 0xAB]), "01 AB");
        assert_eq!(to_ascii(b"Hi\x00"), "Hi.");
        let (d, sw) = split_sw(&[0x11, 0x90, 0x00]).unwrap();
        assert_eq!((d, sw), (&[0x11][..], 0x9000));
        assert!(expect_ok(&[0x63, 0x00]).is_err());
    }

    #[test]
    fn builds_mifare_commands() {
        assert_eq!(authenticate(4, KeyType::B, 1), vec![0xFF, 0x86, 0, 0, 5, 1, 0, 4, 0x61, 1]);
        assert_eq!(update_binary(2, &[1, 2]), vec![0xFF, 0xD6, 0, 2, 2, 1, 2]);
        assert!(is_sector_trailer(3) && is_sector_trailer(143) && !is_sector_trailer(4));
    }
}
