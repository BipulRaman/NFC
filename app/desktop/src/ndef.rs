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

/// What a record means to a person, used to pick an icon and label in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Text,
    Website,
    Phone,
    Email,
    Sms,
    Location,
    Link,
    Contact,
    Wifi,
    App,
    Data,
}

impl RecordKind {
    pub fn label(self) -> &'static str {
        match self {
            RecordKind::Text => "Text",
            RecordKind::Website => "Website",
            RecordKind::Phone => "Phone number",
            RecordKind::Email => "Email address",
            RecordKind::Sms => "Text message (SMS)",
            RecordKind::Location => "Location",
            RecordKind::Link => "Link",
            RecordKind::Contact => "Contact card",
            RecordKind::Wifi => "Wi-Fi network",
            RecordKind::App => "Android app",
            RecordKind::Data => "Other data",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            RecordKind::Text => "📝",
            RecordKind::Website => "🌐",
            RecordKind::Phone => "📞",
            RecordKind::Email => "✉",
            RecordKind::Sms => "💬",
            RecordKind::Location => "📍",
            RecordKind::Link => "🔗",
            RecordKind::Contact => "👤",
            RecordKind::Wifi => "📶",
            RecordKind::App => "📱",
            RecordKind::Data => "📦",
        }
    }
}

impl Record {
    pub fn kind(&self) -> RecordKind {
        match self {
            Record::Text { .. } => RecordKind::Text,
            Record::Uri(u) => {
                let lower = u.to_ascii_lowercase();
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    RecordKind::Website
                } else if lower.starts_with("tel:") {
                    RecordKind::Phone
                } else if lower.starts_with("mailto:") {
                    RecordKind::Email
                } else if lower.starts_with("sms:") || lower.starts_with("smsto:") {
                    RecordKind::Sms
                } else if lower.starts_with("geo:") {
                    RecordKind::Location
                } else {
                    RecordKind::Link
                }
            }
            Record::Other { tnf: 0x02, rtype, .. } => match rtype.to_ascii_lowercase().as_slice() {
                b"text/vcard" | b"text/x-vcard" => RecordKind::Contact,
                b"application/vnd.wfa.wsc" => RecordKind::Wifi,
                _ => RecordKind::Data,
            },
            Record::Other { tnf: 0x04, rtype, .. } if rtype == b"android.com:pkg" => RecordKind::App,
            Record::Other { .. } => RecordKind::Data,
        }
    }

    /// The value as a person would read it, e.g. `+123` rather than `tel:+123`.
    pub fn summary(&self) -> String {
        match self {
            Record::Text { text, .. } => text.clone(),
            Record::Uri(u) => match self.kind() {
                RecordKind::Phone | RecordKind::Location => after_scheme(u).to_string(),
                RecordKind::Sms => after_scheme(u).split('?').next().unwrap_or("").to_string(),
                RecordKind::Email => after_scheme(u).split('?').next().unwrap_or("").to_string(),
                _ => u.clone(),
            },
            Record::Other { rtype, payload, .. } => match self.kind() {
                RecordKind::Contact => {
                    let text = String::from_utf8_lossy(payload);
                    text.lines()
                        .find_map(|l| l.strip_prefix("FN:").or_else(|| l.strip_prefix("FN;CHARSET=UTF-8:")))
                        .map(|n| n.trim().to_string())
                        .unwrap_or_else(|| "Contact details".into())
                }
                RecordKind::Wifi => wifi_ssid(payload)
                    .map(|s| format!("Network: {s}"))
                    .unwrap_or_else(|| "Wi-Fi settings".into()),
                RecordKind::App => String::from_utf8_lossy(payload).into_owned(),
                _ => {
                    let printable = !payload.is_empty()
                        && payload.iter().all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7F).contains(&b));
                    if printable {
                        String::from_utf8_lossy(payload).into_owned()
                    } else {
                        let kind = String::from_utf8_lossy(rtype);
                        let kind = if kind.is_empty() { "unknown".into() } else { kind };
                        format!("{} bytes ({kind})", payload.len())
                    }
                }
            },
        }
    }

    /// A URL the operating system can open (website, email, phone), if any.
    pub fn open_target(&self) -> Option<&str> {
        match (self, self.kind()) {
            (Record::Uri(u), RecordKind::Website | RecordKind::Email | RecordKind::Phone | RecordKind::Sms | RecordKind::Link) => {
                Some(u)
            }
            _ => None,
        }
    }
}

fn after_scheme(uri: &str) -> &str {
    uri.split_once(':').map(|(_, rest)| rest).unwrap_or(uri)
}

/// Extracts the SSID (attribute 0x1045) from a Wi-Fi Simple Config payload.
fn wifi_ssid(payload: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 4 <= payload.len() {
        let id = u16::from_be_bytes([payload[i], payload[i + 1]]);
        let len = u16::from_be_bytes([payload[i + 2], payload[i + 3]]) as usize;
        let start = i + 4;
        let end = start.checked_add(len)?.min(payload.len());
        match id {
            0x1045 => return Some(String::from_utf8_lossy(&payload[start..end]).into_owned()),
            // Credential is a container; descend into it.
            0x100E => i = start,
            _ => i = end,
        }
    }
    None
}

/// The kinds of content the simple "Write to card" form can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteKind {
    Text,
    Website,
    Phone,
    Email,
}

impl WriteKind {
    pub const ALL: [WriteKind; 4] = [WriteKind::Text, WriteKind::Website, WriteKind::Phone, WriteKind::Email];

    pub fn record_kind(self) -> RecordKind {
        match self {
            WriteKind::Text => RecordKind::Text,
            WriteKind::Website => RecordKind::Website,
            WriteKind::Phone => RecordKind::Phone,
            WriteKind::Email => RecordKind::Email,
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            WriteKind::Text => "Type a message, e.g. Hello! This is my card.",
            WriteKind::Website => "e.g. example.com",
            WriteKind::Phone => "e.g. +91 98765 43210",
            WriteKind::Email => "e.g. name@example.com",
        }
    }

    /// Validates the user's input and turns it into an NDEF record.
    pub fn build(self, input: &str) -> Result<Record, String> {
        let value = input.trim();
        if value.is_empty() {
            return Err("Please enter something to write.".into());
        }
        match self {
            WriteKind::Text => Ok(text_record(value, "en")),
            WriteKind::Website => {
                if value.contains(char::is_whitespace) || !value.contains('.') {
                    return Err("That doesn't look like a website address.".into());
                }
                let lower = value.to_ascii_lowercase();
                if lower.starts_with("http://") || lower.starts_with("https://") {
                    Ok(uri_record(value))
                } else {
                    Ok(uri_record(&format!("https://{value}")))
                }
            }
            WriteKind::Phone => {
                let number: String = value.chars().filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.')).collect();
                let digits = number.strip_prefix('+').unwrap_or(&number);
                if digits.len() < 3 || !digits.chars().all(|c| c.is_ascii_digit()) {
                    return Err("A phone number can only contain digits, spaces and a leading +.".into());
                }
                Ok(uri_record(&format!("tel:{number}")))
            }
            WriteKind::Email => {
                let (user, domain) = value.split_once('@').unwrap_or(("", ""));
                if user.is_empty() || !domain.contains('.') || value.contains(char::is_whitespace) {
                    return Err("That doesn't look like an email address.".into());
                }
                Ok(uri_record(&format!("mailto:{value}")))
            }
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

/// Result of scanning (possibly partial) Type 2 tag memory for the NDEF TLV.
#[derive(Debug, PartialEq)]
pub enum TlvScan {
    /// The NDEF message (may be empty) and the number of bytes its TLV occupies.
    Found(Vec<u8>, usize),
    /// A terminator or end-of-data was reached with no NDEF TLV.
    Empty,
    /// More memory is needed to finish parsing.
    Incomplete,
}

/// Scans Type 2 tag user memory for the NDEF message TLV.
pub fn scan_tlv(mem: &[u8]) -> TlvScan {
    let mut i = 0;
    while i < mem.len() {
        let t = mem[i];
        match t {
            0x00 => {
                i += 1;
                continue;
            }
            0xFE => return TlvScan::Empty,
            _ => {}
        }
        if i + 1 >= mem.len() {
            return TlvScan::Incomplete;
        }
        let (len, hdr) = if mem[i + 1] == 0xFF {
            if i + 3 >= mem.len() {
                return TlvScan::Incomplete;
            }
            (u16::from_be_bytes([mem[i + 2], mem[i + 3]]) as usize, 4)
        } else {
            (mem[i + 1] as usize, 2)
        };
        let start = i + hdr;
        if start + len > mem.len() {
            return TlvScan::Incomplete;
        }
        if t == 0x03 {
            return TlvScan::Found(mem[start..start + len].to_vec(), hdr + len);
        }
        i = start + len;
    }
    TlvScan::Incomplete
}

/// Finds the NDEF message TLV in Type 2 tag user memory.
pub fn find_ndef_tlv(mem: &[u8]) -> Result<Vec<u8>, String> {
    match scan_tlv(mem) {
        TlvScan::Found(msg, _) => Ok(msg),
        TlvScan::Empty => Err("No NDEF message TLV found".into()),
        TlvScan::Incomplete => Err("NDEF TLV extends past read memory".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_reports_incomplete_found_and_empty() {
        let mem = wrap_tlv(&encode_message(&[text_record("Hi", "en")]));
        assert_eq!(scan_tlv(&mem[..4]), TlvScan::Incomplete);
        let TlvScan::Found(msg, used) = scan_tlv(&mem) else { panic!("not found") };
        assert_eq!(used, mem.len() - 1);
        assert_eq!(decode_message(&msg).unwrap(), vec![text_record("Hi", "en")]);
        assert_eq!(scan_tlv(&[0x00, 0xFE, 0x03]), TlvScan::Empty);
        assert_eq!(scan_tlv(&[0x03, 0x00, 0xFE]), TlvScan::Found(vec![], 2));
    }

    #[test]
    fn friendly_kinds_and_summaries() {
        assert_eq!(uri_record("https://example.com").kind(), RecordKind::Website);
        let phone = uri_record("tel:+919876543210");
        assert_eq!((phone.kind(), phone.summary().as_str()), (RecordKind::Phone, "+919876543210"));
        let mail = uri_record("mailto:a@b.co?subject=x");
        assert_eq!((mail.kind(), mail.summary().as_str()), (RecordKind::Email, "a@b.co"));
        let vcard = Record::Other { tnf: 2, rtype: b"text/vcard".to_vec(), payload: b"BEGIN:VCARD\nFN:Asha Rao\nEND:VCARD".to_vec() };
        assert_eq!((vcard.kind(), vcard.summary().as_str()), (RecordKind::Contact, "Asha Rao"));
        let wifi_payload = [0x10, 0x0E, 0x00, 0x08, 0x10, 0x45, 0x00, 0x04, b'H', b'o', b'm', b'e'];
        let wifi = Record::Other { tnf: 2, rtype: b"application/vnd.wfa.wsc".to_vec(), payload: wifi_payload.to_vec() };
        assert_eq!((wifi.kind(), wifi.summary().as_str()), (RecordKind::Wifi, "Network: Home"));
        assert_eq!(text_record("Hello", "en").open_target(), None);
    }

    #[test]
    fn write_kinds_validate_and_build() {
        assert_eq!(WriteKind::Website.build("example.com").unwrap(), uri_record("https://example.com"));
        assert_eq!(WriteKind::Website.build("http://a.io").unwrap(), uri_record("http://a.io"));
        assert_eq!(WriteKind::Phone.build("+91 98765-43210").unwrap(), uri_record("tel:+919876543210"));
        assert_eq!(WriteKind::Email.build(" a@b.com ").unwrap(), uri_record("mailto:a@b.com"));
        assert_eq!(WriteKind::Text.build("Hi").unwrap(), text_record("Hi", "en"));
        assert!(WriteKind::Text.build("   ").is_err());
        assert!(WriteKind::Website.build("not a site").is_err());
        assert!(WriteKind::Phone.build("call me").is_err());
        assert!(WriteKind::Email.build("nobody").is_err());
    }

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
