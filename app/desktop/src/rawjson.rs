//! Shows NDEF records the app doesn't understand as raw JSON. The shape matches the Android app
//! (`data/RawJson.kt`): `tnf`, `type`, optional `id`, `size`, `payload` (parsed JSON or text, when
//! the bytes are readable) and `payloadHex`.

use crate::apdu::to_hex;
use crate::seal::RawRecord;
use serde_json::{Map, Value};

const TNF: [&str; 8] = ["Empty", "Well-known", "MIME media", "Absolute URI", "External", "Unknown", "Unchanged", "Reserved"];

pub fn tnf_name(tnf: u8) -> &'static str {
    TNF.get(tnf as usize).copied().unwrap_or("Reserved")
}

/// The bytes as text if they're valid UTF-8 without control characters (other than whitespace).
pub fn text(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok().filter(|s| !s.is_empty())?;
    s.chars().all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')).then(|| s.to_string())
}

fn payload(b: &[u8]) -> Option<Value> {
    let t = text(b)?;
    let trimmed = t.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
            return Some(v);
        }
    }
    Some(Value::String(t))
}

pub fn record(r: &RawRecord) -> Value {
    let mut m = Map::new();
    m.insert("tnf".into(), tnf_name(r.tnf).into());
    m.insert("type".into(), text(&r.rtype).unwrap_or_else(|| to_hex(&r.rtype)).into());
    if !r.id.is_empty() {
        m.insert("id".into(), text(&r.id).unwrap_or_else(|| to_hex(&r.id)).into());
    }
    m.insert("size".into(), r.payload.len().into());
    if let Some(p) = payload(&r.payload) {
        m.insert("payload".into(), p);
    }
    m.insert("payloadHex".into(), to_hex(&r.payload).into());
    Value::Object(m)
}

pub fn records(rs: &[RawRecord]) -> Value {
    Value::Array(rs.iter().map(record).collect())
}

pub fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(tnf: u8, t: &[u8], id: &[u8], p: &[u8]) -> RawRecord {
        RawRecord { tnf, rtype: t.to_vec(), id: id.to_vec(), payload: p.to_vec() }
    }

    #[test]
    fn json_payload_is_embedded_as_json() {
        let v = record(&raw(2, b"application/json", b"", br#"{"sku":"A-12","qty":3}"#));
        assert_eq!(v["tnf"], "MIME media");
        assert_eq!(v["payload"]["qty"], 3);
        let s = pretty(&v);
        let keys: Vec<&str> = ["\"tnf\"", "\"type\"", "\"size\"", "\"payload\"", "\"payloadHex\""].to_vec();
        let pos: Vec<usize> = keys.iter().map(|k| s.find(k).unwrap()).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "fields keep their order: {s}");
    }

    #[test]
    fn text_and_binary_payloads() {
        let t = record(&raw(4, b"acme.com:note", b"", b"hello\nworld"));
        assert_eq!(t["payload"], "hello\nworld");
        let b = record(&raw(5, b"", b"id1", &[0x00, 0xFF, 0x10]));
        assert!(b.get("payload").is_none());
        assert_eq!(b["payloadHex"], "00 FF 10");
        assert_eq!(b["id"], "id1");
        assert_eq!(b["tnf"], "Unknown");
        assert_eq!(records(&[t.clone()].iter().map(|_| raw(1, b"T", b"", b"")).collect::<Vec<_>>()).as_array().unwrap().len(), 1);
    }
}
