//! 125 kHz RFID badges (EM4100, HID Prox, T5577 …) read with USB "keyboard wedge" readers.
//!
//! These readers don't use PC/SC: they type the card number followed by Enter, much faster than a
//! person can. [`WedgeDecoder`] picks those bursts out of keyboard input and [`interpret`] explains
//! the number in the formats printed on badges.

use std::time::{Duration, Instant};

/// Longest gap between characters typed by a reader; people type far slower.
const MAX_GAP: Duration = Duration::from_millis(80);
const MIN_LEN: usize = 4;
const MAX_LEN: usize = 40;

#[derive(Default)]
pub struct WedgeDecoder {
    buf: String,
    last: Option<Instant>,
}

impl WedgeDecoder {
    /// Feeds typed text received at `now`.
    pub fn push(&mut self, text: &str, now: Instant) {
        if self.last.is_some_and(|t| now.saturating_duration_since(t) > MAX_GAP) {
            self.buf.clear();
        }
        for c in text.chars() {
            if c.is_ascii_alphanumeric() || matches!(c, ',' | ':' | '-') {
                self.buf.push(c);
            } else {
                self.buf.clear();
            }
        }
        if self.buf.len() > MAX_LEN {
            self.buf.clear();
        }
        self.last = Some(now);
    }

    /// Called when Enter or Tab is pressed; returns the badge ID if the burst came from a reader.
    pub fn finish(&mut self, now: Instant) -> Option<String> {
        let fast = self.last.is_some_and(|t| now.saturating_duration_since(t) <= MAX_GAP);
        let id = std::mem::take(&mut self.buf);
        self.last = None;
        (fast && id.len() >= MIN_LEN && id.chars().any(|c| c.is_ascii_digit())).then_some(id)
    }
}

/// The badge number in the formats people usually need, as (label, value) pairs.
pub fn interpret(raw: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let w26 = |n: u64| format!("{:03},{:05}", (n >> 16) & 0xFF, n & 0xFFFF);
    if raw.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = raw.parse::<u64>() {
            out.push(("Hex", format!("{n:X}")));
            if n <= 0xFFFF_FFFF {
                out.push(("Facility, card (26-bit)", w26(n)));
            }
        }
    } else if raw.len() >= 8 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let upper = raw.to_ascii_uppercase();
        let low32 = u64::from_str_radix(&upper[upper.len() - 8..], 16).unwrap_or(0);
        if upper.len() == 10 {
            out.push(("EM4100 ID", upper.clone()));
        }
        out.push(("Decimal (last 8 hex digits)", format!("{low32:010}")));
        out.push(("Facility, card (26-bit)", w26(low32)));
    } else if let Some((facility, card)) = raw.split_once(',') {
        if facility.chars().all(|c| c.is_ascii_digit()) && card.chars().all(|c| c.is_ascii_digit()) {
            out.push(("Facility code", facility.trim_start_matches('0').to_string()));
            out.push(("Card number", card.trim_start_matches('0').to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_burst(d: &mut WedgeDecoder, s: &str, start: Instant, gap_ms: u64) -> Instant {
        let mut t = start;
        for c in s.chars() {
            d.push(&c.to_string(), t);
            t += Duration::from_millis(gap_ms);
        }
        t - Duration::from_millis(gap_ms)
    }

    #[test]
    fn detects_reader_bursts_but_not_people() {
        let mut d = WedgeDecoder::default();
        let t0 = Instant::now();
        let end = type_burst(&mut d, "0004521873", t0, 8);
        assert_eq!(d.finish(end + Duration::from_millis(8)).as_deref(), Some("0004521873"));

        let end = type_burst(&mut d, "123456", end + Duration::from_secs(1), 180);
        assert_eq!(d.finish(end + Duration::from_millis(150)), None, "human typing");

        // Readers that send a whole burst in one event, then Enter in the same frame.
        d.push("0A00F1C2D3", t0 + Duration::from_secs(5));
        assert_eq!(d.finish(t0 + Duration::from_secs(5)).as_deref(), Some("0A00F1C2D3"));
        d.push("ok", t0 + Duration::from_secs(6));
        assert_eq!(d.finish(t0 + Duration::from_secs(6)), None, "too short, no digits");
    }

    #[test]
    fn interprets_common_badge_formats() {
        let dec = interpret("0004521873");
        assert!(dec.contains(&("Hex", "44FF91".into())));
        assert!(dec.contains(&("Facility, card (26-bit)", "068,65425".into())));

        let em = interpret("0a00f1c2d3");
        assert!(em.contains(&("EM4100 ID", "0A00F1C2D3".into())));
        assert!(em.contains(&("Decimal (last 8 hex digits)", "0015844051".into())));

        let fc = interpret("069,05777");
        assert_eq!(fc, vec![("Facility code", "69".into()), ("Card number", "5777".into())]);
    }
}
