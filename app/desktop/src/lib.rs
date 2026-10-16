//! Core of NFC Studio: APDU helpers and an NDEF codec (portable), plus the
//! PC/SC reader wrapper (desktop feature).

pub mod apdu;
pub mod ndef;

#[cfg(feature = "desktop")]
pub mod card;
