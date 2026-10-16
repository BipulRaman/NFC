//! JNI bindings for `dev.bipul.nfcstudio.NfcCore`.
//!
//! Errors are raised as `java.lang.IllegalArgumentException`.

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jint, jstring};
use nfc_studio::{apdu, ndef};

const IAE: &str = "java/lang/IllegalArgumentException";

fn throw(env: &mut JNIEnv, msg: &str) {
    let _ = env.throw_new(IAE, msg);
}

fn get_string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    env.get_string(s)
        .map(Into::into)
        .map_err(|e| format!("invalid string: {e}"))
}

fn get_bytes(env: &mut JNIEnv, a: &JByteArray) -> Result<Vec<u8>, String> {
    env.convert_byte_array(a)
        .map_err(|e| format!("invalid byte array: {e}"))
}

fn ret_string(env: &mut JNIEnv, r: Result<String, String>) -> jstring {
    match r.and_then(|s| env.new_string(s).map_err(|e| e.to_string())) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            throw(env, &e);
            std::ptr::null_mut()
        }
    }
}

fn ret_bytes(env: &mut JNIEnv, r: Result<Vec<u8>, String>) -> jbyteArray {
    match r.and_then(|b| env.byte_array_from_slice(&b).map_err(|e| e.to_string())) {
        Ok(a) => a.into_raw(),
        Err(e) => {
            throw(env, &e);
            std::ptr::null_mut()
        }
    }
}

fn decode_to_text(msg: &[u8]) -> Result<String, String> {
    let records = ndef::decode_message(msg)?;
    if records.is_empty() {
        return Ok("(empty NDEF message)".into());
    }
    Ok(records
        .iter()
        .enumerate()
        .map(|(i, r)| format!("#{}: {r}", i + 1))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Formats a raw APDU response as `data | SW xxxx description`.
pub fn describe_response(resp: &[u8]) -> Result<String, String> {
    let (data, sw) = apdu::split_sw(resp)?;
    let mut out = String::new();
    if !data.is_empty() {
        out.push_str(&apdu::to_hex(data));
        out.push_str(" | ");
    }
    out.push_str(&format!("SW {sw:04X} {}", apdu::describe_sw(sw)));
    Ok(out)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_parseHex<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    hex: JString<'l>,
) -> jbyteArray {
    let r = get_string(&mut env, &hex).and_then(|s| apdu::parse_hex(&s));
    ret_bytes(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_toHex<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    data: JByteArray<'l>,
) -> jstring {
    let r = get_bytes(&mut env, &data).map(|b| apdu::to_hex(&b));
    ret_string(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_toAscii<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    data: JByteArray<'l>,
) -> jstring {
    let r = get_bytes(&mut env, &data).map(|b| apdu::to_ascii(&b));
    ret_string(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_describeResponse<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    data: JByteArray<'l>,
) -> jstring {
    let r = get_bytes(&mut env, &data).and_then(|b| describe_response(&b));
    ret_string(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_encodeText<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    text: JString<'l>,
    lang: JString<'l>,
) -> jbyteArray {
    let r = get_string(&mut env, &text).and_then(|t| {
        let l = get_string(&mut env, &lang)?;
        Ok(ndef::encode_message(&[ndef::text_record(&t, &l)]))
    });
    ret_bytes(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_encodeUri<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    uri: JString<'l>,
) -> jbyteArray {
    let r = get_string(&mut env, &uri).map(|u| ndef::encode_message(&[ndef::uri_record(&u)]));
    ret_bytes(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_wrapTlv<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    msg: JByteArray<'l>,
) -> jbyteArray {
    let r = get_bytes(&mut env, &msg).map(|m| ndef::wrap_tlv(&m));
    ret_bytes(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_decodeMessage<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    msg: JByteArray<'l>,
) -> jstring {
    let r = get_bytes(&mut env, &msg).and_then(|m| decode_to_text(&m));
    ret_string(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_decodeTlvMemory<'l>(
    mut env: JNIEnv<'l>,
    _c: JClass<'l>,
    mem: JByteArray<'l>,
) -> jstring {
    let r = get_bytes(&mut env, &mem)
        .and_then(|m| ndef::find_ndef_tlv(&m))
        .and_then(|m| decode_to_text(&m));
    ret_string(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bipul_nfcstudio_NfcCore_isSectorTrailer<'l>(
    _env: JNIEnv<'l>,
    _c: JClass<'l>,
    block: jint,
) -> jboolean {
    ((0..=255).contains(&block) && apdu::is_sector_trailer(block as u8)) as jboolean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_response() {
        assert_eq!(
            describe_response(&[0x01, 0x02, 0x90, 0x00]).unwrap(),
            format!("01 02 | SW 9000 {}", apdu::describe_sw(0x9000))
        );
        assert!(describe_response(&[0x90]).is_err());
    }

    #[test]
    fn decodes_uri() {
        let msg = ndef::encode_message(&[ndef::uri_record("https://example.com")]);
        assert!(decode_to_text(&msg).unwrap().starts_with("#1: "));
    }
}
