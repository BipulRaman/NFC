package dev.bipul.nfcstudio

/** Bindings to the Rust core (`app/android/rust`, library `nfc_jni`). */
object NfcCore {
    init {
        System.loadLibrary("nfc_jni")
    }

    external fun parseHex(hex: String): ByteArray
    external fun toHex(data: ByteArray): String
    external fun toAscii(data: ByteArray): String
    external fun describeResponse(response: ByteArray): String
    external fun encodeText(text: String, lang: String): ByteArray
    external fun encodeUri(uri: String): ByteArray
    external fun wrapTlv(message: ByteArray): ByteArray
    external fun decodeMessage(message: ByteArray): String
    external fun decodeTlvMemory(memory: ByteArray): String
    external fun isSectorTrailer(block: Int): Boolean
}
