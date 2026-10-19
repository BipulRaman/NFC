package dev.bipul.nfcstudio.data

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import org.json.JSONArray
import org.json.JSONObject

/**
 * Shows NDEF records the app doesn't understand as raw JSON. The shape matches the desktop app
 * (`app/desktop/src/rawjson.rs`): `tnf`, `type`, optional `id`, `size`, `payload` (parsed JSON or
 * text, when the bytes are readable) and `payloadHex`.
 */
object RawJson {
    private val TNF = listOf(
        "Empty", "Well-known", "MIME media", "Absolute URI", "External", "Unknown", "Unchanged", "Reserved",
    )

    fun tnfName(tnf: Short) = TNF.getOrElse(tnf.toInt()) { "Reserved" }

    fun hex(b: ByteArray) = b.joinToString(" ") { "%02X".format(it) }

    /** The bytes as text if they're valid UTF-8 without control characters (other than whitespace). */
    fun text(b: ByteArray): String? {
        if (b.isEmpty()) return null
        val s = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(b)).toString()
        } catch (e: CharacterCodingException) {
            return null
        }
        return s.takeIf { it.none { c -> c.isISOControl() && c != '\n' && c != '\r' && c != '\t' } }
    }

    private fun payload(b: ByteArray): Any? {
        val t = text(b) ?: return null
        val trimmed = t.trim()
        if (trimmed.startsWith("{")) runCatching { return JSONObject(trimmed) }
        if (trimmed.startsWith("[")) runCatching { return JSONArray(trimmed) }
        return t
    }

    fun record(r: RawRecord): JSONObject = JSONObject().apply {
        put("tnf", tnfName(r.tnf))
        put("type", text(r.type) ?: hex(r.type))
        if (r.id.isNotEmpty()) put("id", text(r.id) ?: hex(r.id))
        put("size", r.payload.size)
        payload(r.payload)?.let { put("payload", it) }
        put("payloadHex", hex(r.payload))
    }

    fun records(list: List<RawRecord>) = JSONArray().apply { list.forEach { put(record(it)) } }

    /** Indented JSON; Android's org.json escapes '/', which only makes URLs harder to read. */
    fun pretty(json: Any): String = when (json) {
        is JSONObject -> json.toString(2)
        is JSONArray -> json.toString(2)
        else -> json.toString()
    }.replace("\\/", "/")
}
