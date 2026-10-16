package dev.bipul.nfcstudio.data

import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import org.json.JSONObject

/** An NDEF record as plain bytes, independent of `android.nfc` so the codec can be unit-tested. */
class RawRecord(
    val tnf: Short,
    val type: ByteArray,
    val payload: ByteArray,
    val id: ByteArray = ByteArray(0),
) {
    /** Bytes this record takes inside an NDEF message. */
    val byteSize: Int
        get() = 2 + (if (payload.size < 256) 1 else 4) + (if (id.isNotEmpty()) 1 + id.size else 0) +
            type.size + payload.size

    val typeString: String get() = String(type, Charsets.US_ASCII)

    override fun equals(other: Any?) = other is RawRecord && tnf == other.tnf &&
        type.contentEquals(other.type) && payload.contentEquals(other.payload) && id.contentEquals(other.id)

    override fun hashCode() = ((tnf * 31 + type.contentHashCode()) * 31 + payload.contentHashCode()) * 31 +
        id.contentHashCode()

    companion object {
        const val TNF_EMPTY: Short = 0
        const val TNF_WELL_KNOWN: Short = 1
        const val TNF_MIME: Short = 2
        const val TNF_ABSOLUTE_URI: Short = 3
        const val TNF_EXTERNAL: Short = 4

        fun mime(type: String, payload: ByteArray) = RawRecord(TNF_MIME, type.toByteArray(Charsets.US_ASCII), payload)
    }
}

/** Size of an NDEF message holding [records]; an empty card still needs a 3-byte empty record. */
fun messageSize(records: List<RawRecord>): Int = if (records.isEmpty()) 3 else records.sumOf { it.byteSize }

enum class WifiSecurity(val label: String) { WPA2("WPA2 / WPA3 Personal"), OPEN("Open (no password)") }

enum class ItemKind(val label: String) {
    PASSWORD("Password"),
    NOTE("Note"),
    WEBSITE("Website"),
    PHONE("Phone number"),
    EMAIL("Email"),
    WIFI("Wi-Fi network"),
    CONTACT("Contact"),
    LOCKED("Protected item"),
    UNKNOWN("Other data"),
}

/** Something stored on a card, in the form people think about it. */
sealed class CardItem {
    abstract val kind: ItemKind

    data class Note(val text: String) : CardItem() {
        override val kind get() = ItemKind.NOTE
    }

    data class Website(val url: String) : CardItem() {
        override val kind get() = ItemKind.WEBSITE
    }

    data class Phone(val number: String) : CardItem() {
        override val kind get() = ItemKind.PHONE
    }

    data class Email(val address: String) : CardItem() {
        override val kind get() = ItemKind.EMAIL
    }

    data class Wifi(val ssid: String, val password: String, val security: WifiSecurity) : CardItem() {
        override val kind get() = ItemKind.WIFI
    }

    data class Contact(val name: String, val phone: String, val email: String, val organization: String) : CardItem() {
        override val kind get() = ItemKind.CONTACT
    }

    data class Password(
        val title: String,
        val username: String,
        val password: String,
        val website: String,
        val notes: String,
    ) : CardItem() {
        override val kind get() = ItemKind.PASSWORD
    }

    /** An encrypted item; [label] and [innerKind] are readable without the PIN. */
    class Locked(val innerKind: ItemKind, val label: String, val sealed: ByteArray) : CardItem() {
        override val kind get() = ItemKind.LOCKED
        override fun equals(other: Any?) = other is Locked && sealed.contentEquals(other.sealed)
        override fun hashCode() = sealed.contentHashCode()
    }

    data class Unknown(val record: RawRecord) : CardItem() {
        override val kind get() = ItemKind.UNKNOWN
    }
}

object ItemCodec {
    const val MIME_PASSWORD = "application/vnd.nfcstudio.password"
    const val MIME_LOCKED = "application/vnd.nfcstudio.locked"
    const val MIME_WIFI = "application/vnd.wfa.wsc"
    const val MIME_VCARD = "text/vcard"

    private val URI_PREFIXES = listOf(
        "", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
        "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://",
        "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:",
        "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://",
        "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
        "urn:nfc:",
    )

    fun decode(r: RawRecord): CardItem = runCatching { decodeOrThrow(r) }.getOrElse { CardItem.Unknown(r) }

    private fun decodeOrThrow(r: RawRecord): CardItem {
        val type = r.typeString
        return when {
            r.tnf == RawRecord.TNF_WELL_KNOWN && type == "T" -> CardItem.Note(decodeText(r.payload))
            r.tnf == RawRecord.TNF_WELL_KNOWN && type == "U" -> fromUri(decodeUri(r.payload), r)
            r.tnf == RawRecord.TNF_ABSOLUTE_URI -> fromUri(type, r)
            r.tnf == RawRecord.TNF_MIME -> when (type.lowercase()) {
                MIME_WIFI -> decodeWifi(r.payload) ?: CardItem.Unknown(r)
                MIME_VCARD, "text/x-vcard" -> decodeVcard(String(r.payload, Charsets.UTF_8))
                MIME_PASSWORD -> fromJson(JSONObject(String(r.payload, Charsets.UTF_8)))
                MIME_LOCKED -> Vault.parse(r.payload)
                "text/plain" -> CardItem.Note(String(r.payload, Charsets.UTF_8))
                else -> CardItem.Unknown(r)
            }
            else -> CardItem.Unknown(r)
        }
    }

    fun encode(item: CardItem): RawRecord = when (item) {
        is CardItem.Note -> textRecord(item.text)
        is CardItem.Website -> uriRecord(item.url)
        is CardItem.Phone -> uriRecord("tel:" + item.number.filterNot { it == ' ' || it == '-' || it == '(' || it == ')' })
        is CardItem.Email -> uriRecord("mailto:" + item.address.trim())
        is CardItem.Wifi -> RawRecord.mime(MIME_WIFI, encodeWifi(item))
        is CardItem.Contact -> RawRecord.mime(MIME_VCARD, encodeVcard(item).toByteArray(Charsets.UTF_8))
        is CardItem.Password -> RawRecord.mime(MIME_PASSWORD, toJson(item).toString().toByteArray(Charsets.UTF_8))
        is CardItem.Locked -> RawRecord.mime(MIME_LOCKED, item.sealed)
        is CardItem.Unknown -> item.record
    }

    // ---- Text / URI ----------------------------------------------------------

    fun textRecord(text: String, lang: String = "en"): RawRecord {
        val l = lang.toByteArray(Charsets.US_ASCII)
        val t = text.toByteArray(Charsets.UTF_8)
        return RawRecord(RawRecord.TNF_WELL_KNOWN, byteArrayOf('T'.code.toByte()), byteArrayOf(l.size.toByte()) + l + t)
    }

    private fun decodeText(p: ByteArray): String {
        val status = p[0].toInt()
        val langLen = status and 0x3F
        val charset: Charset = if (status and 0x80 != 0) Charsets.UTF_16 else Charsets.UTF_8
        return String(p, 1 + langLen, p.size - 1 - langLen, charset)
    }

    fun uriRecord(uri: String): RawRecord {
        val (code, prefix) = URI_PREFIXES.withIndex().drop(1)
            .filter { uri.startsWith(it.value) }
            .maxByOrNull { it.value.length }
            ?.let { it.index to it.value } ?: (0 to "")
        val rest = uri.substring(prefix.length).toByteArray(Charsets.UTF_8)
        return RawRecord(RawRecord.TNF_WELL_KNOWN, byteArrayOf('U'.code.toByte()), byteArrayOf(code.toByte()) + rest)
    }

    private fun decodeUri(p: ByteArray): String {
        val prefix = URI_PREFIXES.getOrElse(p[0].toInt() and 0xFF) { "" }
        return prefix + String(p, 1, p.size - 1, Charsets.UTF_8)
    }

    private fun fromUri(uri: String, r: RawRecord): CardItem {
        val lower = uri.lowercase()
        return when {
            lower.startsWith("tel:") -> CardItem.Phone(uri.substring(4))
            // A mailto with subject/body stays a link so nothing is lost when re-saving.
            lower.startsWith("mailto:") && !uri.contains('?') -> CardItem.Email(uri.substring(7))
            uri.isNotEmpty() -> CardItem.Website(uri)
            else -> CardItem.Unknown(r)
        }
    }

    // ---- Wi-Fi Simple Config (what phones use for "tap to join Wi-Fi") ---------

    private const val CREDENTIAL = 0x100E
    private const val SSID = 0x1045
    private const val NETWORK_KEY = 0x1027
    private const val AUTH_TYPE = 0x1003
    private const val ENCRYPTION_TYPE = 0x100F

    private fun attr(out: ByteArrayOutputStream, id: Int, value: ByteArray) {
        out.write(id shr 8); out.write(id and 0xFF)
        out.write(value.size shr 8); out.write(value.size and 0xFF)
        out.write(value)
    }

    private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), (v and 0xFF).toByte())

    private fun encodeWifi(w: CardItem.Wifi): ByteArray {
        val open = w.security == WifiSecurity.OPEN
        val cred = ByteArrayOutputStream()
        attr(cred, 0x1026, byteArrayOf(1))
        attr(cred, SSID, w.ssid.toByteArray(Charsets.UTF_8))
        attr(cred, AUTH_TYPE, u16(if (open) 0x0001 else 0x0020))
        attr(cred, ENCRYPTION_TYPE, u16(if (open) 0x0001 else 0x0008))
        attr(cred, NETWORK_KEY, if (open) ByteArray(0) else w.password.toByteArray(Charsets.UTF_8))
        attr(cred, 0x1020, ByteArray(6) { 0xFF.toByte() })
        return ByteArrayOutputStream().also { attr(it, CREDENTIAL, cred.toByteArray()) }.toByteArray()
    }

    private fun decodeWifi(p: ByteArray): CardItem.Wifi? {
        var ssid: String? = null
        var key = ""
        var auth = 0x0020
        fun walk(from: Int, to: Int) {
            var i = from
            while (i + 4 <= to) {
                val id = ((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)
                val len = ((p[i + 2].toInt() and 0xFF) shl 8) or (p[i + 3].toInt() and 0xFF)
                val start = i + 4
                val end = minOf(start + len, to)
                when (id) {
                    CREDENTIAL -> walk(start, end)
                    SSID -> ssid = String(p, start, end - start, Charsets.UTF_8)
                    NETWORK_KEY -> key = String(p, start, end - start, Charsets.UTF_8)
                    AUTH_TYPE -> if (end - start == 2) {
                        auth = ((p[start].toInt() and 0xFF) shl 8) or (p[start + 1].toInt() and 0xFF)
                    }
                }
                i = end
            }
        }
        walk(0, p.size)
        val name = ssid ?: return null
        val security = if (auth == 0x0001) WifiSecurity.OPEN else WifiSecurity.WPA2
        return CardItem.Wifi(name, key, security)
    }

    // ---- vCard -------------------------------------------------------------------

    private fun esc(v: String) = v.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")

    private fun unesc(v: String) = buildString {
        var i = 0
        while (i < v.length) {
            val c = v[i]
            if (c == '\\' && i + 1 < v.length) {
                append(if (v[i + 1] == 'n' || v[i + 1] == 'N') '\n' else v[i + 1])
                i += 2
            } else {
                append(c)
                i++
            }
        }
    }

    private fun encodeVcard(c: CardItem.Contact) = buildString {
        append("BEGIN:VCARD\r\nVERSION:3.0\r\n")
        append("N:;${esc(c.name)};;;\r\nFN:${esc(c.name)}\r\n")
        if (c.organization.isNotBlank()) append("ORG:${esc(c.organization)}\r\n")
        if (c.phone.isNotBlank()) append("TEL;TYPE=CELL:${esc(c.phone)}\r\n")
        if (c.email.isNotBlank()) append("EMAIL:${esc(c.email)}\r\n")
        append("END:VCARD\r\n")
    }

    private fun decodeVcard(text: String): CardItem.Contact {
        val lines = text.replace("\r\n ", "").replace("\n ", "").lines()
        fun field(key: String) = lines.firstOrNull {
            it.substringBefore(':').substringBefore(';').equals(key, ignoreCase = true)
        }?.substringAfter(':')?.let(::unesc)?.trim() ?: ""
        val name = field("FN").ifEmpty {
            field("N").split(';').filter { it.isNotBlank() }.reversed().joinToString(" ")
        }
        return CardItem.Contact(name, field("TEL"), field("EMAIL"), field("ORG").trimEnd(';'))
    }

    // ---- JSON (password items, and the plaintext inside locked items) ------------

    fun toJson(item: CardItem): JSONObject = when (item) {
        is CardItem.Password -> JSONObject()
            .put("k", "password").put("title", item.title).put("username", item.username)
            .put("password", item.password).put("website", item.website).put("notes", item.notes)
        is CardItem.Note -> JSONObject().put("k", "note").put("text", item.text)
        else -> throw IllegalArgumentException("${item.kind.label} can't be protected")
    }

    fun fromJson(o: JSONObject): CardItem = when (o.optString("k", "password")) {
        "note" -> CardItem.Note(o.optString("text"))
        else -> CardItem.Password(
            o.optString("title"), o.optString("username"), o.optString("password"),
            o.optString("website"), o.optString("notes"),
        )
    }
}
