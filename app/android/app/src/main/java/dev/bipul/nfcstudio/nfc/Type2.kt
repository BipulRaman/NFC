package dev.bipul.nfcstudio.nfc

import dev.bipul.nfcstudio.data.Pbkdf2
import java.io.IOException
import java.security.SecureRandom

open class Type2Exception(message: String) : IOException(message)

class WrongPasswordException : Type2Exception("Wrong card password.")

/** The card has a write password and none was given. */
class NeedsPasswordException : Type2Exception("This card is protected with a password.")

/** The card left the field; unlike a refused command, retrying won't help until it's tapped again. */
class CardGoneException : IOException("The card moved away.")

enum class NtagModel(val label: String, val cfgPage: Int) {
    NTAG213("NTAG213", 0x29),
    NTAG215("NTAG215", 0x83),
    NTAG216("NTAG216", 0xE3),
    UL_EV1_SMALL("MIFARE Ultralight EV1", 0x10),
    UL_EV1_LARGE("MIFARE Ultralight EV1", 0x25);

    private val isNtag get() = this == NTAG213 || this == NTAG215 || this == NTAG216

    /** AUTHLIM value for the wrong-password limit: NTAG allows 2^AUTHLIM tries, Ultralight EV1 AUTHLIM. */
    val authLimit get() = if (isNtag) 3 else 7

    /** Wrong passwords in a row before a card configured with [authLimit] freezes. */
    val maxAttempts get() = if (isNtag) 8 else 7

    fun attemptsFor(authLimit: Int) = if (authLimit == 0) 0 else if (isNtag) 1 shl authLimit else authLimit
}

sealed interface WriteProtection {
    data object Open : WriteProtection

    /** [readProtected]: even reading the card's content needs the password. */
    data class Password(val limited: Boolean, val readProtected: Boolean = false) : WriteProtection
    data object Locked : WriteProtection
}

/** An NDEF message read straight from Type 2 tag memory. */
class Type2Ndef(val message: ByteArray, val used: Int, val capacity: Int, val writable: Boolean)

/** How a typed password becomes the chip's 4-byte PWD, depending on which app set it. */
enum class PasswordScheme(val label: String) {
    NFC_STUDIO("NFC Studio"),

    /** NFC Tools (wakdev) and compatible apps: first 4 bytes of MD5(password). */
    NFC_TOOLS("NFC Tools or a similar app"),

    /** The raw PWD as 8 hex digits, e.g. FFFFFFFF. */
    HEX("Raw password (8 hex digits)"),
}

/**
 * Hardware write protection for NTAG213/215/216 and MIFARE Ultralight EV1 (NFC Forum Type 2):
 * a 32-bit write password with an optional wrong-attempt limit, permanent locking, and NDEF writes
 * after authenticating. Matches the desktop app (`app/desktop/src/ntag.rs`).
 *
 * The [Transceiver] must return `[0x0A]` for an accepted WRITE and a 1-byte NAK for a refused
 * WRITE or PWD_AUTH.
 */
class Type2Tag(private val io: Transceiver, private val uid: ByteArray) {

    fun identify(): NtagModel? {
        val v = runCatching { io.transceive(byteArrayOf(0x60)) }.getOrNull() ?: return null
        if (v.size < 8 || v[1].toInt() != 0x04) return null
        return when (v[2].toInt() to v[6].toInt()) {
            0x04 to 0x0F -> NtagModel.NTAG213
            0x04 to 0x11 -> NtagModel.NTAG215
            0x04 to 0x13 -> NtagModel.NTAG216
            0x03 to 0x0B -> NtagModel.UL_EV1_SMALL
            0x03 to 0x0E -> NtagModel.UL_EV1_LARGE
            else -> null
        }
    }

    fun read4(page: Int): ByteArray {
        val d = io.transceive(byteArrayOf(0x30, page.toByte()))
        if (d.size < 16) throw Type2Exception("The card returned too little data.")
        return d.copyOf(16)
    }

    private fun write(page: Int, data: ByteArray) {
        val r = io.transceive(byteArrayOf(0xA2.toByte(), page.toByte()) + data)
        if (r.size == 1 && r[0].toInt() and 0x0F != 0x0A) throw Type2Exception("The card refused the change.")
    }

    fun status(model: NtagModel): WriteProtection {
        val head = read4(0)
        val ccReadOnly = head[15].toInt() and 0x0F == 0x0F
        val staticLocked = head[10] == 0xFF.toByte() && head[11] == 0xFF.toByte()
        if (ccReadOnly && staticLocked) return WriteProtection.Locked
        val cfg = try {
            read4(model.cfgPage)
        } catch (e: CardGoneException) {
            throw e
        } catch (e: IOException) {
            // The configuration is only unreadable when reading is password-protected.
            return WriteProtection.Password(limited = true, readProtected = true)
        }
        val auth0 = cfg[3].toInt() and 0xFF
        return when {
            auth0 <= model.cfgPage + 3 -> WriteProtection.Password(
                limited = cfg[4].toInt() and 0x07 != 0,
                readProtected = cfg[4].toInt() and 0x80 != 0,
            )
            else -> WriteProtection.Open
        }
    }

    /** Reads the NDEF message directly; null when the tag isn't set up for NFC messages. */
    fun readNdef(): Type2Ndef? {
        val head = read4(3)
        if (head[0] != 0xE1.toByte()) return null
        val capacity = (head[2].toInt() and 0xFF) * 8
        val writable = head[3].toInt() and 0x0F == 0
        var mem = head.copyOfRange(4, 16)
        var page = 7
        while (true) {
            val area = mem.copyOf(minOf(mem.size, capacity))
            when (val s = Tlv.scan(area)) {
                is TlvScan.Found -> return Type2Ndef(s.message, s.used, capacity, writable)
                TlvScan.Empty -> return Type2Ndef(ByteArray(0), 0, capacity, writable)
                TlvScan.Incomplete -> {
                    if (mem.size >= capacity) {
                        if (area.all { it == 0.toByte() }) return Type2Ndef(ByteArray(0), 0, capacity, writable)
                        throw Type2Exception("The data on this card is damaged.")
                    }
                    mem += read4(page)
                    page += 4
                }
            }
        }
    }

    /** Human-readable protection details for the memory dump. */
    fun describe(): List<String> {
        val out = mutableListOf<String>()
        val model = identify()
        out += "Chip: ${model?.label ?: "unknown (no GET_VERSION answer)"}"
        val head = read4(0)
        out += "Static lock bytes: %02X %02X · CC: %02X %02X %02X %02X".format(
            head[10], head[11], head[12], head[13], head[14], head[15],
        )
        if (model != null) {
            val cfg = runCatching { read4(model.cfgPage) }.getOrNull()
            if (cfg == null) {
                out += "Configuration: unreadable, so reading is password-protected"
            } else {
                val auth0 = cfg[3].toInt() and 0xFF
                out += "AUTH0: %02X (%s)".format(auth0, if (auth0 <= model.cfgPage + 3) "protected from page $auth0" else "no password")
                out += "PROT (read protection): ${if (cfg[4].toInt() and 0x80 != 0) "on" else "off"}"
                val limit = cfg[4].toInt() and 0x07
                out += "AUTHLIM: ${if (limit == 0) "unlimited attempts" else "freezes after ${model.attemptsFor(limit)} wrong passwords"}"
                out += "CFGLCK (settings locked): ${if (cfg[4].toInt() and 0x40 != 0) "yes" else "no"}"
            }
        }
        return out
    }

    fun authenticate(password: String, scheme: PasswordScheme = PasswordScheme.NFC_STUDIO) {
        val (pwd, pack) = pwdFor(scheme, password, uid)
        val r = io.transceive(byteArrayOf(0x1B) + pwd)
        if (r.size < 2) throw WrongPasswordException()
        if (pack != null && !r.copyOf(2).contentEquals(pack)) {
            throw Type2Exception("The card answered the password check incorrectly. It may be counterfeit.")
        }
    }

    private fun configure(model: NtagModel, auth0: Int, authLimit: Int) {
        val cur = read4(model.cfgPage)
        // CFG1 first: once AUTH0 is set, the config pages themselves are protected.
        write(model.cfgPage + 1, byteArrayOf(((cur[4].toInt() and 0x78) or authLimit).toByte(), cur[5], cur[6], cur[7]))
        write(model.cfgPage, byteArrayOf(cur[0], cur[1], cur[2], auth0.toByte()))
    }

    fun setPassword(model: NtagModel, newPassword: String, limitAttempts: Boolean, current: String?) {
        when (status(model)) {
            WriteProtection.Locked -> throw Type2Exception("This card is locked permanently.")
            is WriteProtection.Password -> authenticate(current ?: throw NeedsPasswordException())
            WriteProtection.Open -> {}
        }
        val (pwd, pack) = derive(newPassword, uid)
        write(model.cfgPage + 2, pwd)
        write(model.cfgPage + 3, pack + byteArrayOf(0, 0))
        configure(model, PROTECT_FROM, if (limitAttempts) model.authLimit else 0)
        try {
            authenticate(newPassword)
        } catch (e: Type2Exception) {
            throw Type2Exception("The password was set but couldn't be confirmed. Try again.")
        }
    }

    fun removePassword(model: NtagModel, current: String) {
        authenticate(current)
        clearPassword(model)
    }

    private fun clearPassword(model: NtagModel) {
        configure(model, 0xFF, 0)
        write(model.cfgPage + 2, ByteArray(4) { 0xFF.toByte() })
        write(model.cfgPage + 3, ByteArray(4))
    }

    /** Last page of user memory; lock and configuration pages follow it. */
    private fun lastUserPage(model: NtagModel) =
        if (model == NtagModel.UL_EV1_SMALL) model.cfgPage - 1 else model.cfgPage - 2

    /**
     * Wipes all user memory (leaving an empty NDEF message) and removes the write password.
     * [current] is needed when the card has a password; [scheme] says which app set it.
     */
    fun factoryReset(model: NtagModel, current: String?, scheme: PasswordScheme = PasswordScheme.NFC_STUDIO) {
        val hadPassword = when (status(model)) {
            WriteProtection.Locked -> throw Type2Exception(LOCKED_FOREVER)
            is WriteProtection.Password -> {
                authenticate(current ?: throw NeedsPasswordException(), scheme)
                true
            }
            WriteProtection.Open -> false
        }
        try {
            // The empty message goes first so the card is valid even if the wipe is interrupted.
            write(4, byteArrayOf(0x03, 0x00, 0xFE.toByte(), 0x00))
            for (p in 5..lastUserPage(model)) write(p, ByteArray(4))
        } catch (e: Type2Exception) {
            throw Type2Exception("Part of this card is locked permanently, so it couldn't be fully erased.")
        }
        if (hadPassword) clearPassword(model)
    }

    /**
     * Makes the card read-only forever: static lock bits and the read-only CC flag cover pages 3–15;
     * the rest is protected by a random password nobody knows, frozen after one wrong guess.
     */
    fun lockForever(model: NtagModel?, current: String?, random: SecureRandom = SecureRandom()) {
        val head = read4(0)
        val userBytes = (head[14].toInt() and 0xFF) * 8
        if (model == null && 16 + userBytes > 64) throw Type2Exception("This tag type can't be locked permanently.")
        if (model != null) {
            if (status(model) is WriteProtection.Password) authenticate(current ?: throw NeedsPasswordException())
            val secret = ByteArray(6).also(random::nextBytes)
            write(model.cfgPage + 2, secret.copyOf(4))
            write(model.cfgPage + 3, secret.copyOfRange(4, 6) + byteArrayOf(0, 0))
            configure(model, PROTECT_FROM, 1)
        }
        write(3, byteArrayOf(head[12], head[13], head[14], (head[15].toInt() or 0x0F).toByte()))
        write(2, byteArrayOf(head[8], head[9], 0xFF.toByte(), 0xFF.toByte()))
    }

    /** Writes an NDEF message as a Type 2 TLV from page 4 (call [authenticate] first if protected). */
    fun writeNdef(message: ByteArray) {
        val cc = read4(3)
        if (cc[0] != 0xE1.toByte()) throw Type2Exception("This tag isn't set up for NFC messages.")
        if (cc[3].toInt() and 0x0F != 0) throw Type2Exception("This card is locked (read-only), so it can't be changed.")
        val capacity = (cc[2].toInt() and 0xFF) * 8
        val tlv = Tlv.wrap(message)
        val needed = tlv.size - 1
        if (needed > capacity) {
            throw Type2Exception("That's too much for this card: it needs $needed bytes but holds $capacity.")
        }
        val body = if (tlv.size > capacity) tlv.copyOf(tlv.size - 1) else tlv
        val padded = body.copyOf((body.size + 3) / 4 * 4)
        for (i in 0 until padded.size / 4) write(4 + i, padded.copyOfRange(i * 4, i * 4 + 4))
    }

    companion object {
        private const val PROTECT_FROM = 4
        const val LOCKED_FOREVER = "This card is locked permanently, so it can never be erased. " +
            "That's what makes the lock tamper-proof."

        /** PWD for [password], plus the PACK the card should answer with when we know it. */
        fun pwdFor(scheme: PasswordScheme, password: String, uid: ByteArray): Pair<ByteArray, ByteArray?> = when (scheme) {
            PasswordScheme.NFC_STUDIO -> derive(password, uid)
            PasswordScheme.NFC_TOOLS ->
                java.security.MessageDigest.getInstance("MD5").digest(password.toByteArray(Charsets.UTF_8)).copyOf(4) to null
            PasswordScheme.HEX -> {
                val h = password.filter { !it.isWhitespace() && it != ':' && it != '-' }
                if (h.length != 8 || !h.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                    throw Type2Exception("Enter exactly 8 hex digits, for example FFFFFFFF.")
                }
                ByteArray(4) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() } to null
            }
        }

        /** Card password → (PWD, PACK); the UID salt makes the same password different on every card. */
        fun derive(password: String, uid: ByteArray): Pair<ByteArray, ByteArray> {
            val salt = "NFCStudio-PWD".toByteArray(Charsets.US_ASCII) + uid
            val out = Pbkdf2.sha256(password, salt, 10_000, 6)
            return out.copyOf(4) to out.copyOfRange(4, 6)
        }
    }
}
