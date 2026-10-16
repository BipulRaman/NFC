package dev.bipul.nfcstudio.data

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class WrongPinException : Exception("Wrong PIN")

/**
 * Locks items with a PIN or passphrase: PBKDF2-HMAC-SHA256 → AES-256-GCM.
 *
 * Payload layout (all integers big-endian):
 * `version(1) kind(1) labelLen(1) label iterations(4) salt(16) iv(12) ciphertext+tag`.
 * Everything before the ciphertext is authenticated, so the visible label can't be swapped.
 */
object Vault {
    const val VERSION: Byte = 1
    const val ITERATIONS = 120_000
    private const val SALT = 16
    private const val IV = 12
    private const val TAG_BITS = 128
    private const val MAX_LABEL = 60

    private val kindCodes = mapOf(ItemKind.PASSWORD to 1, ItemKind.NOTE to 2)

    fun canLock(item: CardItem) = item.kind in kindCodes

    fun seal(
        inner: CardItem,
        label: String,
        pin: String,
        iterations: Int = ITERATIONS,
        random: SecureRandom = SecureRandom(),
    ): CardItem.Locked {
        val kind = kindCodes[inner.kind] ?: throw IllegalArgumentException("${inner.kind.label} can't be protected")
        val labelBytes = trimLabel(label)
        val salt = ByteArray(SALT).also(random::nextBytes)
        val iv = ByteArray(IV).also(random::nextBytes)
        val header = ByteArrayOutputStream().apply {
            write(VERSION.toInt()); write(kind); write(labelBytes.size); write(labelBytes)
            write(ByteBuffer.allocate(4).putInt(iterations).array()); write(salt); write(iv)
        }.toByteArray()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(pin, salt, iterations), GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(header)
        val ct = cipher.doFinal(ItemCodec.toJson(inner).toString().toByteArray(Charsets.UTF_8))
        return CardItem.Locked(inner.kind, String(labelBytes, Charsets.UTF_8), header + ct)
    }

    /** Reads the visible part of a locked payload; throws if it isn't one. */
    fun parse(payload: ByteArray): CardItem.Locked {
        require(payload.size > 3 && payload[0] == VERSION) { "Unsupported protected item" }
        val kind = kindCodes.entries.firstOrNull { it.value == payload[1].toInt() }?.key ?: ItemKind.NOTE
        val labelLen = payload[2].toInt() and 0xFF
        require(payload.size >= 3 + labelLen + 4 + SALT + IV + TAG_BITS / 8) { "Truncated protected item" }
        return CardItem.Locked(kind, String(payload, 3, labelLen, Charsets.UTF_8), payload)
    }

    fun open(locked: CardItem.Locked, pin: String): CardItem {
        val p = locked.sealed
        val labelLen = p[2].toInt() and 0xFF
        var i = 3 + labelLen
        val iterations = ByteBuffer.wrap(p, i, 4).int
        i += 4
        val salt = p.copyOfRange(i, i + SALT)
        i += SALT
        val iv = p.copyOfRange(i, i + IV)
        i += IV
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(pin, salt, iterations), GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(p, 0, i)
        val plain = try {
            cipher.doFinal(p, i, p.size - i)
        } catch (e: AEADBadTagException) {
            throw WrongPinException()
        }
        return ItemCodec.fromJson(org.json.JSONObject(String(plain, Charsets.UTF_8)))
    }

    /** Bytes the locked record for [inner] will take on the card (exact). */
    fun sealedRecordSize(inner: CardItem, label: String): Int {
        val plain = ItemCodec.toJson(inner).toString().toByteArray(Charsets.UTF_8).size
        val payload = 3 + trimLabel(label).size + 4 + SALT + IV + plain + TAG_BITS / 8
        return RawRecord.mime(ItemCodec.MIME_LOCKED, ByteArray(payload)).byteSize
    }

    private fun trimLabel(label: String): ByteArray {
        var l = label.trim()
        while (l.toByteArray(Charsets.UTF_8).size > MAX_LABEL) l = l.dropLast(1)
        return l.toByteArray(Charsets.UTF_8)
    }

    private fun deriveKey(pin: String, salt: ByteArray, iterations: Int): SecretKeySpec {
        val spec = PBEKeySpec(pin.toCharArray(), salt, iterations, 256)
        try {
            val key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            return SecretKeySpec(key, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    /** A strong random password using letters, digits and symbols. */
    fun generatePassword(length: Int = 16, random: SecureRandom = SecureRandom()): String {
        val sets = listOf("ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*-_=+?")
        val all = sets.joinToString("")
        val chars = MutableList(length) { all[random.nextInt(all.length)] }
        sets.forEachIndexed { i, s -> chars[i] = s[random.nextInt(s.length)] }
        for (i in chars.indices.reversed()) {
            val j = random.nextInt(i + 1)
            chars[i] = chars[j].also { chars[j] = chars[i] }
        }
        return chars.joinToString("")
    }
}
