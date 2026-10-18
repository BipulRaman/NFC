package dev.bipul.nfcstudio.data

import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * PBKDF2-HMAC-SHA256 (RFC 8018). Android only provides it as a SecretKeyFactory from API 26, so
 * older versions use a version built on HmacSHA256. Both encode passwords as UTF-8 and give
 * identical results.
 */
object Pbkdf2 {
    fun sha256(password: String, salt: ByteArray, iterations: Int, length: Int): ByteArray =
        runCatching { platform(password, salt, iterations, length) }.getOrNull()
            ?: portable(password, salt, iterations, length)

    internal fun platform(password: String, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, length * 8)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    internal fun portable(password: String, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val pw = password.toByteArray(Charsets.UTF_8)
        // HMAC accepts an empty key; SecretKeySpec doesn't, so use a single zero byte (same HMAC result).
        mac.init(SecretKeySpec(if (pw.isEmpty()) ByteArray(1) else pw, "HmacSHA256"))
        pw.fill(0)
        val out = ByteArray(length)
        var block = 1
        var offset = 0
        while (offset < length) {
            mac.update(salt)
            mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            repeat(iterations - 1) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            val n = minOf(t.size, length - offset)
            t.copyInto(out, offset, 0, n)
            offset += n
            block++
        }
        return out
    }
}
