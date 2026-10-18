package dev.bipul.nfcstudio.data

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Tamper seals: an ECDSA P-256 signature over a card's content and unique ID, stored as an extra
 * NDEF record. Any change to the content, or copying it to another card, breaks the seal.
 * The format matches the desktop app (`app/desktop/src/seal.rs`).
 */
object Seal {
    const val TYPE = "nfcstudio.dev:seal"
    private const val VERSION: Byte = 1
    private val DOMAIN = "NFCSTUDIO-SEAL-v1\u0000".toByteArray(Charsets.US_ASCII)

    /** Bytes a seal record adds to a card's NDEF message. */
    const val RECORD_SIZE = 3 + 18 + 1 + 33 + 64

    /** Signs with a P-256 key; [sign] returns a DER signature over SHA-256 of the data. */
    interface Signer {
        val publicKey: ByteArray
        fun sign(data: ByteArray): ByteArray
    }

    sealed interface Status {
        data object None : Status
        class Valid(val key: ByteArray) : Status
        data object Broken : Status
    }

    fun isSeal(r: RawRecord) = r.tnf == RawRecord.TNF_EXTERNAL && r.typeString == TYPE

    /** Puts ISO 15693 UIDs (sent least significant byte first by Android) in one canonical order. */
    fun normalizeUid(uid: ByteArray): ByteArray =
        if (uid.size == 8 && uid[7] == 0xE0.toByte()) uid.reversedArray() else uid

    /** Cards whose ID changes on every tap (random IDs start with 0x08) can't be sealed. */
    fun uidIsStable(uid: ByteArray) = uid.isNotEmpty() && !(uid.size == 4 && uid[0] == 0x08.toByte())

    fun signedBytes(uid: ByteArray, records: List<RawRecord>): ByteArray {
        val id = normalizeUid(uid)
        val out = ByteArrayOutputStream()
        out.write(DOMAIN)
        out.write(id.size)
        out.write(id)
        for (r in records) {
            out.write(r.tnf.toInt())
            for (part in listOf(r.type, r.id, r.payload)) {
                out.write(u32(part.size))
                out.write(part)
            }
        }
        return out.toByteArray()
    }

    fun sealRecord(signer: Signer, uid: ByteArray, records: List<RawRecord>): RawRecord {
        val raw = derToRaw(signer.sign(signedBytes(uid, records)))
        return RawRecord(
            RawRecord.TNF_EXTERNAL,
            TYPE.toByteArray(Charsets.US_ASCII),
            byteArrayOf(VERSION) + signer.publicKey + raw,
        )
    }

    /** Splits [records] into content and seal and checks the seal against [uid]. */
    fun verify(uid: ByteArray, records: List<RawRecord>): Pair<Status, List<RawRecord>> {
        val content = records.filterNot(::isSeal)
        val seal = records.lastOrNull(::isSeal) ?: return Status.None to content
        val p = seal.payload
        val ok = runCatching {
            require(p.size == 1 + 33 + 64 && p[0] == VERSION)
            val key = p.copyOfRange(1, 34)
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(decompress(key))
            verifier.update(signedBytes(uid, content))
            verifier.verify(rawToDer(p.copyOfRange(34, 98)))
        }.getOrDefault(false)
        return (if (ok) Status.Valid(p.copyOfRange(1, 34)) else Status.Broken) to content
    }

    /** A short, human-comparable ID for a sealing key, e.g. `3F2A-91C4-0B7E`. */
    fun fingerprint(key: ByteArray): String {
        val h = MessageDigest.getInstance("SHA-256").digest(key)
        return "%02X%02X-%02X%02X-%02X%02X".format(h[0], h[1], h[2], h[3], h[4], h[5])
    }

    // ---- P-256 helpers -----------------------------------------------------------

    private val params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    fun compress(key: ECPublicKey): ByteArray {
        val x = unsigned32(key.w.affineX)
        val prefix = if (key.w.affineY.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix.toByte()) + x
    }

    fun decompress(bytes: ByteArray): ECPublicKey {
        require(bytes.size == 33 && (bytes[0].toInt() == 2 || bytes[0].toInt() == 3))
        val p = (params.curve.field as ECFieldFp).p
        val x = BigInteger(1, bytes.copyOfRange(1, 33))
        val rhs = x.pow(3).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
        var y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        require(y.modPow(BigInteger.TWO, p) == rhs) { "Not a point on P-256" }
        if (y.testBit(0) != (bytes[0].toInt() == 3)) y = p.subtract(y)
        val spec = ECPublicKeySpec(ECPoint(x, y), params)
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    private val order: BigInteger get() = params.order

    /** DER ECDSA signature → 64-byte r ‖ s with low S (as the desktop app expects). */
    fun derToRaw(der: ByteArray): ByteArray {
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7F
        fun next(): BigInteger {
            require(der[i].toInt() == 0x02)
            val len = der[i + 1].toInt()
            val v = BigInteger(1, der.copyOfRange(i + 2, i + 2 + len))
            i += 2 + len
            return v
        }
        val r = next()
        var s = next()
        if (s > order.shiftRight(1)) s = order.subtract(s)
        return unsigned32(r) + unsigned32(s)
    }

    fun rawToDer(raw: ByteArray): ByteArray {
        fun int(v: ByteArray): ByteArray {
            val b = BigInteger(1, v).toByteArray()
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun unsigned32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }

    private fun u32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
