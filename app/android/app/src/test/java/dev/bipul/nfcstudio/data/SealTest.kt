package dev.bipul.nfcstudio.data

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SealTest {

    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private val uid = hex("04A1B2C3D4E5F6")
    private val sample = listOf(
        RawRecord(1, "T".toByteArray(), "\u0002enHello".toByteArray()),
        RawRecord(1, "U".toByteArray(), "\u0004example.com".toByteArray()),
    )

    private fun softwareSigner(): Seal.Signer {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return object : Seal.Signer {
            override val publicKey = Seal.compress(kp.public as ECPublicKey)
            override fun sign(data: ByteArray): ByteArray =
                Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(data); sign() }
        }
    }

    @Test
    fun matchesSharedVector() {
        assertEquals(
            "4e464353545544494f2d5345414c2d7631000704a1b2c3d4e5f6010000000154000000000000000802656e48656c6c6f" +
                "010000000155000000000000000c046578616d706c652e636f6d",
            Seal.signedBytes(uid, sample).joinToString("") { "%02x".format(it) },
        )
        // Signed by an independent implementation (Python `cryptography`); the desktop test uses it too.
        val payload = byteArrayOf(1) +
            hex("02bd7c73b88b2e9b4ceda62022b2da8be13193a5b56edc26e7df7842e24cd0b5eb") +
            hex("c9ee6e3f1d48913f65ce340ebde16eb3bb0e121edc693949148adc7402d61060") +
            hex("2f7a9d99f5f68f51c5310d80fb9e7297614083cdbf97a1e73e50922ef318979d")
        val seal = RawRecord(RawRecord.TNF_EXTERNAL, Seal.TYPE.toByteArray(), payload)
        val (status, content) = Seal.verify(uid, sample + seal)
        assertTrue(status is Seal.Status.Valid)
        assertEquals(sample, content)
    }

    @Test
    fun detectsChangesAndCopies() {
        val signer = softwareSigner()
        val seal = Seal.sealRecord(signer, uid, sample)
        assertEquals(Seal.RECORD_SIZE, seal.byteSize)
        val status = Seal.verify(uid, sample + seal).first
        assertArrayEquals(signer.publicKey, (status as Seal.Status.Valid).key)

        val changed = listOf(RawRecord(1, "T".toByteArray(), "\u0002enHellO".toByteArray()), sample[1])
        assertEquals(Seal.Status.Broken, Seal.verify(uid, changed + seal).first)
        assertEquals(Seal.Status.Broken, Seal.verify(hex("04A1B2C3D4E5F7"), sample + seal).first)
        assertEquals(Seal.Status.None, Seal.verify(uid, sample).first)
    }

    @Test
    fun keyAndUidHelpers() {
        val signer = softwareSigner()
        assertEquals(33, signer.publicKey.size)
        val back = Seal.compress(Seal.decompress(signer.publicKey))
        assertArrayEquals(signer.publicKey, back)
        assertArrayEquals(hex("E00F060504030201"), Seal.normalizeUid(hex("0102030405060FE0")))
        assertTrue(!Seal.uidIsStable(hex("08AABBCC")))
        assertEquals(14, Seal.fingerprint(signer.publicKey).length)
    }
}
