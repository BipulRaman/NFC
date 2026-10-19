package dev.bipul.nfcstudio.nfc

import dev.bipul.nfcstudio.data.Pbkdf2
import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Type2Test {

    /** An NTAG215 that enforces static locks, AUTH0, AUTHLIM and the read-only CC. NAKs are `[0x00]`. */
    private class FakeNtag : Transceiver {
        val mem = ByteArray(135 * 4)
        private var authed = false
        private var failures = 0
        private var frozen = false
        private val cfg = 0x83 * 4
        private val nak = byteArrayOf(0x00)

        init {
            byteArrayOf(0x04, 0xA1.toByte(), 0xB2.toByte(), 0x5F, 0xC3.toByte(), 0xD4.toByte(), 0xE5.toByte(), 0xF6.toByte(), 0x41)
                .copyInto(mem)
            byteArrayOf(0xE1.toByte(), 0x10, 0x3E, 0x00).copyInto(mem, 12)
            byteArrayOf(0x03, 0x00, 0xFE.toByte(), 0x00).copyInto(mem, 16)
            byteArrayOf(0x04, 0x00, 0x00, 0xFF.toByte()).copyInto(mem, cfg)
            ByteArray(4) { 0xFF.toByte() }.copyInto(mem, cfg + 8)
        }

        val uid get() = mem.copyOfRange(0, 3) + mem.copyOfRange(4, 8)

        fun reset() {
            authed = false
        }

        private fun writable(page: Int): Boolean {
            val lock = (mem[10].toInt() and 0xFF) or ((mem[11].toInt() and 0xFF) shl 8)
            return when (page) {
                0, 1 -> false
                2 -> true
                in 3..15 -> lock and (1 shl page) == 0
                else -> page < 135
            }
        }

        override fun transceive(frame: ByteArray): ByteArray {
            return when (frame[0].toInt() and 0xFF) {
                0x60 -> byteArrayOf(0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03)
                0x30 -> {
                    val p = (frame[1].toInt() and 0xFF) * 4
                    ByteArray(16) { k ->
                        val i = p + k
                        if (i in 0x85 * 4 until 0x87 * 4) 0 else mem.getOrElse(i) { 0 }
                    }
                }
                0xA2 -> {
                    val page = frame[1].toInt() and 0xFF
                    val auth0 = mem[cfg + 3].toInt() and 0xFF
                    if (!writable(page) || (page >= auth0 && !authed)) return nak
                    val p = page * 4
                    when (page) {
                        2 -> {
                            mem[p + 2] = (mem[p + 2].toInt() or frame[4].toInt()).toByte()
                            mem[p + 3] = (mem[p + 3].toInt() or frame[5].toInt()).toByte()
                        }
                        3 -> for (i in 0 until 4) mem[p + i] = (mem[p + i].toInt() or frame[2 + i].toInt()).toByte()
                        else -> frame.copyInto(mem, p, 2, 6)
                    }
                    byteArrayOf(0x0A)
                }
                0x1B -> {
                    val limit = mem[cfg + 4].toInt() and 0x07
                    if (!frozen && frame.copyOfRange(1, 5).contentEquals(mem.copyOfRange(0x85 * 4, 0x85 * 4 + 4))) {
                        failures = 0
                        authed = true
                        return mem.copyOfRange(0x86 * 4, 0x86 * 4 + 2)
                    }
                    failures++
                    if (limit != 0 && failures >= limit) frozen = true
                    nak
                }
                else -> nak
            }
        }
    }

    private fun message(text: String) = byteArrayOf(0xD1.toByte(), 1, (text.length + 3).toByte(), 'T'.code.toByte(), 2) +
        "en".toByteArray() + text.toByteArray()

    private fun storedMessage(t: FakeNtag): ByteArray =
        (Tlv.scan(t.mem.copyOfRange(16, t.mem.size)) as TlvScan.Found).message

    @Test
    fun derivationMatchesSharedVectorAndPlatform() {
        val uid = byteArrayOf(0x04, 0xA1.toByte(), 0xB2.toByte(), 0xC3.toByte(), 0xD4.toByte(), 0xE5.toByte(), 0xF6.toByte())
        val (pwd, pack) = Type2Tag.derive("correct horse", uid)
        assertEquals("fffcc6c0aef8", (pwd + pack).joinToString("") { "%02x".format(it) })
        val salt = ByteArray(16) { it.toByte() }
        for (pw in listOf("", "1234", "pässwörd ✓")) {
            assertArrayEquals(Pbkdf2.platform(pw.ifEmpty { "x" }, salt, 1000, 32), Pbkdf2.portable(pw.ifEmpty { "x" }, salt, 1000, 32))
        }
    }

    @Test
    fun passwordBlocksChangesUntilAuthenticated() {
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        val model = t.identify()
        assertEquals(NtagModel.NTAG215, model)
        assertEquals(WriteProtection.Open, t.status(model!!))
        t.writeNdef(message("original"))

        t.setPassword(model, "s3cret", limitAttempts = true, current = null)
        fake.reset()
        assertEquals(WriteProtection.Password(limited = true), t.status(model))
        assertFails<Exception> { t.writeNdef(message("tampered")) }
        assertArrayEquals(message("original"), storedMessage(fake))

        assertFails<WrongPasswordException> { t.authenticate("wrong") }
        t.authenticate("s3cret")
        t.writeNdef(message("updated"))
        assertArrayEquals(message("updated"), storedMessage(fake))

        fake.reset()
        assertFails<NeedsPasswordException> { t.setPassword(model, "new", false, null) }
        t.setPassword(model, "new", limitAttempts = false, current = "s3cret")
        fake.reset()
        assertEquals(WriteProtection.Password(limited = false), t.status(model))
        t.removePassword(model, "new")
        fake.reset()
        assertEquals(WriteProtection.Open, t.status(model))
        t.writeNdef(message("free"))
    }

    @Test
    fun attemptLimitFreezesTheCard() {
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        t.setPassword(NtagModel.NTAG215, "pin", limitAttempts = true, current = null)
        repeat(Type2Tag.ATTEMPT_LIMIT) { assertFails<WrongPasswordException> { t.authenticate("guess") } }
        assertFails<WrongPasswordException> { t.authenticate("pin") }
    }

    @Test
    fun factoryResetWipesEverythingAndRemovesPassword() {
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        t.writeNdef(message("secret data ".repeat(20)))
        t.setPassword(NtagModel.NTAG215, "pw", limitAttempts = true, current = null)
        fake.reset()
        assertFails<NeedsPasswordException> { t.factoryReset(NtagModel.NTAG215, null) }
        assertFails<WrongPasswordException> { t.factoryReset(NtagModel.NTAG215, "bad") }
        t.factoryReset(NtagModel.NTAG215, "pw")
        fake.reset()
        assertEquals(WriteProtection.Open, t.status(NtagModel.NTAG215))
        assertArrayEquals(byteArrayOf(0x03, 0x00, 0xFE.toByte(), 0x00), fake.mem.copyOfRange(16, 20))
        assertTrue(fake.mem.copyOfRange(20, 130 * 4).all { it == 0.toByte() })
        t.writeNdef(message("fresh"))

        t.lockForever(NtagModel.NTAG215, null)
        fake.reset()
        try {
            t.factoryReset(NtagModel.NTAG215, null)
            fail("locked cards can't be erased")
        } catch (e: Type2Exception) {
            assertEquals(Type2Tag.LOCKED_FOREVER, e.message)
        }
    }

    @Test
    fun erasesCardsProtectedByOtherApps() {
        val md5 = Type2Tag.pwdFor(PasswordScheme.NFC_TOOLS, "1234", ByteArray(0)).first
        assertEquals("81dc9bdb", md5.joinToString("") { "%02x".format(it) })
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        t.writeNdef(message("from another app"))
        md5.copyInto(fake.mem, 0x85 * 4)
        fake.mem[0x83 * 4 + 3] = 0x04
        fake.reset()
        assertFails<Exception> { t.factoryReset(NtagModel.NTAG215, "1234", PasswordScheme.NFC_STUDIO) }
        t.factoryReset(NtagModel.NTAG215, "1234", PasswordScheme.NFC_TOOLS)
        fake.reset()
        assertEquals(WriteProtection.Open, t.status(NtagModel.NTAG215))

        byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()).copyInto(fake.mem, 0x85 * 4)
        fake.mem[0x83 * 4 + 3] = 0x04
        fake.reset()
        t.factoryReset(NtagModel.NTAG215, "de:ad:be:ef", PasswordScheme.HEX)
        fake.reset()
        assertEquals(WriteProtection.Open, t.status(NtagModel.NTAG215))
        assertFails<Type2Exception> { Type2Tag.pwdFor(PasswordScheme.HEX, "FFFF", ByteArray(0)) }
    }

    @Test
    fun lockForeverIsPermanent() {
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        t.writeNdef(message("final"))
        t.setPassword(NtagModel.NTAG215, "pw", limitAttempts = false, current = null)
        fake.reset()
        assertFails<WrongPasswordException> { t.lockForever(NtagModel.NTAG215, "nope", SecureRandom()) }
        fake.reset()
        t.lockForever(NtagModel.NTAG215, "pw")
        fake.reset()
        assertEquals(WriteProtection.Locked, t.status(NtagModel.NTAG215))
        assertFails<Exception> { t.authenticate("pw") }
        assertFails<Exception> { t.writeNdef(message("changed")) }
        assertArrayEquals(message("final"), storedMessage(fake))
    }

    @Test
    fun oversizedMessagesAreRejected() {
        val fake = FakeNtag()
        val t = Type2Tag(fake, fake.uid)
        try {
            t.writeNdef(ByteArray(600))
            fail("too big")
        } catch (e: Type2Exception) {
            assertTrue(e.message!!.contains("too much"))
        }
    }

    private inline fun <reified E : Throwable> assertFails(block: () -> Unit) {
        try {
            block()
        } catch (e: Throwable) {
            assertTrue("expected ${E::class.simpleName} but got $e", e is E)
            return
        }
        fail("expected ${E::class.simpleName}")
    }

}
