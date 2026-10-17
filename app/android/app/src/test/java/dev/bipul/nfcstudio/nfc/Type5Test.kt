package dev.bipul.nfcstudio.nfc

import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Type5Test {

    /** An ISO 15693 tag answering addressed READ/WRITE SINGLE BLOCK and GET SYSTEM INFO. */
    private class FakeVicinity(
        val blockSize: Int = 4,
        val blocks: Int = 28,
        val systemInfo: Boolean = true,
        val needsOptionFlag: Boolean = false,
    ) : Transceiver {
        val uid = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val mem = ByteArray(blockSize * blocks)

        override fun transceive(frame: ByteArray): ByteArray {
            assertArrayEquals("addressed to this tag", uid, frame.copyOfRange(2, 10))
            val error = byteArrayOf(0x01, 0x0F)
            return when (frame[1].toInt()) {
                0x2B -> if (!systemInfo) error else
                    byteArrayOf(0x00, 0x0F) + uid + byteArrayOf(0x00, 0x00, (blocks - 1).toByte(), (blockSize - 1).toByte(), 0x01)
                0x20 -> {
                    val b = frame[10].toInt() and 0xFF
                    if (b >= blocks) error else byteArrayOf(0x00) + mem.copyOfRange(b * blockSize, (b + 1) * blockSize)
                }
                0x21 -> {
                    val b = frame[10].toInt() and 0xFF
                    if (needsOptionFlag && frame[0].toInt() and 0x40 == 0) throw IOException("no response")
                    if (b >= blocks) return error
                    frame.copyInto(mem, b * blockSize, 11, 11 + blockSize)
                    byteArrayOf(0x00)
                }
                else -> error
            }
        }
    }

    private fun tag(f: FakeVicinity) = Type5Tag(f, f.uid).also { it.open() }

    @Test
    fun blankTagIsSetUpOnFirstWriteAndRoundTrips() {
        for ((bs, info) in listOf(4 to true, 4 to false, 8 to true)) {
            val fake = FakeVicinity(blockSize = bs, blocks = 112 / bs, systemInfo = info)
            val t = tag(fake)
            assertEquals(112, t.memorySize)
            assertTrue(t.read() is Type5Tag.Content.Blank)

            val message = "hello rfid".toByteArray()
            t.write(message)
            assertArrayEquals(byteArrayOf(0xE1.toByte(), 0x40, 0x0E, 0x00), fake.mem.copyOf(4))
            val c = t.read() as Type5Tag.Content.Ndef
            assertArrayEquals(message, c.message)
            assertEquals(108, c.capacity)
            assertEquals(message.size + 2, c.used)

            t.write(ByteArray(0))
            assertEquals(0, (t.read() as Type5Tag.Content.Ndef).message.size)
        }
    }

    @Test
    fun foreignDataIsNeverOverwritten() {
        val fake = FakeVicinity()
        byteArrayOf(0x11, 0x01, 0x31, 0x32).copyInto(fake.mem)
        val t = tag(fake)
        assertEquals(Type5Tag.Content.Foreign, t.read())
        try {
            t.write("x".toByteArray())
            fail("must not overwrite")
        } catch (e: Type5Exception) {
            assertTrue(e.message!!.contains("another system"))
        }
        assertEquals(0x11.toByte(), fake.mem[0])
    }

    @Test
    fun lockedOversizedAndOptionFlagTags() {
        val fake = FakeVicinity(needsOptionFlag = true)
        val t = tag(fake)
        t.write("ok".toByteArray())
        assertArrayEquals("ok".toByteArray(), (t.read() as Type5Tag.Content.Ndef).message)
        try {
            t.write(ByteArray(200))
            fail("too big")
        } catch (e: Type5Exception) {
            assertTrue(e.message!!.contains("too much"))
        }
        fake.mem[1] = 0x43
        try {
            t.write("x".toByteArray())
            fail("locked")
        } catch (e: Type5Exception) {
            assertTrue(e.message!!.contains("locked"))
        }
    }

    @Test
    fun tlvHandlesLongMessages() {
        val msg = ByteArray(300) { it.toByte() }
        val wrapped = Tlv.wrap(msg)
        assertEquals(0xFF.toByte(), wrapped[1])
        val found = Tlv.scan(byteArrayOf(0, 0) + wrapped) as TlvScan.Found
        assertArrayEquals(msg, found.message)
        assertEquals(TlvScan.Incomplete, Tlv.scan(wrapped.copyOf(10)))
    }
}
