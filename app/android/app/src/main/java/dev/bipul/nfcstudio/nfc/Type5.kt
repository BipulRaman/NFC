package dev.bipul.nfcstudio.nfc

import java.io.IOException

/** Sends a raw ISO 15693 frame and returns the tag's raw response (Android's `NfcV.transceive`). */
fun interface Transceiver {
    fun transceive(frame: ByteArray): ByteArray
}

class Type5Exception(message: String) : IOException(message)

/** Result of looking for an NDEF message in NFC Forum Type 2/5 tag memory. */
sealed interface TlvScan {
    data class Found(val message: ByteArray, val used: Int) : TlvScan
    data object Empty : TlvScan
    data object Incomplete : TlvScan
}

object Tlv {
    fun wrap(message: ByteArray): ByteArray {
        val header = if (message.size < 0xFF) {
            byteArrayOf(0x03, message.size.toByte())
        } else {
            byteArrayOf(0x03, 0xFF.toByte(), (message.size shr 8).toByte(), message.size.toByte())
        }
        return header + message + byteArrayOf(0xFE.toByte())
    }

    fun scan(mem: ByteArray): TlvScan {
        var i = 0
        while (i < mem.size) {
            val t = mem[i].toInt() and 0xFF
            if (t == 0x00) { i++; continue }
            if (t == 0xFE) return TlvScan.Empty
            if (i + 1 >= mem.size) return TlvScan.Incomplete
            var len = mem[i + 1].toInt() and 0xFF
            var hdr = 2
            if (len == 0xFF) {
                if (i + 3 >= mem.size) return TlvScan.Incomplete
                len = ((mem[i + 2].toInt() and 0xFF) shl 8) or (mem[i + 3].toInt() and 0xFF)
                hdr = 4
            }
            val start = i + hdr
            if (start + len > mem.size) return TlvScan.Incomplete
            if (t == 0x03) return TlvScan.Found(mem.copyOfRange(start, start + len), hdr + len)
            i = start + len
        }
        return TlvScan.Incomplete
    }
}

/**
 * NFC Forum Type 5 (ISO 15693 / NFC-V, e.g. NXP ICODE SLIX, TI Tag-it, ST LRI) over raw commands,
 * for phones whose NFC stack doesn't offer NDEF on these tags.
 */
class Type5Tag(private val io: Transceiver, private val uid: ByteArray) {

    sealed interface Content {
        /** [message] is the raw NDEF message; [capacity] the bytes available for it. */
        class Ndef(val message: ByteArray, val used: Int, val capacity: Int, val writable: Boolean) : Content
        data class Blank(val capacity: Int) : Content
        data object Foreign : Content
    }

    var blockSize = 4
        private set
    var blockCount = 0
        private set

    private class Cc(val length: Int, val capacity: Int, val writable: Boolean)

    // ---- Commands -------------------------------------------------------------

    private fun command(code: Int, flags: Int = 0x22, params: ByteArray = ByteArray(0)): ByteArray {
        val frame = byteArrayOf(flags.toByte(), code.toByte()) + uid + params
        val r = io.transceive(frame)
        if (r.isEmpty()) throw Type5Exception("The tag didn't answer.")
        if (r[0].toInt() and 0x01 != 0) {
            val code2 = if (r.size > 1) r[1].toInt() and 0xFF else 0
            throw Type5Exception("The tag refused the command (error %02X).".format(code2))
        }
        return r.copyOfRange(1, r.size)
    }

    /** Reads block size and count with GET SYSTEM INFO, or by probing when it isn't supported. */
    fun open() {
        val info = runCatching { command(0x2B) }.getOrNull()
        if (info != null && info.size >= 9) {
            val flags = info[0].toInt()
            var i = 9
            if (flags and 0x01 != 0) i++ // DSFID
            if (flags and 0x02 != 0) i++ // AFI
            if (flags and 0x04 != 0 && info.size >= i + 2) {
                blockCount = (info[i].toInt() and 0xFF) + 1
                blockSize = (info[i + 1].toInt() and 0x1F) + 1
                return
            }
        }
        blockSize = readBlock(0).size
        var n = 1
        while (n < 256 && runCatching { readBlock(n) }.isSuccess) n++
        blockCount = n
    }

    fun readBlock(n: Int): ByteArray = command(0x20, params = byteArrayOf(n.toByte()))

    fun writeBlock(n: Int, data: ByteArray) {
        require(data.size == blockSize)
        try {
            command(0x21, params = byteArrayOf(n.toByte()) + data)
        } catch (e: IOException) {
            // TI Tag-it and some others only accept writes with the Option flag set.
            command(0x21, flags = 0x62, params = byteArrayOf(n.toByte()) + data)
        }
    }

    private val usableBlocks get() = minOf(blockCount, 256)
    val memorySize get() = usableBlocks * blockSize

    private fun readUpTo(bytes: Int, into: MutableList<Byte>) {
        var n = into.size / blockSize
        while (into.size < bytes && n < usableBlocks) {
            into += readBlock(n).toList()
            n++
        }
    }

    private fun parseCc(mem: ByteArray): Cc? {
        if (mem.size < 4) return null
        val magic = mem[0].toInt() and 0xFF
        if (magic != 0xE1 && magic != 0xE2) return null
        val writable = mem[1].toInt() and 0x03 == 0
        val mlen = mem[2].toInt() and 0xFF
        if (mlen != 0) return Cc(4, (mlen * 8 - 4).coerceAtLeast(0), writable)
        if (mem.size < 8) return null
        val big = ((mem[6].toInt() and 0xFF) shl 8) or (mem[7].toInt() and 0xFF)
        return Cc(8, (big * 8 - 8).coerceAtLeast(0), writable)
    }

    // ---- NDEF -------------------------------------------------------------------

    fun read(): Content {
        val mem = mutableListOf<Byte>()
        readUpTo(8, mem)
        val cc = parseCc(mem.toByteArray())
            ?: return if (mem.all { it == 0.toByte() }) Content.Blank(memorySize - 4) else Content.Foreign
        val limit = minOf(cc.length + cc.capacity, memorySize)
        while (true) {
            val area = mem.toByteArray().copyOfRange(cc.length, minOf(mem.size, limit))
            when (val s = Tlv.scan(area)) {
                is TlvScan.Found -> return Content.Ndef(s.message, s.used, cc.capacity, cc.writable)
                TlvScan.Empty -> return Content.Ndef(ByteArray(0), 0, cc.capacity, cc.writable)
                TlvScan.Incomplete -> {
                    if (mem.size >= limit) {
                        if (area.all { it == 0.toByte() }) return Content.Ndef(ByteArray(0), 0, cc.capacity, cc.writable)
                        throw Type5Exception("The data on this tag is damaged.")
                    }
                    readUpTo(mem.size + blockSize, mem)
                }
            }
        }
    }

    /** Writes [message] (a raw NDEF message), setting up a blank tag first. */
    fun write(message: ByteArray) {
        val mem = mutableListOf<Byte>()
        readUpTo(8, mem)
        var head = mem.toByteArray()
        var cc = parseCc(head)
        if (cc == null) {
            if (!head.all { it == 0.toByte() }) {
                throw Type5Exception("This RFID tag holds data from another system, so it won't be overwritten.")
            }
            head = ccFor(memorySize)
            cc = parseCc(head)!!
        }
        if (!cc.writable) throw Type5Exception("This tag is locked (read-only), so it can't be changed.")
        val tlv = Tlv.wrap(message)
        val needed = tlv.size - 1
        if (needed > cc.capacity) {
            throw Type5Exception("That's too much for this tag: it needs $needed bytes but holds ${cc.capacity}.")
        }
        val body = if (tlv.size > cc.capacity) tlv.copyOf(tlv.size - 1) else tlv
        val data = head.copyOf(cc.length) + body
        val padded = data.copyOf((data.size + blockSize - 1) / blockSize * blockSize)
        for (b in 0 until padded.size / blockSize) {
            writeBlock(b, padded.copyOfRange(b * blockSize, (b + 1) * blockSize))
        }
    }

    fun dump(): List<String> = (0 until usableBlocks).map { b ->
        val d = runCatching { readBlock(b) }.getOrNull()
        if (d == null) "Block %3d: (locked)".format(b)
        else "Block %3d: %s  %s".format(b, d.joinToString(" ") { "%02X".format(it) },
            d.map { c -> if (c in 0x20..0x7E) c.toInt().toChar() else '.' }.joinToString(""))
    }

    companion object {
        fun ccFor(memory: Int): ByteArray {
            val mlen = memory / 8
            return if (mlen <= 0xFF) {
                byteArrayOf(0xE1.toByte(), 0x40, mlen.toByte(), 0x00)
            } else {
                byteArrayOf(0xE2.toByte(), 0x40, 0, 0, 0, 0, (mlen shr 8).toByte(), mlen.toByte())
            }
        }
    }
}
