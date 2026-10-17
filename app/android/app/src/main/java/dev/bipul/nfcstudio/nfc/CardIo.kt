package dev.bipul.nfcstudio.nfc

import android.nfc.FormatException
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.nfc.tech.NfcV
import dev.bipul.nfcstudio.NfcCore
import dev.bipul.nfcstudio.data.RawRecord
import java.io.IOException

/** What we learned from one tap. */
data class CardSnapshot(
    val id: ByteArray,
    val typeName: String,
    val techs: List<String>,
    val records: List<RawRecord>,
    /** Bytes available for content, or null when unknown (blank cards). */
    val capacity: Int?,
    val used: Int,
    val writable: Boolean,
    val canMakeReadOnly: Boolean,
    /** True for blank cards that will be set up on first save. */
    val blank: Boolean,
    /** Explanation shown when the card can't hold content. */
    val notice: String?,
    /** The stored data couldn't be parsed; saving or erasing fixes it. */
    val damaged: Boolean = false,
) {
    val supported get() = notice == null
    val idHex: String get() = id.joinToString(":") { "%02X".format(it) }
}

class CardException(message: String) : Exception(message)

object CardIo {

    fun read(tag: Tag): CardSnapshot {
        val techs = tag.techList.map { it.substringAfterLast('.') }
        val name = describe(tag)
        Ndef.get(tag)?.let { ndef ->
            return guard {
                ndef.use {
                    it.connect()
                    val (records, damaged) = try {
                        (it.ndefMessage?.records?.map(::toRaw) ?: emptyList()) to false
                    } catch (e: FormatException) {
                        emptyList<RawRecord>() to true
                    }
                    val content = records.filter { r -> r.tnf != RawRecord.TNF_EMPTY }
                    CardSnapshot(
                        id = tag.id, typeName = name, techs = techs,
                        records = content,
                        capacity = it.maxSize,
                        used = if (content.isEmpty()) 0 else content.sumOf(RawRecord::byteSize),
                        writable = it.isWritable,
                        canMakeReadOnly = it.isWritable && it.canMakeReadOnly(),
                        blank = false,
                        notice = null,
                        damaged = damaged,
                    )
                }
            }
        }
        if (NfcV.get(tag) != null) return guard { readType5(tag, name, techs) }
        if (NdefFormatable.get(tag) != null) {
            return CardSnapshot(tag.id, name, techs, emptyList(), null, 0, true, false, true, null)
        }
        val notice = when {
            MifareClassic.get(tag) != null ->
                "This MIFARE Classic card uses private keys (for example an office or transit card), " +
                    "so its contents can't be read."
            IsoDep.get(tag) != null ->
                "This is a secure smart card, such as a bank, ID or transit card. Its data is protected, " +
                    "so there's nothing that can be shown or changed."
            "NfcA" in techs ->
                "Your phone can't read this card type. Many phones can't read MIFARE Classic cards; " +
                    "NTAG stickers work everywhere."
            else -> "This card type can't store content."
        }
        return CardSnapshot(tag.id, name, techs, emptyList(), null, 0, false, false, false, notice)
    }

    private const val FOREIGN_DATA = "This RFID tag holds data in another system's format (for example a library or " +
        "inventory system), so it isn't shown or changed here. Advanced tools can show its raw memory."

    /** Opens an ISO 15693 tag for raw Type 5 access. */
    private inline fun <T> withType5(tag: Tag, block: (Type5Tag) -> T): T {
        val nfcV = NfcV.get(tag) ?: throw CardException("This isn't an ISO 15693 tag.")
        return nfcV.use {
            it.connect()
            val t = Type5Tag({ frame -> it.transceive(frame) }, tag.id)
            t.open()
            block(t)
        }
    }

    /** Bytes left for the NDEF message once its TLV header is counted. */
    private fun messageRoom(area: Int) = if (area - 2 < 0xFF) area - 2 else area - 4

    private fun readType5(tag: Tag, name: String, techs: List<String>): CardSnapshot = withType5(tag) { t ->
        when (val c = t.read()) {
            is Type5Tag.Content.Ndef -> {
                val (records, damaged) = if (c.message.isEmpty()) {
                    emptyList<RawRecord>() to false
                } else {
                    try {
                        NdefMessage(c.message).records.map(::toRaw) to false
                    } catch (e: FormatException) {
                        emptyList<RawRecord>() to true
                    }
                }
                val content = records.filter { r -> r.tnf != RawRecord.TNF_EMPTY }
                CardSnapshot(
                    id = tag.id, typeName = name, techs = techs, records = content,
                    capacity = messageRoom(c.capacity),
                    used = if (content.isEmpty()) 0 else content.sumOf(RawRecord::byteSize),
                    writable = c.writable, canMakeReadOnly = false, blank = false, notice = null, damaged = damaged,
                )
            }
            is Type5Tag.Content.Blank ->
                CardSnapshot(tag.id, name, techs, emptyList(), messageRoom(c.capacity), 0, true, false, true, null)
            Type5Tag.Content.Foreign ->
                CardSnapshot(tag.id, name, techs, emptyList(), null, 0, false, false, false, FOREIGN_DATA)
        }
    }

    /** Replaces everything on the card with [records] (empty = erase). */
    fun write(tag: Tag, records: List<RawRecord>) {
        val message = if (records.isEmpty()) {
            NdefMessage(NdefRecord(NdefRecord.TNF_EMPTY, null, null, null))
        } else {
            NdefMessage(records.map(::toNdef).toTypedArray())
        }
        guard {
            Ndef.get(tag)?.let { ndef ->
                ndef.use {
                    it.connect()
                    if (!it.isWritable) throw CardException("This card is locked (read-only), so it can't be changed.")
                    val size = message.byteArrayLength
                    if (size > it.maxSize) {
                        throw CardException("That's too much for this card: it needs $size bytes but holds ${it.maxSize}.")
                    }
                    it.writeNdefMessage(message)
                }
                return@guard
            }
            if (NfcV.get(tag) != null) {
                withType5(tag) { it.write(message.toByteArray()) }
                return@guard
            }
            NdefFormatable.get(tag)?.let { f ->
                f.use {
                    it.connect()
                    it.format(message)
                }
                return@guard
            }
            throw CardException("This card can't store content.")
        }
    }

    fun makeReadOnly(tag: Tag) {
        guard {
            val ndef = Ndef.get(tag) ?: throw CardException("This card can't be locked.")
            ndef.use {
                it.connect()
                if (!it.canMakeReadOnly() || !it.makeReadOnly()) {
                    throw CardException("This card type can't be locked permanently.")
                }
            }
        }
    }

    // ---- Diagnostics ----------------------------------------------------------

    fun dump(tag: Tag): List<String> = guard {
        val out = mutableListOf(
            "Card ${NfcCore.toHex(tag.id)}",
            "Technologies: ${tag.techList.joinToString { it.substringAfterLast('.') }}",
        )
        MifareUltralight.get(tag)?.let { ul ->
            ul.use {
                it.connect()
                var page = 0
                while (page < 256) {
                    val chunk = try { it.readPages(page) } catch (e: IOException) { break }
                    for (p in 0 until 4) {
                        val bytes = chunk.copyOfRange(p * 4, p * 4 + 4)
                        out += "Page %3d: %s  %s".format(page + p, NfcCore.toHex(bytes), NfcCore.toAscii(bytes))
                    }
                    page += 4
                }
            }
            return@guard out
        }
        MifareClassic.get(tag)?.let { mc ->
            mc.use {
                it.connect()
                out += "MIFARE Classic: ${it.sectorCount} sectors, ${it.blockCount} blocks"
                for (sector in 0 until it.sectorCount) {
                    val ok = it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT) ||
                        it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_NFC_FORUM) ||
                        it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)
                    if (!ok) {
                        out += "Sector %2d: locked with a private key".format(sector)
                        continue
                    }
                    val first = it.sectorToBlock(sector)
                    for (b in first until first + it.getBlockCountInSector(sector)) {
                        val data = it.readBlock(b)
                        val trailer = if (NfcCore.isSectorTrailer(b)) "  (keys)" else ""
                        out += "Block %3d: %s  %s%s".format(b, NfcCore.toHex(data), NfcCore.toAscii(data), trailer)
                    }
                }
            }
            return@guard out
        }
        if (NfcV.get(tag) != null) {
            out += withType5(tag) { t -> listOf("ISO 15693: ${t.blockCount} blocks of ${t.blockSize} bytes") + t.dump() }
            return@guard out
        }
        Ndef.get(tag)?.let { ndef ->
            ndef.use {
                it.connect()
                val bytes = it.ndefMessage?.toByteArray() ?: ByteArray(0)
                out += "NDEF (${bytes.size} of ${it.maxSize} bytes):"
                bytes.toList().chunked(16).forEach { row ->
                    val b = row.toByteArray()
                    out += "  ${NfcCore.toHex(b)}  ${NfcCore.toAscii(b)}"
                }
            }
            return@guard out
        }
        IsoDep.get(tag)?.let { iso ->
            iso.use {
                it.connect()
                out += "ISO-DEP historical bytes: ${it.historicalBytes?.let(NfcCore::toHex) ?: "-"}"
            }
        }
        out
    }

    fun sendApdus(tag: Tag, commands: List<ByteArray>): List<String> = guard {
        val iso = IsoDep.get(tag) ?: throw CardException("Raw commands need a smart card (ISO-DEP).")
        val out = mutableListOf<String>()
        iso.use {
            it.connect()
            it.timeout = 3000
            for (cmd in commands) {
                out += "> ${NfcCore.toHex(cmd)}"
                out += "< ${NfcCore.describeResponse(it.transceive(cmd))}"
            }
        }
        out
    }

    // ---- Helpers ---------------------------------------------------------------

    private fun describe(tag: Tag): String {
        val techs = tag.techList.map { it.substringAfterLast('.') }
        MifareClassic.get(tag)?.let {
            return when (it.size) {
                MifareClassic.SIZE_1K -> "MIFARE Classic 1K"
                MifareClassic.SIZE_4K -> "MIFARE Classic 4K"
                MifareClassic.SIZE_MINI -> "MIFARE Mini"
                else -> "MIFARE Classic"
            }
        }
        return when {
            "NfcV" in techs -> "RFID tag (ISO 15693)"
            "MifareUltralight" in techs -> "NFC tag (NTAG / Ultralight)"
            "IsoDep" in techs && "Ndef" in techs -> "NFC Type 4 tag"
            "IsoDep" in techs -> "Smart card"
            "NfcF" in techs -> "FeliCa card"
            else -> "NFC tag"
        }
    }

    private fun toRaw(r: NdefRecord) = RawRecord(r.tnf, r.type ?: ByteArray(0), r.payload ?: ByteArray(0), r.id ?: ByteArray(0))

    private fun toNdef(r: RawRecord) = NdefRecord(r.tnf, r.type, r.id, r.payload)

    /** Maps radio errors to messages a person can act on. */
    private inline fun <T> guard(block: () -> T): T = try {
        block()
    } catch (e: CardException) {
        throw e
    } catch (e: TagLostException) {
        throw CardException("The card moved away too soon. Hold it still against the phone and try again.")
    } catch (e: Type5Exception) {
        throw CardException(e.message ?: "The tag didn't respond as expected. Try again.")
    } catch (e: IOException) {
        throw CardException("Couldn't talk to the card. Hold it still against the phone and try again.")
    } catch (e: FormatException) {
        throw CardException("The data on this card is damaged. Erase the card to fix it.")
    } catch (e: SecurityException) {
        throw CardException("The card was removed. Tap it again.")
    } catch (e: IllegalStateException) {
        throw CardException(e.message ?: "Something went wrong. Try again.")
    }
}
