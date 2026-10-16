package dev.bipul.nfcstudio

import android.nfc.NdefMessage
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private enum class Mode { READ, WRITE_TEXT, WRITE_URI, APDU }

    private var adapter: NfcAdapter? = null
    @Volatile private var mode = Mode.READ
    @Volatile private var input = ""

    private lateinit var status: TextView
    private lateinit var log: TextView
    private lateinit var logScroll: ScrollView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        log = findViewById(R.id.log)
        logScroll = findViewById(R.id.logScroll)

        findViewById<RadioGroup>(R.id.modeGroup).setOnCheckedChangeListener { _, id ->
            mode = when (id) {
                R.id.modeWriteText -> Mode.WRITE_TEXT
                R.id.modeWriteUri -> Mode.WRITE_URI
                R.id.modeApdu -> Mode.APDU
                else -> Mode.READ
            }
        }
        val inputView = findViewById<EditText>(R.id.input)
        inputView.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) { input = s?.toString() ?: "" }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        findViewById<Button>(R.id.clearLog).setOnClickListener { log.text = "" }

        adapter = NfcAdapter.getDefaultAdapter(this)
        if (adapter == null) status.setText(R.string.nfc_missing)
    }

    override fun onResume() {
        super.onResume()
        val nfc = adapter ?: return
        if (!nfc.isEnabled) {
            status.setText(R.string.nfc_disabled)
            return
        }
        status.setText(R.string.tap_prompt)
        val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_NFC_V
        nfc.enableReaderMode(this, this, flags, null)
    }

    override fun onPause() {
        super.onPause()
        adapter?.disableReaderMode(this)
    }

    /** Called on a binder thread whenever a tag enters the field. */
    override fun onTagDiscovered(tag: Tag) {
        append("── Tag ${NfcCore.toHex(tag.id)}  [${tag.techList.joinToString { it.substringAfterLast('.') }}]")
        try {
            when (mode) {
                Mode.READ -> read(tag)
                Mode.WRITE_TEXT -> writeNdef(tag, NfcCore.encodeText(input, "en"))
                Mode.WRITE_URI -> writeNdef(tag, NfcCore.encodeUri(input))
                Mode.APDU -> apdu(tag)
            }
        } catch (e: Exception) {
            append("Error: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun read(tag: Tag) {
        Ndef.get(tag)?.let { ndef ->
            ndef.use {
                it.connect()
                append("NDEF type=${it.type} size=${it.maxSize} writable=${it.isWritable}")
                val msg = it.ndefMessage ?: it.cachedNdefMessage
                append(if (msg == null) "(no NDEF message)" else NfcCore.decodeMessage(msg.toByteArray()))
            }
            return
        }
        MifareUltralight.get(tag)?.let { ul ->
            ul.use {
                it.connect()
                // readPages returns 4 pages (16 bytes) at a time; dump user memory from page 4.
                val mem = java.io.ByteArrayOutputStream()
                var page = 4
                while (page < 64) {
                    val chunk = try { it.readPages(page) } catch (e: Exception) { break }
                    append("p%02d: %s".format(page, NfcCore.toHex(chunk)))
                    mem.write(chunk)
                    page += 4
                }
                append(runCatching { NfcCore.decodeTlvMemory(mem.toByteArray()) }
                    .getOrElse { "No NDEF TLV: ${it.message}" })
            }
            return
        }
        MifareClassic.get(tag)?.let { mc ->
            mc.use {
                it.connect()
                append("MIFARE Classic: ${it.sectorCount} sectors, ${it.blockCount} blocks")
                for (sector in 0 until it.sectorCount) {
                    val ok = it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT) ||
                        it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_NFC_FORUM) ||
                        it.authenticateSectorWithKeyA(sector, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY)
                    if (!ok) {
                        append("S%02d: auth failed".format(sector))
                        continue
                    }
                    val first = it.sectorToBlock(sector)
                    for (b in first until first + it.getBlockCountInSector(sector)) {
                        val data = it.readBlock(b)
                        val tag2 = if (NfcCore.isSectorTrailer(b)) " (trailer)" else ""
                        append("B%03d: %s  %s%s".format(b, NfcCore.toHex(data), NfcCore.toAscii(data), tag2))
                    }
                }
            }
            return
        }
        IsoDep.get(tag)?.let { iso ->
            iso.use {
                it.connect()
                append("ISO-DEP historical: ${it.historicalBytes?.let(NfcCore::toHex) ?: "-"}")
            }
            return
        }
        append("No supported technology for reading.")
    }

    private fun writeNdef(tag: Tag, encoded: ByteArray) {
        if (input.isBlank()) {
            append("Enter text/URI to write first.")
            return
        }
        val message = NdefMessage(encoded)
        Ndef.get(tag)?.let { ndef ->
            ndef.use {
                it.connect()
                if (!it.isWritable) throw IllegalStateException("tag is read-only")
                if (encoded.size > it.maxSize) throw IllegalStateException("message ${encoded.size} B > capacity ${it.maxSize} B")
                it.writeNdefMessage(message)
            }
            append("Wrote ${encoded.size} bytes NDEF ✔")
            return
        }
        NdefFormatable.get(tag)?.let { f ->
            f.use {
                it.connect()
                it.format(message)
            }
            append("Formatted and wrote ${encoded.size} bytes NDEF ✔")
            return
        }
        append("Tag does not support NDEF.")
    }

    private fun apdu(tag: Tag) {
        val iso = IsoDep.get(tag) ?: run {
            append("Tag is not ISO-DEP; APDUs need an ISO 14443-4 card.")
            return
        }
        val commands = input.split(';').map { it.trim() }.filter { it.isNotEmpty() }
        if (commands.isEmpty()) {
            append("Enter APDU hex (separate multiple with ';').")
            return
        }
        iso.use {
            it.connect()
            it.timeout = 3000
            for (cmd in commands) {
                val bytes = NfcCore.parseHex(cmd)
                append("> ${NfcCore.toHex(bytes)}")
                append("< ${NfcCore.describeResponse(it.transceive(bytes))}")
            }
        }
    }

    private fun append(line: String) {
        runOnUiThread {
            log.append(line + "\n")
            logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }
}
