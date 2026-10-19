package dev.bipul.nfcstudio.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RawJsonTest {

    @Test
    fun jsonPayloadIsEmbeddedAsJson() {
        val r = RawRecord.mime("application/json", """{"sku":"A-12","qty":3,"url":"https://x.io/a"}""".toByteArray())
        val o = RawJson.record(r)
        assertEquals("MIME media", o.getString("tnf"))
        assertEquals("application/json", o.getString("type"))
        assertEquals(3, o.getJSONObject("payload").getInt("qty"))
        val pretty = RawJson.pretty(o)
        assertTrue(pretty.contains("https://x.io/a"))
        assertEquals("A-12", JSONObject(pretty).getJSONObject("payload").getString("sku"))
    }

    @Test
    fun textAndBinaryPayloads() {
        val text = RawJson.record(RawRecord(RawRecord.TNF_EXTERNAL, "acme.com:note".toByteArray(), "hello\nworld".toByteArray()))
        assertEquals("External", text.getString("tnf"))
        assertEquals("hello\nworld", text.getString("payload"))

        val bin = RawJson.record(RawRecord(5, ByteArray(0), byteArrayOf(0x00, 0xFF.toByte(), 0x10), "id1".toByteArray()))
        assertFalse(bin.has("payload"))
        assertEquals("00 FF 10", bin.getString("payloadHex"))
        assertEquals("id1", bin.getString("id"))
        assertEquals("Unknown", bin.getString("tnf"))
        assertEquals(1, RawJson.records(listOf(bin.let { RawRecord(1, "T".toByteArray(), ByteArray(0)) })).length())
    }
}
