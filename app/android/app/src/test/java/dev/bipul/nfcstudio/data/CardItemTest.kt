package dev.bipul.nfcstudio.data

import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CardItemTest {

    private fun roundTrip(item: CardItem) = ItemCodec.decode(ItemCodec.encode(item))

    @Test
    fun everyKindRoundTrips() {
        val items = listOf(
            CardItem.Note("Hello ✓ नमस्ते"),
            CardItem.Website("https://www.example.com/path?q=1"),
            CardItem.Phone("+919876543210"),
            CardItem.Email("a@b.co"),
            CardItem.Wifi("Home, Sweet; Home", "s3cret pass", WifiSecurity.WPA2),
            CardItem.Wifi("Cafe", "", WifiSecurity.OPEN),
            CardItem.Contact("Asha Rao", "+91 98765 43210", "asha@example.com", "Acme; Inc"),
            CardItem.Password("Gmail", "asha@gmail.com", "p@ss,w;rd\"", "https://mail.google.com", "line1\nline2"),
        )
        for (item in items) assertEquals(item, roundTrip(item))
    }

    @Test
    fun urisUsePrefixCompressionAndPhoneIsCleaned() {
        val r = ItemCodec.encode(CardItem.Website("https://www.rust-lang.org"))
        assertEquals(2, r.payload[0].toInt())
        assertEquals(CardItem.Phone("+911234"), roundTrip(CardItem.Phone("+91 (12) 3-4")))
    }

    @Test
    fun mailtoWithSubjectStaysALinkSoNothingIsLost() {
        assertEquals(CardItem.Website("mailto:a@b.co?subject=hi"), roundTrip(CardItem.Website("mailto:a@b.co?subject=hi")))
    }

    @Test
    fun unknownRecordsArePreserved() {
        val raw = RawRecord(RawRecord.TNF_EXTERNAL, "android.com:pkg".toByteArray(), "com.example".toByteArray())
        assertEquals(CardItem.Unknown(raw), ItemCodec.decode(raw))
        assertEquals(raw, ItemCodec.encode(ItemCodec.decode(raw)))
    }

    @Test
    fun messageSizeMatchesNdefLayout() {
        val short = ItemCodec.encode(CardItem.Note("hi"))
        assertEquals(1 + 1 + 1 + 1 + 3 + 2, short.byteSize)
        val long = ItemCodec.encode(CardItem.Note("x".repeat(300)))
        assertEquals(1 + 1 + 4 + 1 + 3 + 300, long.byteSize)
        assertEquals(3, messageSize(emptyList()))
    }

    private val fast = 1_000

    @Test
    fun lockedItemsOpenOnlyWithTheRightPin() {
        val secret = CardItem.Password("Bank", "me", "hunter2", "", "")
        val locked = Vault.seal(secret, "Bank", "correct horse", fast)
        val decoded = ItemCodec.decode(ItemCodec.encode(locked)) as CardItem.Locked
        assertEquals("Bank", decoded.label)
        assertEquals(ItemKind.PASSWORD, decoded.innerKind)
        assertEquals(secret, Vault.open(decoded, "correct horse"))
        try {
            Vault.open(decoded, "wrong")
            fail("expected WrongPinException")
        } catch (_: WrongPinException) {
        }
        assertTrue(!String(locked.sealed, Charsets.ISO_8859_1).contains("hunter2"))
    }

    @Test
    fun visibleLabelIsAuthenticated() {
        val locked = Vault.seal(CardItem.Note("diary"), "Diary", "1234", fast)
        val tampered = locked.sealed.copyOf().also { it[3] = 'X'.code.toByte() }
        try {
            Vault.open(Vault.parse(tampered), "1234")
            fail("tampered label must be rejected")
        } catch (_: WrongPinException) {
        }
    }

    @Test
    fun sealedSizeIsExactAndSealingIsRandomised() {
        val note = CardItem.Note("A secret note")
        val a = Vault.seal(note, "Note", "1234", fast)
        val b = Vault.seal(note, "Note", "1234", fast)
        assertEquals(Vault.sealedRecordSize(note, "Note"), ItemCodec.encode(a).byteSize)
        assertNotEquals(a, b)
    }

    @Test
    fun generatedPasswordsMixCharacterClasses() {
        repeat(50) {
            val p = Vault.generatePassword(16, SecureRandom())
            assertEquals(16, p.length)
            assertTrue(p.any(Char::isUpperCase) && p.any(Char::isLowerCase) && p.any(Char::isDigit))
            assertTrue(p.any { !it.isLetterOrDigit() })
        }
    }
}
