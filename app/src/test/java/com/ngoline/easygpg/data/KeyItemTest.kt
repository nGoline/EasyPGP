package com.ngoline.easygpg.data

import com.ngoline.easygpg.TestKeyRings
import java.util.Date
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyItemTest {

    private val publicRing by lazy { TestKeyRings.generate("secret".toCharArray()).second }

    /** The fingerprint is the stored one, so a literal keeps the label test off real key material. */
    private val keyItem by lazy {
        KeyItem("Alice", "1a2b3c4d5e6f70819ab4cdef", TestKeyRings.signingKey(publicRing), publicRing)
    }

    private fun keyItem(publicRing: org.bouncycastle.openpgp.PGPPublicKeyRing) =
        KeyItem("Alice", "1a2b3c4d5e6f70819ab4cdef", publicRing.publicKeys.next(), publicRing)

    @Test
    fun `a short fingerprint is the last eight characters, uppercased`() {
        assertEquals("9AB4CDEF", shortFingerprint("1a2b3c4d5e6f70819ab4cdef"))
    }

    @Test
    fun `a short fingerprint of a fingerprint shorter than eight characters is the whole thing`() {
        assertEquals("ABCD", shortFingerprint("abcd"))
        assertEquals("", shortFingerprint(""))
    }

    @Test
    fun `a key label names the primary key`() {
        assertEquals("Alice (9AB4CDEF)", keyItem.label)
    }

    @Test
    fun `the encryption key of a ring is its subkey, not the signing primary`() {
        // The label names the primary key, but the message still goes to the encryption subkey.
        assertEquals(TestKeyRings.encryptionKey(publicRing).keyID, keyItem.encryptionKey?.keyID)
    }

    @Test
    fun `the encryption key of an RSA ring is the subkey, not the sign-only primary`() {
        // Both keys are RSA, so isEncryptionKey answers true for the primary too. Encrypting to it
        // produces a message the recipient cannot open: the encryption subkey is the half they hold.
        val (_, rsaRing) = TestKeyRings.generateRsa("secret".toCharArray())
        val subkey = TestKeyRings.encryptionKey(rsaRing)

        val picked = keyItem(rsaRing).encryptionKey

        assertEquals(subkey.keyID, picked?.keyID)
        assertEquals(false, picked?.isMasterKey)
    }

    @Test
    fun `an expired encryption subkey is not encrypted to`() {
        val aYearAgo = Date(System.currentTimeMillis() - 365L * 24 * 60 * 60 * 1000)
        val (_, rsaRing) = TestKeyRings.generateRsa(
            "secret".toCharArray(), createdAt = aYearAgo, subkeyValidSeconds = 60
        )

        // The sign-only primary must not be the fallback once the subkey is out of date.
        assertNull(keyItem(rsaRing).encryptionKey)
    }
}
