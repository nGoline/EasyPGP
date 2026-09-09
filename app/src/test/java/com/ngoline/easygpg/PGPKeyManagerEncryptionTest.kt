package com.ngoline.easygpg

import android.content.Context
import androidx.preference.PreferenceManager
import androidx.test.core.app.ApplicationProvider
import com.ngoline.easygpg.data.KeyItem
import com.ngoline.easygpg.data.encryptionKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.encoders.Hex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Covers the one half of `PGPKeyManager` that never touches the Android Keystore: encryption takes
 * a public key straight from the caller, so it can be exercised on the JVM. Everything that reads
 * or writes a stored key ring goes through the Keystore and lives in the instrumented tests.
 */
@RunWith(RobolectricTestRunner::class)
class PGPKeyManagerEncryptionTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private lateinit var manager: PGPKeyManager

    private val passphrase = "correct horse".toCharArray()
    private val keyRings by lazy { TestKeyRings.generate(passphrase.copyOf()) }
    private val secretKeyRing by lazy { keyRings.first }
    private val publicKeyRing by lazy { keyRings.second }

    @Before
    fun setUp() {
        // Matches MainActivity: without the bundled provider, encrypting to a Curve25519
        // subkey fails on a device even though Robolectric's own "BC" would carry it.
        installBouncyCastleProvider()
        manager = PGPKeyManager(context)
        context.filesDir.listFiles()?.forEach { it.delete() }
        PreferenceManager.getDefaultSharedPreferences(context).edit().clear().commit()
    }

    private fun setObfuscation(enabled: Boolean) {
        PreferenceManager.getDefaultSharedPreferences(context).edit()
            .putBoolean(context.getString(R.string.obfuscate_pgp_markers), enabled)
            .commit()
    }

    @Test
    fun `a message to an RSA ring opens with the encryption subkey alone`() {
        // The shape that broke: both keys are RSA, so isEncryptionKey answers true for the sign-only
        // primary too. Encrypting to that primary yields a message the recipient cannot open, since
        // on the usual offline-primary setup the subkey is the only secret half on the device.
        val (rsaSecret, rsaPublic) = TestKeyRings.generateRsa(passphrase.copyOf())
        val keyItem = KeyItem(
            "Alice", Hex.toHexString(rsaPublic.publicKeys.next().fingerprint),
            rsaPublic.publicKeys.next(), rsaPublic
        )

        val armored = manager.encryptMessage("attack at dawn".toCharArray(), keyItem.encryptionKey!!)

        val subkeyOnly = PGPSecretKeyRing.removeSecretKey(rsaSecret, rsaSecret.secretKey)
        assertEquals(
            "attack at dawn",
            TestKeyRings.decrypt(armored, subkeyOnly, passphrase.copyOf()),
        )
    }

    @Test
    fun `an encrypted message decrypts back to the original`() {
        val armored = manager.encryptMessage(
            "attack at dawn".toCharArray(),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        // Decrypted with Bouncy Castle directly, so this proves real OpenPGP came out.
        assertEquals(
            "attack at dawn",
            TestKeyRings.decrypt(armored, secretKeyRing, passphrase.copyOf()),
        )
    }

    @Test
    fun `unicode survives the encryption round trip`() {
        val message = "acentuação 🔐 秘密"

        val armored = manager.encryptMessage(
            message.toCharArray(),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        assertEquals(message, TestKeyRings.decrypt(armored, secretKeyRing, passphrase.copyOf()))
    }

    @Test
    fun `an empty message round trips`() {
        val armored = manager.encryptMessage(
            CharArray(0),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        assertEquals("", TestKeyRings.decrypt(armored, secretKeyRing, passphrase.copyOf()))
    }

    @Test
    fun `encrypting leaves the caller's buffer intact`() {
        // The caller owns the plaintext and wipes it itself; encryption must not pull it out from
        // under a caller that still needs it.
        val message = "attack at dawn".toCharArray()

        manager.encryptMessage(message, TestKeyRings.encryptionKey(publicKeyRing))

        assertArrayEquals("attack at dawn".toCharArray(), message)
    }

    @Test
    fun `two encryptions of the same text differ`() {
        val key = TestKeyRings.encryptionKey(publicKeyRing)

        val first = manager.encryptMessage("attack at dawn".toCharArray(), key)
        val second = manager.encryptMessage("attack at dawn".toCharArray(), key)

        // A fresh session key each time; identical output would leak that the messages match.
        assertFalse("ciphertext repeated across encryptions", first == second)
    }

    @Test
    fun `armored output is produced when markers are not obfuscated`() {
        setObfuscation(false)

        val armored = manager.encryptMessage(
            "attack at dawn".toCharArray(),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        assertTrue(armored, armored.trimStart().startsWith(PGPConstants.PGP_MARKER))
        assertTrue(armored, armored.contains("-----END PGP MESSAGE-----"))
    }

    @Test
    fun `obfuscation replaces the markers that identify a PGP message`() {
        setObfuscation(true)

        val armored = manager.encryptMessage(
            "attack at dawn".toCharArray(),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        assertTrue(armored, armored.contains(PGPConstants.OBFUSCATED_MARKER))
        assertFalse("BEGIN marker survived obfuscation", armored.contains("-----BEGIN"))
        assertFalse("END marker survived obfuscation", armored.contains("-----END"))
    }

    @Test
    fun `an obfuscated message is still decryptable by the app`() {
        setObfuscation(true)
        val obfuscated = manager.encryptMessage(
            "attack at dawn".toCharArray(),
            TestKeyRings.encryptionKey(publicKeyRing),
        )

        // Round trip through the app's own deobfuscation, which is what a recipient runs.
        setObfuscation(false)
        val restored = manager.deobfuscateMarkers(obfuscated)

        assertEquals(
            "attack at dawn",
            TestKeyRings.decrypt(restored, secretKeyRing, passphrase.copyOf()),
        )
    }

    @Test
    fun `encrypting to a signing-only key fails instead of producing something unreadable`() {
        // The UI filters to encryption-capable keys; this pins what happens if one slips through.
        val result = manager.encryptMessage(
            "attack at dawn".toCharArray(),
            TestKeyRings.signingKey(publicKeyRing),
        )

        assertEquals("Encryption failed", result)
    }

    @Test
    fun `hasKeys reports whether a key ring has been stored`() {
        assertFalse(manager.hasKeys())

        java.io.File(context.filesDir, "alice.public_keyring.pgp").writeText("anything")

        assertTrue(manager.hasKeys())
    }

    @Test
    fun `hasKeys ignores files that are not key rings`() {
        java.io.File(context.filesDir, "notes.txt").writeText("anything")
        java.io.File(context.filesDir, "alice.imported.pgp").writeText("anything")

        // Only a key ring the user owns counts; an imported public key is somebody else's.
        assertFalse(manager.hasKeys())
    }
}
