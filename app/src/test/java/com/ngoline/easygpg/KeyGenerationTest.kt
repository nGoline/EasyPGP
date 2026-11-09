package com.ngoline.easygpg

import java.io.File
import java.util.concurrent.TimeUnit
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Pins the algorithms [buildKeyRings] generates, so exported public keys stay importable by GnuPG.
 *
 * GnuPG does not implement the RFC 9580 Ed25519 algorithm (27): a primary key using it imports
 * with "unsupported public-key algorithm (27)" and "no valid user IDs".
 */
class KeyGenerationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val keyRings = TestKeyRings.generate("passphrase".toCharArray())
    private val publicKeyRing = keyRings.second

    @Test
    fun primaryKeyUsesLegacyEdDsa() {
        val primary = publicKeyRing.publicKey
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, primary.algorithm)
        primary.signatures.forEach { assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, it.keyAlgorithm) }
    }

    @Test
    fun encryptionSubkeyUsesEcdh() {
        assertEquals(PublicKeyAlgorithmTags.ECDH, TestKeyRings.encryptionKey(publicKeyRing).algorithm)
    }

    @Test
    fun selfSignaturesVerify() {
        val primary = publicKeyRing.publicKey
        val userId = primary.userIDs.next()
        val certification = primary.getSignaturesForID(userId).next()
        certification.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue(certification.verifyCertification(userId, primary))

        val subkey = TestKeyRings.encryptionKey(publicKeyRing)
        val binding = subkey.signatures.next()
        binding.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue(binding.verifyCertification(primary, subkey))
    }

    /** Imports into a throwaway GnuPG home when `gpg` is installed; skipped otherwise. */
    @Test
    fun gnupgImportsThePublicKey() {
        assumeTrue("gpg not installed", gpgAvailable())

        val home = tmp.newFolder("gnupg").apply {
            setReadable(false, false); setReadable(true, true)
            setWritable(false, false); setWritable(true, true)
            setExecutable(false, false); setExecutable(true, true)
        }
        val keyFile = File(tmp.root, "pub.asc").apply { writeText(TestKeyRings.armor(publicKeyRing)) }

        val result = run("gpg", "--homedir", home.path, "--batch", "--status-fd", "1", "--import", keyFile.path)
        assertTrue("gpg rejected the key:\n${result.second}", result.first == 0)
        assertTrue("gpg imported nothing:\n${result.second}", result.second.contains("IMPORT_OK"))
    }

    private fun gpgAvailable(): Boolean =
        try { run("gpg", "--version").first == 0 } catch (e: java.io.IOException) { false }

    private fun run(vararg command: String): Pair<Int, String> {
        val process = ProcessBuilder(*command).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor(60, TimeUnit.SECONDS)) { "${command.first()} timed out" }
        return process.exitValue() to output
    }
}
