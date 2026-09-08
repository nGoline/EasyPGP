package com.ngoline.easygpg

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Marker obfuscation exists to stop a message looking like PGP, so what it emits matters as much
 * as whether it round trips. Both are pinned here.
 */
@RunWith(RobolectricTestRunner::class)
class ObfuscationTest {

    private lateinit var manager: PGPKeyManager
    private val marker = PGPConstants.OBFUSCATED_MARKER

    /** What Bouncy Castle actually produces: a version header, a blank line, then the body. */
    private val armored = buildString {
        append("-----BEGIN PGP MESSAGE-----\n")
        append("Version: BCPG v1.81\n")
        append("\n")
        append("wV4DTmkMQQGcaxcSAQdANo1t8BWzhOFza9jwZQIc7uS59MO5E4gmVyK5laDT0w\n")
        append("7TgjnZ6sV1Qccg1SHgYRLREAHraEeRmWVwelavItS5HvTJ2LRU6NFrZV6wlka\n")
        append("=x9Yz\n")
        append("-----END PGP MESSAGE-----\n")
    }

    @Before
    fun setUp() {
        installBouncyCastleProvider()
        manager = PGPKeyManager(ApplicationProvider.getApplicationContext<Context>())
    }

    @Test
    fun `the marker is not repeated back to back`() {
        // The bug this guards: blank lines were replaced with the marker too, and armored output
        // has one after the version header and one at the end, so the marker appeared twice at
        // each end. A doubled hex run is a more distinctive signature than a single one.
        val obfuscated = manager.obfuscateMarkers(armored)

        assertFalse(
            "marker appears twice in a row: $obfuscated",
            obfuscated.contains(marker + marker),
        )
    }

    @Test
    fun `there is exactly one marker at each end`() {
        val obfuscated = manager.obfuscateMarkers(armored)

        assertEquals("expected two markers in total, in $obfuscated", 2,
            Regex(Regex.escape(marker)).findAll(obfuscated).count())
        assertTrue(obfuscated, obfuscated.startsWith(marker))
        assertTrue(obfuscated, obfuscated.endsWith(marker))
    }

    @Test
    fun `no PGP armor survives obfuscation`() {
        val obfuscated = manager.obfuscateMarkers(armored)

        assertFalse(obfuscated, obfuscated.contains("-----BEGIN"))
        assertFalse(obfuscated, obfuscated.contains("-----END"))
        assertFalse("the version header identifies the implementation", obfuscated.contains("BCPG"))
    }

    @Test
    fun `the payload itself is untouched`() {
        val obfuscated = manager.obfuscateMarkers(armored)

        assertTrue(obfuscated, obfuscated.contains("wV4DTmkMQQGcaxcSAQdANo1t8BWzhOFza9jwZQIc7uS59MO5E4gmVyK5laDT0w"))
        assertTrue("the checksum must survive", obfuscated.contains("=x9Yz"))
    }

    @Test
    fun `obfuscating and deobfuscating returns usable armor`() {
        val restored = manager.deobfuscateMarkers(manager.obfuscateMarkers(armored))

        assertTrue(restored, restored.trimStart().startsWith("-----BEGIN PGP MESSAGE-----"))
        assertTrue(restored, restored.trimEnd().endsWith("-----END PGP MESSAGE-----"))
        // The body has to come back byte for byte, or the message will not decrypt.
        val body = { s: String -> s.lines().filter { it.isNotBlank() }
            .filterNot { it.startsWith("-----") || it.startsWith("Version:") }
            .joinToString("") }
        assertEquals(body(armored), body(restored))
    }

    @Test
    fun `messages obfuscated by the previous version still deobfuscate`() {
        // Anything already sent carries the doubled markers. Deobfuscation strips every
        // occurrence, so those must keep working.
        val oldFormat = marker + marker +
            "wV4DTmkMQQGcaxcSAQdANo1t8BWzhOFza9jwZQIc7uS59MO5E4gmVyK5laDT0w" +
            "7TgjnZ6sV1Qccg1SHgYRLREAHraEeRmWVwelavItS5HvTJ2LRU6NFrZV6wlka" +
            "=x9Yz" + marker + marker

        val restored = manager.deobfuscateMarkers(oldFormat)

        assertTrue(restored, restored.trimStart().startsWith("-----BEGIN PGP MESSAGE-----"))
        assertFalse("a marker leaked into the output", restored.contains(marker))
        assertTrue("the checksum was lost", restored.contains("=x9Yz"))
    }

    @Test
    fun `an obfuscated message is still recognised as one`() {
        // decryptMessage and the notification listener both detect by leading marker.
        val obfuscated = manager.obfuscateMarkers(armored)

        assertTrue(obfuscated.trimStart().startsWith(marker))
    }
}
