package com.ngoline.easygpg.data

import java.util.Date
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing

data class KeyItem(
    val alias: String,
    val fingerprint: String,
    val publicKey: PGPPublicKey,
    val publicKeyRing: PGPPublicKeyRing
)

fun shortFingerprint(fingerprint: String): String = fingerprint.takeLast(8).uppercase()

/** How a key ring is named in a one-line list: its alias and its primary key's fingerprint. */
val KeyItem.label: String
    get() = "$alias (${shortFingerprint(fingerprint)})"

private const val ENCRYPTION_FLAGS = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE

/**
 * The key flags this key's most recent self-signature declares, or null if no signature on it
 * carries a key-flags subpacket. Rings this app generates itself set no flags, so "no flags at all"
 * has to stay distinguishable from "flagged for something other than encryption".
 */
private val PGPPublicKey.declaredKeyFlags: Int?
    get() {
        var flags: Int? = null
        var newest = Long.MIN_VALUE
        val signatures = signatures
        while (signatures.hasNext()) {
            val signature = signatures.next()
            val hashed = signature.hashedSubPackets ?: continue
            if (!hashed.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS)) continue
            val created = signature.creationTime.time
            if (created >= newest) {
                newest = created
                flags = hashed.keyFlags
            }
        }
        return flags
    }

private fun PGPPublicKey.isExpired(now: Date): Boolean {
    val seconds = validSeconds
    return seconds > 0L && creationTime.time + seconds * 1000L < now.time
}

/**
 * The key a message to this ring is encrypted to, or null if the ring has none and so cannot be
 * encrypted to at all. Which subkey it is is not offered to the user as a choice.
 *
 * `isEncryptionKey` alone is not enough to choose with: it reports what the *algorithm* can do, so
 * an RSA primary answers true even when its key flags say certify and sign only. Picking that key
 * produces a message the recipient cannot open, because the encryption subkey is the one they hold
 * (and, on the usual offline-primary setup, the only secret half they have on the device at all).
 * So prefer keys actually flagged for encryption, skip revoked and expired ones, and prefer a
 * subkey over the primary, which is the convention every other OpenPGP implementation follows.
 */
val KeyItem.encryptionKey: PGPPublicKey?
    get() {
        val now = Date()
        val usable = publicKeyRing.filter {
            it.isEncryptionKey && !it.hasRevocation() && !it.isExpired(now)
        }
        val flaggedForEncryption = usable.filter { key ->
            key.declaredKeyFlags?.and(ENCRYPTION_FLAGS)?.takeIf { it != 0 } != null
        }
        // A ring whose keys carry no flags at all predates the convention, or this app generated
        // it; there the algorithm is all there is to go on.
        val candidates = flaggedForEncryption.ifEmpty {
            usable.filter { it.declaredKeyFlags == null }
        }
        return candidates.minWithOrNull(
            compareBy<PGPPublicKey> { it.isMasterKey }.thenByDescending { it.creationTime }
        )
    }
