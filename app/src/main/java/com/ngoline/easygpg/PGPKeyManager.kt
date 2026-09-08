package com.ngoline.easygpg

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import android.widget.Toast
import androidx.annotation.VisibleForTesting
import com.ngoline.easygpg.data.KeyItem
import java.io.ByteArrayInputStream
import java.io.File
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.security.Security
import java.security.UnrecoverableKeyException
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.collections.filter
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.util.encoders.Hex
import java.security.KeyStore
import androidx.preference.PreferenceManager
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.io.IOException

const val BcPGPVersion: Int = 4 // Use version 4 for ECDH keys
const val LOG_TAG = "PGPKeyManager"
const val ANDROID_KEYSTORE = "AndroidKeyStore"

/** Keystore key for public and imported key rings, which are not secret. */
const val KEY_ALIAS = "easygpg_aes_key"

/** Keystore key for secret key rings. Usable only after a recent user authentication. */
const val SECRET_KEY_ALIAS = "easygpg_secret_aes_key"

/**
 * How long a device authentication keeps [SECRET_KEY_ALIAS] usable. Keystore enforces this, so a
 * secret key ring file that leaves the device — or is read without the user being present — cannot
 * be decrypted at all.
 */
const val SECRET_KEY_AUTH_VALIDITY_SECONDS = 300

const val SECRET_KEYRING_SUFFIX = ".secret_keyring.pgp"

private const val AES_GCM = "AES/GCM/NoPadding"
private const val GCM_TAG_BITS = 128

/** Start of an armored key ring, used to tell a stored key ring from undecryptable bytes. */
private val ARMOR_PREFIX = "-----BEGIN".toByteArray()

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }

/**
 * Passphrase every key ring was protected with before passphrases were user-supplied.
 * Key rings still using it are re-encrypted by [PGPKeyManager.migrateLegacyKeyPassphrases].
 */
private const val LEGACY_PASSPHRASE = "passphrase"

/**
 * Replaces Android's cut-down BouncyCastle with the full build this app bundles, and puts it first
 * so `setProvider("BC")` resolves to it.
 *
 * [PGPKeyManager.encryptMessage] goes through Bouncy Castle's JCE operators, which look algorithms
 * up by provider name. Android ships its own trimmed "BC" provider with no `XDH`, so without this
 * call encrypting to a Curve25519 subkey fails with `NoSuchAlgorithmException: no such algorithm:
 * XDH for provider BC`. Decryption uses the lightweight `Bc*` operators and does not depend on it.
 *
 * Idempotent, so every entry point into the app can call it.
 */
fun installBouncyCastleProvider() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    Security.insertProviderAt(BouncyCastleProvider(), 1)
}

object PGPConstants {
    const val PGP_MARKER = "-----BEGIN PGP MESSAGE-----"
    const val OBFUSCATED_MARKER = "00023CD1"
}

/**
 * The secret key rings cannot be reached right now. These must travel up to the UI instead of being
 * swallowed as a load failure, so every layer in between rethrows this type as a whole.
 */
sealed class SecretKeyAccessException(cause: Throwable) : Exception(cause)

/**
 * The secret key ring Keystore key needs a fresh user authentication before it can be used. Show a
 * `BiometricPrompt` and retry.
 */
class AuthenticationRequiredException(cause: Throwable) : SecretKeyAccessException(cause)

/**
 * The Keystore key protecting the secret key rings was invalidated — the device lock screen was
 * removed or reset — which makes the stored secret key rings unreadable.
 */
class SecretKeyStoreLostException(cause: Throwable) : SecretKeyAccessException(cause)

/** Outcome of [PGPKeyManager.decryptMessage]. */
sealed interface DecryptionResult {
    /**
     * The caller owns [plaintext] and must [wipe] it once it is no longer displayed. Wiping reaches
     * this buffer alone: displaying it in a selectable `TextView` also copies it into a `String`
     * that no app can overwrite.
     */
    class Decrypted(val plaintext: CharArray) : DecryptionResult

    /** A stored key ring is addressed by the message, but the passphrase did not unlock it. */
    object WrongPassphrase : DecryptionResult

    /** No stored private key could open the message. */
    object NoUsableKey : DecryptionResult
}

class PGPKeyManager(private val context: Context) {

    /** Set once a sweep found no key ring under the legacy passphrase. */
    private var noLegacyProtectedKeys = false

    /**
     * Generates a key ring whose secret keys are protected by [passphrase] and, on disk, by the
     * authenticated Keystore key.
     *
     * The caller owns [passphrase] and should [wipe] it once this returns. Returns false if the key
     * ring could not be generated; throws [AuthenticationRequiredException] if the user has to
     * authenticate first.
     */
    fun generateAndSaveKeys(alias: String, passphrase: CharArray): Boolean {
        try {
            // --- Ed25519 for signing (primary key) ---
            val edKeyGen = Ed25519KeyPairGenerator()
            edKeyGen.init(Ed25519KeyGenerationParameters(SecureRandom()))
            val edKeyPair = edKeyGen.generateKeyPair()

            val digestCalculator = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
            val encryptorBuilder = secretKeyEncryptor(passphrase)
            val signerBuilder = BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.Ed25519, HashAlgorithmTags.SHA256)
            val bcEdKeyPair = BcPGPKeyPair(BcPGPVersion, PublicKeyAlgorithmTags.Ed25519, edKeyPair, Date())

            // --- Curve25519 for encryption (subkey) ---
            val ecdhGen = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
            ecdhGen.init(org.bouncycastle.crypto.params.X25519KeyGenerationParameters(SecureRandom()))
            val ecdhKeyPair = ecdhGen.generateKeyPair()
            val bcEcdhKeyPair = BcPGPKeyPair(BcPGPVersion, PublicKeyAlgorithmTags.ECDH, ecdhKeyPair, Date())

            // --- Create secret key ring with subkey ---
            val secretKey = PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                bcEdKeyPair,
                "user@example.com",
                digestCalculator,
                null,
                null,
                signerBuilder,
                encryptorBuilder
            )
            val subkey = PGPSecretKey(
                bcEdKeyPair,
                bcEcdhKeyPair,
                digestCalculator,
                signerBuilder,
                encryptorBuilder
            )

            val secretKeyRing = PGPSecretKeyRing(listOf(secretKey, subkey))
            val publicKeyRing = PGPPublicKeyRing(listOf(secretKey.publicKey, subkey.publicKey))

            saveNewSecretKeyRing(secretKeyRing, "$alias$SECRET_KEYRING_SUFFIX")
            saveKeyRing(publicKeyRing, "$alias.public_keyring.pgp")
            return true
        } catch (e: SecretKeyAccessException) {
            throw e
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Failed to generate a key ring for '$alias'", e)
            return false
        }
    }

    /**
     * Saves a freshly generated key ring, replacing the Keystore key if it was invalidated: nothing
     * readable was protected by it, so a dead key must not leave the user unable to generate keys.
     */
    private fun saveNewSecretKeyRing(secretKeyRing: PGPSecretKeyRing, filename: String) {
        try {
            saveSecretKeyRing(secretKeyRing, filename)
        } catch (e: SecretKeyStoreLostException) {
            Log.w(LOG_TAG, "Replacing invalidated secret keyring key: ${e.message}")
            resetSecretKeyringKey()
            saveSecretKeyRing(secretKeyRing, filename)
        }
    }

    private fun secretKeyEncryptor(passphrase: CharArray): PBESecretKeyEncryptor =
        BcPBESecretKeyEncryptorBuilder(
            PGPEncryptedData.AES_256,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        )
            .setSecureRandom(SecureRandom())
            .build(passphrase)

    private fun secretKeyDecryptor(passphrase: CharArray): PBESecretKeyDecryptor =
        BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)

    fun hasKeys(): Boolean {
        val files = context.filesDir.listFiles() ?: return false
        return files.any { it.isFile && it.name.endsWith(".public_keyring.pgp") }
    }

    fun getAllPublicKeys(): MutableList<KeyItem> {
        val keys = mutableListOf<KeyItem>()
        val files = context.filesDir.listFiles() ?: return keys
        files.filter { it.isFile && it.name.endsWith(".imported.pgp") }.forEach { file ->
            val publicKeyRing = loadImportedKeyRing(file)
            publicKeyRing?.let {
                val publicKey = it.publicKeys.next()
                if (publicKey != null) {
                    val fingerprint = String(Hex.encode(publicKey.fingerprint))
                    keys.add(
                        KeyItem(
                            file.name.replace(".imported.pgp", ""),
                            fingerprint,
                            publicKey,
                            it
                        )
                    )
                }
            }
        }
        return keys
    }

    fun deleteMyKey(alias: String): Boolean {
        val deletedSecret = context.deleteFile("$alias$SECRET_KEYRING_SUFFIX")
        val deletedPublic = context.deleteFile("$alias.public_keyring.pgp")
        return deletedSecret || deletedPublic
    }

    fun getMyPublicKeys(): MutableList<KeyItem> {
        val keys = mutableListOf<KeyItem>()
        val files = context.filesDir.listFiles() ?: return keys
        files.filter { it.isFile && it.name.endsWith(".public_keyring.pgp") }.forEach { file ->
            val publicKeyRing = loadImportedKeyRing(file)
            publicKeyRing?.let {
                val publicKey = it.publicKeys.next()
                if (publicKey != null) {
                    val fingerprint = String(Hex.encode(publicKey.fingerprint))
                    keys.add(
                        KeyItem(
                            file.name.replace(".public_keyring.pgp", ""),
                            fingerprint,
                            publicKey,
                            it
                        )
                    )
                }
            }
        }
        return keys
    }

    fun exportPrivateKey(alias: String): String? {
        val file = File(context.filesDir, "$alias.secret_keyring.pgp")
        if (!file.isFile) return null

        return try {
            val data = decryptFromFile(file)
            val secretKeyRing = PGPSecretKeyRing(
                PGPUtil.getDecoderStream(data.inputStream()),
                BcKeyFingerprintCalculator()
            )
            ByteArrayOutputStream().use { output ->
                ArmoredOutputStream(output).use { armored ->
                    secretKeyRing.encode(armored)
                }
                output.toString(Charsets.UTF_8.name())
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Failed to export private key for alias '$alias'", e)
            null
        }
    }

    fun importPublicKey(alias: String, keyData: String): PGPPublicKey? {
        try {
            val inputStream = ByteArrayInputStream(keyData.toByteArray())
            ArmoredInputStream(inputStream).use { ais ->
                val pgpObjectFactory = PGPObjectFactory(PGPUtil.getDecoderStream(ais), BcKeyFingerprintCalculator())
                var obj: Any?

                while (pgpObjectFactory.nextObject().also { obj = it } != null) {
                    when (obj) {
                        is PGPPublicKeyRing -> {
                            saveImportedKeyRing(alias, obj)
                            Toast.makeText(context, "Public key imported successfully", Toast.LENGTH_SHORT).show()
                            return obj.publicKey
                        }
                        is PGPPublicKey -> {
                            // Wrap single key in a keyring
                            val keyRing = PGPPublicKeyRing(listOf(obj))
                            saveImportedKeyRing(alias, keyRing)
                            Toast.makeText(context, "Public key imported successfully", Toast.LENGTH_SHORT).show()
                            return obj
                        }
                    }
                }
                Toast.makeText(context, "Invalid public key format", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Toast.makeText(context, "Failed to import public key: ${e.message}", Toast.LENGTH_LONG).show()
        }

        return null
    }

    /**
     * The Keystore handles, kept for the life of this manager: opening the Keystore is an IPC per
     * lookup and authentication is enforced when a [Cipher] is initialised, not here.
     */
    private val keystoreKeys = ConcurrentHashMap<String, SecretKey>()

    private fun keystore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun keystoreKey(alias: String, requireUserAuthentication: Boolean): SecretKey =
        keystoreKeys.getOrPut(alias) { loadOrCreateKeystoreKey(alias, requireUserAuthentication) }

    private fun loadOrCreateKeystoreKey(alias: String, requireUserAuthentication: Boolean): SecretKey {
        val keyStore = keystore()
        val existingKey = try {
            keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        } catch (e: UnrecoverableKeyException) {
            // Some devices report an invalidated key here rather than when it is used.
            if (requireUserAuthentication) throw SecretKeyStoreLostException(e) else throw e
        }
        if (existingKey != null) {
            return existingKey.secretKey
        }
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(requireUserAuthentication)
            .apply {
                if (requireUserAuthentication) {
                    setUserAuthenticationParameters(
                        SECRET_KEY_AUTH_VALIDITY_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                    // Enrolling another fingerprint must not destroy the user's key rings.
                    setInvalidatedByBiometricEnrollment(false)
                }
            }
            .build()
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    /** Key for material that is not secret: public and imported key rings. */
    private fun publicDataKey(): SecretKey = keystoreKey(KEY_ALIAS, requireUserAuthentication = false)

    /** Key for secret key rings, usable only after a recent user authentication. */
    private fun secretKeyringKey(): SecretKey =
        keystoreKey(SECRET_KEY_ALIAS, requireUserAuthentication = true)

    /** Deletes the secret key ring Keystore key, so a fresh one is generated on next use. */
    private fun resetSecretKeyringKey() {
        keystore().deleteEntry(SECRET_KEY_ALIAS)
        keystoreKeys.remove(SECRET_KEY_ALIAS)
    }

    /** Turns the Keystore's authentication failures into something the UI can act on. */
    private fun <T> keystoreOperation(block: () -> T): T =
        try {
            block()
        } catch (e: UserNotAuthenticatedException) {
            throw AuthenticationRequiredException(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw SecretKeyStoreLostException(e)
        }

    /**
     * Writes [plainData] as `[IV length][IV][AES-GCM ciphertext]`, the one envelope every key ring
     * file on disk uses, through a temporary file so a failure cannot leave a truncated key ring.
     */
    private fun writeEncryptedFile(file: File, key: SecretKey, plainData: ByteArray) {
        val (iv, body) = keystoreOperation {
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.iv to cipher.doFinal(plainData)
        }
        val tempFile = File(file.parentFile, "${file.name}.tmp")
        try {
            tempFile.outputStream().use { out ->
                out.write(iv.size)
                out.write(iv)
                out.write(body)
            }
            if (!tempFile.renameTo(file)) {
                throw IOException("Could not replace ${file.name}")
            }
        } finally {
            tempFile.delete()
        }
    }

    /**
     * Reads the envelope written by [writeEncryptedFile], or null when [file] holds no envelope
     * [key] can open — decrypting in one `doFinal` so a wrong key is a GCM tag failure this code can
     * act on rather than a stream error yielding partial data.
     */
    private fun readEncryptedFile(file: File, key: SecretKey): ByteArray? {
        val raw = file.readBytes()
        val ivSize = if (raw.isNotEmpty()) raw[0].toInt() and 0xFF else 0
        // A GCM IV is 12-16 bytes; anything else was not written by writeEncryptedFile.
        if (ivSize !in 12..16 || raw.size <= 1 + ivSize) return null
        return try {
            keystoreOperation {
                val cipher = Cipher.getInstance(AES_GCM)
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, raw, 1, ivSize))
                cipher.doFinal(raw, 1 + ivSize, raw.size - 1 - ivSize)
            }
        } catch (e: GeneralSecurityException) {
            Log.i(LOG_TAG, "${file.name} cannot be opened with this key: ${e.message}")
            null
        }
    }

    private fun encryptToFile(plainData: ByteArray, file: File) =
        writeEncryptedFile(file, publicDataKey(), plainData)

    /** Public key rings written before they were encrypted are encrypted on first read. */
    private fun decryptFromFile(file: File): ByteArray =
        readEncryptedFile(file, publicDataKey()) ?: file.readBytes().also { plainData ->
            Log.i(LOG_TAG, "${file.name} is not encrypted, encrypting it.")
            encryptToFile(plainData, file)
        }

    /**
     * Reads a secret key ring, moving it under the authenticated Keystore key if an earlier version
     * left it under the key that needs no authentication, or unencrypted.
     */
    private fun readSecretKeyringFile(file: File): ByteArray {
        readEncryptedFile(file, secretKeyringKey())?.let { return it }
        val plainData = readEncryptedFile(file, publicDataKey())
            // Only bytes that really are a key ring are adopted as plaintext, so a corrupt file is
            // reported instead of being re-encrypted into something still unreadable.
            ?: file.readBytes().takeIf { it.startsWith(ARMOR_PREFIX) }
            ?: throw IOException("${file.name} cannot be decrypted")
        writeSecretKeyringFile(file, plainData)
        Log.i(LOG_TAG, "Moved secret key ring ${file.name} under the authenticated Keystore key.")
        return plainData
    }

    private fun writeSecretKeyringFile(file: File, plainData: ByteArray) =
        writeEncryptedFile(file, secretKeyringKey(), plainData)

    private fun saveImportedKeyRing(alias: String, publicKeyRing: PGPPublicKeyRing) {
        val filename = "$alias.imported.pgp"
        val file = File(context.filesDir, filename)
        val baos = java.io.ByteArrayOutputStream()
        ArmoredOutputStream(baos).use { aos ->
            publicKeyRing.encode(aos)
        }
        encryptToFile(baos.toByteArray(), file)
        Toast.makeText(context, "Public key saved successfully under alias '$alias'", Toast.LENGTH_SHORT).show()
    }

    private fun saveKeyRing(keyRing: PGPKeyRing, filename: String) {
        val baos = java.io.ByteArrayOutputStream()
        ArmoredOutputStream(baos).use { aos ->
            keyRing.encode(aos)
        }
        // Write to a temporary file first so a failure part-way through cannot leave a truncated
        // key ring behind.
        val file = File(context.filesDir, filename)
        val tempFile = File(context.filesDir, "$filename.tmp")
        try {
            encryptToFile(baos.toByteArray(), tempFile)
            if (!tempFile.renameTo(file)) {
                throw IOException("Could not replace $filename")
            }
        } finally {
            tempFile.delete()
        }
    }

    private fun saveSecretKeyRing(secretKeyRing: PGPSecretKeyRing, filename: String) {
        val baos = WipeableByteArrayOutputStream()
        try {
            ArmoredOutputStream(baos).use { aos ->
                secretKeyRing.encode(aos)
            }
            baos.toByteArray().useThenWipe { encoded ->
                writeSecretKeyringFile(File(context.filesDir, filename), encoded)
            }
        } finally {
            baos.wipe()
        }
    }

    fun loadImportedKeyRing(file: File): PGPPublicKeyRing? {
        val data = decryptFromFile(file)
        return PGPPublicKeyRing(PGPUtil.getDecoderStream(data.inputStream()), BcKeyFingerprintCalculator())
    }

    private fun loadSecretKeyRing(file: File): PGPSecretKeyRing? {
        return try {
            // Bouncy Castle keeps its own copy of the key material once parsed, which cannot be
            // scrubbed; wiping our buffer at least drops the armored copy.
            readSecretKeyringFile(file).useThenWipe { data ->
                PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(data.inputStream()),
                    BcKeyFingerprintCalculator()
                )
            }
        } catch (e: SecretKeyAccessException) {
            throw e
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Failed to load keyring ${file.name}: ${e.message}")
            null
        }
    }

    private fun secretKeyringFiles(): List<File> {
        val files = context.filesDir.listFiles() ?: return emptyList()
        return files.filter { it.isFile && it.name.endsWith(SECRET_KEYRING_SUFFIX) }
    }

    /** Key rings still protected by [LEGACY_PASSPHRASE], paired with the file they came from. */
    private fun legacyProtectedKeyRings(): List<Pair<File, PGPSecretKeyRing>> =
        secretKeyringFiles().mapNotNull { file ->
            loadSecretKeyRing(file)?.takeIf { isLegacyProtected(it) }?.let { file to it }
        }

    /**
     * True while any stored key ring is still protected by [LEGACY_PASSPHRASE]. Answering costs a
     * key derivation per stored key, so once there are none the answer is kept: a migrated key ring
     * cannot go back to the legacy passphrase.
     */
    fun hasLegacyProtectedKeys(): Boolean {
        if (noLegacyProtectedKeys) return false
        val legacyKeyRings = legacyProtectedKeyRings()
        noLegacyProtectedKeys = legacyKeyRings.isEmpty()
        return legacyKeyRings.isNotEmpty()
    }

    /**
     * Re-encrypts every key ring still protected by [LEGACY_PASSPHRASE] with [newPassphrase]
     * and returns how many were migrated. The caller owns [newPassphrase].
     */
    fun migrateLegacyKeyPassphrases(newPassphrase: CharArray): Int {
        var migrated = 0
        for ((file, secretKeyRing) in legacyProtectedKeyRings()) {
            val legacyPassphrase = LEGACY_PASSPHRASE.toCharArray()
            try {
                val reEncrypted = PGPSecretKeyRing.copyWithNewPassword(
                    secretKeyRing,
                    secretKeyDecryptor(legacyPassphrase),
                    secretKeyEncryptor(newPassphrase)
                )
                saveSecretKeyRing(reEncrypted, file.name)
                migrated++
            } catch (e: SecretKeyAccessException) {
                throw e
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Failed to migrate passphrase for ${file.name}: ${e.message}")
            } finally {
                legacyPassphrase.wipe()
            }
        }
        return migrated
    }

    private fun isLegacyProtected(secretKeyRing: PGPSecretKeyRing): Boolean {
        val legacyPassphrase = LEGACY_PASSPHRASE.toCharArray()
        try {
            val secretKeys = secretKeyRing.secretKeys
            while (secretKeys.hasNext()) {
                val secretKey = secretKeys.next()
                if (secretKey.isPrivateKeyEmpty) continue
                try {
                    secretKey.extractPrivateKey(secretKeyDecryptor(legacyPassphrase))
                    return true
                } catch (_: PGPException) {
                    // Protected by something other than the legacy passphrase.
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Could not inspect key ring protection: ${e.message}")
        } finally {
            legacyPassphrase.wipe()
        }
        return false
    }

    /** [DecryptionResult.NoUsableKey] here means this one key ring cannot open the message. */
    private fun tryDecryptWithKeyring(
        secretKeyRing: PGPSecretKeyRing,
        encryptedMessage: String,
        passphrase: CharArray
    ): DecryptionResult {
        try {
            val decoderStream = PGPUtil.getDecoderStream(encryptedMessage.byteInputStream())
            val pgpFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())
            var encList: PGPEncryptedDataList? = null
            var obj = pgpFactory.nextObject()
            if (obj is PGPEncryptedDataList) {
                encList = obj
            } else {
                obj = pgpFactory.nextObject()
                if (obj is PGPEncryptedDataList) {
                    encList = obj
                }
            }
            if (encList == null) return DecryptionResult.NoUsableKey
            var privateKey: PGPPrivateKey? = null
            var encData: PGPPublicKeyEncryptedData? = null
            val it = encList.encryptedDataObjects
            while (it.hasNext()) {
                val edata = it.next()
                if (edata is PGPPublicKeyEncryptedData) {
                    val secretKey = secretKeyRing.getSecretKey(edata.keyIdentifier)
                    if (secretKey != null) {
                        privateKey = try {
                            secretKey.extractPrivateKey(secretKeyDecryptor(passphrase))
                        } catch (e: PGPException) {
                            Log.e(LOG_TAG, "Could not unlock secret key: ${e.message}")
                            return DecryptionResult.WrongPassphrase
                        }
                        encData = edata
                        break
                    }
                }
            }
            if (privateKey == null || encData == null) return DecryptionResult.NoUsableKey
            val clear = encData.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
            val plainFactory = PGPObjectFactory(clear, BcKeyFingerprintCalculator())
            var message: Any? = plainFactory.nextObject()
            while (message != null) {
                if (message is PGPLiteralData) {
                    return message.inputStream.readBytes().useThenWipe { plainBytes ->
                        DecryptionResult.Decrypted(plainBytes.toUtf8Chars())
                    }
                }
                message = plainFactory.nextObject()
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Decryption failed: ${e.message}")
        }
        return DecryptionResult.NoUsableKey
    }

    /**
     * Decrypts [encryptedMessage] with whichever stored key ring [passphrase] unlocks.
     * The caller owns [passphrase] and should [wipe] it once this returns.
     */
    fun decryptMessage(encryptedMessage: String, passphrase: CharArray): DecryptionResult {
        // Deobfuscate markers if present
        var message = encryptedMessage
        val foundObf = message.trimStart().startsWith(PGPConstants.OBFUSCATED_MARKER)
        if (foundObf) {
            Log.d(LOG_TAG, "Detected obfuscated PGP message, deobfuscating markers.")
            message = deobfuscateMarkers(message)
        }

        var wrongPassphrase = false
        for (file in secretKeyringFiles()) {
            val secretKeyRing = loadSecretKeyRing(file) ?: continue
            when (val attempt = tryDecryptWithKeyring(secretKeyRing, message, passphrase)) {
                is DecryptionResult.Decrypted -> return attempt
                is DecryptionResult.WrongPassphrase -> wrongPassphrase = true
                is DecryptionResult.NoUsableKey -> {}
            }
        }
        return if (wrongPassphrase) DecryptionResult.WrongPassphrase else DecryptionResult.NoUsableKey
    }

    /**
     * Encrypts [message] to [publicKey]. The caller owns [message] and must [wipe] it once this
     * returns; the plaintext buffers used along the way are wiped here.
     */
    fun encryptMessage(message: CharArray, publicKey: PGPPublicKey): String {
        try {
            return message.toUtf8Bytes().useThenWipe { messageBytes ->
                // encGen streams the plaintext through this buffer, so it holds it too.
                val plaintextBuffer = ByteArray(4096)
                try {
                    val encryptedData = ByteArrayOutputStream()
                    val armorStream = ArmoredOutputStream(encryptedData)

                    val encGen = PGPEncryptedDataGenerator(
                        JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(SecureRandom())
                            .setProvider("BC")
                    )

                    val keyEncryptionMethodGenerator = JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC")
                    encGen.addMethod(keyEncryptionMethodGenerator)

                    val encOut = encGen.open(armorStream, plaintextBuffer)
                    val lData = PGPLiteralDataGenerator()
                    val pOut = lData.open(encOut, PGPLiteralData.BINARY, "filename", messageBytes.size.toLong(), Date())
                    pOut.write(messageBytes)
                    pOut.close()

                    encOut.close()
                    armorStream.close()

                    var encryptedMessage = String(encryptedData.toByteArray())
                    if (isObfuscateMarkersEnabled()) {
                        Log.d(LOG_TAG, "Obfuscating PGP markers in encrypted message.")
                        encryptedMessage = obfuscateMarkers(encryptedMessage)
                    }
                    encryptedMessage
                } finally {
                    plaintextBuffer.wipe()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            return "Encryption failed"
        }
    }

    private fun isObfuscateMarkersEnabled(): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        return prefs.getBoolean(context.getString(R.string.obfuscate_pgp_markers), false)
    }

    /**
     * Replaces the armor header and footer with [PGPConstants.OBFUSCATED_MARKER].
     *
     * Blank lines are dropped rather than replaced. Armored output carries one after the version
     * header and another at the end, so replacing them emitted the marker twice at each end — and
     * a doubled sixteen-character hex run is a more distinctive signature than a single one, which
     * works against the point of obfuscating at all.
     *
     * Internal rather than private so the round trip can be tested directly.
     */
    @VisibleForTesting
    internal fun obfuscateMarkers(input: String): String =
        input.lines().joinToString("") { line ->
            when {
                line.startsWith("-----BEGIN ") || line.startsWith("-----END ") ->
                    PGPConstants.OBFUSCATED_MARKER
                // Version and Comment identify the implementation; blank lines carry nothing.
                // Deobfuscation re-chunks the base64 regardless, so neither is needed.
                line.isBlank() -> ""
                line.startsWith("Version:") || line.startsWith("Comment:") -> ""
                else -> line
            }
        }

    /** Internal rather than private only so the obfuscation round trip can be tested directly. */
    @VisibleForTesting
    internal fun deobfuscateMarkers(input: String): String {
        // Remove all obfuscated markers, add BEGIN/END markers, and break lines to 64 chars
        val clean = input.replace(PGPConstants.OBFUSCATED_MARKER, "")
            .replace("\n", "")
            .replace("\r", "")
            .trim()
        // Separate checksum if present (starts with '=')
        val checksumIndex = clean.lastIndexOf('=')
        val (base64Data, checksum) = if (checksumIndex != -1 && clean.length - checksumIndex <= 5) {
            clean.substring(0, checksumIndex) to clean.substring(checksumIndex)
        } else {
            clean to null
        }
        val sb = StringBuilder()
        sb.append(PGPConstants.PGP_MARKER).append("\n\n")
        var i = 0
        while (i < base64Data.length) {
            val end = (i + 64).coerceAtMost(base64Data.length)
            sb.append(base64Data.substring(i, end)).append("\n")
            i = end
        }
        if (checksum != null) {
            sb.append(checksum).append("\n")
        }
        val endMarker = PGPConstants.PGP_MARKER.replace("BEGIN", "END")
        sb.append(endMarker).append("\n")
        return sb.toString()
    }
}
