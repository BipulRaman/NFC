package dev.bipul.nfcstudio.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** This phone's tamper-seal key, kept in the Android Keystore (hardware-backed where available). */
object KeystoreSigner : Seal.Signer {
    private const val ALIAS = "nfcstudio-seal"

    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** The public key if one was created before, without creating one. */
    fun existingPublicKey(): ByteArray? = runCatching {
        (store().getCertificate(ALIAS)?.publicKey as? ECPublicKey)?.let(Seal::compress)
    }.getOrNull()

    private fun ensureKey(): Pair<PrivateKey, ECPublicKey> {
        val ks = store()
        val entry = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (entry != null) return entry.privateKey to (entry.certificate.publicKey as ECPublicKey)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build(),
        )
        val kp = kpg.generateKeyPair()
        return kp.private to (kp.public as ECPublicKey)
    }

    override val publicKey: ByteArray get() = Seal.compress(ensureKey().second)

    override fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(ensureKey().first)
            update(data)
            sign()
        }
}
