package tools.obli.obligarth.agent

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.B64
import tools.obli.obligarth.agent.core.SecretSealer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The secrets of the stored policy sealed with an AES-256-GCM key of the AndroidKeyStore (1.3.0, §10.6, D17): alias
 * obligarth-policy, no user authentication, a fresh 12-byte IV per value (chosen by the key store), stored as
 * b64(iv | ciphertext). Any key store failure seals nothing: the agent then asks the server for a full configuration
 * when a secret is needed. The key is deleted with the identity.
 */
class KeystoreSealer(private val log: AgentLog) : SecretSealer {

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    @Synchronized
    private fun key(create: Boolean): SecretKey? {
        val ks = keyStore()
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    override fun seal(plain: String): String? {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key(create = true) ?: return null)
            val iv = cipher.iv
            val ct = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            if (iv.size != IV_BYTES) null else B64.encodeStd(iv + ct)
        } catch (e: Exception) {
            log.warn("policy sealing unavailable: ${e.javaClass.simpleName}")
            null
        }
    }

    override fun open(sealed: String): String? {
        val raw = B64.decode(sealed)
        if (raw == null || raw.size <= IV_BYTES + 16) return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(create = false) ?: return null, GCMParameterSpec(128, raw, 0, IV_BYTES))
            String(cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES), Charsets.UTF_8)
        } catch (e: Exception) {
            log.warn("policy secret cannot be opened: ${e.javaClass.simpleName}")
            null
        }
    }

    @Synchronized
    override fun erase() {
        try { keyStore().deleteEntry(ALIAS) } catch (e: Exception) { log.warn("policy key erase: ${e.javaClass.simpleName}") }
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val ALIAS = "obligarth-policy"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_BYTES = 12
    }
}
