package tools.obli.obligarth.agent

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.AgentSigner
import tools.obli.obligarth.agent.core.Ec
import java.io.File
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * The agent's identity key (spec §8.2 AgentKey): EC P-256 in AndroidKeyStore,
 * signing only, no user authentication. When the Keystore fails, a software key
 * in private storage (keyStorage = software, PAR-9).
 */
class AgentKey(private val context: Context, private val log: AgentLog) : AgentSigner {
    private val softFile get() = File(context.noBackupFilesDirCompat(), "agent-key.pkcs8")

    @Volatile private var cached: Pair<PrivateKey, ByteArray>? = null
    @Volatile private var cachedStorage: String = "unknown"

    override val storage: String
        get() { load(); return cachedStorage }

    override fun spki(): ByteArray = load().second

    override fun sign(data: ByteArray): ByteArray = Ec.sign(load().first, data)

    @Synchronized
    private fun load(): Pair<PrivateKey, ByteArray> {
        cached?.let { return it }
        val fromStore = try { loadOrCreateKeystore() } catch (e: Exception) {
            log.warn("Keystore unavailable: ${e.javaClass.simpleName}: ${e.message}")
            null
        }
        val pair = fromStore ?: loadOrCreateSoftware()
        cached = pair
        return pair
    }

    private fun loadOrCreateKeystore(): Pair<PrivateKey, ByteArray>? {
        if (softFile.exists()) return null // a software key was already the identity: keep it
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(ALIAS)) {
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            gen.initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
            gen.generateKeyPair()
        }
        val entry = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return null
        val spki = entry.certificate.publicKey.encoded
        cachedStorage = try {
            val info = KeyFactory.getInstance(entry.privateKey.algorithm, KEYSTORE).getKeySpec(entry.privateKey, KeyInfo::class.java)
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "hardware" else "software"
        } catch (e: Exception) {
            "unknown"
        }
        return entry.privateKey to spki
    }

    private fun loadOrCreateSoftware(): Pair<PrivateKey, ByteArray> {
        cachedStorage = "software"
        val pubFile = File(softFile.path + ".spki")
        if (softFile.exists() && pubFile.exists()) {
            return Ec.privateKeyFromPkcs8(softFile.readBytes()) to pubFile.readBytes()
        }
        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        val kp = gen.generateKeyPair()
        softFile.parentFile?.mkdirs()
        softFile.writeBytes(kp.private.encoded)
        pubFile.writeBytes(kp.public.encoded)
        return kp.private to kp.public.encoded
    }

    @Synchronized
    override fun erase() {
        cached = null
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
        } catch (e: Exception) {
            log.warn("Keystore delete: ${e.message}")
        }
        softFile.delete()
        File(softFile.path + ".spki").delete()
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "obligarth-agent"
    }
}

fun Context.noBackupFilesDirCompat(): File = noBackupFilesDir
