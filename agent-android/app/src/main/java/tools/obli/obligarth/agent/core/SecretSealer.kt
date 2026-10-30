package tools.obli.obligarth.agent.core

/**
 * Seals the secrets of the stored policy (Wi-Fi PSK, EAP password; §10.6, B10): AES-256-GCM with an AndroidKeyStore key
 * on the device (KeystoreSealer), a fake in the JVM tests. A sealed value is stored as {"$sealed": "<b64 iv|ct>"}.
 */
interface SecretSealer {
    /** The sealed form of [plain]; null when the key store is unavailable (the secret is then not stored at all). */
    fun seal(plain: String): String?

    /** The clear value; null when it cannot be opened (key lost or erased, value damaged). */
    fun open(sealed: String): String?

    /** Forgets the key (identity erased). */
    fun erase() {}

    /** No key store: nothing is stored, every secret is asked again from the server when it is needed. */
    object None : SecretSealer {
        override fun seal(plain: String): String? = null
        override fun open(sealed: String): String? = null
    }
}
