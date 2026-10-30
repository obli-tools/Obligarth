package tools.obli.obligarth.agent.core

/** Canonical JSON (map keys sorted, recursively): the digests of the policy items and of the report. */
object Canon {
    fun write(value: Any?): String = Json.write(sorted(value))

    fun sha256(value: Any?): String = Sha256.hex(write(value))

    private fun sorted(v: Any?): Any? = when (v) {
        is Map<*, *> -> java.util.TreeMap<String, Any?>().also { m -> for ((k, x) in v) m[k.toString()] = sorted(x) }
        is Iterable<*> -> v.map { sorted(it) }
        is Array<*> -> v.map { sorted(it) }
        else -> v
    }
}

/**
 * The policy of the bridge agent (1.3.0, lot PONT-POL §6.2, §8.2): the object `policy` of a signed configuration,
 * parsed without ever throwing. The bounds of the shared limits apply; an item the agent cannot read is left out and
 * named in [invalidKeys] (reported error/invalid_item, A10); unknown keys are ignored (a later server may add some).
 * Secrets (Wi-Fi PSK, EAP password) live in fields never printed: [toString] redacts everything; the stored form seals
 * them ([toJson]). Each item carries the digest of its desired value (secrets included, computed here, never sent): the
 * ledger compares it to decide whether to apply again.
 */
class Policy(
    val v: Int,
    val hash: String,
    val reportSeconds: Long,
    val files: List<FileItem>,
    val wifi: List<Wifi>,
    val wifiRemove: List<WifiRemove>,
    val dpm: List<Setting>,
    val knox: List<Setting>,
    val certs: List<Cert>,
    val kiosk: Kiosk?,
    val blobs: List<String>,
    val dropped: List<Dropped>,
    val undeliverable: List<String>,
    val withheld: List<String>,
    /** Keys of the items left out because they could not be read. */
    val invalidKeys: List<String>,
    /** Items without a readable key, left out too (only the item agent:policy reports them). */
    val invalidUnkeyed: Int,
    /** A sealed secret of the stored form could not be opened: a Wi-Fi item needs a full configuration again. */
    val secretsMissing: Boolean,
) {
    class BlobRef(val sha256: String, val size: Long)

    class FileItem(
        val key: String, val digest: String, val id: String, val paths: List<String>, val allowAppDataDir: Boolean,
        val overwrite: String, val onRemove: String, val mediaScan: Boolean,
        val blob: BlobRef?, val inline: ByteArray?, val inlineSha256: String?,
    ) {
        /** The SHA-256 of the content to deposit (the blob's, or the one the server announced for the inline bytes). */
        val sha256: String get() = blob?.sha256 ?: inlineSha256!!
        val size: Long get() = blob?.size ?: inline!!.size.toLong()
        override fun toString() = "FileItem($key)"
    }

    class Eap(
        val identity: String, val anonymousIdentity: String?, val password: String?, val caPem: String?,
        val domainSuffixMatch: String?, val allowNoCa: Boolean,
    ) {
        override fun toString() = "Eap(redacted)"
    }

    class Wifi(
        val key: String, val digest: String, val ssid: String, val security: String, val hidden: Boolean, val priority: Int,
        val autoConnect: Boolean, val preferOver: List<String>, val psk: String?, val eap: Eap?,
    ) {
        /** The secret needed to (re)create the network is in memory. */
        val hasSecrets: Boolean get() = if (security == PSK) psk != null else eap?.password != null
        override fun toString() = "Wifi($key)"
    }

    class WifiRemove(val key: String, val digest: String, val ssid: String)

    /** One device-administrator or Knox setting: its field and its value (Boolean, Long, String or List<String>). */
    class Setting(val key: String, val digest: String, val field: String, val value: Any?) {
        override fun toString() = "Setting($key)"
    }

    class Cert(val key: String, val digest: String, val id: String, val name: String, val pem: String) {
        override fun toString() = "Cert($key)"
    }

    class TileAction(val type: String, val pkg: String?, val url: String?, val uri: String?)

    class Tile(val id: String, val label: String, val image: BlobRef?, val launchOnStart: Boolean, val action: TileAction)

    class Hard(
        val hideSystemBar: Boolean, val disableStatusBarExpansion: Boolean, val disableTaskManager: Boolean,
        val blockKeys: List<String>, val disableSettingsChanges: Boolean,
    ) {
        val any: Boolean get() = hideSystemBar || disableStatusBarExpansion || disableTaskManager || blockKeys.isNotEmpty() || disableSettingsChanges
    }

    class Kiosk(
        val key: String, val digest: String, val enabled: Boolean, val title: String?, val showDeviceName: Boolean,
        val deviceName: String?, val columns: Int, val logo: BlobRef?, val tiles: List<Tile>, val exitPin: PinRecord?,
        val hard: Hard?,
    ) {
        override fun toString() = "Kiosk($key, enabled=$enabled, tiles=${tiles.size})"
    }

    class Dropped(val key: String, val code: String)

    /** Every key of the policy the agent applies (items read), in no particular order. */
    val itemKeys: List<String>
        get() = files.map { it.key } + wifi.map { it.key } + wifiRemove.map { it.key } + dpm.map { it.key } + knox.map { it.key } +
            certs.map { it.key } + listOfNotNull(kiosk?.key)

    override fun toString() = "Policy(hash=${hash.take(8)}, items=${itemKeys.size}, invalid=${invalidKeys.size})"

    /** The kiosk key is withheld here (undeliverable: the server could not open its PIN; or unreadable by this agent). */
    val kioskWithheld: Boolean get() = KIOSK_KEY in undeliverable || KIOSK_KEY in invalidKeys

    /**
     * This policy with the kiosk of [previous] when its own kiosk key is withheld and the previous policy had one: the
     * device keeps the kiosk it applied (no undo), so the kiosk screen, its PIN exit and kiosk.suspend keep reading it.
     * Its images stay among the blobs. Unchanged otherwise.
     */
    fun keepingKioskOf(previous: Policy?): Policy {
        val k = previous?.kiosk
        if (kiosk != null || k == null || !kioskWithheld) return this
        val images = listOfNotNull(k.logo?.sha256) + k.tiles.mapNotNull { it.image?.sha256 }
        return Policy(v, hash, reportSeconds, files, wifi, wifiRemove, dpm, knox, certs, k, (blobs + images).distinct(), dropped,
            undeliverable, withheld, invalidKeys, invalidUnkeyed, secretsMissing)
    }

    /**
     * The stored form (app-private preferences): the wire form plus each item's digest, the secrets sealed by [sealer].
     * A secret the sealer cannot seal is not stored at all and the stored form says secretsMissing.
     */
    fun toJson(sealer: SecretSealer): Map<String, Any?> {
        var missing = secretsMissing
        fun sealed(v: String?): Any? {
            if (v == null) return null
            val s = sealer.seal(v)
            if (s == null) { missing = true; return null }
            return linkedMapOf(SEALED to s)
        }
        fun ref(b: BlobRef?) = b?.let { linkedMapOf("sha256" to it.sha256, "size" to it.size) }
        val out = linkedMapOf<String, Any?>(
            "v" to v, "hash" to hash, "reportSeconds" to reportSeconds,
            "files" to files.map { f ->
                linkedMapOf(
                    "key" to f.key, DIGEST to f.digest, "id" to f.id, "paths" to f.paths, "allowAppDataDir" to f.allowAppDataDir,
                    "overwrite" to f.overwrite, "onRemove" to f.onRemove, "mediaScan" to f.mediaScan, "blob" to ref(f.blob),
                    "inline" to f.inline?.let { linkedMapOf("b64" to B64.encodeStd(it), "sha256" to f.inlineSha256, "size" to it.size) },
                )
            },
            "wifi" to wifi.map { w ->
                linkedMapOf(
                    "key" to w.key, DIGEST to w.digest, "ssid" to w.ssid, "security" to w.security, "hidden" to w.hidden,
                    "priority" to w.priority, "autoConnect" to w.autoConnect, "preferOver" to w.preferOver, "psk" to sealed(w.psk),
                    "eap" to w.eap?.let { e ->
                        linkedMapOf(
                            "identity" to e.identity, "anonymousIdentity" to e.anonymousIdentity, "password" to sealed(e.password),
                            "phase2" to MSCHAPV2, "caPem" to e.caPem, "domainSuffixMatch" to e.domainSuffixMatch, "allowNoCa" to e.allowNoCa,
                        )
                    },
                )
            },
            "wifiRemove" to wifiRemove.map { linkedMapOf("key" to it.key, DIGEST to it.digest, "ssid" to it.ssid) },
            "dpm" to dpm.map { linkedMapOf("key" to it.key, DIGEST to it.digest, "field" to it.field, "value" to it.value) },
            "knox" to knox.map { linkedMapOf("key" to it.key, DIGEST to it.digest, "field" to it.field, "value" to it.value) },
            "certs" to certs.map { linkedMapOf("key" to it.key, DIGEST to it.digest, "id" to it.id, "name" to it.name, "pem" to it.pem) },
            "kiosk" to kiosk?.let { k ->
                linkedMapOf(
                    "key" to k.key, DIGEST to k.digest, "enabled" to k.enabled, "title" to k.title, "showDeviceName" to k.showDeviceName,
                    "deviceName" to k.deviceName, "columns" to k.columns, "logo" to ref(k.logo),
                    "tiles" to k.tiles.map { t ->
                        linkedMapOf(
                            "id" to t.id, "label" to t.label, "image" to ref(t.image), "launchOnStart" to t.launchOnStart,
                            "action" to linkedMapOf("type" to t.action.type, "package" to t.action.pkg, "url" to t.action.url, "uri" to t.action.uri),
                        )
                    },
                    "exitPin" to k.exitPin?.toJson(),
                    "hard" to k.hard?.let { h ->
                        linkedMapOf(
                            "hideSystemBar" to h.hideSystemBar, "disableStatusBarExpansion" to h.disableStatusBarExpansion,
                            "disableTaskManager" to h.disableTaskManager, "blockKeys" to h.blockKeys, "disableSettingsChanges" to h.disableSettingsChanges,
                        )
                    },
                )
            },
            "blobs" to blobs,
            "dropped" to dropped.map { linkedMapOf("key" to it.key, "code" to it.code) },
            "undeliverable" to undeliverable,
            "withheld" to withheld,
            INVALID to invalidKeys,
            INVALID_UNKEYED to invalidUnkeyed,
        )
        out[SECRETS_MISSING] = missing
        return out
    }

    sealed class ParseResult {
        class Ok(val policy: Policy) : ParseResult()
        /** v is not 1: the agent keeps its current policy and reports policy_version_unsupported. */
        class Unsupported(val hash: String?) : ParseResult()
        /** Not a policy at all (no hash): ignored, the current policy kept. */
        object Malformed : ParseResult()
    }

    companion object {
        const val FORMAT = 1
        const val PSK = "wpa2_psk"
        const val PEAP = "wpa2_eap_peap"
        const val MSCHAPV2 = "mschapv2"
        const val KIOSK_KEY = "agent:kiosk"
        const val SEALED = "\$sealed"
        private const val DIGEST = "\$digest"
        private const val INVALID = "\$invalid"
        private const val INVALID_UNKEYED = "\$invalidUnkeyed"
        private const val SECRETS_MISSING = "\$secretsMissing"

        // Bounds of the shared LEGACY_AGENT_POLICY_LIMITS.
        const val MAX_FILES = 64
        const val MAX_PATHS = 4
        const val MAX_WIFI = 16
        const val MAX_WIFI_REMOVE = 16
        const val MAX_PREFER_OVER = 8
        const val MAX_TILES = 48
        const val MAX_CERTS = 8
        const val MAX_KNOX_LIST = 64
        const val TEMPLATE_BYTES = 32 * 1024
        const val PEM_BYTES = 8 * 1024
        const val STORE_FILE_BYTES = 64L * 1024 * 1024
        const val IMAGE_BYTES = 256L * 1024
        const val REPORT_SECONDS_DEFAULT = 21_600L

        private val KEY_RE = Regex("^agent:[^\\u0000-\\u001f\\u007f]{1,154}$")
        private val ID_RE = Regex("^[a-z0-9][a-z0-9_-]{0,47}$")
        private val CODE_RE = Regex("^[a-z_]{1,48}$")
        private val DOMAIN_RE = Regex("^[A-Za-z0-9.-]{1,253}$")
        private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

        val PASSWORD_QUALITIES = listOf("unspecified", "something", "numeric", "numeric_complex", "alphabetic", "alphanumeric", "complex")
        val KEYGUARD_FEATURES = listOf("camera", "notifications", "unredacted_notifications", "trust_agents", "fingerprint")
        val BLOCK_KEYS = listOf("home", "recent", "back", "menu", "search")

        /** Device-administrator fields (shared AGENT_DPM_FIELDS): type, bounds, the value restored on undo. */
        class DpmSpec(val type: String, val min: Long = 0, val max: Long = 0, val values: List<String> = emptyList(), val undo: Any?, val checkOnly: Boolean = false)

        val DPM_FIELDS: Map<String, DpmSpec> = linkedMapOf(
            "cameraDisabled" to DpmSpec("bool", undo = false),
            "passwordQuality" to DpmSpec("enum", values = PASSWORD_QUALITIES, undo = "unspecified"),
            "passwordMinLength" to DpmSpec("int", 0, 16, undo = 0L),
            "passwordMinLetters" to DpmSpec("int", 0, 16, undo = 0L),
            "passwordMinNumeric" to DpmSpec("int", 0, 16, undo = 0L),
            "passwordMinSymbols" to DpmSpec("int", 0, 16, undo = 0L),
            "passwordHistoryLength" to DpmSpec("int", 0, 50, undo = 0L),
            "passwordExpirationDays" to DpmSpec("int", 0, 730, undo = 0L),
            "keyguardDisabledFeatures" to DpmSpec("flags", values = KEYGUARD_FEATURES, undo = emptyList<String>()),
            "maxTimeToLockSeconds" to DpmSpec("int", 0, 3600, undo = 0L),
            "maxFailedPasswordsForWipe" to DpmSpec("int", 0, 30, undo = 0L),
            "requireEncryption" to DpmSpec("bool", undo = null, checkOnly = true),
            "promptPasswordChange" to DpmSpec("bool", undo = null, checkOnly = true),
        )

        val KNOX_BOOLS = listOf(
            "camera", "microphone", "bluetooth", "nfc", "cellularData", "smsIncoming", "smsOutgoing", "mms", "tethering", "unknownSources",
            "clipboard", "screenCapture", "usbDebugging", "usbMediaPlayer", "mockLocation", "factoryReset", "airplaneMode", "safeMode",
            "statusBarExpansion", "settingsChanges", "multiWindow", "sdCard", "otaUpgrade", "wifiUserProfiles", "appUninstall",
        )
        val KNOX_LISTS = listOf("disabledApps", "uninstallBlocked")

        /** The value a Knox field gets back when its key leaves the policy: allowed, or an empty list. */
        fun knoxUndo(field: String): Any = if (field in KNOX_LISTS) emptyList<String>() else true

        /** An SSID: 1 to 32 UTF-8 bytes, no control character, no square bracket (shared isValidSsid). */
        fun isValidSsid(s: String?): Boolean {
            if (s.isNullOrEmpty()) return false
            if (s.toByteArray(Charsets.UTF_8).size > 32) return false
            return s.none { it < ' ' || it in '\u007f'..'\u009f' || it == '[' || it == ']' }
        }

        /** A PSK: 8 to 63 printable ASCII characters, or 64 hex digits. */
        fun isValidPsk(s: String?): Boolean =
            s != null && (HEX64.matches(s) || (s.length in 8..63 && s.all { it in ' '..'~' }))

        fun isKey(k: String?): Boolean = k != null && k.length <= 160 && KEY_RE.matches(k)

        /**
         * Reads the `policy` object of a configuration ([stored] false) or the stored form ([stored] true, its secrets
         * opened by [sealer]). Never throws.
         */
        fun parse(m: Map<String, Any?>, stored: Boolean = false, sealer: SecretSealer? = null): ParseResult = try {
            parseOrThrow(m, stored, sealer)
        } catch (e: RuntimeException) {
            ParseResult.Malformed
        }

        private fun parseOrThrow(m: Map<String, Any?>, stored: Boolean, sealer: SecretSealer?): ParseResult {
            val hash = m.str("hash")?.takeIf { Hex.isSha256(it) }
            val v = m.long("v")
            if (v != FORMAT.toLong()) return if (v != null || hash != null) ParseResult.Unsupported(hash) else ParseResult.Malformed
            if (hash == null) return ParseResult.Malformed
            val invalid = LinkedHashSet<String>()
            if (stored) m.list(INVALID).orEmpty().filterIsInstance<String>().forEach { invalid += it }
            var unkeyed = if (stored) m.int(INVALID_UNKEYED) ?: 0 else 0
            var missing = stored && m.bool(SECRETS_MISSING) == true

            /** Each object of [list] read by [read] (null: invalid); past [max], every further item is invalid. */
            fun <T> items(list: List<Any?>?, max: Int, prefix: String, read: (Map<String, Any?>, String, String) -> T?): List<T> {
                val out = ArrayList<T>()
                val seen = HashSet<String>()
                for ((i, raw) in list.orEmpty().withIndex()) {
                    @Suppress("UNCHECKED_CAST") val o = raw as? Map<String, Any?>
                    val key = o?.str("key")
                    if (!isKey(key) || !key!!.startsWith(prefix) || !seen.add(key)) { unkeyed++; continue }
                    val item = if (i >= max) null else try { read(o, key, digestOf(o, stored)) } catch (e: RuntimeException) { null }
                    if (item == null) invalid += key else out += item
                }
                return out
            }

            fun secret(v: Any?): String? {
                if (v == null) return null
                if (!stored) return v as? String
                @Suppress("UNCHECKED_CAST") val s = (v as? Map<String, Any?>)?.str(SEALED) ?: return null
                val open = sealer?.open(s)
                if (open == null) missing = true
                return open
            }

            val files = items(m.list("files"), MAX_FILES, "agent:file[") { o, key, digest -> readFile(o, key, digest) }
            val wifi = items(m.list("wifi"), MAX_WIFI, "agent:wifi[") { o, key, digest ->
                val ssid = o.str("ssid")?.takeIf { isValidSsid(it) && key == "agent:wifi[$it]" } ?: return@items null
                val security = o.str("security")?.takeIf { it == PSK || it == PEAP } ?: return@items null
                val prefer = o.list("preferOver").orEmpty()
                if (prefer.size > MAX_PREFER_OVER || prefer.any { it !is String || !isValidSsid(it) || it == ssid }) return@items null
                val priority = (o.long("priority") ?: 40L).takeIf { it in 0..100 }?.toInt() ?: return@items null
                var psk: String? = null
                var eap: Eap? = null
                if (security == PSK) {
                    psk = secret(o["psk"])
                    if (psk != null && !isValidPsk(psk)) return@items null
                    if (psk == null && !stored) return@items null
                } else {
                    val e = o.obj("eap") ?: return@items null
                    val identity = e.str("identity")?.takeIf { it.length in 1..128 && it.none { c -> c < ' ' } } ?: return@items null
                    val anon = optString(e, "anonymousIdentity", 128) ?: return@items null
                    val password = secret(e["password"])
                    if (password == null && !stored) return@items null
                    if (password != null && (password.isEmpty() || password.length > 128)) return@items null
                    if (e.str("phase2") != MSCHAPV2) return@items null
                    val ca = optString(e, "caPem", PEM_BYTES * 2) ?: return@items null
                    if (ca.value != null && !ca.value.contains("-----BEGIN CERTIFICATE-----")) return@items null
                    val domain = optString(e, "domainSuffixMatch", 253) ?: return@items null
                    if (domain.value != null && !DOMAIN_RE.matches(domain.value)) return@items null
                    val allowNoCa = e.bool("allowNoCa") ?: false
                    if (ca.value == null && !allowNoCa) return@items null
                    eap = Eap(identity, anon.value, password, ca.value, domain.value, allowNoCa)
                }
                Wifi(key, digest, ssid, security, o.bool("hidden") ?: false, priority, o.bool("autoConnect") ?: true,
                    prefer.filterIsInstance<String>(), psk, eap)
            }
            val wifiRemove = items(m.list("wifiRemove"), MAX_WIFI_REMOVE, "agent:wifi.remove[") { o, key, digest ->
                o.str("ssid")?.takeIf { isValidSsid(it) && key == "agent:wifi.remove[$it]" }?.let { WifiRemove(key, digest, it) }
            }
            val dpm = items(m.list("dpm"), DPM_FIELDS.size, "agent:dpm.") { o, key, digest ->
                val field = o.str("field")?.takeIf { key == "agent:dpm.$it" } ?: return@items null
                val spec = DPM_FIELDS[field] ?: return@items null
                dpmValue(spec, o["value"])?.let { Setting(key, digest, field, it) }
            }
            val knox = items(m.list("knox"), KNOX_BOOLS.size + KNOX_LISTS.size, "agent:knox.") { o, key, digest ->
                val field = o.str("field")?.takeIf { key == "agent:knox.$it" } ?: return@items null
                val value: Any? = when (field) {
                    in KNOX_BOOLS -> o.bool("value")
                    in KNOX_LISTS -> o.list("value")?.takeIf { l -> l.size <= MAX_KNOX_LIST && l.all { it is String && CommandParser.isPackageName(it) } }
                        ?.filterIsInstance<String>()
                    else -> null
                }
                value?.let { Setting(key, digest, field, it) }
            }
            val certs = items(m.list("certs"), MAX_CERTS, "agent:cert[") { o, key, digest ->
                val id = o.str("id")?.takeIf { ID_RE.matches(it) && key == "agent:cert[$it]" } ?: return@items null
                val name = o.str("name")?.takeIf { it.length in 1..200 && it.none { c -> c < ' ' } } ?: return@items null
                val pem = o.str("pem")?.takeIf { it.length <= PEM_BYTES * 2 && it.contains("-----BEGIN CERTIFICATE-----") } ?: return@items null
                Cert(key, digest, id, name, pem)
            }
            var kiosk: Kiosk? = null
            @Suppress("UNCHECKED_CAST") val k = m["kiosk"] as? Map<String, Any?>
            if (k != null) {
                val key = k.str("key")
                if (key != "agent:kiosk") unkeyed++
                else kiosk = try { readKiosk(k, key, digestOf(k, stored)) } catch (e: RuntimeException) { null }.also { if (it == null) invalid += key }
            }
            val blobs = m.list("blobs").orEmpty().filterIsInstance<String>().filter { Hex.isSha256(it) }.distinct()
            val dropped = m.list("dropped").orEmpty().mapNotNull { d ->
                @Suppress("UNCHECKED_CAST") val o = d as? Map<String, Any?> ?: return@mapNotNull null
                val key = o.str("key")?.takeIf { isKey(it) } ?: return@mapNotNull null
                val code = o.str("code")?.takeIf { CODE_RE.matches(it) } ?: PolicyCodes.INVALID_ITEM
                Dropped(key, code)
            }
            val undeliverable = m.list("undeliverable").orEmpty().filterIsInstance<String>().filter { isKey(it) }.distinct()
            val withheld = m.list("withheld").orEmpty().filterIsInstance<String>().filter { isKey(it) }.distinct()
            val report = (m.long("reportSeconds") ?: REPORT_SECONDS_DEFAULT).coerceIn(3_600L, 7 * 86_400L)
            return ParseResult.Ok(Policy(
                FORMAT, hash, report, files, wifi, wifiRemove, dpm, knox, certs, kiosk, blobs, dropped, undeliverable, withheld,
                invalid.toList(), unkeyed, missing,
            ))
        }

        /** The digest of an item: computed from the wire form (secrets in clear), kept as such in the stored form. */
        private fun digestOf(o: Map<String, Any?>, stored: Boolean): String =
            (if (stored) o.str(DIGEST)?.takeIf { Hex.isSha256(it) } else null) ?: Canon.sha256(o - DIGEST)

        private class Opt(val value: String?)

        /** Absent or null: Opt(null); a string of [max] characters at most without control character: Opt(it); else null. */
        private fun optString(o: Map<String, Any?>, key: String, max: Int): Opt? = when (val v = o[key]) {
            null -> Opt(null)
            is String -> if (v.length > max || v.any { it < ' ' && it != '\n' && it != '\r' }) null else Opt(v.ifEmpty { null })
            else -> null
        }

        private fun blobRef(o: Map<String, Any?>?, max: Long): BlobRef? {
            if (o == null) return null
            val sha = o.str("sha256")?.takeIf { Hex.isSha256(it) } ?: return null
            val size = o.long("size")?.takeIf { it in 1..max } ?: return null
            return BlobRef(sha, size)
        }

        private fun readFile(o: Map<String, Any?>, key: String, digest: String): FileItem? {
            val id = o.str("id")?.takeIf { ID_RE.matches(it) && key == "agent:file[$it]" } ?: return null
            val allowAppData = o.bool("allowAppDataDir") ?: false
            val paths = o.list("paths").orEmpty()
            if (paths.isEmpty() || paths.size > MAX_PATHS || paths.any { it !is String || !PathRules.isAllowed(it, allowAppData) }) return null
            val p = paths.filterIsInstance<String>()
            if (p.map { PathRules.key(it) }.toSet().size != p.size) return null
            val overwrite = (o.str("overwrite") ?: "always").takeIf { it == "always" || it == "if_absent" } ?: return null
            val onRemove = (o.str("onRemove") ?: "keep").takeIf { it == "keep" || it == "delete" } ?: return null
            val blob = blobRef(o.obj("blob"), STORE_FILE_BYTES)
            var inline: ByteArray? = null
            var inlineSha: String? = null
            o.obj("inline")?.let { i ->
                val bytes = i.str("b64")?.let { B64.decode(it) } ?: return null
                if (bytes.size > TEMPLATE_BYTES || i.long("size") != bytes.size.toLong()) return null
                inlineSha = i.str("sha256")?.takeIf { Hex.isSha256(it) } ?: return null
                inline = bytes
            }
            if ((blob == null) == (inline == null)) return null
            return FileItem(key, digest, id, p, allowAppData, overwrite, onRemove, o.bool("mediaScan") ?: true, blob, inline, inlineSha)
        }

        private fun dpmValue(spec: DpmSpec, v: Any?): Any? = when (spec.type) {
            "bool" -> v as? Boolean
            "int" -> (v as? Long ?: (v as? Int)?.toLong())?.takeIf { it in spec.min..spec.max }
            "enum" -> (v as? String)?.takeIf { it in spec.values }
            "flags" -> (v as? List<*>)?.takeIf { l -> l.all { it is String && it in spec.values } }?.filterIsInstance<String>()?.distinct()?.sorted()
            else -> null
        }

        private fun readKiosk(k: Map<String, Any?>, key: String, digest: String): Kiosk? {
            val enabled = k.bool("enabled") ?: return null
            val title = optString(k, "title", 60) ?: return null
            val deviceName = optString(k, "deviceName", 200) ?: return null
            val columns = (k.long("columns") ?: 3L).takeIf { it in 2..5 }?.toInt() ?: return null
            val logo = k.obj("logo")?.let { blobRef(it, IMAGE_BYTES) ?: return null }
            val rawTiles = k.list("tiles").orEmpty()
            if (rawTiles.size > MAX_TILES) return null
            val ids = HashSet<String>()
            val tiles = rawTiles.map { raw ->
                @Suppress("UNCHECKED_CAST") val t = raw as? Map<String, Any?> ?: return null
                val id = t.str("id")?.takeIf { ID_RE.matches(it) && ids.add(it) } ?: return null
                val label = t.str("label")?.takeIf { it.length in 1..40 && it.none { c -> c < ' ' || c == '\u007f' } } ?: return null
                val image = t.obj("image")?.let { blobRef(it, IMAGE_BYTES) ?: return null }
                val a = t.obj("action") ?: return null
                val type = a.str("type")?.takeIf { it == "app" || it == "url" || it == "intent" } ?: return null
                val action = TileAction(type, a.str("package"), a.str("url"), a.str("uri")?.let { KioskModel.normalizeIntentUri(it) ?: it })
                when (type) {
                    "app" -> if (action.pkg == null) return null
                    "url" -> if (action.url == null) return null
                    "intent" -> if (action.uri == null) return null
                }
                Tile(id, label, image, t.bool("launchOnStart") ?: false, action)
            }
            val pin = PinRecord.parse(k.obj("exitPin"))
            if (enabled && pin == null) return null
            val hard = k.obj("hard")?.let { h ->
                val keys = h.list("blockKeys").orEmpty()
                if (keys.any { it !is String || it !in BLOCK_KEYS }) return null
                Hard(h.bool("hideSystemBar") ?: false, h.bool("disableStatusBarExpansion") ?: false, h.bool("disableTaskManager") ?: false,
                    keys.filterIsInstance<String>().distinct(), h.bool("disableSettingsChanges") ?: false)
            }
            return Kiosk(key, digest, enabled, title.value, k.bool("showDeviceName") ?: false, deviceName.value, columns, logo, tiles, pin, hard)
        }
    }
}
