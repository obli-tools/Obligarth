package tools.obli.obligarth.agent.core

import java.net.URI

/** What the build compiles in (spec PB11, §4.9, RC-2). */
class TrustPolicy(
    allowedHosts: Collection<String>,
    serverKeyPins: Collection<String>,
    /** true in release: the configuration must carry serverKeySha256, and it must be one of [serverKeyPins]. */
    val requireServerKeyPin: Boolean,
) {
    val allowedHosts: Set<String> = allowedHosts.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
    val serverKeyPins: Set<String> = serverKeyPins.map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()

    companion object {
        fun fromBuild(hosts: String, pins: String, require: Boolean) =
            TrustPolicy(hosts.split(','), pins.split(','), require)
    }
}

/** The configuration dropped by MobiControl (spec §4.9), validated. */
data class AgentConfig(
    /** https://host[:port], without trailing slash. */
    val serverBase: String,
    val host: String,
    val token: String,
    val serverKeySha256: String?,
    val knoxLicenseKey: String?,
    val hints: Map<String, Any?>,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "v" to 1, "server" to serverBase, "token" to token, "serverKeySha256" to serverKeySha256,
        "knoxLicenseKey" to knoxLicenseKey, "hints" to hints,
    )

    companion object {
        val TOKEN_RE = Regex("^OLE1\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}$")
        private const val MAX_CONFIG_CHARS = 16 * 1024

        /**
         * Reads a configuration given as the base64url extra (intent), as raw JSON
         * (file) or either one typed by hand. Never throws.
         */
        fun parse(input: String?, policy: TrustPolicy): ConfigResult {
            if (input.isNullOrBlank()) return ConfigResult.Invalid("empty")
            val trimmed = input.trim()
            if (trimmed.length > MAX_CONFIG_CHARS) return ConfigResult.Invalid("too_large")
            val jsonText = if (trimmed.startsWith("{")) trimmed else {
                val bytes = B64.decode(trimmed) ?: return ConfigResult.Invalid("not_base64url")
                String(bytes, Charsets.UTF_8)
            }
            val root = Json.parseObjectOrNull(jsonText) ?: return ConfigResult.Invalid("not_json")
            return validate(root, policy)
        }

        fun validate(root: Map<String, Any?>, policy: TrustPolicy): ConfigResult {
            if (root.long("v") != 1L) return ConfigResult.Invalid("bad_version")
            val server = root.str("server") ?: return ConfigResult.Invalid("server_missing")
            val uri = try { URI(server) } catch (e: Exception) { return ConfigResult.Invalid("server_malformed") }
            if (uri.scheme?.lowercase() != "https") return ConfigResult.Invalid("server_not_https")
            if (uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) return ConfigResult.Invalid("server_malformed")
            val path = uri.rawPath ?: ""
            if (path.isNotEmpty() && path != "/") return ConfigResult.Invalid("server_malformed")
            val host = uri.host?.lowercase() ?: return ConfigResult.Invalid("server_malformed")
            if (host !in policy.allowedHosts) return ConfigResult.Invalid("host_not_allowed")
            val port = uri.port
            if (port != -1 && port !in 1..65535) return ConfigResult.Invalid("server_malformed")
            val base = "https://" + host + (if (port == -1 || port == 443) "" else ":$port")

            val token = root.str("token") ?: return ConfigResult.Invalid("token_missing")
            if (!TOKEN_RE.matches(token)) return ConfigResult.Invalid("token_malformed")

            val pinRaw = root["serverKeySha256"]
            val pin = when (pinRaw) {
                null -> null
                is String -> pinRaw.lowercase().takeIf { Hex.isSha256(it) } ?: return ConfigResult.Invalid("server_key_malformed")
                else -> return ConfigResult.Invalid("server_key_malformed")
            }
            if (policy.requireServerKeyPin) {
                if (pin == null) return ConfigResult.Invalid("server_key_required")
                if (pin !in policy.serverKeyPins) return ConfigResult.Invalid("server_key_not_pinned")
            } else if (pin != null && policy.serverKeyPins.isNotEmpty() && pin !in policy.serverKeyPins) {
                return ConfigResult.Invalid("server_key_not_pinned")
            }

            val knox = when (val k = root["knoxLicenseKey"]) {
                null -> null
                is String -> k.takeIf { it.isNotBlank() && it.length <= 256 } ?: return ConfigResult.Invalid("knox_key_malformed")
                else -> return ConfigResult.Invalid("knox_key_malformed")
            }
            val hints = LinkedHashMap<String, Any?>()
            root.obj("hints")?.let { h ->
                for (name in listOf("deviceName", "serial", "imei")) {
                    val v = h[name] as? String
                    // MobiControl leaves an unexpanded macro (%DEVICENAME%) when it lacks one.
                    hints[name] = v?.trim()?.takeIf { it.isNotEmpty() && it.length <= 100 && !(it.startsWith("%") && it.endsWith("%")) }
                }
            }
            return ConfigResult.Valid(AgentConfig(base, host, token, pin, knox, hints))
        }
    }
}

sealed class ConfigResult {
    data class Valid(val config: AgentConfig) : ConfigResult()
    data class Invalid(val reason: String) : ConfigResult()
}
