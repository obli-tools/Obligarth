package tools.obli.obligarth.agent.core

/** Result codes (spec §5.3). */
object Codes {
    const val DONE = "done"
    const val WIPE_STARTED = "wipe_started"
    const val REBOOT_STARTED = "reboot_started"
    const val LOCK_DONE = "lock_done"
    const val INSTALLED = "installed"
    const val UNINSTALLED = "uninstalled"
    const val UPDATE_INSTALLED = "update_installed"
    const val MESSAGE_SHOWN = "message_shown"
    const val ADMIN_INACTIVE = "admin_inactive"
    const val KNOX_REQUIRED = "knox_required"
    const val KNOX_ERROR = "knox_error"
    const val DOWNLOAD_FAILED = "download_failed"
    const val HASH_MISMATCH = "hash_mismatch"
    const val SIGNER_MISMATCH = "signer_mismatch"
    const val PACKAGE_MISMATCH = "package_mismatch"
    const val VERSION_NOT_HIGHER = "version_not_higher"
    const val INSTALL_FAILED = "install_failed"
    const val USER_DECLINED = "user_declined"
    const val USER_TIMEOUT = "user_timeout"
    const val FORBIDDEN_PACKAGE = "forbidden_package"
    const val UNSUPPORTED = "unsupported"
    const val EXPIRED_ON_DEVICE = "expired_on_device"
    const val BAD_PARAMS = "bad_params"
    const val INTERNAL = "internal"
}

/** Result status of the contract (§4.5). */
enum class ResultStatus(val wire: String) { ACKNOWLEDGED("acknowledged"), ERROR("error"), REJECTED("rejected") }

data class CommandResult(
    val commandId: String,
    val status: ResultStatus,
    val code: String,
    val detail: Map<String, Any?> = emptyMap(),
    val at: Long,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "commandId" to commandId, "status" to status.wire, "code" to code, "detail" to boundedDetail(detail), "at" to at,
    )

    companion object {
        /** detail is 2 KiB at most (§4.5): truncated to a marker past that. */
        fun boundedDetail(detail: Map<String, Any?>): Map<String, Any?> =
            if (Json.bytes(detail).size <= 2048) detail else mapOf("truncated" to true)

        fun fromJson(m: Map<String, Any?>): CommandResult? {
            val id = m.str("commandId") ?: return null
            val status = ResultStatus.values().firstOrNull { it.wire == m.str("status") } ?: return null
            return CommandResult(id, status, m.str("code") ?: return null, m.obj("detail") ?: emptyMap(), m.long("at") ?: 0)
        }
    }
}

/** Command types of the v0 catalogue (§5.1). agent.retire left v0 (§15.4): unsupported. */
enum class CommandType(val wire: String, val immediate: Boolean) {
    INVENTORY_REFRESH("inventory.refresh", true),
    DEVICE_MESSAGE("device.message", true),
    DEVICE_LOCK("device.lock", true),
    DEVICE_WIPE("device.wipe", true),
    DEVICE_REBOOT("device.reboot", true),
    APP_INSTALL("app.install", false),
    APP_UNINSTALL("app.uninstall", false),
    AGENT_UPDATE("agent.update", false);

    companion object {
        fun of(wire: String?): CommandType? = values().firstOrNull { it.wire == wire }
    }
}

/** Validated parameters, one class per type. */
sealed class Params {
    object None : Params()
    data class Message(val title: String, val text: String, val fullscreen: Boolean) : Params()
    data class Wipe(val wipeExternal: Boolean) : Params()
    data class Install(
        val packageId: String, val packageName: String, val versionCode: Long,
        val sha256: String, val size: Long, val signerSha256: String?,
    ) : Params()
    data class Uninstall(val packageName: String) : Params()
    data class AgentUpdate(val releaseId: String, val versionCode: Long, val sha256: String, val size: Long) : Params()
}

data class Command(
    val id: String,
    val type: CommandType,
    val params: Params,
    val issuedAt: Long,
    val expiresAt: Long,
    /** The raw JSON as received, kept in the install queue. */
    val raw: Map<String, Any?>,
)

sealed class ParsedCommand {
    data class Ok(val command: Command) : ParsedCommand()
    /** Refused with a result to send back (unsupported type, bad params). */
    data class Refused(val id: String, val code: String) : ParsedCommand()
    /** Not even an id: dropped (nothing to answer to). */
    object Dropped : ParsedCommand()
}

object CommandParser {
    private val PACKAGE_RE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
    const val MAX_APK_SIZE = 104_857_600L

    fun parse(m: Any?): ParsedCommand {
        if (m !is Map<*, *>) return ParsedCommand.Dropped
        @Suppress("UNCHECKED_CAST")
        val o = m as Map<String, Any?>
        val id = o.str("id")?.takeIf { Uuids.isLower(it) } ?: return ParsedCommand.Dropped
        val type = CommandType.of(o.str("type")) ?: return ParsedCommand.Refused(id, Codes.UNSUPPORTED)
        val issuedAt = o.long("issuedAt") ?: return ParsedCommand.Refused(id, Codes.BAD_PARAMS)
        val expiresAt = o.long("expiresAt") ?: return ParsedCommand.Refused(id, Codes.BAD_PARAMS)
        val p = o["params"] as? Map<*, *> ?: return ParsedCommand.Refused(id, Codes.BAD_PARAMS)
        @Suppress("UNCHECKED_CAST")
        val params = parseParams(type, p as Map<String, Any?>) ?: return ParsedCommand.Refused(id, Codes.BAD_PARAMS)
        return ParsedCommand.Ok(Command(id, type, params, issuedAt, expiresAt, o))
    }

    fun isPackageName(s: String?): Boolean = s != null && s.length <= 255 && PACKAGE_RE.matches(s)

    private fun sha(p: Map<String, Any?>, key: String): String? = p.str(key)?.takeIf { Hex.isSha256(it) }

    private fun parseParams(type: CommandType, p: Map<String, Any?>): Params? = when (type) {
        CommandType.INVENTORY_REFRESH, CommandType.DEVICE_LOCK, CommandType.DEVICE_REBOOT -> Params.None
        CommandType.DEVICE_MESSAGE -> {
            val title = p.str("title")
            val text = p.str("text")
            val mode = p.str("mode")
            if (title == null || text == null || title.length > 80 || text.length > 500 || text.isEmpty()) null
            else when (mode) {
                "notification" -> Params.Message(title, text, false)
                "fullscreen" -> Params.Message(title, text, true)
                else -> null
            }
        }
        CommandType.DEVICE_WIPE -> when (val w = p["wipeExternal"]) {
            null -> Params.Wipe(false)
            is Boolean -> Params.Wipe(w)
            else -> null
        }
        CommandType.APP_INSTALL -> {
            val packageId = p.str("packageId")
            val name = p.str("packageName")
            val vc = p.long("versionCode")
            val sha = sha(p, "sha256")
            val size = p.long("size")
            val signerRaw = p["signerSha256"]
            val signer = sha(p, "signerSha256")
            if (packageId == null || !Uuids.isLower(packageId) || !isPackageName(name) || vc == null || vc < 1 ||
                sha == null || size == null || size !in 1..MAX_APK_SIZE || (signerRaw != null && signer == null)
            ) null else Params.Install(packageId, name!!, vc, sha, size, signer)
        }
        CommandType.APP_UNINSTALL -> p.str("packageName")?.takeIf { isPackageName(it) }?.let { Params.Uninstall(it) }
        CommandType.AGENT_UPDATE -> {
            val releaseId = p.str("releaseId")
            val vc = p.long("versionCode")
            val sha = sha(p, "sha256")
            val size = p.long("size")
            if (releaseId == null || !Uuids.isLower(releaseId) || vc == null || vc < 1 || sha == null || size == null ||
                size !in 1..MAX_APK_SIZE
            ) null else Params.AgentUpdate(releaseId, vc, sha, size)
        }
    }
}
