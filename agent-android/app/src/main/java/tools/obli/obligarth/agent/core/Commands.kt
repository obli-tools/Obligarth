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
    // Remote assistance (1.1.0, P0-15 §4.3, §0.1: nobody on the device answers, so neither user_declined, user_timeout
    // nor indicator_unavailable for a remote.open).
    const val PROJECTION_DENIED = "projection_denied"
    const val REMOTE_INJECTION_UNAVAILABLE = "remote_injection_unavailable"
    const val SESSION_GONE = "session_gone"
    const val AGENT_BUSY = "agent_busy"
    // app.pull (1.2.0): the APK of an installed app sent back to the server.
    const val PULLED = "pulled"
    const val NOT_INSTALLED = "not_installed"
    const val UPLOAD_FAILED = "upload_failed"
    // kiosk.suspend (1.3.0, lot PONT-POL): the kiosk left for some minutes, or no kiosk enabled to leave.
    const val KIOSK_SUSPENDED = "kiosk_suspended"
    const val KIOSK_INACTIVE = "kiosk_inactive"
}

/** Event types an interrogation carries (shared LEGACY_AGENT_EVENT_TYPES); the 1.3.0 ones go to a policy server only. */
object EventTypes {
    const val BOOT = "boot"
    const val ADMIN_ENABLED = "admin_enabled"
    const val ADMIN_DISABLED = "admin_disabled"
    const val ADMIN_DISABLE_REQUESTED = "admin_disable_requested"
    const val KNOX_LICENSE = "knox_license"
    const val CONFIG_IMPORTED = "config_imported"
    const val UPDATE_INSTALLED = "update_installed"
    const val CLOCK_CORRECTED = "clock_corrected"
    /** 1.3.0: the kiosk left, detail {via: pin|command, minutes}. */
    const val KIOSK_EXIT = "kiosk_exit"
    /** 1.3.0: the exit PIN locked out after failures, detail {failures}. */
    const val KIOSK_PIN_LOCKOUT = "kiosk_pin_lockout"
    /** 1.3.0: the undo of a revoked policy left unfinished, detail {done, left}. */
    const val POLICY_REVOKE_UNDO = "policy_revoke_undo"

    /** The events only a server that delivers policies knows (an older one would answer 400). */
    val POLICY_ONLY = setOf(KIOSK_EXIT, KIOSK_PIN_LOCKOUT, POLICY_REVOKE_UNDO)
}

/**
 * Item codes of the policy report (1.3.0, shared AGENT_POLICY_ITEM_CODES; T354 checks the parity). The server stores
 * any code of [a-z_]{1,48}, and the console shows an unknown one as is.
 */
object PolicyCodes {
    const val OK = "ok"
    const val UNCHANGED = "unchanged"
    const val APPLIED = "applied"
    const val UNDONE = "undone"
    const val FILE_WRITTEN = "file_written"
    const val FILE_UNCHANGED = "file_unchanged"
    const val FILE_PRESENT = "file_present"
    const val FILE_DELETED = "file_deleted"
    const val PERMISSION_MISSING = "permission_missing"
    const val PATH_FORBIDDEN = "path_forbidden"
    const val DOWNLOAD_FAILED = "download_failed"
    const val DOWNLOAD_LIMITED = "download_limited"
    const val HASH_MISMATCH = "hash_mismatch"
    const val STORAGE_UNAVAILABLE = "storage_unavailable"
    const val IO_ERROR = "io_error"
    const val WIFI_ADDED = "wifi_added"
    const val WIFI_UPDATED = "wifi_updated"
    const val WIFI_DISABLED = "wifi_disabled"
    const val WIFI_FOREIGN_PROFILE = "wifi_foreign_profile"
    const val WIFI_ADD_FAILED = "wifi_add_failed"
    const val WIFI_REMOVED = "wifi_removed"
    const val WIFI_PREFERRED = "wifi_preferred"
    const val ADMIN_INACTIVE = "admin_inactive"
    const val ADMIN_POLICY_MISSING = "admin_policy_missing"
    const val PASSWORD_INSUFFICIENT = "password_insufficient"
    const val ENCRYPTION_MISSING = "encryption_missing"
    const val KNOX_REQUIRED = "knox_required"
    const val KNOX_ERROR = "knox_error"
    const val KNOX_REFUSED = "knox_refused"
    const val KNOX_METHOD_MISSING = "knox_method_missing"
    const val BLOCKED_BY_ORDER = "blocked_by_order"
    const val HOME_NOT_DEFAULT = "home_not_default"
    const val KIOSK_FOREIGN_LOCKDOWN = "kiosk_foreign_lockdown"
    const val KIOSK_ACTIVE = "kiosk_active"
    const val KIOSK_SUSPENDED = "kiosk_suspended"
    const val KIOSK_DISABLED = "kiosk_disabled"
    const val IMAGE_UNREADABLE = "image_unreadable"
    const val APP_MISSING = "app_missing"
    const val INTENT_INVALID = "intent_invalid"
    const val CERT_INSTALLED = "cert_installed"
    const val POLICY_VERSION_UNSUPPORTED = "policy_version_unsupported"
    const val INVALID_ITEM = "invalid_item"
    const val UNDELIVERABLE = "undeliverable"
    const val INTERNAL = "internal"
    // Drops of the server's compilation (body.dropped), reported as error/<code>; wipe_withheld as pending.
    const val PATH_CONFLICT = "path_conflict"
    const val INLINE_TOO_LARGE = "inline_too_large"
    const val TEMPLATE_TOO_LARGE = "template_too_large"
    const val INVALID_JSON = "invalid_json"
    const val WIPE_WITHOUT_PASSWORD = "wipe_without_password"
    const val FOREIGN_TENANT_RESOURCE = "foreign_tenant_resource"
    const val WIPE_WITHHELD = "wipe_withheld"
}

/** States of a report item and of a whole report (shared AGENT_POLICY_ITEM_STATES, AGENT_POLICY_REPORT_STATES). */
object PolicyStates {
    const val COMPLIANT = "compliant"
    const val NON_COMPLIANT = "non_compliant"
    const val PENDING = "pending"
    const val PENDING_LICENCE = "pending_licence"
    const val UNSUPPORTED = "unsupported"
    const val ERROR = "error"
    val ITEM = listOf(COMPLIANT, NON_COMPLIANT, PENDING, PENDING_LICENCE, UNSUPPORTED, ERROR)
    val REPORT = listOf("applied", "partial", "pending", "error", "none")
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
    AGENT_UPDATE("agent.update", false),
    /** 1.1.0 (P0-15 §4.3, §0.1): a remote assistance session, opened at once and told to the user. */
    REMOTE_OPEN("remote.open", true),
    /** 1.2.0: the APK of an installed app sent back by chunks (POST /agent/v1/pull/<id>), in the install queue. */
    APP_PULL("app.pull", false),
    /** 1.3.0 (lot PONT-POL): the kiosk of the policy left for 1 to 240 minutes. */
    KIOSK_SUSPEND("kiosk.suspend", true),
    /** 1.3.0: the policy ledger forgotten, a full configuration asked, everything reconciled and reported again. */
    POLICY_REAPPLY("policy.reapply", true);

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
    data class Pull(val packageName: String) : Params()
    data class AgentUpdate(val releaseId: String, val versionCode: Long, val sha256: String, val size: Long) : Params()
    /**
     * remote.open (§4.3): operator and operatorOrg are filled by the server (shown to the user in the notifications);
     * controllerName and the operator's reason are optional since §0.1 (null when absent or blank) and not shown. No
     * secret ever travels here.
     */
    data class RemoteOpen(
        val sessionId: String, val mode: RemoteMode, val operator: String, val operatorOrg: String,
        val controllerName: String?, val reason: String?, val maxMinutes: Int,
    ) : Params()
    /** kiosk.suspend (1.3.0): 1 to 240 minutes. */
    data class KioskSuspend(val minutes: Int) : Params()
    /** policy.reapply (1.3.0): no parameter. */
    object PolicyReapply : Params()
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
        CommandType.APP_PULL -> p.str("packageName")?.takeIf { isPackageName(it) }?.let { Params.Pull(it) }
        CommandType.AGENT_UPDATE -> {
            val releaseId = p.str("releaseId")
            val vc = p.long("versionCode")
            val sha = sha(p, "sha256")
            val size = p.long("size")
            if (releaseId == null || !Uuids.isLower(releaseId) || vc == null || vc < 1 || sha == null || size == null ||
                size !in 1..MAX_APK_SIZE
            ) null else Params.AgentUpdate(releaseId, vc, sha, size)
        }
        CommandType.REMOTE_OPEN -> {
            val sessionId = p.str("sessionId")?.takeIf { Uuids.isLower(it) }
            val mode = RemoteMode.of(p.str("mode"))
            val operator = text(p, "operator", 1, 80)
            val org = text(p, "operatorOrg", 1, 120)
            val controller = optionalText(p, "controllerName", 200)
            val reason = optionalText(p, "reason", 200)
            val minutes = p.int("maxMinutes")?.takeIf { it in 15..240 }
            if (sessionId == null || mode == null || operator == null || org == null || controller == null || reason == null || minutes == null) null
            else Params.RemoteOpen(sessionId, mode, operator, org, controller.value, reason.value, minutes)
        }
        CommandType.KIOSK_SUSPEND -> p.int("minutes")?.takeIf { it in 1..MAX_SUSPEND_MINUTES }?.let { Params.KioskSuspend(it) }
        CommandType.POLICY_REAPPLY -> Params.PolicyReapply
    }

    /** kiosk.suspend: the longest suspension (shared suspendMinutesMax). */
    const val MAX_SUSPEND_MINUTES = 240

    /**
     * A non-blank string of [min]..[max] UTF-16 units (zod's count, the server's bounds: one value refused here would
     * end the session in bad_params). Control and direction characters are neutralised where it is shown (T7b).
     */
    private fun text(p: Map<String, Any?>, key: String, min: Int, max: Int): String? =
        p.str(key)?.takeIf { it.length in min..max && it.isNotBlank() }

    /** An optional field read: [value] null when absent, null or blank. */
    private class OptionalText(val value: String?)

    /**
     * An optional string of at most [max] UTF-16 units: absent, null or blank is an [OptionalText] of null; another
     * type or a longer string is null (bad_params).
     */
    private fun optionalText(p: Map<String, Any?>, key: String, max: Int): OptionalText? = when (val v = p[key]) {
        null -> OptionalText(null)
        is String -> if (v.length > max) null else OptionalText(v.takeIf { it.isNotBlank() })
        else -> null
    }
}
