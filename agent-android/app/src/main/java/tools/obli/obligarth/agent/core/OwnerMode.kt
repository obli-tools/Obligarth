package tools.obli.obligarth.agent.core

/** The role of the agent on its device (1.4.0, lot BANC §7.2): owner of the device, administrator, or neither. */
enum class AgentRole(val wire: String) {
    NONE("NONE"),
    ADMIN("ADMIN"),
    OWNER("OWNER"),
}

/** What the agent can do on its own, by role and API level (§7.2, §7.3). */
enum class Capability {
    /** PackageInstaller sessions committed without a prompt (device owner). */
    SILENT_INSTALL,
    /** A restart without Knox (DevicePolicyManager.reboot, API 24) or through Knox. */
    REBOOT,
    /** Lock task mode (setLockTaskPackages, API 21; its features from API 28). */
    LOCK_TASK,
    /** addUserRestriction (device owner). */
    USER_RESTRICTIONS,
    /** setPermissionGrantState (API 23). */
    PERMISSION_GRANT,
    /** installCaCert (device owner) or Knox CertificateProvisioning. */
    CA_INSTALL,
    /** setSystemUpdatePolicy (API 23). */
    SYSTEM_UPDATE_POLICY,
    /** Changing or removing the Wi-Fi networks other apps created (device owner, API 23). */
    WIFI_ANY_NETWORK,
    /** Giving the device back (clearDeviceOwnerApp). */
    RELEASE,
}

/** How an app is installed (§7.3): silently by the owner, through Knox, or by the system prompt. */
enum class InstallPath { OWNER_SESSION, KNOX, PROMPT }

/** The install path chosen, and why the Knox one was left out (knox_restricted, written to the local log only). */
data class InstallPlan(val path: InstallPath, val note: String? = null)

/**
 * The pure rules of the owner role (1.4.0, lot BANC §7.2, §7.3, §7.6): no Android import, every branch tested
 * (T380, T384). The Android side reads the role (DevicePolicyManager.isDeviceOwnerApp) and asks here what it allows.
 */
object OwnerMode {
    /** The feature of the server (config.features) that lets the agent send status.deviceOwner, adbEnabled and the
     *  device_owner_* events (§3.4). */
    const val FEATURE_DEVICE_OWNER_V1 = "device_owner_v1"
    /** Knox 3.11 (Android 15, API 35) refuses its restricted methods to a device administrator (§0.1, §7.6). */
    const val KNOX_RESTRICTED_SDK = 35
    /** The note of an install that skipped Knox for this reason. */
    const val KNOX_RESTRICTED = "knox_restricted"

    fun roleOf(adminActive: Boolean, deviceOwner: Boolean): AgentRole = when {
        deviceOwner -> AgentRole.OWNER
        adminActive -> AgentRole.ADMIN
        else -> AgentRole.NONE
    }

    /**
     * Knox restricted methods (ApplicationPolicy installs, setAdminRemovable, the firewall) are refused to an
     * administrator from Android 15: never tried there (§7.6).
     */
    fun knoxRestricted(role: AgentRole, sdk: Int): Boolean = role != AgentRole.OWNER && sdk >= KNOX_RESTRICTED_SDK

    fun capabilitiesFor(role: AgentRole, sdk: Int, knoxLicensed: Boolean): Set<Capability> {
        val out = LinkedHashSet<Capability>()
        val owner = role == AgentRole.OWNER
        val knox = knoxLicensed && role != AgentRole.NONE
        if (owner) {
            out += Capability.SILENT_INSTALL
            out += Capability.LOCK_TASK
            out += Capability.USER_RESTRICTIONS
            out += Capability.CA_INSTALL
            out += Capability.RELEASE
            if (sdk >= 23) {
                out += Capability.PERMISSION_GRANT
                out += Capability.SYSTEM_UPDATE_POLICY
                out += Capability.WIFI_ANY_NETWORK
            }
            if (sdk >= 24) out += Capability.REBOOT
        }
        if (knox) {
            // ApplicationPolicy is among the methods Knox 3.11 refuses to an administrator (§0.1): not counted there.
            if (!knoxRestricted(role, sdk)) out += Capability.SILENT_INSTALL
            out += Capability.REBOOT
            out += Capability.CA_INSTALL
        }
        return out
    }

    /**
     * §7.3: the owner installs silently through a PackageInstaller session; otherwise Knox when licensed and allowed for
     * the role (never an administrator on Android 15+: knox_restricted, written locally); otherwise the system prompt
     * (the behaviour of 1.3.0).
     */
    fun installPath(role: AgentRole, sdk: Int, knoxLicensed: Boolean): InstallPlan = when {
        role == AgentRole.OWNER -> InstallPlan(InstallPath.OWNER_SESSION)
        knoxLicensed && knoxRestricted(role, sdk) -> InstallPlan(InstallPath.PROMPT, KNOX_RESTRICTED)
        knoxLicensed -> InstallPlan(InstallPath.KNOX)
        else -> InstallPlan(InstallPath.PROMPT)
    }

    /** §3.8: a restart is possible with the Knox licence, or as the owner (API 24). */
    fun canReboot(role: AgentRole, sdk: Int, knoxLicensed: Boolean): Boolean = Capability.REBOOT in capabilitiesFor(role, sdk, knoxLicensed)
}

/**
 * The events of a change of the owner role (§3.4, §7.2), sent only to a server announcing device_owner_v1 (T389).
 * [previousOwner] null: unknown (the first cycle after an update from 1.3.0).
 */
object RoleTransitions {
    fun events(previousOwner: Boolean?, nowOwner: Boolean, releasing: Boolean): List<String> = when {
        nowOwner && previousOwner != true -> listOf(EventTypes.DEVICE_OWNER_GAINED)
        !nowOwner && previousOwner == true -> listOf(if (releasing) EventTypes.DEVICE_OWNER_RELEASED else EventTypes.DEVICE_OWNER_LOST)
        else -> emptyList()
    }
}

/**
 * The diagnostic line of the bench (§7.4): `phase=<…> role=<…> last=<code>` under the tag ObligarthBench, read by the
 * station (`logcat -d -s ObligarthBench:I`) when `content call` is unavailable. Codes only: never a token, a
 * configuration, a URL or a hardware identifier (T388).
 */
object BenchLog {
    const val TAG = "ObligarthBench"
    private val CODE_RE = Regex("^[a-z0-9_]{1,48}$")

    /** A status code as the bench may read it: lower case letters, digits and underscores, else "other". */
    fun code(raw: String?): String {
        if (raw == null) return "none"
        val c = raw.trim().lowercase()
        return if (CODE_RE.matches(c)) c else "other"
    }

    fun line(phase: Phase, role: AgentRole, last: String?): String = "phase=${phase.name} role=${role.wire} last=${code(last)}"
}

/** The rules of the bench channel (BenchProvider, §7.4, §7.5). */
object BenchRules {
    const val SHELL_UID = 2000
    const val ROOT_UID = 0
    /** prepare_owner: the Knox lock of the administrator is not set again for this long (§6.5). */
    const val WINDOW_S = 30 * 60L
    /** poll: one cycle every 10 s at most (§7.4). */
    const val POLL_MIN_S = 10L
    /** The configuration source of the bench: the only one an owner not yet enrolled accepts (§7.1). */
    const val SOURCE = "bench"

    /** Only the shell (adb) or root may call the channel (§7.1): an app never does, whatever permission it holds. */
    fun callerAllowed(uid: Int): Boolean = uid == SHELL_UID || uid == ROOT_UID

    /** prepare_owner (§6.5): before the enrollment always; an enrolled agent only while the server allows a conversion. */
    fun windowAllowed(phase: Phase, serverAllows: Boolean): Boolean = phase != Phase.ENROLLED || serverAllows

    /** The bench gives the device back only before the enrollment; an enrolled device is released by the server only. */
    fun releaseAllowed(phase: Phase): Boolean = phase == Phase.NEW || phase == Phase.CONFIGURED || phase == Phase.TOKEN_REJECTED

    /** §7.1: an owner of the device not enrolled takes a configuration from the bench channel only. */
    fun configSourceAllowed(source: String, deviceOwner: Boolean, phase: Phase): Boolean =
        source == SOURCE || !deviceOwner || phase == Phase.ENROLLED
}
