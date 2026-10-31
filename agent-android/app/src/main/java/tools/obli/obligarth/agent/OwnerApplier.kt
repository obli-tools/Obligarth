package tools.obli.obligarth.agent

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.app.admin.SystemUpdatePolicy
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.KnoxLicence
import tools.obli.obligarth.agent.core.Policy
import tools.obli.obligarth.agent.core.PolicyCodes
import tools.obli.obligarth.agent.core.ReleaseHost
import java.security.cert.CertificateFactory

/**
 * The owner of the device (1.4.0, lot BANC §7.3, §7.5): what the agent does once `dpm set-device-owner` made it the
 * owner. Every call is guarded by isDeviceOwnerApp and the API level; a SecurityException is reported (never thrown
 * through a cycle). Nothing here runs for an administrator: the branches of 1.3.0 stay as they were.
 */
class OwnerApplier(
    private val context: Context,
    private val facts: AndroidFacts,
    private val knox: KnoxBridge,
    private val kiosk: KioskController,
    private val wifi: WifiApplier,
    private val log: AgentLog,
) : ReleaseHost {
    private val dpm get() = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val admin get() = facts.adminComponent()
    private val sdk = Build.VERSION.SDK_INT

    override fun isDeviceOwner(): Boolean = facts.deviceOwner()
    override fun adminActive(): Boolean = facts.adminActive()
    override fun knoxLicensed(): Boolean = knox.state() == KnoxLicence.LICENSED

    // ---- Protections and the agent's own permissions (§7.3) ----

    /**
     * Run at each cycle while the agent owns the device: its uninstall blocked, its runtime permissions granted (D1 of
     * PONT-POL without a tap), the Knox lock of the administrator lifted (useless for an owner, and in the way of a
     * future release, §7.3).
     */
    fun upkeep() {
        if (!isDeviceOwner()) return
        try {
            if (!dpm.isUninstallBlocked(admin, context.packageName)) dpm.setUninstallBlocked(admin, context.packageName, true)
        } catch (e: Exception) {
            log.warn("owner: uninstall block (${e.javaClass.simpleName})")
        }
        grantOwnPermissions()
        if (knoxLicensed() && !knox.adminRemovable()) {
            if (knox.setAdminRemovable(true)) log.info("owner: Knox lock of the administrator lifted")
        }
    }

    private fun grantOwnPermissions() {
        val wanted = buildList {
            add(Manifest.permission.READ_PHONE_STATE)
            add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            add(Manifest.permission.READ_EXTERNAL_STORAGE)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            if (sdk >= 33) add(POST_NOTIFICATIONS)
        }
        for (p in wanted) {
            if (context.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED) continue
            try {
                val ok = dpm.setPermissionGrantState(admin, context.packageName, p, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
                log.info("owner: ${p.substringAfterLast('.')} ${if (ok) "granted" else "not granted"}")
            } catch (e: Exception) {
                log.warn("owner: grant ${p.substringAfterLast('.')} (${e.javaClass.simpleName})")
            }
        }
    }

    // ---- Restart (§3.8) ----

    fun reboot(): Boolean = try {
        if (!isDeviceOwner() || sdk < 24) false else { dpm.reboot(admin); true }
    } catch (e: Exception) {
        log.warn("owner reboot: ${e.javaClass.simpleName}")
        false
    }

    // ---- Policy items of the owner (§7.3) ----

    private inline fun owned(minSdk: Int, block: () -> ItemOutcome): ItemOutcome = when {
        !isDeviceOwner() -> ItemOutcome.pending(PolicyCodes.PENDING_OWNER)
        sdk < minSdk -> ItemOutcome.unsupported(PolicyCodes.UNSUPPORTED_API)
        else -> try {
            block()
        } catch (e: SecurityException) {
            ItemOutcome.error(PolicyCodes.INTERNAL, "SecurityException")
        }
    }

    fun restrictionRead(field: String): Boolean? {
        val spec = Policy.OWNER_FIELDS[field] ?: return null
        if (!isDeviceOwner() || sdk < spec.minSdk) return null
        return try { dpm.getUserRestrictions(admin).getBoolean(spec.restriction, false) } catch (e: Exception) { null }
    }

    fun restrictionApply(field: String, on: Boolean): ItemOutcome {
        val spec = Policy.OWNER_FIELDS[field] ?: return ItemOutcome.error(PolicyCodes.INVALID_ITEM)
        return owned(spec.minSdk) {
            if (on) dpm.addUserRestriction(admin, spec.restriction) else dpm.clearUserRestriction(admin, spec.restriction)
            log.info("owner restriction $field ${if (on) "set" else "cleared"}")
            ItemOutcome.compliant(PolicyCodes.APPLIED)
        }
    }

    fun permissionGrant(pkg: String, permission: String, state: String): ItemOutcome = owned(23) {
        val target = try { context.packageManager.getApplicationInfo(pkg, 0) } catch (e: PackageManager.NameNotFoundException) { null }
        when {
            target == null -> ItemOutcome.pending(PolicyCodes.APP_MISSING, pkg)
            // An app targeting an API below 23 holds its permissions from the install: the grant state does nothing.
            target.targetSdkVersion < 23 -> ItemOutcome.unsupported(PolicyCodes.NOT_APPLICABLE)
            else -> {
                val value = when (state) {
                    "granted" -> DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
                    "denied" -> DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED
                    else -> DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT
                }
                if (dpm.setPermissionGrantState(admin, pkg, permission, value)) ItemOutcome.compliant(PolicyCodes.APPLIED)
                else ItemOutcome.error(PolicyCodes.INTERNAL, "grant_refused")
            }
        }
    }

    fun systemUpdate(u: Policy.SystemUpdate?): ItemOutcome = owned(23) {
        val p = when (u?.type) {
            null -> null
            "automatic" -> SystemUpdatePolicy.createAutomaticInstallPolicy()
            "windowed" -> SystemUpdatePolicy.createWindowedInstallPolicy(u.windowStartMin, u.windowEndMin)
            else -> SystemUpdatePolicy.createPostponeInstallPolicy()
        }
        dpm.setSystemUpdatePolicy(admin, p)
        ItemOutcome.compliant(if (u == null) PolicyCodes.UNDONE else PolicyCodes.APPLIED)
    }

    private fun der(pem: String): ByteArray? = try {
        CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()).encoded
    } catch (e: Exception) {
        null
    }

    fun certInstall(pem: String): ItemOutcome = owned(21) {
        val bytes = der(pem) ?: return@owned ItemOutcome.error(PolicyCodes.INVALID_ITEM, "pem")
        if (dpm.installCaCert(admin, bytes)) ItemOutcome.compliant(PolicyCodes.CERT_INSTALLED) else ItemOutcome.error(PolicyCodes.INTERNAL, "ca_refused")
    }

    fun certRemove(pem: String): ItemOutcome = owned(21) {
        der(pem)?.let { dpm.uninstallCaCert(admin, it) }
        ItemOutcome.compliant(PolicyCodes.UNDONE)
    }

    fun wifiRemove(ssid: String): ItemOutcome = owned(23) { wifi.removeAny(ssid) }

    // ---- Release (§7.5, OwnerRelease decides the order) ----

    override fun kioskOff(): Boolean = kiosk.ownerRelease()

    override fun clearUserRestrictions(): Boolean {
        var ok = true
        for (spec in Policy.OWNER_FIELDS.values) {
            if (sdk < spec.minSdk) continue
            try { dpm.clearUserRestriction(admin, spec.restriction) } catch (e: Exception) { ok = false }
        }
        return ok
    }

    override fun setUninstallBlocked(blocked: Boolean): Boolean = try {
        dpm.setUninstallBlocked(admin, context.packageName, blocked)
        true
    } catch (e: Exception) {
        false
    }

    override fun knoxSetAdminRemovable(removable: Boolean): Boolean = knox.setAdminRemovable(removable)

    @Suppress("DEPRECATION") // clearDeviceOwnerApp: deprecated in API 26, still the way for the owner to step down
    override fun clearDeviceOwner(): Boolean = try {
        dpm.clearDeviceOwnerApp(context.packageName)
        true
    } catch (e: Exception) {
        log.warn("owner: clearDeviceOwnerApp (${e.javaClass.simpleName})")
        false
    }

    override fun removeActiveAdmin(): Boolean = try {
        if (facts.adminActive()) {
            dpm.removeActiveAdmin(admin)
            // The removal is asynchronous: the read back that follows waits for it a little.
            var waited = 0
            while (facts.adminActive() && waited < 3_000) { Thread.sleep(100); waited += 100 }
        }
        true
    } catch (e: Exception) {
        log.warn("owner: removeActiveAdmin (${e.javaClass.simpleName})")
        false
    }

    companion object {
        /** Manifest.permission.POST_NOTIFICATIONS (API 33), by name: compiled against 36, run from 24. */
        const val POST_NOTIFICATIONS = "android.permission.POST_NOTIFICATIONS"
    }
}
