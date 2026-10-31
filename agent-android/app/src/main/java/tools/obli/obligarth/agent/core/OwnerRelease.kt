package tools.obli.obligarth.agent.core

/** What giving the device back needs from the device (§7.5): each step alone, never throwing (Android: OwnerApplier). */
interface ReleaseHost {
    fun isDeviceOwner(): Boolean
    fun adminActive(): Boolean
    fun knoxLicensed(): Boolean
    /** Lock task stopped, the persistent HOME cleared, the alias KioskHome disabled. */
    fun kioskOff(): Boolean
    /** The user restrictions of the owner catalogue cleared. */
    fun clearUserRestrictions(): Boolean
    fun setUninstallBlocked(blocked: Boolean): Boolean
    /** Knox EnterpriseDeviceManager.setAdminRemovable (an administrator locked by 1.3.0 refuses its removal). */
    fun knoxSetAdminRemovable(removable: Boolean): Boolean
    fun clearDeviceOwner(): Boolean
    fun removeActiveAdmin(): Boolean
}

/** The outcome of a release, read back from the device (written to the local log; the bench reads it by `state`). */
data class ReleaseOutcome(val ownerCleared: Boolean, val adminActive: Boolean, val steps: List<String>) {
    val complete: Boolean get() = ownerCleared && !adminActive
}

/**
 * Gives the device back (1.4.0, lot BANC §7.5, T383), in this order: the kiosk, the user restrictions, the uninstall
 * block, Knox setAdminRemovable(true) when licensed (before any removal of the administrator), clearDeviceOwnerApp,
 * removeActiveAdmin, then a read back. Every step runs even when an earlier one failed.
 */
object OwnerRelease {
    fun run(host: ReleaseHost, log: AgentLog = AgentLog.None): ReleaseOutcome {
        val steps = ArrayList<String>()
        fun step(name: String, block: () -> Boolean) {
            val ok = try { block() } catch (e: Throwable) { false }
            steps += if (ok) name else "$name:failed"
            if (!ok) log.warn("release: $name failed")
        }
        val owner = try { host.isDeviceOwner() } catch (e: Throwable) { false }
        if (owner) {
            step("kiosk") { host.kioskOff() }
            step("restrictions") { host.clearUserRestrictions() }
            step("uninstall_unblocked") { host.setUninstallBlocked(false) }
        }
        if (try { host.knoxLicensed() } catch (e: Throwable) { false }) step("knox_removable") { host.knoxSetAdminRemovable(true) }
        if (owner) step("owner_cleared") { host.clearDeviceOwner() }
        step("admin_removed") { host.removeActiveAdmin() }
        val ownerAfter = try { host.isDeviceOwner() } catch (e: Throwable) { true }
        val adminAfter = try { host.adminActive() } catch (e: Throwable) { true }
        val outcome = ReleaseOutcome(!ownerAfter, adminAfter, steps)
        log.info("release: owner cleared=${outcome.ownerCleared} admin active=${outcome.adminActive}")
        return outcome
    }
}
