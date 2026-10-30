package tools.obli.obligarth.agent

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.view.KeyEvent
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.Policy
import tools.obli.obligarth.agent.core.PolicyCodes

/**
 * The kiosk of the policy (1.3.0, lot PONT-POL §10.5): the agent becomes the HOME launcher through the alias KioskHome
 * (soft kiosk), and with the Knox licence and `hard` options, the Knox kiosk mode locks the rest. Escape prevention
 * without Knox is impossible for a device administrator: the soft kiosk is a launcher only. A MobiControl lockdown
 * still present (its launcher as default home, or a Knox kiosk of another package) blocks it (C6, D20).
 */
class KioskController(private val context: Context, private val knox: KnoxBridge, private val log: AgentLog) {
    private val pm: PackageManager = context.packageManager
    /** The alias is declared in the namespace of the classes (the debug build only suffixes the application id). */
    private val alias = ComponentName(context, KioskActivity::class.java.name.removeSuffix("KioskActivity") + "KioskHome")

    /** The package of the default HOME activity ("android": the system chooser, no default yet). */
    fun defaultHome(): String? = try {
        pm.resolveActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName
    } catch (e: Exception) {
        null
    }

    fun homeIsAgent(): Boolean = defaultHome() == context.packageName

    fun appLaunchable(pkg: String): Boolean = try { pm.getLaunchIntentForPackage(pkg) != null } catch (e: Exception) { false }

    private fun setAlias(on: Boolean) {
        val want = if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        if (pm.getComponentEnabledSetting(alias) != want) {
            pm.setComponentEnabledSetting(alias, want, PackageManager.DONT_KILL_APP)
            log.info("kiosk home ${if (on) "enabled" else "disabled"}")
        }
    }

    fun apply(k: Policy.Kiosk?, suspended: Boolean, storageWritable: () -> Boolean): ItemOutcome {
        if (k == null || !k.enabled) {
            setAlias(false)
            knoxKiosk(null)
            Notifications.cancelPolicy(context, Notifications.NEED_HOME)
            return ItemOutcome.compliant(PolicyCodes.KIOSK_DISABLED)
        }
        val home = defaultHome()
        val foreign = when {
            home != null && home.startsWith("net.soti.") -> home
            else -> foreignKnoxKiosk()
        }
        if (foreign != null) {
            // MobiControl first (D20): the soft part is not even tried.
            return ItemOutcome.nonCompliant(PolicyCodes.KIOSK_FOREIGN_LOCKDOWN, foreign)
        }
        setAlias(true)
        var hardPending = false
        val hard = k.hard?.takeIf { it.any }
        if (hard != null) {
            if (knox.state() == "licensed") knoxKiosk(if (suspended) null else hard, storageWritable)?.let { return it }
            else hardPending = true
        } else {
            // A soft kiosk only (hard dropped, or every option off): a Knox kiosk mode left by a previous policy ends.
            knoxKiosk(null)
        }
        if (home != context.packageName) {
            Notifications.policy(context, Notifications.NEED_HOME, R.string.policy_need_home)
            return ItemOutcome.pending(PolicyCodes.HOME_NOT_DEFAULT, home)
        }
        Notifications.cancelPolicy(context, Notifications.NEED_HOME)
        return when {
            hardPending -> ItemOutcome.pendingLicence()
            suspended -> ItemOutcome.compliant(PolicyCodes.KIOSK_SUSPENDED)
            else -> ItemOutcome.compliant(PolicyCodes.KIOSK_ACTIVE)
        }
    }

    /** The package of a Knox kiosk that is not the agent's (MobiControl's), null when none. */
    private fun foreignKnoxKiosk(): String? {
        if (knox.state() != "licensed") return null
        val km = knox.kioskMode() ?: return null
        return try {
            val on = (knox.invoke(km, listOf("isKioskModeEnabled")) as? KnoxBridge.KnoxCall.Ok)?.value == true
            if (!on) return null
            val pkg = (knox.invoke(km, listOf("getKioskHomePackage")) as? KnoxBridge.KnoxCall.Ok)?.value as? String
            pkg?.takeIf { it != context.packageName }
        } catch (e: Exception) {
            null
        }
    }

    /** The kiosk alias is the HOME of the device (enabled by a kiosk this agent applied). */
    fun aliasEnabled(): Boolean = try {
        pm.getComponentEnabledSetting(alias) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    } catch (e: Exception) {
        false
    }

    /**
     * The kiosk screen has nothing to show while the alias holds HOME (no kiosk readable): the alias and the agent's Knox
     * kiosk released, so the stock launcher takes over instead of a HOME that closes itself in a loop. The reconciler
     * enables them again with the next kiosk it applies.
     */
    fun releaseOrphanHome() {
        log.warn("kiosk home without a kiosk: released")
        setAlias(false)
        knoxKiosk(null)
    }

    /**
     * The Knox kiosk mode on with [hard] (null: off, while suspended or removed): the agent's HOME forced, the system bar
     * hidden, the task manager and the hardware keys blocked, the status bar expansion and (in the C5 order) the
     * settings changes. Null when done, else the outcome of the failure.
     *
     * The hardware keys, the task manager and the settings changes are standing restrictions, not tied to the kiosk mode:
     * what this agent closed is recorded ([HardRecord]) and given back when the kiosk ends, is suspended, or no longer
     * asks for it (a key dropped from blockKeys, an option turned off), even with the kiosk mode already off.
     */
    private fun knoxKiosk(hard: Policy.Hard?, storageWritable: () -> Boolean = { false }): ItemOutcome? {
        if (knox.state() != "licensed") return null
        val km = knox.kioskMode() ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, "kioskMode")
        val applied = HardRecord.read(prefs)
        return try {
            val enabled = (knox.invoke(km, listOf("isKioskModeEnabled")) as? KnoxBridge.KnoxCall.Ok)?.value == true
            if (hard == null) {
                // Only the agent's own kiosk mode is ended (never another package's).
                val owner = (knox.invoke(km, listOf("getKioskHomePackage")) as? KnoxBridge.KnoxCall.Ok)?.value as? String
                if (enabled && (owner == null || owner == context.packageName)) {
                    knox.invoke(km, listOf("disableKioskMode"))
                    knox.policyObject(KnoxPolicies.RESTRICTION)?.let { knox.invoke(it, listOf("allowStatusBarExpansion"), true) }
                }
                giveBack(km, applied, HardRecord.NONE)
                return null
            }
            if (!enabled && knox.invoke(km, listOf("enableKioskMode"), context.packageName) is KnoxBridge.KnoxCall.Missing) {
                return ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, "enableKioskMode")
            }
            val keys = hard.blockKeys.mapNotNull { KEYS[it] }.toSet()
            // C5: the settings are closed only once the storage is writable and the agent is the default home.
            val closeSettings = hard.disableSettingsChanges && storageWritable() && homeIsAgent()
            val want = HardRecord(keys, hard.disableTaskManager, hard.hideSystemBar, closeSettings || (hard.disableSettingsChanges && applied.settings))
            giveBack(km, applied, want)
            knox.invoke(km, listOf("hideSystemBar"), hard.hideSystemBar)
            knox.invoke(km, listOf("allowTaskManager"), !hard.disableTaskManager)
            if (keys.isNotEmpty()) knox.invoke(km, listOf("allowHardwareKeys"), ArrayList(keys), false)
            knox.policyObject(KnoxPolicies.RESTRICTION)?.let { r ->
                knox.invoke(r, listOf("allowStatusBarExpansion"), !hard.disableStatusBarExpansion)
                if (closeSettings) knox.invoke(r, listOf("allowSettingsChanges"), false)
            }
            want.write(prefs)
            null
        } catch (e: SecurityException) {
            ItemOutcome.error(PolicyCodes.KNOX_REFUSED)
        } catch (e: Exception) {
            log.warn("Knox kiosk: ${KnoxBridge.describe(e)}")
            ItemOutcome.error(PolicyCodes.KNOX_ERROR)
        }
    }

    /** What [applied] closed and [want] no longer asks for, opened again (each call alone: one failure never stops the
     *  others); the record then says [want]. */
    private fun giveBack(km: Any, applied: HardRecord, want: HardRecord) {
        if (applied == HardRecord.NONE) return
        fun attempt(what: String, block: () -> Unit) = try { block() } catch (e: Exception) { log.warn("Knox kiosk give back $what: ${KnoxBridge.describe(e)}") }
        val keys = applied.keys - want.keys
        if (keys.isNotEmpty()) attempt("keys") { knox.invoke(km, listOf("allowHardwareKeys"), ArrayList(keys), true) }
        if (applied.taskManager && !want.taskManager) attempt("task manager") { knox.invoke(km, listOf("allowTaskManager"), true) }
        if (applied.systemBar && !want.systemBar) attempt("system bar") { knox.invoke(km, listOf("hideSystemBar"), false) }
        if (applied.settings && !want.settings) attempt("settings") {
            knox.policyObject(KnoxPolicies.RESTRICTION)?.let { knox.invoke(it, listOf("allowSettingsChanges"), true) }
        }
        want.write(prefs)
    }

    /** What the hard kiosk of this agent closed: the hardware keys (key codes), the task manager, the system bar, the
     *  settings changes. */
    private data class HardRecord(val keys: Set<Int>, val taskManager: Boolean, val systemBar: Boolean, val settings: Boolean) {
        fun write(p: SharedPreferences) {
            p.edit().putString(K_KEYS, keys.sorted().joinToString(",")).putBoolean(K_TASK_MANAGER, taskManager)
                .putBoolean(K_SYSTEM_BAR, systemBar).putBoolean(K_SETTINGS, settings).apply()
        }

        companion object {
            val NONE = HardRecord(emptySet(), taskManager = false, systemBar = false, settings = false)
            fun read(p: SharedPreferences) = HardRecord(
                p.getString(K_KEYS, "").orEmpty().split(',').mapNotNull { it.toIntOrNull() }.toSet(),
                p.getBoolean(K_TASK_MANAGER, false), p.getBoolean(K_SYSTEM_BAR, false), p.getBoolean(K_SETTINGS, false),
            )
        }
    }

    private val prefs: SharedPreferences get() = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    companion object {
        private val KEYS = mapOf(
            "home" to KeyEvent.KEYCODE_HOME, "recent" to KeyEvent.KEYCODE_APP_SWITCH, "back" to KeyEvent.KEYCODE_BACK,
            "menu" to KeyEvent.KEYCODE_MENU, "search" to KeyEvent.KEYCODE_SEARCH,
        )
        private const val PREFS = "kiosk_hard"
        private const val K_KEYS = "keys"
        private const val K_TASK_MANAGER = "taskManager"
        private const val K_SYSTEM_BAR = "systemBar"
        private const val K_SETTINGS = "settings"
    }
}
