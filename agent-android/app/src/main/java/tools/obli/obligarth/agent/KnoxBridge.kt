package tools.obli.obligarth.agent

import android.annotation.SuppressLint
import android.content.Context
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.KnoxLicence
import tools.obli.obligarth.agent.core.Sha256
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method

/**
 * Samsung Knox reached by reflection (spec §8.5, PB9, F-1, F-2): no file of the
 * Knox SDK in the repository. The old namespace (android.app.enterprise, Knox
 * before 2.8, the target fleet: SamsungMdmV57) first, the new one
 * (com.samsung.android.knox) second. Any reflection failure is reported, never
 * a crash. Names and signatures are to be confirmed on a real device (PAR-2, PAR-3).
 */
@SuppressLint("ApplySharedPref") // licence state written synchronously, read by other threads at once
class KnoxBridge(private val context: Context, private val log: AgentLog) {

    private class Space(val edmClass: String, val elmClass: String, val klmClass: String?, val label: String)

    private val spaces = listOf(
        Space("android.app.enterprise.EnterpriseDeviceManager", "android.app.enterprise.license.EnterpriseLicenseManager", null, "legacy"),
        Space(
            "com.samsung.android.knox.EnterpriseDeviceManager", "com.samsung.android.knox.license.EnterpriseLicenseManager",
            "com.samsung.android.knox.license.KnoxEnterpriseLicenseManager", "knox",
        ),
    )

    private val prefs = context.getSharedPreferences("knox", Context.MODE_PRIVATE)

    /** The first namespace whose EnterpriseDeviceManager class exists. */
    private val space: Space? by lazy {
        spaces.firstOrNull { s -> try { Class.forName(s.edmClass); true } catch (e: Throwable) { false } }
    }

    val present: Boolean get() = space != null

    private fun edm(): Any? {
        val s = space ?: return null
        return try {
            val cls = Class.forName(s.edmClass)
            if (s.label == "legacy") {
                context.getSystemService("enterprise_policy") ?: cls.getConstructor(Context::class.java).newInstance(context)
            } else {
                cls.getMethod("getInstance", Context::class.java).invoke(null, context)
            }
        } catch (e: Throwable) {
            log.warn("Knox EDM unavailable: ${describe(e)}")
            null
        }
    }

    /** Raw version strings: { version, mdmApiLevel }. */
    fun versionInfo(): Pair<String?, String?> {
        val s = space ?: return null to null
        val level = try {
            Class.forName(s.edmClass).getMethod("getAPILevel").invoke(null)?.toString()
        } catch (e: Throwable) { null }
        val version = try {
            edm()?.let { call(it, "getEnterpriseSdkVer") }?.toString()
        } catch (e: Throwable) { null }
        return version to level
    }

    /**
     * absent | present | licensed | license_error (spec §3.2 knox_state; KnoxLicence.state). A Knox
     * licence is bound to the package that activated it: with no key ever sent by this agent, "present",
     * whatever the probe answers (some Knox versions answer it without a licence). Then the probe first:
     * the receiver is exported and the key goes to two managers, so a status broadcast never decides
     * alone; a refusal gives license_error only when the probe fails too.
     */
    fun state(): String =
        KnoxLicence.state(present, activatedKeySha(), prefs.getString(K_STATUS, null)) { probeLicensed() }

    fun lastError(): String? = prefs.getString(K_ERROR, null)

    /**
     * A harmless licensed call: a SecurityException means no licence. The agent itself is installed,
     * so a working call answers true; a wrapper that swallows the refusal answers false.
     */
    private fun probeLicensed(): Boolean = try {
        val app = edm()?.let { call(it, "getApplicationPolicy") } ?: return false
        call(app, "isApplicationInstalled", context.packageName) == true
    } catch (e: Throwable) {
        false
    }

    /**
     * Activates a licence key (admin must be active). The status arrives by broadcast (KnoxLicenseReceiver):
     * synchronized with onLicenseStatus, a status is read once the sending is recorded.
     */
    @Synchronized
    fun activateLicense(key: String): Boolean {
        val s = space ?: return false
        val keySha = Sha256.hex(key)
        var sent = false
        // New namespace: KPE key first; then the backwards-compatible (ELM) key, the only one of Knox < 2.8.
        for (cls in listOfNotNull(s.klmClass, s.elmClass)) {
            try {
                val mgr = Class.forName(cls).getMethod("getInstance", Context::class.java).invoke(null, context)
                call(mgr!!, "activateLicense", key)
                sent = true
                log.info("Knox licence activation sent ($cls)")
            } catch (e: Throwable) {
                log.warn("Knox licence activation $cls: ${describe(e)}")
            }
        }
        if (sent) prefs.edit().putString(K_KEY_SHA, keySha).putLong(K_SENT_AT, now()).remove(K_STATUS).remove(K_ERROR).commit()
        return sent
    }

    fun activatedKeySha(): String? = prefs.getString(K_KEY_SHA, null)

    /** Whether to send [key]: a new key, or one refused or never answered a while ago (KnoxLicence.activationDue). */
    fun activationDue(key: String): Boolean = KnoxLicence.activationDue(
        Sha256.hex(key), activatedKeySha(), prefs.getString(K_STATUS, null), prefs.getLong(K_SENT_AT, 0L), now(),
    ) { state() == KnoxLicence.LICENSED }

    /**
     * A status broadcast: kept only in the window after a sending of this agent, a success of one
     * manager never undone by the refusal of the other (KnoxLicence.nextStatus). False when ignored.
     */
    @Synchronized
    fun onLicenseStatus(success: Boolean, errorCode: Int?): Boolean {
        val next = KnoxLicence.nextStatus(activatedKeySha(), prefs.getLong(K_SENT_AT, 0L), now(), prefs.getString(K_STATUS, null), success)
            ?: return false
        prefs.edit().putString(K_STATUS, next).putString(K_ERROR, if (next == KnoxLicence.FAIL) errorCode?.toString() else null).commit()
        return true
    }

    private fun now(): Long = System.currentTimeMillis() / 1000

    // ---- Policies (each returns null when done, else an error code of §5.3) ----

    fun setAdminRemovable(removable: Boolean): Boolean = try {
        val manager = edm() ?: throw IllegalStateException("no EnterpriseDeviceManager")
        // The Knox call answers false when refused: the state is kept only when it worked (retried otherwise).
        if (call(manager, "setAdminRemovable", removable) == false) throw IllegalStateException("refused")
        prefs.edit().putBoolean(K_REMOVABLE, removable).commit()
        true
    } catch (e: Throwable) {
        log.warn("Knox setAdminRemovable: ${describe(e)}")
        false
    }

    fun adminRemovable(): Boolean = prefs.getBoolean(K_REMOVABLE, true)

    fun install(path: String, update: Boolean): String? = policyCall("getApplicationPolicy") { app ->
        val ok = if (update) call(app, "updateApplication", path) else call(app, "installApplication", path, false)
        if (ok == false) "install_failed" else null
    }

    fun uninstall(packageName: String): String? = policyCall("getApplicationPolicy") { app ->
        if (call(app, "uninstallApplication", packageName, false) == false) "install_failed" else null
    }

    fun reboot(reason: String): String? = policyCall("getPasswordPolicy") { pw ->
        call(pw, "reboot", reason)
        null
    }

    fun wipe(external: Boolean): String? = policyCall("getSecurityPolicy") { sec ->
        val cls = sec.javaClass
        val internal = intConstant(cls, "WIPE_INTERNAL_MEMORY", 1)
        val flags = if (external) internal or intConstant(cls, "WIPE_EXTERNAL_MEMORY", 2) else internal
        if (call(sec, "wipeDevice", flags) == false) "knox_error" else null
    }

    fun serialNumber(): String? = try {
        val inv = edm()?.let { call(it, "getDeviceInventory") }
        (inv?.let { call(it, "getSerialNumber") } as? String)?.takeIf { it.isNotBlank() }
    } catch (e: Throwable) {
        null
    }

    private inline fun policyCall(getter: String, block: (Any) -> String?): String? {
        if (!present) return "knox_required"
        return try {
            val e = edm() ?: return "knox_error"
            val policy = call(e, getter) ?: return "knox_error"
            block(policy)
        } catch (t: Throwable) {
            log.warn("Knox $getter: ${describe(t)}")
            if (rootCause(t) is SecurityException) "knox_required" else "knox_error"
        }
    }

    private fun intConstant(cls: Class<*>, name: String, fallback: Int): Int = try {
        cls.getField(name).getInt(null)
    } catch (e: Throwable) {
        fallback
    }

    companion object {
        private const val K_STATUS = "licenseStatus"
        private const val K_ERROR = "licenseError"
        private const val K_KEY_SHA = "licenseKeySha"
        private const val K_SENT_AT = "licenseSentAt"
        private const val K_REMOVABLE = "adminRemovable"

        /** Invokes the public method [name] whose parameters accept [args] (boxed primitives accepted). */
        fun call(target: Any, name: String, vararg args: Any?): Any? {
            val m = findMethod(target.javaClass, name, args) ?: throw NoSuchMethodException("${target.javaClass.name}.$name/${args.size}")
            return try {
                m.invoke(target, *args)
            } catch (e: InvocationTargetException) {
                throw e.targetException ?: e
            }
        }

        private fun findMethod(cls: Class<*>, name: String, args: Array<out Any?>): Method? =
            cls.methods.firstOrNull { m ->
                m.name == name && m.parameterTypes.size == args.size &&
                    m.parameterTypes.withIndex().all { (i, t) -> accepts(t, args[i]) }
            }

        private fun accepts(type: Class<*>, arg: Any?): Boolean = when {
            arg == null -> !type.isPrimitive
            type == java.lang.Boolean.TYPE -> arg is Boolean
            type == Integer.TYPE -> arg is Int
            type == java.lang.Long.TYPE -> arg is Long
            else -> type.isInstance(arg)
        }

        fun rootCause(t: Throwable): Throwable {
            var c = t
            while (true) {
                val next = (if (c is InvocationTargetException) c.targetException else c.cause) ?: return c
                if (next === c) return c
                c = next
            }
        }

        fun describe(t: Throwable): String = rootCause(t).let { "${it.javaClass.simpleName}: ${it.message}" }
    }
}
