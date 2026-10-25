package tools.obli.obligarth.agent

import android.app.PendingIntent
import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import tools.obli.obligarth.agent.core.Phase
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/** Device administrator (spec §8.2): force-lock and wipe-data only. */
class AgentAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        rt.state.addEvent("admin_enabled", rt.client.correctedNow())
        rt.log.info("administrator enabled")
        rt.applyKnoxAndKeepAlive()
        rt.refreshStatusNotification()
        PollScheduler.pollNow(context)
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        val rt = AgentRuntime.get(context)
        rt.state.addEvent("admin_disable_requested", rt.client.correctedNow())
        PollScheduler.pollNow(context)
        return context.getString(R.string.admin_disable_warning)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        rt.state.addEvent("admin_disabled", rt.client.correctedNow())
        rt.log.warn("administrator disabled")
        rt.refreshStatusNotification()
        PollScheduler.pollNow(context)
    }
}

/**
 * Each time the device is unlocked while the administrator is still off, the
 * activation screen comes back (at most every few minutes): administration can
 * only be enabled by a tap on the device, and a declined screen must not end
 * the matter. Manifest receiver, delivered under targetSdk 25; from Android 10
 * the start needs the "display over other apps" access (MobiControl:
 * request_appops_permission), otherwise the notification remains.
 */
class UnlockReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_USER_PRESENT) return
        val rt = AgentRuntime.get(context)
        if (rt.facts.adminActive()) return
        if (rt.state.phase != Phase.CONFIGURED && rt.state.phase != Phase.ENROLLED) return
        val prefs = context.getSharedPreferences("unlock", Context.MODE_PRIVATE)
        val now = SystemClock.elapsedRealtime()
        val last = prefs.getLong("lastPrompt", 0L)
        if (last in 1..now && now - last < PROMPT_INTERVAL_MS) return
        prefs.edit().putLong("lastPrompt", now).apply()
        try {
            context.startActivity(
                Intent(context, SetupActivity::class.java).setAction(SetupActivity.ACTION_ACTIVATE_ADMIN)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        } catch (e: Exception) {
            rt.log.warn("administrator prompt on unlock: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    companion object {
        private const val PROMPT_INTERVAL_MS = 3 * 60 * 1000L
    }
}

/**
 * Configuration dropped by MobiControl (spec §4.9, §9 step 3):
 * action tools.obli.obligarth.agent.action.CONFIGURE, extra "config" (base64url JSON).
 */
class ConfigReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CONFIGURE) return
        val raw = intent.getStringExtra("config")
        // Off the main thread: the import waits for a running cycle (engine lock, network time-outs).
        runAsync(context, "obligarth-config") { rt ->
            val refusal = rt.importConfig(raw, "intent")
            if (refusal != null) rt.log.warn("configuration intent refused: $refusal")
        }
    }

    companion object {
        const val ACTION_CONFIGURE = "tools.obli.obligarth.agent.action.CONFIGURE"
    }
}

/**
 * Fallback path (spec §8.2 ConfigFile): Android/data/<package>/files/obligarth-agent.json,
 * read then erased (the app directory needs no permission from API 19).
 */
object ConfigFile {
    const val NAME = "obligarth-agent.json"

    fun importIfPresent(rt: AgentRuntime): String? {
        val dir = rt.app.getExternalFilesDir(null) ?: return null
        val file = File(dir, NAME)
        if (!file.isFile) return null
        val text = try {
            if (file.length() > 16 * 1024) null else file.readText()
        } catch (e: Exception) {
            null
        }
        file.delete()
        val refusal = rt.importConfig(text, "file")
        if (refusal != null) rt.log.warn("configuration file refused: $refusal")
        return refusal
    }
}

/** Status of installer sessions and uninstall requests (PackageInstaller). */
class InstallStatusReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        val commandId = intent.getStringExtra(EXTRA_COMMAND) ?: return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION")
                val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                Notifications.installPrompt(context, commandId, confirm)
                try {
                    context.startActivity(confirm)
                } catch (e: Exception) {
                    rt.log.warn("installer prompt: ${e.message}")
                }
            }
            else -> {
                Notifications.cancelInstallPrompt(context, commandId)
                // Off the main thread: the engine lock may be held by a cycle waiting on the network.
                runAsync(context, "obligarth-install-status") { r ->
                    r.engine.onInstallerStatus(
                        commandId, status == PackageInstaller.STATUS_SUCCESS, status == PackageInstaller.STATUS_FAILURE_ABORTED, message,
                    )
                    PollScheduler.pollNow(context)
                }
            }
        }
    }

    companion object {
        private const val EXTRA_COMMAND = "commandId"

        fun sender(context: Context, commandId: String): IntentSender {
            val i = Intent(context, InstallStatusReceiver::class.java).putExtra(EXTRA_COMMAND, commandId)
            // Mutable: the installer adds its status extras.
            return PendingIntent.getBroadcast(
                context, commandId.hashCode(), i, PendingIntent.FLAG_UPDATE_CURRENT or AndroidActions.mutableFlag(),
            ).intentSender
        }
    }
}

/** Knox licence status broadcasts, old (ELM) and new (KPE) namespaces (§8.5). */
class KnoxLicenseReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        val extras = intent.extras ?: return
        var success: Boolean? = null
        var error: Int? = null
        for (key in extras.keySet()) {
            val lower = key.lowercase()
            @Suppress("DEPRECATION")
            val value = extras.get(key)
            if (lower.contains("status") && value is String) success = value.equals("success", ignoreCase = true)
            if (lower.contains("error") && value is Int) error = value
        }
        val ok = success ?: return
        val action = intent.action
        rt.knox.onLicenseStatus(ok, error)
        rt.state.addEvent("knox_license", rt.client.correctedNow(), mapOf("success" to ok, "errorCode" to error, "action" to action))
        rt.log.info("Knox licence status: ${if (ok) "success" else "fail ($error)"}")
        // Knox calls (licence probe, setAdminRemovable) off the main thread.
        runAsync(context, "obligarth-knox") { r ->
            r.applyKnoxAndKeepAlive()
            PollScheduler.pollNow(context)
        }
    }
}

/**
 * Runs [block] on a worker thread: a receiver never blocks the main thread on
 * the engine lock (held by a cycle waiting on the network) or on Knox, which
 * would end in an ANR and the process killed in the middle of a cycle. The
 * broadcast is kept alive (goAsync) while the work is short, and released
 * after 8 s at most (well under the broadcast time-out); a longer wait only
 * happens while a cycle runs, whose job keeps the process alive.
 */
private fun BroadcastReceiver.runAsync(context: Context, name: String, block: (AgentRuntime) -> Unit) {
    val pending = goAsync()
    val released = AtomicBoolean(false)
    val release = { if (released.compareAndSet(false, true)) pending.finish() }
    Handler(Looper.getMainLooper()).postDelayed({ release() }, 8_000)
    val app = context.applicationContext
    Thread({
        try {
            block(AgentRuntime.get(app))
        } catch (e: Throwable) {
            AgentRuntime.get(app).log.warn("$name failed: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            release()
        }
    }, name).start()
}
