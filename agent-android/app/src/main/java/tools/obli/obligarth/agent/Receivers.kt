package tools.obli.obligarth.agent

import android.app.PendingIntent
import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import java.io.File

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
 * Configuration dropped by MobiControl (spec §4.9, §9 step 3):
 * action tools.obli.obligarth.agent.action.CONFIGURE, extra "config" (base64url JSON).
 */
class ConfigReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_CONFIGURE) return
        val rt = AgentRuntime.get(context)
        val refusal = rt.importConfig(intent.getStringExtra("config"), "intent")
        if (refusal != null) rt.log.warn("configuration intent refused: $refusal")
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
                rt.engine.onInstallerStatus(
                    commandId, status == PackageInstaller.STATUS_SUCCESS, status == PackageInstaller.STATUS_FAILURE_ABORTED, message,
                )
                PollScheduler.pollNow(context)
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
        rt.knox.onLicenseStatus(ok, error)
        rt.state.addEvent("knox_license", rt.client.correctedNow(), mapOf("success" to ok, "errorCode" to error, "action" to intent.action))
        rt.log.info("Knox licence status: ${if (ok) "success" else "fail ($error)"}")
        rt.applyKnoxAndKeepAlive()
        PollScheduler.pollNow(context)
    }
}
