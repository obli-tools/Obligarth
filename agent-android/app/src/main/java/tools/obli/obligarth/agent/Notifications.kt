package tools.obli.obligarth.agent

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/**
 * Notifications. targetSdk 25: no channel is required (Android 8+ files them
 * under the default channel of a pre-26 app).
 */
@Suppress("DEPRECATION")
object Notifications {
    const val ID_KEEPALIVE = 1
    private const val ID_ADMIN = 2
    private const val ID_STATUS = 3
    private const val TAG_MESSAGE = "message"
    private const val TAG_INSTALL = "install"

    private fun nm(ctx: Context) = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun openSetup(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, SetupActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    fun keepAlive(ctx: Context): Notification = Notification.Builder(ctx)
        .setSmallIcon(R.drawable.ic_agent)
        .setContentTitle(ctx.getString(R.string.keepalive_title))
        .setPriority(Notification.PRIORITY_MIN)
        .setOngoing(true)
        .setContentIntent(openSetup(ctx))
        .build()

    /** Persistent notification while the administrator is inactive (§8.3, PAR-1). */
    fun adminRequired(ctx: Context) {
        nm(ctx).notify(
            ID_ADMIN,
            Notification.Builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(ctx.getString(R.string.admin_required_title))
                .setContentText(ctx.getString(R.string.admin_required_text))
                .setOngoing(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setContentIntent(openSetup(ctx))
                .build(),
        )
    }

    fun cancelAdminRequired(ctx: Context) = nm(ctx).cancel(ID_ADMIN)

    fun status(ctx: Context, text: String) {
        nm(ctx).notify(
            ID_STATUS,
            Notification.Builder(ctx).setSmallIcon(R.drawable.ic_agent).setContentTitle(ctx.getString(R.string.app_name))
                .setContentText(text).setContentIntent(openSetup(ctx)).build(),
        )
    }

    fun message(ctx: Context, commandId: String, title: String, text: String) {
        val open = PendingIntent.getActivity(
            ctx, commandId.hashCode(), MessageActivity.intent(ctx, title, text).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        nm(ctx).notify(
            TAG_MESSAGE, commandId.hashCode(),
            Notification.Builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(title.ifEmpty { ctx.getString(R.string.app_name) })
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setPriority(Notification.PRIORITY_HIGH)
                .setDefaults(Notification.DEFAULT_ALL)
                .setAutoCancel(true)
                .setContentIntent(open)
                .build(),
        )
    }

    /** Re-opens a pending installer confirmation. */
    fun installPrompt(ctx: Context, commandId: String, confirm: Intent) {
        val pi = PendingIntent.getActivity(ctx, commandId.hashCode(), confirm, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        nm(ctx).notify(
            TAG_INSTALL, commandId.hashCode(),
            Notification.Builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(ctx.getString(R.string.install_prompt_title))
                .setContentText(ctx.getString(R.string.install_prompt_text))
                .setOngoing(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setContentIntent(pi)
                .build(),
        )
    }

    fun cancelInstallPrompt(ctx: Context, commandId: String) = nm(ctx).cancel(TAG_INSTALL, commandId.hashCode())

    // ---- Policy (1.3.0, lot PONT-POL): what the policy needs from the person holding the device ----

    private const val TAG_POLICY = "policy"
    const val NEED_STORAGE = 1
    const val NEED_HOME = 2
    const val NEED_ADMIN_POLICIES = 3
    const val NEED_PASSWORD = 4

    /** A need of the policy (storage access, default home, new admin permissions): opens the status screen. */
    fun policy(ctx: Context, need: Int, text: Int) {
        nm(ctx).notify(
            TAG_POLICY, need,
            Notification.Builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(ctx.getString(R.string.policy_need_title))
                .setContentText(ctx.getString(text))
                .setStyle(Notification.BigTextStyle().bigText(ctx.getString(text)))
                .setOngoing(true)
                .setContentIntent(openSetup(ctx))
                .build(),
        )
    }

    fun cancelPolicy(ctx: Context, need: Int) = nm(ctx).cancel(TAG_POLICY, need)

    /** The password does not meet the policy: opens ACTION_SET_NEW_PASSWORD. */
    fun passwordChange(ctx: Context) {
        val pi = PendingIntent.getActivity(
            ctx, NEED_PASSWORD, Intent(android.app.admin.DevicePolicyManager.ACTION_SET_NEW_PASSWORD).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        nm(ctx).notify(
            TAG_POLICY, NEED_PASSWORD,
            Notification.Builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(ctx.getString(R.string.policy_need_title))
                .setContentText(ctx.getString(R.string.policy_need_password))
                .setPriority(Notification.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi)
                .build(),
        )
    }
}
