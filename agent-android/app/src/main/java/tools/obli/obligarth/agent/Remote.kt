package tools.obli.obligarth.agent

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.icu.text.MeasureFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.format.DateFormat
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.RemoteEndCause
import tools.obli.obligarth.agent.core.RemotePhase
import tools.obli.obligarth.agent.core.RemoteSessionController
import tools.obli.obligarth.agent.core.RemoteText
import tools.obli.obligarth.agent.core.RemoteUi
import java.lang.ref.WeakReference
import java.util.Date
import java.util.concurrent.TimeUnit

// =============================================================================
// Remote assistance, what the device shows (P0-15 §0.1, §8): the MSP model of
// Oblireach (notify_windows.go, the LIVE watermark). Nobody on the device answers:
// a notification tells who opens the session, the system dialog of MediaProjection
// is asked (never answered by the agent; 60 s), a permanent notification stays all
// along the session (no Stop), a last one tells its end. The capture and the
// service are in RemoteCapture.kt.
// =============================================================================

/** The answer of the system dialog, kept in memory for the service (never stored). */
class ProjectionGrant(val resultCode: Int, val data: Intent)

/** [RemoteUi] on Android: everything runs on the main thread. */
class AndroidRemoteUi(private val app: Context, private val log: AgentLog) : RemoteUi {
    private val main = Handler(Looper.getMainLooper())
    @Volatile var projectionActivity: WeakReference<ProjectionRequestActivity>? = null

    /**
     * The opening told, then the system dialog. Android 7 to 9: the dialog starts from the background (the poll's
     * thread). From Android 10 a background start is blocked whatever the targetSdk: the notification of the opening
     * carries a full-screen intent to the dialog, unless the agent may draw over other apps (which exempts it). The
     * notification leads to the dialog in both cases while it waits.
     */
    override fun open(session: RemoteSessionController) {
        main.post {
            val direct = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || Settings.canDrawOverlays(app)
            RemoteNotifications.opening(app, session, projectionPending = true, fullScreen = !direct)
            if (direct) {
                try {
                    app.startActivity(ProjectionRequestActivity.intent(app, session.commandId).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                } catch (e: Exception) {
                    // The notification still leads to the dialog; the 60 s run.
                    log.warn("remote projection dialog: ${e.javaClass.simpleName}")
                }
            }
        }
    }

    /** The dialog answered or given up: it goes, and the opening stays told without leading to it any more. */
    override fun closeProjection(session: RemoteSessionController) {
        main.post {
            projectionActivity?.get()?.takeIf { it.commandId == session.commandId }?.close()
            if (!session.isEnded) RemoteNotifications.opening(app, session, projectionPending = false, fullScreen = false)
        }
    }

    override fun startService(session: RemoteSessionController) {
        main.post {
            if (!ScreenShareService.start(app, session.commandId)) session.serviceFailed()
        }
    }

    override fun finished(session: RemoteSessionController, cause: RemoteEndCause, liveMs: Long?) {
        main.post {
            projectionActivity?.get()?.takeIf { it.commandId == session.commandId }?.close()
            ScreenShareService.stop(app)
            RemoteNotifications.cancelOpening(app)
            // The end stays in the shade: who, when, how long (§0.1, rule 2).
            RemoteNotifications.ended(app, session, liveMs)
        }
    }

    override fun resultQueued() = PollScheduler.pollNow(app)
}

/**
 * The system dialog of MediaProjection (§8), behind a transparent screen: its answer goes to the session; not answered
 * in 60 s, the session closes it (projection_denied). The agent never answers it for the user: once "Don't show again"
 * is ticked there, Android itself grants the next sessions. Not exported.
 */
class ProjectionRequestActivity : Activity() {
    var commandId: String? = null
        private set
    private var answered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        commandId = intent?.getStringExtra(EXTRA_COMMAND)
        val rt = AgentRuntime.get(this)
        val s = rt.remoteSessions.session(commandId)
        // One dialog per session: started directly and again from the notification, the second one goes.
        val running = rt.remoteUi.projectionActivity?.get()?.takeIf { it !== this && !it.isFinishing && it.commandId == commandId }
        if (s == null || s.phase != RemotePhase.PROJECTION || running != null) {
            answered = true
            finish()
            return
        }
        rt.remoteUi.projectionActivity = WeakReference(this)
        if (savedInstanceState == null) {
            try {
                val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
                startActivityForResult(mpm.createScreenCaptureIntent(), REQUEST)
            } catch (e: Exception) {
                rt.log.warn("remote projection dialog: ${e.javaClass.simpleName}")
                answer(false, null)
            }
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST) return
        val granted = resultCode == RESULT_OK && data != null
        answer(granted, if (granted) ProjectionGrant(resultCode, data!!) else null)
    }

    private fun answer(granted: Boolean, grant: ProjectionGrant?) {
        if (answered) return
        answered = true
        AgentRuntime.get(this).remoteSessions.session(commandId)?.projectionResult(granted, grant)
        finish()
    }

    /** The session gave up waiting (60 s) or ended: the system dialog goes with this screen. */
    fun close() {
        if (!answered) {
            answered = true
            try {
                @Suppress("DEPRECATION")
                finishActivity(REQUEST)
            } catch (e: Exception) {
                // Already gone.
            }
        }
        finish()
    }

    override fun onDestroy() {
        val ui = AgentRuntime.get(this).remoteUi
        if (ui.projectionActivity?.get() === this) ui.projectionActivity = null
        super.onDestroy()
    }

    companion object {
        const val EXTRA_COMMAND = "commandId"
        private const val REQUEST = 1

        fun intent(ctx: Context, commandId: String): Intent =
            Intent(ctx, ProjectionRequestActivity::class.java).putExtra(EXTRA_COMMAND, commandId)
    }
}

/**
 * The notifications of a session (§0.1, rule 2, as the toasts and the LIVE watermark of Oblireach): the opening, the
 * session (permanent, the service's), the end. Android 8 and later: a channel of high importance of their own (the
 * opening shows at once, the session's notification stays in sight); before: the per-notification priority
 * (targetSdk 25).
 */
@Suppress("DEPRECATION")
object RemoteNotifications {
    const val CHANNEL = "remote_assistance"
    const val ID_OPENING = 10
    const val ID_LIVE = 11
    private const val TAG_ENDED = "remote_ended"

    private fun nm(ctx: Context) = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun builder(ctx: Context): Notification.Builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ensureChannel(ctx)
            Notification.Builder(ctx, CHANNEL)
        } else {
            Notification.Builder(ctx).setPriority(Notification.PRIORITY_HIGH)
        }

    private fun ensureChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = nm(ctx)
        if (nm.getNotificationChannel(CHANNEL) != null) return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, ctx.getString(R.string.remote_channel_name), NotificationManager.IMPORTANCE_HIGH).apply {
                description = ctx.getString(R.string.remote_channel_description)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            },
        )
    }

    /**
     * The notifications of the agent can be seen: not blocked, nor their channel (Android 8+). Told to /accept, never a
     * refusal (§0.1, rule 2).
     */
    fun enabled(ctx: Context): Boolean {
        val nm = nm(ctx)
        if (!nm.areNotificationsEnabled()) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = nm.getNotificationChannel(CHANNEL)
            if (channel != null && channel.importance == NotificationManager.IMPORTANCE_NONE) return false
        }
        return true
    }

    private fun projection(ctx: Context, commandId: String, code: Int): PendingIntent = PendingIntent.getActivity(
        ctx, code, ProjectionRequestActivity.intent(ctx, commandId).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    /**
     * "<technician> (<organisation>) opens a remote assistance session". While the system dialog waits
     * ([projectionPending]) it leads to the dialog, full screen from Android 10 ([fullScreen]: background starts
     * blocked); afterwards it only tells.
     */
    fun opening(ctx: Context, session: RemoteSessionController, projectionPending: Boolean, fullScreen: Boolean) {
        val r = session.request
        val text = ctx.getString(R.string.remote_open_text, RemoteText.display(r.operator, 80), RemoteText.display(r.operatorOrg, 120))
        val b = builder(ctx)
            .setSmallIcon(R.drawable.ic_agent)
            .setContentTitle(ctx.getString(R.string.remote_open_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setOnlyAlertOnce(true)
            .setDefaults(Notification.DEFAULT_ALL)
            .setShowWhen(true)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
        if (projectionPending) {
            b.setCategory(Notification.CATEGORY_CALL).setContentIntent(projection(ctx, session.commandId, 1))
            if (fullScreen) b.setFullScreenIntent(projection(ctx, session.commandId, 2), true)
        }
        nm(ctx).notify(ID_OPENING, b.build())
    }

    fun cancelOpening(ctx: Context) = nm(ctx).cancel(ID_OPENING)

    /** The session's notification (foreground service, permanent): "Assistance session in progress: <technician>". */
    fun live(ctx: Context, session: RemoteSessionController): Notification {
        val r = session.request
        val operator = RemoteText.display(r.operator, 80)
        val text = ctx.getString(R.string.remote_live_text, operator, RemoteText.display(r.operatorOrg, 120))
        return builder(ctx)
            .setSmallIcon(R.drawable.ic_agent)
            .setContentTitle(ctx.getString(R.string.remote_live_title, operator))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(true)
            .setWhen(System.currentTimeMillis())
            .setUsesChronometer(true)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }

    /**
     * The end, kept in the shade (dismissable): "<technician> closed the assistance session", when, and how long the
     * screen was shared; or that it ended before any image ([liveMs] null).
     */
    fun ended(ctx: Context, session: RemoteSessionController, liveMs: Long?) {
        val at = DateFormat.getTimeFormat(ctx).format(Date())
        val operator = RemoteText.display(session.request.operator, 80)
        val text = if (liveMs != null) ctx.getString(R.string.remote_ended_text, operator, at, duration(ctx, liveMs / 1000))
        else ctx.getString(R.string.remote_ended_text_short, operator, at)
        nm(ctx).notify(
            TAG_ENDED, session.commandId.hashCode(),
            builder(ctx)
                .setSmallIcon(R.drawable.ic_agent)
                .setContentTitle(ctx.getString(R.string.remote_ended_title))
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setOnlyAlertOnce(true)
                .setShowWhen(true)
                .setVisibility(Notification.VISIBILITY_PUBLIC)
                .build(),
        )
    }

    /**
     * A duration with its units in the language of the device ("12 min 30 s", "1 h 5 min"): next to a time of day,
     * a clock-like 12:30 would read as one.
     */
    private fun duration(ctx: Context, seconds: Long): String = try {
        val measures = RemoteText.durationParts(seconds).map { (unit, n) ->
            Measure(n, when (unit) {
                TimeUnit.HOURS -> MeasureUnit.HOUR
                TimeUnit.MINUTES -> MeasureUnit.MINUTE
                else -> MeasureUnit.SECOND
            })
        }
        MeasureFormat.getInstance(ctx.resources.configuration.locales[0], MeasureFormat.FormatWidth.SHORT).formatMeasures(*measures.toTypedArray())
    } catch (e: Exception) {
        RemoteText.duration(seconds)
    }
}
