package tools.obli.obligarth.agent

import android.app.AlarmManager
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Robust periodic work (spec §8.4): an exact alarm chained at pollSeconds, a
 * persisted 15 min job as a safety net, and the foreground service (keepAlive,
 * on by default). Since 1.2.0 the alarm hands its cycle to the foreground
 * service (CycleRunner, under a wake lock) instead of a job the system may
 * defer for hours; the job stays the path without the service.
 */
object PollScheduler {
    private const val JOB_POLL_NOW = 1001
    private const val JOB_PERIODIC = 1002
    private const val JOB_INSTALL = 1003

    private fun jobs(ctx: Context) = ctx.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler

    fun ensurePeriodic(ctx: Context) {
        val js = jobs(ctx)
        if (js.allPendingJobs.any { it.id == JOB_PERIODIC }) return
        js.schedule(
            JobInfo.Builder(JOB_PERIODIC, ComponentName(ctx, PollJobService::class.java))
                .setPeriodic(15 * 60 * 1000L)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .build(),
        )
    }

    fun pollNow(ctx: Context) {
        jobs(ctx).schedule(
            JobInfo.Builder(JOB_POLL_NOW, ComponentName(ctx, PollJobService::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .build(),
        )
    }

    fun scheduleInstall(ctx: Context) {
        if (jobs(ctx).allPendingJobs.any { it.id == JOB_INSTALL }) return
        jobs(ctx).schedule(
            JobInfo.Builder(JOB_INSTALL, ComponentName(ctx, InstallJobService::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true)
                .build(),
        )
    }

    fun scheduleNext(ctx: Context, delaySeconds: Long) {
        ensurePeriodic(ctx)
        alarm(ctx, ALARM_CYCLE, delaySeconds)
    }

    /**
     * The end of a kiosk suspension (1.3.0, §10.5: restored at expiry): a cycle at that time (its reconciliation puts the
     * Knox kiosk back), on an alarm of its own so the poll chain is left as it is.
     */
    fun scheduleKioskResume(ctx: Context, delaySeconds: Long) = alarm(ctx, ALARM_KIOSK_RESUME, delaySeconds)

    private const val ALARM_CYCLE = 0
    private const val ALARM_KIOSK_RESUME = 1

    private fun alarm(ctx: Context, requestCode: Int, delaySeconds: Long) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = PendingIntent.getBroadcast(
            ctx, requestCode, Intent(ctx, AlarmReceiver::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        // Elapsed time, not wall time: store clocks can be far off and corrected later
        // (F-6); an RTC alarm would then fire years late (or at once in a loop).
        val at = SystemClock.elapsedRealtime() + delaySeconds.coerceIn(5, 86_400) * 1000
        try {
            am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        } catch (e: SecurityException) {
            // Exact alarms can be denied on recent Android versions: inexact fallback.
            am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        }
    }
}

/**
 * The alarm runs the cycle itself (1.2.0): through the foreground service when it runs (keepAlive), under a wake lock,
 * without waiting for the job scheduler, which Android defers (idle, battery saving) for hours. Without the service,
 * the job as before.
 */
class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        if (rt.state.keepAlive && KeepAliveService.poll(context)) return
        PollScheduler.pollNow(context)
    }
}

/** One interrogation cycle at a time, on a worker thread under a partial wake lock (the job and the alarm share it). */
object CycleRunner {
    private val running = AtomicBoolean(false)
    private const val WAKE_MS = 3 * 60 * 1000L

    /** Starts a cycle; false when one already runs ([onDone] is then not called). */
    fun start(ctx: Context, onDone: () -> Unit = {}): Boolean {
        if (!running.compareAndSet(false, true)) return false
        val app = ctx.applicationContext
        val wake = (app.getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "obligarth:cycle").apply { setReferenceCounted(false) }
        Thread({
            try {
                wake.acquire(WAKE_MS)
                val rt = AgentRuntime.get(app)
                ConfigFile.importIfPresent(rt)
                rt.cycle()
                // 1.3.0: the policy reconciled after each cycle, within the wake lock (2 minutes at most).
                rt.reconcile(System.currentTimeMillis() / 1000 + AgentRuntime.RECONCILE_S)
            } catch (e: Throwable) {
                AgentRuntime.get(app).log.warn("cycle failed: ${e.javaClass.simpleName}: ${e.message}")
                // Keep the alarm chain alive: an unexpected failure must not wait for the 15 min job alone.
                try { PollScheduler.scheduleNext(app, 120) } catch (ignored: Throwable) { }
            } finally {
                running.set(false)
                try { if (wake.isHeld) wake.release() } catch (ignored: Throwable) { }
                onDone()
            }
        }, "obligarth-poll").start()
        return true
    }
}

/** Runs one interrogation cycle on a worker thread (a job lasts 60 s at most in practice: request time-outs). */
class PollJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean =
        CycleRunner.start(applicationContext) { jobFinished(params, false) }

    override fun onStopJob(params: JobParameters): Boolean = false
}

/** Downloads and installs (F-7), then the policy files left by a cycle (1.3.0): a dedicated job of 9 minutes at most. */
class InstallJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (!running.compareAndSet(false, true)) return false
        Thread({
            var again = false
            val rt = AgentRuntime.get(applicationContext)
            try {
                val deadline = System.currentTimeMillis() / 1000 + 540
                again = rt.engine.runInstallQueue(deadline)
                if (rt.policyBlobsMissing()) {
                    again = rt.downloadPolicyBlobs(deadline) || again
                    rt.reconcile(deadline)
                }
            } catch (e: Throwable) {
                rt.log.warn("install queue failed: ${e.javaClass.simpleName}: ${e.message}")
                again = true
            } finally {
                running.set(false)
                jobFinished(params, again)
                PollScheduler.pollNow(applicationContext) // results leave at once
            }
        }, "obligarth-install").start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true

    companion object {
        private val running = AtomicBoolean(false)
    }
}

/** Optional foreground service "Device managed by Obligarth" (keepAlive, PAR-7). */
class KeepAliveService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n: Notification = Notifications.keepAlive(this)
        startForeground(Notifications.ID_KEEPALIVE, n)
        // 1.2.0: the alarm's cycle, run here (a foreground service is never deferred); a cycle already running is enough.
        if (intent?.action == ACTION_POLL) CycleRunner.start(this)
        return START_STICKY
    }

    companion object {
        private const val ACTION_POLL = "tools.obli.obligarth.agent.action.POLL"

        /** Asks the service for a cycle now; false when it cannot be started (the caller falls back to the job). */
        fun poll(ctx: Context): Boolean = try {
            ctx.startService(Intent(ctx, KeepAliveService::class.java).setAction(ACTION_POLL)) != null
        } catch (e: Exception) {
            AgentRuntime.get(ctx).log.warn("keep-alive poll: ${e.message}")
            false
        }

        fun start(ctx: Context) {
            try {
                ctx.startService(Intent(ctx, KeepAliveService::class.java))
            } catch (e: Exception) {
                AgentRuntime.get(ctx).log.warn("keep-alive service: ${e.message}")
            }
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, KeepAliveService::class.java))
        }
    }
}

/** BOOT_COMPLETED, MY_PACKAGE_REPLACED: schedule again, report boot (update_installed is settled by the engine). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val rt = AgentRuntime.get(context)
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED -> rt.state.addEvent("boot", rt.client.correctedNow())
            Intent.ACTION_MY_PACKAGE_REPLACED -> rt.log.info("package replaced: version ${rt.facts.versionCode()}")
        }
        PollScheduler.ensurePeriodic(context)
        PollScheduler.pollNow(context)
        rt.applyKnoxAndKeepAlive()
    }
}
