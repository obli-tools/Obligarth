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
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Robust periodic work (spec §8.4): an exact alarm chained at pollSeconds (the
 * receiver only schedules a job, it never does network), a persisted 15 min
 * job as a safety net, and an optional foreground service (keepAlive).
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
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val pi = PendingIntent.getBroadcast(
            ctx, 0, Intent(ctx, AlarmReceiver::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val at = System.currentTimeMillis() + delaySeconds.coerceIn(5, 86_400) * 1000
        try {
            am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi)
        } catch (e: SecurityException) {
            // Exact alarms can be denied on recent Android versions: inexact fallback.
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, at, pi)
        }
    }
}

class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = PollScheduler.pollNow(context)
}

/** Runs one interrogation cycle on a worker thread (a job lasts 60 s at most in practice: request time-outs). */
class PollJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (!running.compareAndSet(false, true)) return false
        Thread({
            try {
                val rt = AgentRuntime.get(applicationContext)
                ConfigFile.importIfPresent(rt)
                rt.cycle()
            } catch (e: Throwable) {
                AgentRuntime.get(applicationContext).log.warn("cycle failed: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                running.set(false)
                jobFinished(params, false)
            }
        }, "obligarth-poll").start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = false

    companion object {
        private val running = AtomicBoolean(false)
    }
}

/** Downloads and installs (F-7): a dedicated job of 9 minutes at most. */
class InstallJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        if (!running.compareAndSet(false, true)) return false
        Thread({
            var again = false
            val rt = AgentRuntime.get(applicationContext)
            try {
                again = rt.engine.runInstallQueue(System.currentTimeMillis() / 1000 + 540)
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
        return START_STICKY
    }

    companion object {
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
