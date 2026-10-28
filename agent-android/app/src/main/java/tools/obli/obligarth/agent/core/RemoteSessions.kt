package tools.obli.obligarth.agent.core

import java.io.IOException
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

// =============================================================================
// Remote assistance, one session from remote.open to its end (P0-15 §0.1, §2, §4.3,
// §8): the machine of RemoteSession.kt driven by the system dialog and a ticker of
// one second, /accept and /end on a network thread of their own, the stream of
// RemoteLive.kt. The notifications, the service and the capture are behind RemoteUi
// and RemoteDevice (Android: Remote.kt, RemoteCapture.kt).
// =============================================================================

/** What a session asks of the screen (Android: notifications, the system dialog, the foreground service). */
interface RemoteUi {
    /**
     * The opening told ("<technician> (<organisation>) opens a remote assistance session") and the system dialog of
     * MediaProjection asked (from Android 10: through a full-screen intent); its answer comes to
     * [RemoteSessionController.projectionResult]. The agent never answers the dialog.
     */
    fun open(session: RemoteSessionController)
    fun closeProjection(session: RemoteSessionController)
    /**
     * The foreground service and its permanent notification; once up it calls [RemoteSessionController.serviceUp], or
     * [RemoteSessionController.serviceFailed].
     */
    fun startService(session: RemoteSessionController)
    /** Over: the service stops, the end is told ([liveMs]: how long the stream flowed, null when it never did). */
    fun finished(session: RemoteSessionController, cause: RemoteEndCause, liveMs: Long?)
    /** A result of remote.open waits in the outbox: interrogate now. */
    fun resultQueued()
}

class RemoteSessionController internal constructor(
    val commandId: String,
    val request: Params.RemoteOpen,
    private val api: RemoteApi,
    private val ui: RemoteUi,
    /** AgentEngine.onRemoteOutcome. */
    private val report: (String, ResultStatus, String) -> Unit,
    /** Server time, Unix seconds (AgentClient.correctedNow). */
    private val serverNow: () -> Long,
    private val timings: RemoteTimings,
    private val clockMs: () -> Long,
    private val log: AgentLog,
) {
    private val lock = Any()
    private val machine = RemoteSessionMachine(timings, request.mode)
    private val net: ExecutorService = Executors.newSingleThreadExecutor(daemon("obligarth-remote-net"))
    private val ticker: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(daemon("obligarth-remote-tick"))
    private val pendingReports = AtomicInteger(0)
    @Volatile private var device: RemoteDevice? = null
    @Volatile private var accepted: RemoteAccepted? = null
    @Volatile private var live: LiveSession? = null
    /** The connection of the attach while it is not a live stream yet: closed when the session ends meanwhile. */
    @Volatile private var attachSocket: Socket? = null
    @Volatile var isEnded = false
        private set
    /** The grant of the system dialog (Android: the result of createScreenCaptureIntent), for the service. */
    @Volatile var projectionGrant: Any? = null
        private set

    val sessionId: String get() = request.sessionId
    val phase: RemotePhase get() = synchronized(lock) { machine.phase }
    /** The mode told to /accept: the mode asked (§0.1, nobody on the device answers). */
    val consentedMode: RemoteMode get() = machine.consentedMode
    val endCause: RemoteEndCause? get() = synchronized(lock) { machine.endCause }
    val liveSession: LiveSession? get() = live

    /** The session holds its command: running, or its result not handed to the engine yet. */
    val holdsCommand: Boolean get() = !isEnded || pendingReports.get() > 0

    fun start() {
        apply(synchronized(lock) { machine.start(clockMs()) })
        // A fixed delay, not a fixed rate: a process back from the cached state does not run the missed ticks in a burst.
        if (!isEnded) ticker.scheduleWithFixedDelay({ tick() }, timings.tickMs, timings.tickMs, TimeUnit.MILLISECONDS)
    }

    // ------------------------------------------------------------------
    // The system dialog and the device
    // ------------------------------------------------------------------

    /** The answer of the system dialog; [grant] is what the service needs to get the projection. */
    fun projectionResult(granted: Boolean, grant: Any?) {
        if (granted && grant != null) projectionGrant = grant
        apply(synchronized(lock) { machine.projection(granted && grant != null) })
    }

    /** The service and its permanent notification are up: /accept. */
    fun serviceUp(device: RemoteDevice) {
        this.device = device
        apply(synchronized(lock) { machine.serviceUp() })
    }

    /** The service could not start (no projection): the session ends. */
    fun serviceFailed() = end(RemoteEndCause.AGENT_ERROR)

    /** The service went away without being asked to (killed): the session cannot go on. */
    fun serviceGone() = live?.end(RemoteEndCause.AGENT_ERROR) ?: end(RemoteEndCause.AGENT_ERROR)

    private fun end(cause: RemoteEndCause) = apply(synchronized(lock) { machine.end(cause) })

    // ------------------------------------------------------------------
    // Every second: the deadlines
    // ------------------------------------------------------------------

    private fun tick() {
        try {
            if (isEnded) return
            apply(synchronized(lock) { machine.tick(clockMs()) })
            live?.tick()
        } catch (e: Throwable) {
            // A failure must not stop the ticker (a scheduled task stops at its first exception).
            log.warn("remote tick: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // Effects, always outside the lock
    // ------------------------------------------------------------------

    private fun apply(effects: List<RemoteEffect>) {
        for (e in effects) when (e) {
            RemoteEffect.Open -> ui.open(this)
            RemoteEffect.CloseProjection -> ui.closeProjection(this)
            RemoteEffect.StartService -> ui.startService(this)
            RemoteEffect.CallAccept -> onNet { doAccept() }
            RemoteEffect.Attach -> onNet { doAttach() }
            is RemoteEffect.Report -> deliver(e)
            is RemoteEffect.CallEnd -> onNet {
                try {
                    if (!api.end(sessionId, e.reason)) log.warn("remote end ${e.reason} not taken by the server")
                } catch (x: IOException) {
                    log.warn("remote end ${e.reason}: ${x.message}")
                }
            }
            is RemoteEffect.Finish -> finish(e)
        }
    }

    /**
     * The result goes to the engine on a thread of its own: the engine's lock may be held by an interrogation for a
     * while, and neither the ticker nor /end waits for it.
     */
    private fun deliver(r: RemoteEffect.Report) {
        pendingReports.incrementAndGet()
        Thread({
            try {
                report(commandId, r.status, r.code)
                ui.resultQueued()
            } catch (e: Throwable) {
                log.warn("remote result: ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                pendingReports.decrementAndGet()
            }
        }, "obligarth-remote-result").apply { isDaemon = true; start() }
    }

    private fun finish(e: RemoteEffect.Finish) {
        isEnded = true
        ticker.shutdown()
        net.shutdown() // what is queued (/accept answered, /end) still runs
        // An attach still waiting (the upgrade's answer, the hello) is given up now, not at its own time-outs.
        if (live == null) attachSocket?.let { closeQuietly(it) }
        val liveMs = synchronized(lock) { machine.liveSinceMs }?.let { clockMs() - it }
        log.info("remote session $sessionId over: ${e.cause.name.lowercase()}")
        ui.finished(this, e.cause, liveMs)
    }

    private fun onNet(block: () -> Unit) {
        try {
            net.execute {
                try { block() } catch (e: Throwable) {
                    log.warn("remote: ${e.javaClass.simpleName}: ${e.message}")
                    end(RemoteEndCause.AGENT_ERROR)
                }
            }
        } catch (e: RejectedExecutionException) {
            // Ended meanwhile.
        }
    }

    private fun doAccept() {
        val d = device ?: return
        val display = d.display()
        // Told as it is, never a refusal (§0.1, rule 2): the server and the console know whether the user saw it.
        val reading = try { d.indicator() } catch (e: Exception) { IndicatorReading(notificationsEnabled = false, overlayShown = false) }
        val caps = RemoteCapabilities(
            inject = false, remoteInject = false,
            codecs = if (d.h264Available()) listOf(CodecPolicy.H264, CodecPolicy.JPEG) else listOf(CodecPolicy.JPEG),
            width = display.width, height = display.height, notificationsEnabled = reading.notificationsEnabled, overlay = reading.overlayShown,
        )
        val outcome = try {
            api.accept(sessionId, consentedMode, caps)
        } catch (e: IOException) {
            AcceptOutcome.Failed(e.message ?: "network")
        }
        val answer = when (outcome) {
            is AcceptOutcome.Accepted -> { accepted = outcome.accepted; RemoteSessionMachine.AcceptAnswer.Accepted }
            is AcceptOutcome.Refused -> {
                log.warn("remote accept refused: ${outcome.status} ${outcome.code}")
                // Only a refusal that closed the session there is left untold; any other leaves it waiting there.
                if (outcome.closesSession) RemoteSessionMachine.AcceptAnswer.Refused else RemoteSessionMachine.AcceptAnswer.Failed
            }
            is AcceptOutcome.Failed -> {
                log.warn("remote accept failed: ${outcome.reason}")
                RemoteSessionMachine.AcceptAnswer.Failed
            }
        }
        val now = clockMs()
        apply(synchronized(lock) {
            if (outcome is AcceptOutcome.Accepted) machine.connectBy(now + outcome.accepted.expiresIn * 1000 + timings.attachGraceMs)
            machine.accepted(answer)
        })
    }

    private fun doAttach() {
        val acc = accepted ?: return
        val d = device ?: return
        if (isEnded) return
        val channel = try {
            api.attach(sessionId, acc, consentedMode) { socket ->
                attachSocket = socket
                if (isEnded) closeQuietly(socket)
            }
        } catch (e: IOException) {
            if (!isEnded) log.warn("remote attach: ${e.javaClass.simpleName}: ${e.message}")
            return end(RemoteEndCause.AGENT_ERROR)
        } finally {
            attachSocket = null
        }
        val now = clockMs()
        val capMs = request.maxMinutes * 60_000L
        val serverLeftMs = acc.maxEndsAt?.let { ((it - serverNow()) * 1000).coerceIn(0, capMs) } ?: capMs
        val limits = LiveLimits(
            idleMs = (acc.idleSeconds ?: DEFAULT_IDLE_S).coerceIn(MIN_IDLE_S, MAX_IDLE_S) * 1000,
            deadlineMs = now + serverLeftMs + timings.maxGraceMs,
            bitrateMaxKbps = acc.bitrateMax?.coerceIn(1, Int.MAX_VALUE.toLong())?.toInt(),
        )
        val session = LiveSession(channel, d, limits, timings, clockMs, log) { cause -> onLiveEnded(cause) }
        val attached = synchronized(lock) { machine.attached(now).also { if (it) live = session } }
        if (!attached) {
            channel.close()
            return
        }
        log.info("remote session $sessionId live (${session.currentCodec})")
        session.start()
    }

    private fun onLiveEnded(cause: RemoteEndCause) = end(cause)

    companion object {
        const val DEFAULT_IDLE_S = 600L
        const val MIN_IDLE_S = 60L
        const val MAX_IDLE_S = 3_600L

        private fun daemon(name: String) = ThreadFactory { r -> Thread(r, name).apply { isDaemon = true } }
    }
}

/**
 * The remote sessions of the agent (one at a time), the [RemoteHost] of the engine. [report] is set once the engine
 * exists (AgentEngine.onRemoteOutcome).
 */
class RemoteSessions(
    private val api: () -> RemoteApi,
    private val ui: RemoteUi,
    private val serverNow: () -> Long,
    private val log: AgentLog = AgentLog.None,
    private val timings: RemoteTimings = RemoteTimings(),
    /** Monotonic milliseconds (Android: SystemClock.elapsedRealtime). */
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000 },
) : RemoteHost {
    @Volatile var report: (String, ResultStatus, String) -> Unit = { _, _, _ -> }
    @Volatile private var current: RemoteSessionController? = null

    /** Lock-free: the engine asks it under its own lock. */
    override fun activeCommand(): String? = current?.takeIf { it.holdsCommand }?.commandId

    @Synchronized
    override fun open(commandId: String, request: Params.RemoteOpen): String? {
        if (activeCommand() != null) return Codes.AGENT_BUSY
        val s = RemoteSessionController(commandId, request, api(), ui, { id, status, code -> report(id, status, code) }, serverNow, timings, clockMs, log)
        current = s
        log.info("remote session ${request.sessionId} asked (${request.mode.wire})")
        s.start()
        return null
    }

    /** The running session of [commandId] (the screens and the service find theirs here). */
    fun session(commandId: String?): RemoteSessionController? = current?.takeIf { it.commandId == commandId && !it.isEnded }

    val active: RemoteSessionController? get() = current?.takeIf { !it.isEnded }
}
