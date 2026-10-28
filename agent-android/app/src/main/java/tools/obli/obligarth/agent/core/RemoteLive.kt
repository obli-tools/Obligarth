package tools.obli.obligarth.agent.core

import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

// =============================================================================
// Remote assistance, the live stream on the device (P0-15 §0.1, §5, §8): the init
// and its generations, the capture started only while the screen is on (the
// keyguard included, as the logon screen of Oblireach, §0.1 rule 7), the messages
// of the viewer (key request, bitrate, codec, quality), the effective mode sent by
// the server (frame mode), inactivity, screen off, maximum duration. No input is
// injected before the control exists on the device (T8, Knox RemoteInjection).
// =============================================================================

/** What the device shows, read about every second. [rotation] in degrees (0, 90, 180, 270). */
data class DisplayState(val width: Int, val height: Int, val rotation: Int, val screenOn: Boolean, val locked: Boolean) {
    /**
     * A picture may leave: the screen is on. The keyguard is shown too (§0.1, rule 7: the technician works on it as on
     * the logon screen of Oblireach); [locked] is told to the viewer (display_state).
     */
    val available: Boolean get() = screenOn
}

/** One start of the capture: one generation of the init. [kbps] for H.264. */
data class CaptureSpec(val codec: String, val width: Int, val height: Int, val kbps: Int, val gen: Long)

/** Where the capture delivers, from its own threads. */
interface VideoSink {
    /** A complete picture of generation [gen]: an H.264 access unit (SPS/PPS before each IDR) or a JPEG. */
    fun onVideo(gen: Long, frameType: Int, data: ByteArray, key: Boolean)
    /** [codec] failed in generation [gen] (configuration, encoder error). */
    fun onCaptureError(gen: Long, codec: String, reason: String)
    /** The system stopped the projection (another capture took it, or the system's own control). */
    fun onProjectionStopped()
}

/** The screen capture of the session (Android: MediaProjection, VirtualDisplay, MediaCodec or ImageReader). */
interface ScreenCapture {
    /** Starts generation [spec] (stops the one before); throws when it cannot start at all. */
    @Throws(Exception::class)
    fun start(spec: CaptureSpec, sink: VideoSink)
    /** Stops the generation running, if any; the projection stays (another generation may start). */
    fun stop()
    fun requestKeyFrame()
    fun setBitrate(kbps: Int)
    /** Stops for good: the projection ends. */
    fun release()
}

/** The device side of a session once its service is up (Android: ScreenShareService). */
interface RemoteDevice {
    fun display(): DisplayState
    /** Read for /accept only (informative, §0.1). */
    fun indicator(): IndicatorReading
    fun h264Available(): Boolean
    val capture: ScreenCapture

    /**
     * The screen can be shown right now (on), read before each picture leaves: cheap enough for every picture, never a
     * cached value.
     */
    fun screenShowable(): Boolean = true

    /**
     * The screen's events as they happen (Android: ACTION_SCREEN_OFF, ACTION_SCREEN_ON, ACTION_USER_PRESENT), on a
     * thread of the device's: [listener] gets true when the screen went off. Null stops them.
     */
    fun watchScreen(listener: ((off: Boolean) -> Unit)?) = Unit
}

/** The bounds of one live session, from the answer of /accept. */
data class LiveLimits(
    val idleMs: Long,
    /** Monotonic end at the latest (the maximum end of the server plus a margin). */
    val deadlineMs: Long,
    val bitrateMaxKbps: Int?,
)

class LiveSession internal constructor(
    private val channel: RemoteChannel,
    private val device: RemoteDevice,
    private val limits: LiveLimits,
    private val timings: RemoteTimings,
    private val clockMs: () -> Long,
    private val log: AgentLog,
    /** Called once, from any thread, when the session ends for [RemoteEndCause]. */
    private val onEnd: (RemoteEndCause) -> Unit,
) : VideoSink {
    private val lock = Any()
    private val ended = AtomicBoolean(false)
    private val outbox = StreamOutbox()
    private val startMs = clockMs()
    private val monitor = LiveMonitor(startMs, limits.idleMs, timings.idleWarningMs, timings.screenOffMs, limits.deadlineMs)
    private val codec = CodecPolicy(device.h264Available())
    private val bitrate = BitrateController(limits.bitrateMaxKbps)
    @Volatile private var gen = -1L
    private var maxShort = VideoGeometry.DEFAULT_MAX_HEIGHT
    private var display: DisplayState = device.display()
    /**
     * The screen cannot be shown (off): no picture is taken in nor sent. Set at once by a screen event, from outside
     * the lock (a tick may hold it), and cleared only once the screen is seen available again.
     */
    @Volatile private var screenBlocked = !display.available
    /** The generation running: when it started, its first picture. */
    @Volatile private var running = false
    private var runningSince = 0L
    @Volatile private var firstFrameAt = 0L
    @Volatile private var lastSentMs = startMs
    /** Set by the capture threads, handled by the next tick (never restart a capture from its own thread). */
    @Volatile private var captureFailure: Pair<Long, String>? = null
    @Volatile private var projectionStopped = false
    /** The outbox dropped pictures: the bitrate goes down at the next tick. */
    @Volatile private var congested = false
    private var reader: Thread? = null
    private var sender: Thread? = null

    val isEnded: Boolean get() = ended.get()
    val generation: Long get() = synchronized(lock) { gen }
    val currentCodec: String get() = synchronized(lock) { codec.current }

    // ------------------------------------------------------------------
    // Start
    // ------------------------------------------------------------------

    fun start() {
        synchronized(lock) {
            restart()
            outbox.control(RemoteMessages.displayState(display.rotation, display.screenOn, display.locked))
            if (codec.current == CodecPolicy.H264) outbox.control(RemoteMessages.bitrate(bitrate.currentKbps))
        }
        sender = Thread({ sendLoop() }, "obligarth-remote-send").apply { isDaemon = true; start() }
        reader = Thread({ readLoop() }, "obligarth-remote-read").apply { isDaemon = true; start() }
        try {
            device.watchScreen { off -> screenEvent(off) }
        } catch (e: Exception) {
            // The tick (every second) and the check before each picture still hold.
            log.warn("remote screen events: ${e.javaClass.simpleName}")
        }
    }

    /** A new generation: the init again, and the capture when the screen can be shown. */
    private fun restart() {
        stopCapture()
        gen++
        val size = VideoGeometry.fit(display.width, display.height, maxShort,
            if (codec.current == CodecPolicy.H264) VideoGeometry.H264_ALIGN else VideoGeometry.JPEG_ALIGN)
        outbox.clearVideo()
        outbox.control(RemoteMessages.init(gen, size.width, size.height, display.rotation, codec.codecs, codec.current, FEATURES))
        if (!display.available) return
        // Running before the start: a capture may deliver its first picture before start returns.
        running = true
        runningSince = clockMs()
        firstFrameAt = 0
        try {
            device.capture.start(CaptureSpec(codec.current, size.width, size.height, bitrate.currentKbps, gen), this)
        } catch (e: Exception) {
            running = false
            log.warn("remote capture ${codec.current}: ${e.javaClass.simpleName}")
            captureFailure = gen to codec.current
        }
    }

    private fun stopCapture() {
        if (!running) return
        running = false
        try { device.capture.stop() } catch (e: Exception) { log.warn("remote capture stop: ${e.javaClass.simpleName}") }
    }

    // ------------------------------------------------------------------
    // The viewer's messages (reader thread)
    // ------------------------------------------------------------------

    private fun readLoop() {
        try {
            while (!ended.get()) {
                val m = channel.receive() ?: return end(RemoteEndCause.STREAM_CLOSED)
                handle(m)
            }
        } catch (e: IOException) {
            if (!ended.get()) log.warn("remote stream: ${e.javaClass.simpleName}: ${e.message}")
            end(RemoteEndCause.AGENT_ERROR)
        }
    }

    internal fun handle(m: RemoteInbound) {
        if (m is RemoteInbound.SessionEnd) return end(RemoteEndCause.SERVER_ENDED)
        synchronized(lock) {
            if (ended.get()) return
            val now = clockMs()
            when (m) {
                RemoteInbound.KeepAlive -> monitor.activity(now)
                RemoteInbound.KeyRequest -> {
                    monitor.activity(now)
                    if (running) device.capture.requestKeyFrame()
                }
                is RemoteInbound.SetBitrate -> {
                    monitor.activity(now)
                    bitrate.setTarget(m.kbps, now)?.let { applyBitrate(it) }
                    outbox.control(RemoteMessages.bitrate(bitrate.currentKbps))
                }
                is RemoteInbound.SetCodec -> {
                    monitor.activity(now)
                    if (codec.request(m.codec)) restart()
                    else if (m.codec != codec.current) outbox.control(RemoteMessages.error("codec_unavailable", false))
                }
                is RemoteInbound.Quality -> {
                    monitor.activity(now)
                    if (m.maxHeight != maxShort) {
                        maxShort = m.maxHeight
                        restart()
                    }
                }
                // The server moved the effective mode, after the technician's checks (§0.1, rule 3): applied as sent.
                is RemoteInbound.Mode -> applyMode(m.effective)
                // Inputs never pass the gate in view (§5.3); none is injected before T8 whatever the gate says.
                else -> Unit
            }
        }
    }

    /**
     * The effective mode sent by the server (frame mode): the gate follows it. A control this device cannot exercise
     * yet (no injection before T8) is told to the viewer; the session goes on.
     */
    private fun applyMode(mode: RemoteMode) {
        if (channel.gate.mode == mode) return
        channel.gate.apply(mode)
        log.info("remote session ${channel.sessionId} mode ${mode.wire}")
        if (mode == RemoteMode.CONTROL && !INJECTION) outbox.control(RemoteMessages.inputUnavailable(Codes.REMOTE_INJECTION_UNAVAILABLE))
    }

    private fun applyBitrate(kbps: Int) {
        if (running && codec.current == CodecPolicy.H264) device.capture.setBitrate(kbps)
    }

    // ------------------------------------------------------------------
    // The pictures (capture threads) and what leaves (sender thread)
    // ------------------------------------------------------------------

    /** From the capture's thread: never the session's lock (a capture that stops waits for this thread). */
    override fun onVideo(gen: Long, frameType: Int, data: ByteArray, key: Boolean) {
        if (ended.get() || screenBlocked || gen != this.gen || !running) return
        if (firstFrameAt == 0L) firstFrameAt = clockMs()
        val offer = outbox.video(VideoFrame(frameType, data, key))
        if (offer is StreamOutbox.Offer.Dropped) {
            if (offer.congestion) congested = true
            if (offer.needKey) device.capture.requestKeyFrame()
        }
    }

    override fun onCaptureError(gen: Long, codec: String, reason: String) {
        log.warn("remote capture $codec failed: $reason")
        captureFailure = gen to codec
    }

    override fun onProjectionStopped() {
        projectionStopped = true
    }

    private fun sendLoop() {
        try {
            while (true) {
                val item = outbox.take(SEND_POLL_MS)
                when (item) {
                    is StreamOutbox.Item.Control -> channel.send(item.message)
                    is StreamOutbox.Item.Video -> if (showable()) {
                        channel.sendVideo(item.frame.frameType, item.frame.data)
                    } else {
                        // The screen went off between two ticks: what waits goes, and the next picture sent is a key
                        // frame (the tick takes the screen's state).
                        outbox.clearVideo()
                    }
                    null -> if (ended.get()) return
                }
                if (item != null) lastSentMs = clockMs()
                if (!ended.get()) channel.tick()
            }
        } catch (e: IOException) {
            if (!ended.get()) {
                log.warn("remote send: ${e.javaClass.simpleName}: ${e.message}")
                end(RemoteEndCause.AGENT_ERROR)
            }
        }
    }

    /** The screen as read now, before a picture leaves. */
    private fun showable(): Boolean {
        if (screenBlocked) return false
        return try { device.screenShowable() } catch (e: Exception) { false }
    }

    /**
     * A screen event, on the device's thread: the screen off stops the capture and drops what waits at once, without
     * waiting for the tick; on or unlocked, the screen is read again (a capture starts again only when it is on).
     */
    internal fun screenEvent(off: Boolean) {
        if (ended.get()) return
        if (off) screenBlocked = true
        synchronized(lock) {
            if (ended.get()) return
            val d = try { device.display() } catch (e: Exception) { display }
            applyDisplay(if (off) d.copy(screenOn = false) else d)
        }
    }

    /** What the screen shows changed (under the lock): told to the viewer; the capture stops, or starts again. */
    private fun applyDisplay(d: DisplayState) {
        if (d == display) return
        val before = display
        display = d
        if (d.rotation != before.rotation || d.screenOn != before.screenOn || d.locked != before.locked) {
            outbox.control(RemoteMessages.displayState(d.rotation, d.screenOn, d.locked))
        }
        when {
            !d.available -> { screenBlocked = true; stopCapture(); outbox.clearVideo() }
            !before.available || d.width != before.width || d.height != before.height || d.rotation != before.rotation -> {
                screenBlocked = false
                restart()
            }
        }
    }

    // ------------------------------------------------------------------
    // Every second (the controller's ticker): never any network here
    // ------------------------------------------------------------------

    fun tick() {
        if (ended.get()) return
        val now = clockMs()
        if (projectionStopped) return end(RemoteEndCause.PROJECTION_STOPPED)
        var finalCause: RemoteEndCause? = null
        synchronized(lock) {
            captureFailure?.let { (g, c) ->
                captureFailure = null
                if (g == gen) {
                    if (codec.failed(c)) restart() else { finalCause = RemoteEndCause.AGENT_ERROR; return@synchronized }
                }
            }
            // The screen's events act at once (screenEvent); this reading is the safety net.
            val d = try { device.display() } catch (e: Exception) { display }
            applyDisplay(d)
            if (running && codec.current == CodecPolicy.H264 && firstFrameAt == 0L && now - runningSince >= timings.codecStallMs) {
                log.warn("remote h264: no output in ${timings.codecStallMs} ms, JPEG fallback")
                codec.failed(CodecPolicy.H264)
                restart()
            }
            when (val e = monitor.tick(now, d.available)) {
                is LiveEvent.IdleWarning -> outbox.control(RemoteMessages.inactivityWarning(e.seconds))
                LiveEvent.IdleTimeout -> { outbox.control(RemoteMessages.inactivityTimeout()); finalCause = RemoteEndCause.IDLE }
                LiveEvent.ScreenOffTimeout -> finalCause = RemoteEndCause.SCREEN_OFF_TIMEOUT
                LiveEvent.MaxDuration -> finalCause = RemoteEndCause.MAX_DURATION
                null -> Unit
            }
            if (finalCause == null) {
                if (congested) {
                    congested = false
                    if (codec.current == CodecPolicy.H264) bitrate.congested(now)?.let { applyBitrate(it); outbox.control(RemoteMessages.bitrate(it)) }
                }
                bitrate.tick(now)?.let { applyBitrate(it); outbox.control(RemoteMessages.bitrate(it)) }
                if (now - lastSentMs >= timings.keepaliveMs && outbox.pendingControl == 0) outbox.control(RemoteMessages.keepalive())
            }
        }
        finalCause?.let { end(it) }
    }

    // ------------------------------------------------------------------
    // End
    // ------------------------------------------------------------------

    /**
     * Ends the session once: the capture and the projection stop at once (on the calling thread), the last control
     * messages leave (error projection_stopped when the system took the projection), then the stream closes on a
     * thread of its own, and [onEnd] is called.
     */
    fun end(cause: RemoteEndCause) {
        if (!ended.compareAndSet(false, true)) return
        try { device.watchScreen(null) } catch (e: Exception) { log.warn("remote screen events: ${e.javaClass.simpleName}") }
        synchronized(lock) { running = false }
        try { device.capture.stop() } catch (e: Exception) { log.warn("remote capture stop: ${e.javaClass.simpleName}") }
        try { device.capture.release() } catch (e: Exception) { log.warn("remote projection stop: ${e.javaClass.simpleName}") }
        if (cause == RemoteEndCause.PROJECTION_STOPPED) outbox.control(RemoteMessages.error("projection_stopped", false))
        outbox.close()
        val closing = cause != RemoteEndCause.STREAM_CLOSED && cause != RemoteEndCause.AGENT_ERROR
        Thread({
            if (closing) {
                // The sender takes the control messages left, then stops (the outbox is closed).
                val deadline = clockMs() + timings.flushMs
                while (outbox.pendingControl > 0 && clockMs() < deadline) Thread.sleep(20)
                sender?.join(Math.max(1, deadline - clockMs()))
                try { channel.close() } catch (e: Exception) { channel.abort() }
            } else {
                channel.abort()
            }
        }, "obligarth-remote-close").apply { isDaemon = true; start() }
        log.info("remote session ${channel.sessionId} ended: ${cause.name.lowercase()}")
        onEnd(cause)
    }

    companion object {
        /** No touch, nav, type_text nor key before the control exists on the device (T8). */
        val FEATURES = listOf("quality", "display_state")
        /** Knox RemoteInjection on this device: never before T8. */
        const val INJECTION = false
        const val SEND_POLL_MS = 200L
    }
}
