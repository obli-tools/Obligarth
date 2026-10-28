package tools.obli.obligarth.agent

import android.app.KeyguardManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaFormat
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.DisplayMetrics
import android.view.Display
import android.view.Gravity
import android.view.Surface
import android.view.View
import android.view.WindowManager
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.CaptureSpec
import tools.obli.obligarth.agent.core.CodecPolicy
import tools.obli.obligarth.agent.core.DisplayState
import tools.obli.obligarth.agent.core.H264Framer
import tools.obli.obligarth.agent.core.IndicatorReading
import tools.obli.obligarth.agent.core.RemoteDevice
import tools.obli.obligarth.agent.core.RemoteFrames
import tools.obli.obligarth.agent.core.ScreenCapture
import tools.obli.obligarth.agent.core.VideoSink
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

// =============================================================================
// Remote assistance, the capture (P0-15 §0.1, §8): the foreground service and its
// permanent notification (the watermark of the session, no Stop), the border drawn
// over the screen when the agent may, MediaProjection → VirtualDisplay → MediaCodec
// H.264 (surface input, SPS/PPS before each IDR), JPEG by ImageReader as the
// fallback. Nothing is injected before the control (T8).
// =============================================================================

/**
 * The session's foreground service (targetSdk 25: no service type; startService from the background is allowed).
 * Holds the projection; its notification stays all along the session ("Assistance session in progress: <technician>").
 * Not exported.
 */
class ScreenShareService : Service() {
    private var device: AndroidRemoteDevice? = null
    private var commandId: String? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val rt = AgentRuntime.get(this)
        val id = intent?.getStringExtra(ProjectionRequestActivity.EXTRA_COMMAND)
        if (intent?.action == ACTION_START) begin(rt, id)
        if (device == null && rt.remoteSessions.active == null) stopSelf()
        return START_NOT_STICKY
    }

    private fun begin(rt: AgentRuntime, id: String?) {
        val s = rt.remoteSessions.session(id) ?: return
        if (device != null) return
        commandId = id
        startForeground(RemoteNotifications.ID_LIVE, RemoteNotifications.live(this, s))
        val grant = s.projectionGrant as? ProjectionGrant
        val projection = try {
            grant?.let { (getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager).getMediaProjection(it.resultCode, it.data) }
        } catch (e: Exception) {
            rt.log.warn("remote projection: ${e.javaClass.simpleName}")
            null
        }
        if (projection == null) {
            s.serviceFailed()
            return
        }
        val overlay = if (Settings.canDrawOverlays(this)) BorderOverlay(this).takeIf { it.show() } else null
        val d = AndroidRemoteDevice(this, projection, overlay, rt.log)
        device = d
        s.serviceUp(d)
    }

    override fun onDestroy() {
        device?.release()
        device = null
        // Killed without being asked: the session cannot go on without its projection nor its notification.
        AgentRuntime.get(this).remoteSessions.session(commandId)?.serviceGone()
        super.onDestroy()
    }

    companion object {
        private const val ACTION_START = "tools.obli.obligarth.agent.action.REMOTE_START"

        fun start(ctx: Context, commandId: String): Boolean = try {
            ctx.startService(Intent(ctx, ScreenShareService::class.java).setAction(ACTION_START).putExtra(ProjectionRequestActivity.EXTRA_COMMAND, commandId)) != null
        } catch (e: Exception) {
            AgentRuntime.get(ctx).log.warn("remote service: ${e.javaClass.simpleName}")
            false
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, ScreenShareService::class.java))
        }
    }
}

/** [RemoteDevice] on Android: the screen, the notifications told to /accept, the encoder of the device. */
class AndroidRemoteDevice(
    context: Context,
    projection: MediaProjection,
    private val overlay: BorderOverlay?,
    private val log: AgentLog,
) : RemoteDevice {
    private val app = context.applicationContext
    private val displays = app.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
    private val power = app.getSystemService(Context.POWER_SERVICE) as PowerManager
    private val keyguard = app.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    private val h264 = AndroidScreenCapture.h264Encoder()
    override val capture = AndroidScreenCapture(projection, context.resources.displayMetrics.densityDpi, h264, log)
    private var screenReceiver: BroadcastReceiver? = null
    private var screenThread: HandlerThread? = null

    /** The keyguard is shown too (§0.1, rule 7). */
    override fun screenShowable(): Boolean = power.isInteractive

    /**
     * The screen's events on a thread of their own (stopping a capture waits for its encoder thread: never the main
     * thread). Registered at run time: ACTION_SCREEN_OFF and ACTION_SCREEN_ON reach no receiver of the manifest.
     */
    @Synchronized
    override fun watchScreen(listener: ((off: Boolean) -> Unit)?) {
        screenReceiver?.let {
            try { app.unregisterReceiver(it) } catch (e: Exception) { /* not registered */ }
        }
        screenReceiver = null
        screenThread?.quitSafely()
        screenThread = null
        if (listener == null) return
        val thread = HandlerThread("obligarth-remote-screen").apply { start() }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                try {
                    listener(intent.action == Intent.ACTION_SCREEN_OFF)
                } catch (e: Exception) {
                    log.warn("remote screen event: ${e.javaClass.simpleName}")
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        try {
            app.registerReceiver(receiver, filter, null, Handler(thread.looper))
            screenReceiver = receiver
            screenThread = thread
        } catch (e: Exception) {
            thread.quitSafely()
            throw e
        }
    }

    override fun display(): DisplayState {
        val d = displays.getDisplay(Display.DEFAULT_DISPLAY)
        val m = DisplayMetrics()
        @Suppress("DEPRECATION") d.getRealMetrics(m)
        val rotation = when (d.rotation) {
            Surface.ROTATION_90 -> 90
            Surface.ROTATION_180 -> 180
            Surface.ROTATION_270 -> 270
            else -> 0
        }
        return DisplayState(m.widthPixels, m.heightPixels, rotation, power.isInteractive, keyguard.isKeyguardLocked)
    }

    override fun indicator() = IndicatorReading(
        notificationsEnabled = RemoteNotifications.enabled(app),
        overlayShown = overlay?.isShown == true,
    )

    override fun h264Available(): Boolean = h264 != null

    /** The projection and the border go (main thread). */
    fun release() {
        watchScreen(null)
        capture.release()
        overlay?.remove()
    }
}

/**
 * The capture by MediaProjection: one VirtualDisplay per generation, mirrored into the encoder's input surface (H.264)
 * or into an ImageReader (JPEG). The projection's own end (the system's stop) is reported to the session.
 */
class AndroidScreenCapture(
    private val projection: MediaProjection,
    private val dpi: Int,
    private val h264Codec: String?,
    private val log: AgentLog,
) : ScreenCapture {
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var sink: VideoSink? = null
    @Volatile private var pipeline: Pipeline? = null
    @Volatile private var released = false
    private val callback = object : MediaProjection.Callback() {
        override fun onStop() {
            if (!released) sink?.onProjectionStopped()
        }
    }

    init {
        projection.registerCallback(callback, main)
    }

    @Synchronized
    override fun start(spec: CaptureSpec, sink: VideoSink) {
        stop()
        check(!released) { "projection released" }
        this.sink = sink
        val p = if (spec.codec == CodecPolicy.H264) {
            H264Pipeline(projection, spec, dpi, h264Codec ?: throw IllegalStateException("no H.264 encoder"), sink, log)
        } else {
            JpegPipeline(projection, spec, dpi, sink, log)
        }
        p.start()
        pipeline = p
    }

    @Synchronized
    override fun stop() {
        pipeline?.stop()
        pipeline = null
    }

    override fun requestKeyFrame() {
        pipeline?.requestKeyFrame()
    }

    override fun setBitrate(kbps: Int) {
        pipeline?.setBitrate(kbps)
    }

    @Synchronized
    override fun release() {
        if (released) return
        released = true
        stop()
        try {
            projection.unregisterCallback(callback)
            projection.stop()
        } catch (e: Exception) {
            log.warn("remote projection stop: ${e.javaClass.simpleName}")
        }
    }

    private interface Pipeline {
        fun start()
        fun stop()
        fun requestKeyFrame()
        fun setBitrate(kbps: Int)
    }

    /** VirtualDisplay → encoder input surface → access units (SPS/PPS before each IDR, H264Framer). */
    private class H264Pipeline(
        private val projection: MediaProjection,
        private val spec: CaptureSpec,
        private val dpi: Int,
        codecName: String,
        private val sink: VideoSink,
        private val log: AgentLog,
    ) : Pipeline {
        private val codec = MediaCodec.createByCodecName(codecName)
        private val framer = H264Framer()
        private var surface: Surface? = null
        private var display: VirtualDisplay? = null
        private var thread: Thread? = null
        @Volatile private var running = false

        override fun start() {
            try {
                try {
                    codec.configure(format(withProfile = true), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                } catch (e: Exception) {
                    // Some encoders refuse an explicit profile: the default one (baseline or main, both decoded).
                    codec.reset()
                    codec.configure(format(withProfile = false), null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
                }
                val input = codec.createInputSurface()
                surface = input
                codec.start()
                display = projection.createVirtualDisplay(
                    "obligarth-remote", spec.width, spec.height, dpi, DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, input, null, null,
                )
                running = true
                thread = Thread({ drain() }, "obligarth-remote-h264").apply { isDaemon = true; start() }
            } catch (e: Exception) {
                stop()
                throw e
            }
        }

        private fun format(withProfile: Boolean) = MediaFormat.createVideoFormat(MIME, spec.width, spec.height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, spec.kbps * 1000)
            setInteger(MediaFormat.KEY_FRAME_RATE, FRAME_RATE)
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, I_FRAME_SECONDS)
            // A still screen produces no frame: the last one is repeated so that a key request is answered.
            setLong(MediaFormat.KEY_REPEAT_PREVIOUS_FRAME_AFTER, REPEAT_US)
            if (withProfile) setInteger(MediaFormat.KEY_PROFILE, MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline)
        }

        private fun drain() {
            val info = MediaCodec.BufferInfo()
            try {
                while (running) {
                    val index = codec.dequeueOutputBuffer(info, DEQUEUE_US)
                    if (index == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                        csd(codec.outputFormat)?.let { framer.config(it) }
                        continue
                    }
                    if (index < 0) continue
                    val buffer = codec.getOutputBuffer(index)
                    if (buffer != null && info.size > 0) {
                        val bytes = ByteArray(info.size)
                        buffer.position(info.offset)
                        buffer.limit(info.offset + info.size)
                        buffer.get(bytes)
                        if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                            framer.config(bytes)
                        } else {
                            when (val out = framer.frame(bytes, info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0)) {
                                is H264Framer.Out.Emit -> sink.onVideo(spec.gen, RemoteFrames.VIDEO_H264, out.data, out.key)
                                is H264Framer.Out.Drop -> if (out.needKey) requestKeyFrame()
                            }
                        }
                    }
                    codec.releaseOutputBuffer(index, false)
                    if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) break
                }
            } catch (e: Exception) {
                if (running) sink.onCaptureError(spec.gen, CodecPolicy.H264, e.javaClass.simpleName)
            }
        }

        /** csd-0 (SPS) then csd-1 (PPS), Annex B. */
        private fun csd(f: MediaFormat): ByteArray? {
            val parts = listOf("csd-0", "csd-1").mapNotNull { key -> f.getByteBuffer(key)?.let { b -> ByteArray(b.remaining()).also { b.duplicate().get(it) } } }
            if (parts.isEmpty()) return null
            return parts.reduce { a, b -> a + b }
        }

        override fun requestKeyFrame() {
            if (!running) return
            try {
                codec.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) })
            } catch (e: IllegalStateException) {
                // Stopping.
            }
        }

        override fun setBitrate(kbps: Int) {
            if (!running) return
            try {
                codec.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_VIDEO_BITRATE, kbps * 1000) })
            } catch (e: IllegalStateException) {
                // Stopping.
            }
        }

        override fun stop() {
            running = false
            try { display?.release() } catch (e: Exception) { log.warn("remote display: ${e.javaClass.simpleName}") }
            display = null
            thread?.let { if (it !== Thread.currentThread()) it.join(JOIN_MS) }
            thread = null
            try { codec.stop() } catch (e: Exception) { /* not started or already stopped */ }
            try { codec.release() } catch (e: Exception) { /* released */ }
            surface?.release()
            surface = null
        }
    }

    /** VirtualDisplay → ImageReader → JPEG, 5 frames per second at most, only when the screen changed. */
    private class JpegPipeline(
        private val projection: MediaProjection,
        private val spec: CaptureSpec,
        private val dpi: Int,
        private val sink: VideoSink,
        private val log: AgentLog,
    ) : Pipeline {
        private val reader = ImageReader.newInstance(spec.width, spec.height, PixelFormat.RGBA_8888, 2)
        private var display: VirtualDisplay? = null
        private var thread: Thread? = null
        @Volatile private var running = false
        @Volatile private var keyWanted = false
        private var last: ByteArray? = null
        private var bitmap: Bitmap? = null
        private var scratch: ByteBuffer? = null

        override fun start() {
            try {
                display = projection.createVirtualDisplay(
                    "obligarth-remote", spec.width, spec.height, dpi, DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, reader.surface, null, null,
                )
                running = true
                thread = Thread({ loop() }, "obligarth-remote-jpeg").apply { isDaemon = true; start() }
            } catch (e: Exception) {
                stop()
                throw e
            }
        }

        private fun loop() {
            var next = 0L
            try {
                while (running) {
                    val now = SystemClock.elapsedRealtime()
                    if (now < next) {
                        Thread.sleep(next - now)
                        continue
                    }
                    next = now + JPEG_INTERVAL_MS
                    val image = try { reader.acquireLatestImage() } catch (e: IllegalStateException) { null }
                    if (image == null) {
                        // Nothing changed: a key request is answered with the last picture.
                        if (keyWanted) {
                            keyWanted = false
                            last?.let { sink.onVideo(spec.gen, RemoteFrames.VIDEO_JPEG, it, true) }
                        }
                        continue
                    }
                    val jpeg = try { encode(image) } finally { image.close() }
                    keyWanted = false
                    last = jpeg
                    sink.onVideo(spec.gen, RemoteFrames.VIDEO_JPEG, jpeg, true)
                }
            } catch (e: InterruptedException) {
                // Stopping.
            } catch (e: Exception) {
                if (running) sink.onCaptureError(spec.gen, CodecPolicy.JPEG, e.javaClass.simpleName)
            }
        }

        private fun encode(image: android.media.Image): ByteArray {
            val plane = image.planes[0]
            val pixelStride = plane.pixelStride
            val rowStride = plane.rowStride
            val w = spec.width
            val h = spec.height
            val paddedWidth = rowStride / pixelStride
            val need = rowStride * h
            var src = plane.buffer
            src.rewind()
            if (src.remaining() < need) {
                // The last row may be shorter than the stride: copied into a buffer of the full size.
                val s = scratch?.takeIf { it.capacity() >= need } ?: ByteBuffer.allocateDirect(need).also { scratch = it }
                s.clear()
                s.put(src)
                s.rewind()
                src = s
            }
            val bmp = bitmap?.takeIf { it.width == paddedWidth && it.height == h }
                ?: Bitmap.createBitmap(paddedWidth, h, Bitmap.Config.ARGB_8888).also { bitmap?.recycle(); bitmap = it }
            bmp.copyPixelsFromBuffer(src)
            val out = ByteArrayOutputStream(64 * 1024)
            if (paddedWidth == w) {
                bmp.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
            } else {
                val cropped = Bitmap.createBitmap(bmp, 0, 0, w, h)
                cropped.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, out)
                cropped.recycle()
            }
            return out.toByteArray()
        }

        override fun requestKeyFrame() {
            keyWanted = true
        }

        override fun setBitrate(kbps: Int) = Unit

        override fun stop() {
            running = false
            try { display?.release() } catch (e: Exception) { log.warn("remote display: ${e.javaClass.simpleName}") }
            display = null
            thread?.let { if (it !== Thread.currentThread()) { it.interrupt(); it.join(JOIN_MS) } }
            thread = null
            try { reader.close() } catch (e: Exception) { /* closed */ }
            bitmap?.recycle()
            bitmap = null
        }
    }

    companion object {
        private const val MIME = MediaFormat.MIMETYPE_VIDEO_AVC
        private const val FRAME_RATE = 30
        /** An IDR every 2 s (§8). */
        private const val I_FRAME_SECONDS = 2
        private const val REPEAT_US = 200_000L
        private const val DEQUEUE_US = 100_000L
        private const val JOIN_MS = 1_000L
        /** 5 pictures per second, quality 60 (§8). */
        private const val JPEG_INTERVAL_MS = 200L
        private const val JPEG_QUALITY = 60

        /** An H.264 encoder that takes a surface as its input, the hardware ones first; null when none. */
        fun h264Encoder(): String? = try {
            MediaCodecList(MediaCodecList.REGULAR_CODECS).codecInfos
                .filter { info -> info.isEncoder && info.supportedTypes.any { it.equals(MIME, ignoreCase = true) } }
                .filter { info ->
                    try {
                        MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface in info.getCapabilitiesForType(MIME).colorFormats
                    } catch (e: Exception) {
                        false
                    }
                }
                .sortedBy { softwareCodec(it) }
                .firstOrNull()?.name
        } catch (e: Exception) {
            null
        }

        private fun softwareCodec(info: MediaCodecInfo): Boolean =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) info.isSoftwareOnly
            else info.name.startsWith("OMX.google.") || info.name.startsWith("c2.android.")
    }
}

/**
 * The coloured border around the screen while the screen is shared (§8), next to the permanent notification, when the
 * agent may draw over other apps
 * (SYSTEM_ALERT_WINDOW granted): four thin windows along the edges, never one over the whole screen. A window of
 * another app over a touch marks it obscured, and the dialogs that filter such touches (permissions, installer)
 * would refuse every gesture of the user for the whole session; only a touch on the edges is marked now. Never takes a
 * touch; translucent enough for Android 12 to let touches through it.
 */
class BorderOverlay(context: Context) {
    private val wm = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val stroke = (STROKE_DP * context.resources.displayMetrics.density).toInt().coerceAtLeast(1)
    private val edges = listOf(Gravity.TOP, Gravity.BOTTOM, Gravity.LEFT, Gravity.RIGHT).map { Edge(context, it) }

    /** One edge: a band of [COLOR], its own window. */
    private class Edge(context: Context, val gravity: Int) : View(context) {
        @Volatile var attached = false
        @Volatile var visible = false

        init {
            setBackgroundColor(COLOR)
        }

        override fun onAttachedToWindow() {
            super.onAttachedToWindow()
            attached = true
        }

        override fun onDetachedFromWindow() {
            attached = false
            super.onDetachedFromWindow()
        }

        override fun onWindowVisibilityChanged(v: Int) {
            super.onWindowVisibilityChanged(v)
            visible = v == View.VISIBLE
        }
    }

    /** On screen now: the four edges attached and visible; read from the session's ticker. */
    val isShown: Boolean get() = edges.all { it.attached && it.visible }

    /** Main thread: the four edges, or none. */
    fun show(): Boolean {
        @Suppress("DEPRECATION")
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        else WindowManager.LayoutParams.TYPE_PHONE
        return try {
            for (e in edges) {
                val horizontal = e.gravity == Gravity.TOP || e.gravity == Gravity.BOTTOM
                val lp = WindowManager.LayoutParams(
                    if (horizontal) WindowManager.LayoutParams.MATCH_PARENT else stroke,
                    if (horizontal) stroke else WindowManager.LayoutParams.MATCH_PARENT,
                    type,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT,
                ).apply {
                    gravity = e.gravity
                    alpha = 0.8f
                }
                wm.addView(e, lp)
                e.visible = true
            }
            true
        } catch (x: Exception) {
            remove()
            false
        }
    }

    /** Main thread. */
    fun remove() {
        for (e in edges) {
            try {
                wm.removeViewImmediate(e)
            } catch (x: Exception) {
                // Not attached.
            }
            e.visible = false
        }
    }

    companion object {
        private val COLOR = Color.rgb(0xF5, 0x7C, 0x00)
        private const val STROKE_DP = 6f
    }
}
