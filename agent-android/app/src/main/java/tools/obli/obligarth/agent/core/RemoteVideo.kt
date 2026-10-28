package tools.obli.obligarth.agent.core

import java.util.ArrayDeque

// =============================================================================
// Remote assistance, the picture (P0-15 §5.1, §8, T7b): the size of the capture,
// the choice of the codec (H.264 by MediaCodec, JPEG fallback), the access units of
// H.264 (Annex B, SPS/PPS before each IDR), the adaptive bitrate, and the queue of
// what leaves (control messages never dropped, video dropped up to the next key
// frame when the link cannot follow). Pure JVM: MediaCodec stays in RemoteCapture.kt.
// =============================================================================

data class VideoSize(val width: Int, val height: Int)

object VideoGeometry {
    /** 720p by default (§8); the viewer asks 480, 720 or 1080 (quality). */
    const val DEFAULT_MAX_HEIGHT = 720
    /** The long side never above this (H.264 level 4.1 of the encoders of the fleet). */
    const val MAX_LONG_SIDE = 1920
    /** H.264 encoders want multiples of 16; JPEG takes any even size. */
    const val H264_ALIGN = 16
    const val JPEG_ALIGN = 2

    /**
     * The size of the picture for a screen of [screenWidth] x [screenHeight]: the short side at most [maxShort], the
     * long side at most [MAX_LONG_SIDE], the ratio kept, never enlarged, each side a multiple of [align].
     */
    fun fit(screenWidth: Int, screenHeight: Int, maxShort: Int, align: Int): VideoSize {
        require(screenWidth > 0 && screenHeight > 0 && maxShort > 0 && align > 0)
        // Integers only: 1080 x (720 / 1080) in floating point is 719.99..., one alignment step too low.
        val short = Math.min(screenWidth, screenHeight).toLong()
        val long = Math.max(screenWidth, screenHeight).toLong()
        var s = Math.min(short, maxShort.toLong())
        var l = long * s / short
        if (l > MAX_LONG_SIDE) {
            l = MAX_LONG_SIDE.toLong()
            s = short * MAX_LONG_SIDE / long
        }
        fun aligned(v: Long) = ((v / align) * align).toInt().coerceAtLeast(align)
        return if (screenWidth <= screenHeight) VideoSize(aligned(s), aligned(l)) else VideoSize(aligned(l), aligned(s))
    }
}

/**
 * H.264 when the device has a surface encoder, JPEG otherwise; the viewer may ask either (set_codec); an H.264 failure
 * (configuration, error, no output) falls back to JPEG for the rest of the session and leaves the list announced.
 */
class CodecPolicy(h264Available: Boolean) {
    private var h264Usable = h264Available
    var current: String = if (h264Available) H264 else JPEG
        private set

    /** The codecs of the init, in order of preference. */
    val codecs: List<String> get() = if (h264Usable) listOf(H264, JPEG) else listOf(JPEG)

    /** set_codec: true when the codec changes. H.264 asked but unusable stays on JPEG. */
    fun request(codec: String): Boolean {
        val next = if (codec == H264 && h264Usable) H264 else JPEG
        if (next == current) return false
        current = next
        return true
    }

    /** [codec] failed: true when the session moves to JPEG. */
    fun failed(codec: String): Boolean {
        if (codec != H264) return false
        h264Usable = false
        if (current != H264) return false
        current = JPEG
        return true
    }

    companion object {
        const val H264 = "h264"
        const val JPEG = "jpeg"
    }
}

/**
 * The access units the agent sends (§5.1): Annex B, the SPS and PPS of the encoder put before each IDR (the viewer
 * reads them in line), nothing before the first IDR, nothing after a drop until the next IDR.
 */
class H264Framer(private val maxAccessUnit: Int = MAX_ACCESS_UNIT) {
    sealed class Out {
        class Emit(val data: ByteArray, val key: Boolean) : Out()
        /** Dropped; [needKey]: a sync frame is to be asked of the encoder. */
        class Drop(val needKey: Boolean) : Out()
    }

    private var config: ByteArray? = null
    private var waitingKey = true

    val hasConfig: Boolean get() = config != null

    /**
     * The codec configuration (BUFFER_FLAG_CODEC_CONFIG, csd-0 then csd-1, or an access unit that carries them in
     * line): Annex B with an SPS and a PPS. Only those units are kept, with their start codes: a picture of the buffer
     * (an IDR written in line with them) is never put again before the next IDR.
     */
    fun config(data: ByteArray): Boolean {
        val units = nalUnits(data) ?: return false
        val kept = units.filter { it.type == NAL_SPS || it.type == NAL_PPS }
        if (kept.none { it.type == NAL_SPS } || kept.none { it.type == NAL_PPS }) return false
        val out = java.io.ByteArrayOutputStream()
        for (u in kept) out.write(data, u.from, u.to - u.from)
        config = out.toByteArray()
        return true
    }

    /** After a frame was dropped downstream (the queue was full): everything waits for the next IDR. */
    fun requireKey() {
        waitingKey = true
    }

    /** One output buffer of the encoder; [keyFlag]: BUFFER_FLAG_KEY_FRAME. */
    fun frame(data: ByteArray, keyFlag: Boolean): Out {
        val types = nalTypes(data) ?: return Out.Drop(false)
        val idr = NAL_IDR in types
        // An encoder that writes its SPS/PPS in line keeps them for the next IDR too.
        if (NAL_SPS in types && NAL_PPS in types) config(data)
        if (waitingKey && !idr) return Out.Drop(!keyFlag)
        val prefix = if (idr && NAL_SPS !in types) config ?: return Out.Drop(true) else null
        val size = data.size + (prefix?.size ?: 0)
        if (size > maxAccessUnit) {
            waitingKey = true
            return Out.Drop(true)
        }
        waitingKey = false
        if (prefix == null) return Out.Emit(data, idr)
        val out = ByteArray(size)
        System.arraycopy(prefix, 0, out, 0, prefix.size)
        System.arraycopy(data, 0, out, prefix.size, data.size)
        return Out.Emit(out, true)
    }

    companion object {
        const val NAL_IDR = 5
        const val NAL_SPS = 7
        const val NAL_PPS = 8
        /** Under the 2 MiB of a WebSocket message and of the relay's buffer (§4.1). */
        const val MAX_ACCESS_UNIT = 1024 * 1024

        /** The NAL unit types of an Annex B buffer; null when it does not start with a start code or holds none. */
        fun nalTypes(data: ByteArray): List<Int>? = nalUnits(data)?.map { it.type }

        /** One NAL unit of an Annex B buffer: its [type], its bytes from its start code ([from]) to the next one ([to]). */
        class NalUnit(val type: Int, val from: Int, val to: Int)

        /** The NAL units of an Annex B buffer; null when it does not start with a start code or holds none. */
        fun nalUnits(data: ByteArray): List<NalUnit>? {
            if (startCodeAt(data, 0) == 0) return null
            // (start code, header) of each unit.
            val starts = ArrayList<IntArray>()
            var i = 0
            while (i < data.size) {
                val sc = startCodeAt(data, i)
                if (sc > 0) {
                    val h = i + sc
                    if (h < data.size) {
                        if (data[h].toInt() and 0x80 != 0) return null // forbidden_zero_bit
                        starts += intArrayOf(i, h)
                    }
                    i = h + 1
                } else {
                    i++
                }
            }
            if (starts.isEmpty()) return null
            return starts.mapIndexed { k, s ->
                NalUnit(data[s[1]].toInt() and 0x1f, s[0], if (k + 1 < starts.size) starts[k + 1][0] else data.size)
            }
        }

        /** 3 or 4 when a start code (00 00 01 or 00 00 00 01) begins at [i], else 0. */
        private fun startCodeAt(d: ByteArray, i: Int): Int {
            if (i + 3 <= d.size && d[i].toInt() == 0 && d[i + 1].toInt() == 0) {
                if (d[i + 2].toInt() == 1) return 3
                if (i + 4 <= d.size && d[i + 2].toInt() == 0 && d[i + 3].toInt() == 1) return 4
            }
            return 0
        }
    }
}

/**
 * The bitrate of H.264 (§8: 2 Mbit/s by default, set_bitrate of the viewer, the agent's uplink bounded by the server's
 * bitrateMax): lowered at each congestion of the link, raised again slowly towards the target.
 */
class BitrateController(
    maxKbps: Int?,
    private val raiseEveryMs: Long = 10_000,
) {
    val maxKbps: Int = (maxKbps ?: DEFAULT_MAX_KBPS).coerceIn(MIN_KBPS, RemoteLimits.MAX_KBPS)
    var targetKbps: Int = Math.min(DEFAULT_KBPS, this.maxKbps)
        private set
    var currentKbps: Int = targetKbps
        private set
    private var lastChangeMs = Long.MIN_VALUE / 2

    /** set_bitrate: the new current value when it changes. */
    fun setTarget(kbps: Int, now: Long): Int? {
        targetKbps = kbps.coerceIn(MIN_KBPS, maxKbps)
        if (currentKbps == targetKbps) return null
        currentKbps = targetKbps
        lastChangeMs = now
        return currentKbps
    }

    /** The link could not follow: 30 % less, down to [MIN_KBPS]. */
    fun congested(now: Long): Int? {
        val next = Math.max(MIN_KBPS, currentKbps * 7 / 10)
        lastChangeMs = now
        if (next == currentKbps) return null
        currentKbps = next
        return next
    }

    /** About every second: back up 15 % (50 kbit/s at least) after [raiseEveryMs] without congestion. */
    fun tick(now: Long): Int? {
        if (currentKbps >= targetKbps || now - lastChangeMs < raiseEveryMs) return null
        currentKbps = Math.min(targetKbps, Math.max(currentKbps + 50, currentKbps * 115 / 100))
        lastChangeMs = now
        return currentKbps
    }

    companion object {
        const val DEFAULT_KBPS = 2_000
        const val MIN_KBPS = 250
        /** REMOTE_LIMITS.agentUplinkKbps when /accept gives none. */
        const val DEFAULT_MAX_KBPS = 4_000
    }
}

/** One picture to send: [frameType] of [RemoteFrames] (byte 0 of the plain binary message). */
class VideoFrame(val frameType: Int, val data: ByteArray, val key: Boolean)

/**
 * What leaves on the stream, taken by one sender thread: the control messages first and never dropped, then the
 * pictures. When the pictures queued would pass [maxBytes] or [maxFrames], the link is congested: a key frame (and
 * every JPEG) replaces what waits; another frame is dropped with the queue, and the frames that follow too until the
 * next key frame (an H.264 frame depends on the one before).
 */
class StreamOutbox(
    private val maxBytes: Int = 1024 * 1024,
    private val maxFrames: Int = 6,
    private val maxControl: Int = 64,
) {
    sealed class Offer {
        object Queued : Offer()
        /** Dropped; [needKey]: ask the encoder for a key frame; [congestion]: the link did not follow. */
        class Dropped(val needKey: Boolean, val congestion: Boolean) : Offer()
    }

    sealed class Item {
        class Control(val message: Map<String, Any?>) : Item()
        class Video(val frame: VideoFrame) : Item()
    }

    private val lock = Object()
    private val control = ArrayDeque<Map<String, Any?>>()
    private val video = ArrayDeque<VideoFrame>()
    private var videoBytes = 0
    private var waitingKey = false
    private var closed = false

    /** A control message; false when closed or [maxControl] are already waiting (the viewer no longer reads). */
    fun control(message: Map<String, Any?>): Boolean = synchronized(lock) {
        if (closed || control.size >= maxControl) return false
        control.addLast(message)
        lock.notifyAll()
        true
    }

    fun video(frame: VideoFrame): Offer = synchronized(lock) {
        if (closed) return Offer.Dropped(false, false)
        if (waitingKey && !frame.key) return Offer.Dropped(false, false)
        val n = frame.data.size
        if (n > maxBytes) {
            dropVideo()
            waitingKey = true
            return Offer.Dropped(true, true)
        }
        var congestion = false
        if (videoBytes + n > maxBytes || video.size + 1 > maxFrames) {
            congestion = true
            dropVideo()
            if (!frame.key) {
                waitingKey = true
                return Offer.Dropped(true, true)
            }
        }
        video.addLast(frame)
        videoBytes += n
        if (frame.key) waitingKey = false
        lock.notifyAll()
        return if (congestion) Offer.Dropped(false, true) else Offer.Queued
    }

    /** Pictures waiting are obsolete (new generation, screen off): dropped, the next one waits for a key frame. */
    fun clearVideo() = synchronized(lock) {
        dropVideo()
        waitingKey = true
    }

    /** The next item, control first; null after [timeoutMs] or once closed and empty of control messages. */
    fun take(timeoutMs: Long): Item? = synchronized(lock) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var left = timeoutMs
        while (control.isEmpty() && video.isEmpty() && !closed && left > 0) {
            lock.wait(left)
            left = deadline - System.currentTimeMillis()
        }
        val c = control.pollFirst()
        when {
            c != null -> Item.Control(c)
            closed -> null
            else -> video.pollFirst()?.let { videoBytes -= it.data.size; Item.Video(it) }
        }
    }

    val pendingControl: Int get() = synchronized(lock) { control.size }

    /** No more pictures; the control messages still waiting can be taken. */
    fun close() = synchronized(lock) {
        closed = true
        dropVideo()
        lock.notifyAll()
    }

    private fun dropVideo() {
        video.clear()
        videoBytes = 0
    }
}
