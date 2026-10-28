package tools.obli.obligarth.agent.core

import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// =============================================================================
// Remote assistance stream, agent side (P0-15 §4.4, §5, T7a): the hello bound to
// the transport (the agent's nonce and ephemeral ECDH key, signed by the instance
// key), the AES-256-GCM channel between the agent and the server (one key per
// direction, HKDF-SHA256), the messages of §5.2 and the filter of the effective
// mode. Pure JVM: the same code on the device and in tests.
// =============================================================================

/** A protocol failure on the remote stream: the session closes. */
class RemoteProtocolException(message: String) : IOException(message)

enum class RemoteMode(val wire: String) {
    VIEW("view"), CONTROL("control");

    /** The lower of the two (the effective mode, §2). */
    fun min(other: RemoteMode): RemoteMode = if (this == CONTROL && other == CONTROL) CONTROL else VIEW

    companion object {
        fun of(wire: String?): RemoteMode? = values().firstOrNull { it.wire == wire }
    }
}

/** Bounds of shared/src/mdm/remote.ts REMOTE_LIMITS used by the agent. */
object RemoteLimits {
    const val TEXT_FRAME_MAX = 4096
    const val TYPE_TEXT_MAX = 256
    const val MAX_POINTERS = 5
    /** Coordinates are image pixels (§5.2); far beyond any screen. */
    const val MAX_COORDINATE = 16_384.0
    const val MAX_KBPS = 100_000
    /** The hello must come this fast after the upgrade. */
    const val HELLO_TIMEOUT_MS = 15_000
    /** The window of the signed times (surface.ts CLOCK_WINDOW_SECONDS). */
    const val CLOCK_WINDOW_S = 300L
}

// -----------------------------------------------------------------------------
// Key agreement and derivation
// -----------------------------------------------------------------------------

/** The two keys of a session: one per direction, never the same (nonce of GCM = counter of its direction). */
class SessionKeys(val agentToServer: ByteArray, val serverToAgent: ByteArray)

object RemoteCrypto {
    const val NONCE_BYTES = 16
    const val INFO_PREFIX = "obl-remote-1|"

    /** An ephemeral P-256 key pair, one per stream attach. */
    fun ephemeralKeyPair(random: SecureRandom): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"), random)
            generateKeyPair()
        }

    /** ECDH P-256: the X coordinate of the shared point (32 bytes); the peer's key is an SPKI of P-256 only. */
    fun sharedSecret(own: PrivateKey, peerSpki: ByteArray): ByteArray {
        val peer = Ec.publicKeyFromSpki(peerSpki) ?: throw RemoteProtocolException("peer key is not P-256")
        return KeyAgreement.getInstance("ECDH").run {
            init(own)
            doPhase(peer, true)
            generateSecret()
        }
    }

    /** HKDF-SHA256 (RFC 5869). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArray(length)
        var t = ByteArray(0)
        var off = 0
        var counter = 1
        while (off < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = Math.min(t.size, length - off)
            System.arraycopy(t, 0, out, off, n)
            off += n
            counter++
        }
        return out
    }

    /**
     * §4.4: HKDF-SHA256, salt = the agent's nonce, info = "obl-remote-1|<sessionId>", 64 bytes: the first 32 are the
     * key of the agent → server direction, the last 32 the key of the server → agent direction.
     */
    fun sessionKeys(sharedSecret: ByteArray, agentNonce: ByteArray, sessionId: String): SessionKeys {
        val okm = hkdfSha256(sharedSecret, agentNonce, (INFO_PREFIX + sessionId).toByteArray(Charsets.UTF_8), 64)
        return SessionKeys(okm.copyOfRange(0, 32), okm.copyOfRange(32, 64))
    }
}

// -----------------------------------------------------------------------------
// Encrypted frames: kind (1) ‖ counter (12, big endian) ‖ AES-256-GCM(plain) ‖ tag (16)
// The 13 header bytes are the additional data: neither the kind nor the counter can
// be changed. The GCM nonce is the counter, which starts at 0 and grows by one per
// frame in each direction; the receiver refuses any counter not above the last one.
// Every encrypted frame travels as a WebSocket binary frame.
// -----------------------------------------------------------------------------

object RemoteFrames {
    /** The plain content is a JSON text message (§5.2). */
    const val KIND_TEXT = 0x01
    /** The plain content is a binary message (byte 0: 0x01 JPEG, 0x02 H.264, §5.1). */
    const val KIND_BINARY = 0x02
    const val HEADER_BYTES = 13
    const val TAG_BYTES = 16

    /** Byte 0 of a plain binary message (§5.1). */
    const val VIDEO_JPEG = 0x01
    const val VIDEO_H264 = 0x02
}

class FrameSealer(key: ByteArray) {
    private val key = SecretKeySpec(key.copyOf(), "AES")
    private val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private var next = 0L

    /** Not thread-safe: the channel seals and sends under one lock, so that the counters leave in order. */
    fun seal(kind: Int, plain: ByteArray): ByteArray {
        require(kind == RemoteFrames.KIND_TEXT || kind == RemoteFrames.KIND_BINARY)
        if (next == Long.MAX_VALUE) throw RemoteProtocolException("counter exhausted")
        val header = header(kind, next++)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(RemoteFrames.TAG_BYTES * 8, header, 1, 12))
        cipher.updateAAD(header)
        val sealed = cipher.doFinal(plain)
        val out = ByteArray(header.size + sealed.size)
        System.arraycopy(header, 0, out, 0, header.size)
        System.arraycopy(sealed, 0, out, header.size, sealed.size)
        return out
    }

    companion object {
        fun header(kind: Int, counter: Long): ByteArray {
            val h = ByteArray(RemoteFrames.HEADER_BYTES)
            h[0] = kind.toByte()
            for (i in 0 until 8) h[5 + i] = (counter ushr (56 - 8 * i)).toByte()
            return h
        }
    }
}

class FrameOpener(key: ByteArray) {
    class Opened(val kind: Int, val plain: ByteArray)

    private val key = SecretKeySpec(key.copyOf(), "AES")
    private val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private var last = -1L

    /** Throws [RemoteProtocolException] on a short or malformed frame, a counter not above the last one, a bad tag. */
    fun open(frame: ByteArray): Opened {
        if (frame.size < RemoteFrames.HEADER_BYTES + RemoteFrames.TAG_BYTES) throw RemoteProtocolException("short frame")
        val kind = frame[0].toInt() and 0xff
        if (kind != RemoteFrames.KIND_TEXT && kind != RemoteFrames.KIND_BINARY) throw RemoteProtocolException("unknown frame kind")
        for (i in 1..4) if (frame[i].toInt() != 0) throw RemoteProtocolException("counter out of range")
        var counter = 0L
        for (i in 5 until 13) counter = (counter shl 8) or (frame[i].toLong() and 0xff)
        if (counter < 0 || counter <= last) throw RemoteProtocolException("counter not increasing")
        val plain = try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(RemoteFrames.TAG_BYTES * 8, frame, 1, 12))
            cipher.updateAAD(frame, 0, RemoteFrames.HEADER_BYTES)
            cipher.doFinal(frame, RemoteFrames.HEADER_BYTES, frame.size - RemoteFrames.HEADER_BYTES)
        } catch (e: AEADBadTagException) {
            throw RemoteProtocolException("frame authentication failed")
        } catch (e: java.security.GeneralSecurityException) {
            throw RemoteProtocolException("frame decryption failed")
        }
        last = counter
        return Opened(kind, plain)
    }
}

// -----------------------------------------------------------------------------
// The hello (§4.4): first frame of the server, in clear, signed by the instance key.
// -----------------------------------------------------------------------------

object RemoteHello {
    const val TAG = "OBL-REMOTE-HELLO-1"

    /**
     * The signed text: the tag, then on one line each the agent's nonce, the agent's ECDH key (SPKI), the server's ECDH
     * key (SPKI), all three base64url without padding, the session id, the mode, ts (Unix seconds).
     */
    fun canonical(agentNonce: ByteArray, agentEcdhSpki: ByteArray, serverEcdhSpki: ByteArray, sessionId: String, mode: String, ts: Long): String =
        listOf(TAG, B64.encodeUrl(agentNonce), B64.encodeUrl(agentEcdhSpki), B64.encodeUrl(serverEcdhSpki), sessionId, mode, ts.toString())
            .joinToString("\n")

    sealed class Result {
        class Ok(val mode: RemoteMode, val serverEcdhSpki: ByteArray) : Result()
        class Refused(val reason: String) : Result()
    }

    /**
     * Checks the hello: its type and fields, the session, ts within 300 s of [serverNow], a P-256 server key, and the
     * signature of one of the trusted instance keys over the agent's own nonce and key (a hello made for another attach
     * never holds).
     */
    fun verify(
        text: String,
        sessionId: String,
        agentNonce: ByteArray,
        agentEcdhSpki: ByteArray,
        keys: Collection<ServerKey>,
        serverNow: Long,
    ): Result {
        if (text.length > RemoteLimits.TEXT_FRAME_MAX) return Result.Refused("too_large")
        val m = Json.parseObjectOrNull(text) ?: return Result.Refused("malformed")
        if (m.str("type") != "hello") return Result.Refused("not_hello")
        if (m.str("sessionId") != sessionId) return Result.Refused("other_session")
        val modeWire = m.str("mode")
        val mode = RemoteMode.of(modeWire) ?: return Result.Refused("malformed")
        val ts = m.long("ts") ?: return Result.Refused("malformed")
        if (Math.abs(ts - serverNow) > RemoteLimits.CLOCK_WINDOW_S) return Result.Refused("clock")
        val serverEcdh = m.str("serverEcdh")?.let { B64.decode(it) } ?: return Result.Refused("malformed")
        if (Ec.publicKeyFromSpki(serverEcdh) == null) return Result.Refused("server_key")
        val sig = m.str("sig")?.let { B64.decode(it) } ?: return Result.Refused("malformed")
        val signed = canonical(agentNonce, agentEcdhSpki, serverEcdh, sessionId, modeWire!!, ts).toByteArray(Charsets.UTF_8)
        val holds = keys.any { k -> k.publicKey?.let { Ec.verify(it, signed, sig) } == true }
        return if (holds) Result.Ok(mode, serverEcdh) else Result.Refused("signature")
    }
}

// -----------------------------------------------------------------------------
// Messages (§5.2), plain JSON inside the encrypted frames
// -----------------------------------------------------------------------------

/** What the agent may receive from the server: the viewer's messages (relayed) and the server's own. */
sealed class RemoteInbound {
    open val isInput: Boolean get() = false

    object KeepAlive : RemoteInbound()
    object KeyRequest : RemoteInbound()
    data class SetBitrate(val kbps: Int) : RemoteInbound()
    data class SetCodec(val codec: String) : RemoteInbound()
    data class Quality(val maxHeight: Int) : RemoteInbound()
    data class Touch(val action: String, val id: Int, val x: Double, val y: Double, val gen: Long) : RemoteInbound() {
        override val isInput get() = true
    }
    data class Scroll(val x: Double, val y: Double, val dx: Double, val dy: Double, val gen: Long) : RemoteInbound() {
        override val isInput get() = true
    }
    data class Nav(val action: String) : RemoteInbound() {
        override val isInput get() = true
    }
    data class TypeText(val text: String) : RemoteInbound() {
        override val isInput get() = true
    }
    data class Key(val code: String) : RemoteInbound() {
        override val isInput get() = true
    }
    /** Server: the effective mode, after the technician's checks (§0.1, rule 3); the agent applies it as sent. */
    data class Mode(val effective: RemoteMode) : RemoteInbound()
    /** Server: the session ended (reason of REMOTE_END_REASONS). */
    data class SessionEnd(val reason: String) : RemoteInbound()
}

object RemoteMessages {
    val CODECS = setOf("h264", "jpeg")
    val QUALITIES = setOf(480, 720, 1080)
    val TOUCH_ACTIONS = setOf("down", "move", "up", "cancel")
    /** No power dialog, lock nor shutdown in v1 (§5.3). */
    val NAV_ACTIONS = setOf("back", "home", "recents", "notifications", "volume_up", "volume_down", "wake")
    val KEY_CODES = setOf("enter", "del", "tab", "left", "right", "up", "down", "escape")
    /**
     * The reasons of session_end (shared/src/mdm/remote.ts REMOTE_END_REASONS): the codes no longer produced since §0.1
     * (user_refused, consent_timeout, indicator_lost, escalation_refused) stay readable, a server may still send them.
     */
    val END_REASONS = setOf(
        "operator", "user_stopped", "user_refused", "consent_timeout", "projection_denied", "device_timeout", "idle",
        "max_duration", "screen_off_timeout", "freeze", "revoked", "indicator_lost", "agent_error", "server_restart",
        "escalation_refused", "approval_denied", "approval_expired",
    )
    val FEATURES = setOf("touch", "nav", "type_text", "key", "quality", "display_state")
    /**
     * Agent → viewer (relayed): what [RemoteChannel.send] admits. Since §0.1 the agent sends nothing to the server
     * alone (no consent_state) and the user never ends a session (no user_ended).
     */
    val OUTBOUND_TYPES = setOf(
        "init", "keepalive", "error", "display_state", "input_unavailable", "bitrate", "inactivity_warning",
        "inactivity_timeout",
    )

    /** A received text message; null when it is to be dropped (too long, malformed, unknown type, out of bounds). */
    fun parse(text: String): RemoteInbound? {
        if (text.toByteArray(Charsets.UTF_8).size > RemoteLimits.TEXT_FRAME_MAX) return null
        val m = Json.parseObjectOrNull(text) ?: return null
        return when (m.str("type")) {
            "keepalive" -> RemoteInbound.KeepAlive
            "key_request" -> RemoteInbound.KeyRequest
            "set_bitrate" -> m.int("kbps")?.takeIf { it in 1..RemoteLimits.MAX_KBPS }?.let { RemoteInbound.SetBitrate(it) }
            "set_codec" -> m.str("codec")?.takeIf { it in CODECS }?.let { RemoteInbound.SetCodec(it) }
            "quality" -> m.int("maxHeight")?.takeIf { it in QUALITIES }?.let { RemoteInbound.Quality(it) }
            "touch" -> {
                val action = m.str("action")?.takeIf { it in TOUCH_ACTIONS }
                val id = m.int("id")?.takeIf { it in 0..255 }
                val x = coordinate(m["x"])
                val y = coordinate(m["y"])
                val gen = m.long("gen")?.takeIf { it >= 0 }
                if (action == null || id == null || x == null || y == null || gen == null) null
                else RemoteInbound.Touch(action, id, x, y, gen)
            }
            "scroll" -> {
                val x = coordinate(m["x"])
                val y = coordinate(m["y"])
                val dx = delta(m["dx"])
                val dy = delta(m["dy"])
                val gen = m.long("gen")?.takeIf { it >= 0 }
                if (x == null || y == null || dx == null || dy == null || gen == null) null else RemoteInbound.Scroll(x, y, dx, dy, gen)
            }
            "nav" -> m.str("action")?.takeIf { it in NAV_ACTIONS }?.let { RemoteInbound.Nav(it) }
            "type_text" -> m.str("text")?.takeIf { it.isNotEmpty() && it.length <= RemoteLimits.TYPE_TEXT_MAX }?.let { RemoteInbound.TypeText(it) }
            "key" -> m.str("code")?.takeIf { it in KEY_CODES }?.let { RemoteInbound.Key(it) }
            "mode" -> RemoteMode.of(m.str("effective"))?.let { RemoteInbound.Mode(it) }
            "session_end" -> m.str("reason")?.takeIf { it in END_REASONS }?.let { RemoteInbound.SessionEnd(it) }
            else -> null
        }
    }

    private fun number(v: Any?): Double? = when (v) {
        is Long -> v.toDouble()
        is Int -> v.toDouble()
        is Double -> v.takeIf { !it.isNaN() && !it.isInfinite() }
        else -> null
    }

    private fun coordinate(v: Any?): Double? = number(v)?.takeIf { it >= 0 && it <= RemoteLimits.MAX_COORDINATE }
    private fun delta(v: Any?): Double? = number(v)?.takeIf { Math.abs(it) <= RemoteLimits.MAX_COORDINATE }

    // ---- What the agent sends ----

    fun init(gen: Long, width: Int, height: Int, rotation: Int, codecs: List<String>, codec: String, features: List<String>): Map<String, Any?> {
        require(codec in codecs && codecs.all { it in CODECS } && features.all { it in FEATURES })
        return linkedMapOf("type" to "init", "gen" to gen, "width" to width, "height" to height, "rotation" to rotation,
            "codecs" to codecs, "codec" to codec, "features" to features)
    }
    fun keepalive(): Map<String, Any?> = linkedMapOf("type" to "keepalive")
    fun error(code: String, retry: Boolean, message: String? = null): Map<String, Any?> =
        linkedMapOf<String, Any?>("type" to "error", "code" to code, "retry" to retry).also { if (message != null) it["message"] = message.clip(200) }
    fun displayState(rotation: Int, screenOn: Boolean, locked: Boolean): Map<String, Any?> =
        linkedMapOf("type" to "display_state", "rotation" to rotation, "screenOn" to screenOn, "locked" to locked)
    fun inputUnavailable(reason: String): Map<String, Any?> = linkedMapOf("type" to "input_unavailable", "reason" to reason)
    fun bitrate(kbps: Int): Map<String, Any?> = linkedMapOf("type" to "bitrate", "kbps" to kbps)
    fun inactivityWarning(seconds: Int): Map<String, Any?> = linkedMapOf("type" to "inactivity_warning", "seconds" to seconds)
    fun inactivityTimeout(): Map<String, Any?> = linkedMapOf("type" to "inactivity_timeout")

    /** A plain binary message: [frameType] ([RemoteFrames.VIDEO_JPEG] or [RemoteFrames.VIDEO_H264]) then the data. */
    fun video(frameType: Int, data: ByteArray): ByteArray {
        require(frameType == RemoteFrames.VIDEO_JPEG || frameType == RemoteFrames.VIDEO_H264)
        val out = ByteArray(1 + data.size)
        out[0] = frameType.toByte()
        System.arraycopy(data, 0, out, 1, data.size)
        return out
    }
}

/**
 * The agent's own barrier (§5.3): in effective mode view, every input is dropped and counted, whatever the relay did.
 * The mode is the hello's at the attach, then the one each frame mode of the server sets ([apply], §0.1 rule 3).
 */
class InputGate(mode: RemoteMode) {
    @Volatile var mode: RemoteMode = mode
        private set
    @Volatile var dropped: Int = 0
        private set

    fun admits(message: RemoteInbound): Boolean {
        if (!message.isInput || mode == RemoteMode.CONTROL) return true
        dropped++
        return false
    }

    /** The effective mode sent by the server (frame mode), up or down. */
    fun apply(newMode: RemoteMode) {
        mode = newMode
    }
}

/**
 * The stream of one session once the hello held (§4.4): every frame sealed with the agent → server key and opened
 * with the server → agent key, as WebSocket binary frames. A clear frame, a frame that does not open, or a counter
 * not increasing closes the stream (policy violation). Messages that are malformed, of an unknown type or not
 * admitted by the [gate] are dropped and counted.
 */
class RemoteChannel internal constructor(
    private val ws: WebSocket,
    keys: SessionKeys,
    val sessionId: String,
    /** min(mode told to /accept, mode of the hello); then the server's frames mode. */
    mode: RemoteMode,
) {
    private val sealer = FrameSealer(keys.agentToServer)
    private val opener = FrameOpener(keys.serverToAgent)
    private val sendLock = Any()
    val gate = InputGate(mode)
    @Volatile var droppedMessages: Int = 0
        private set
    @Volatile var bytesSent: Long = 0
        private set

    val isOpen: Boolean get() = ws.isOpen

    /** A text message of [RemoteMessages.OUTBOUND_TYPES], 4 KiB at most. */
    @Throws(IOException::class)
    fun send(message: Map<String, Any?>) {
        require(message["type"] in RemoteMessages.OUTBOUND_TYPES) { "type not sent by an agent: ${message["type"]}" }
        val bytes = Json.bytes(message)
        require(bytes.size <= RemoteLimits.TEXT_FRAME_MAX) { "text message over 4 KiB" }
        sendSealed(RemoteFrames.KIND_TEXT, bytes)
    }

    /** A video frame ([RemoteFrames.VIDEO_H264] access unit, SPS/PPS before each IDR, or a JPEG). */
    @Throws(IOException::class)
    fun sendVideo(frameType: Int, data: ByteArray) = sendSealed(RemoteFrames.KIND_BINARY, RemoteMessages.video(frameType, data))

    private fun sendSealed(kind: Int, plain: ByteArray) {
        synchronized(sendLock) {
            val frame = sealer.seal(kind, plain)
            ws.sendBinary(frame)
            bytesSent += frame.size
        }
    }

    /** The next admitted message; null once the stream is closed by the server. */
    @Throws(IOException::class)
    fun receive(): RemoteInbound? {
        while (true) {
            when (val m = ws.receive()) {
                is WsMessage.Closed -> return null
                is WsMessage.Text -> violation("clear frame after the hello")
                is WsMessage.Binary -> {
                    val opened = try {
                        opener.open(m.bytes)
                    } catch (e: RemoteProtocolException) {
                        violation(e.message ?: "bad frame")
                    }
                    if (opened.kind != RemoteFrames.KIND_TEXT) { droppedMessages++; continue } // nothing binary comes to an agent in v1
                    val text = try { String(opened.plain, Charsets.UTF_8) } catch (e: Exception) { null }
                    val message = text?.let { RemoteMessages.parse(it) }
                    if (message == null || !gate.admits(message)) { droppedMessages++; continue }
                    return message
                }
            }
        }
    }

    private fun violation(reason: String): Nothing {
        ws.close(WebSocket.CLOSE_POLICY, "")
        throw RemoteProtocolException(reason)
    }

    /** Keep-alive, about every second (the ticker of the session). */
    @Throws(IOException::class)
    fun tick(nowMs: Long = System.currentTimeMillis()) = ws.tick(nowMs)

    fun close() = ws.close(WebSocket.CLOSE_NORMAL, "")

    fun abort() = ws.abort()

    companion object {
        /**
         * Reads the hello on a fresh connection and builds the channel; closes the connection and throws
         * [RemoteProtocolException] when it does not hold.
         */
        @Throws(IOException::class)
        fun afterHello(
            ws: WebSocket,
            sessionId: String,
            consentedMode: RemoteMode,
            agentNonce: ByteArray,
            ephemeral: KeyPair,
            keys: Collection<ServerKey>,
            serverNow: Long,
            /** The hello by then at most, whatever comes meanwhile (a ping answered does not extend it). */
            helloTimeoutMs: Int = RemoteLimits.HELLO_TIMEOUT_MS,
        ): RemoteChannel {
            val first = try {
                ws.readTimeoutMs = helloTimeoutMs
                ws.deadlineMs = ws.nowMs() + helloTimeoutMs
                ws.receive().also {
                    ws.deadlineMs = 0
                    ws.restoreReadTimeout()
                }
            } catch (e: IOException) {
                ws.abort()
                throw e
            }
            val text = (first as? WsMessage.Text)?.text
            if (text == null) {
                ws.close(WebSocket.CLOSE_POLICY, "")
                throw RemoteProtocolException("no hello")
            }
            val agentSpki = ephemeral.public.encoded
            when (val r = RemoteHello.verify(text, sessionId, agentNonce, agentSpki, keys, serverNow)) {
                is RemoteHello.Result.Refused -> {
                    ws.close(WebSocket.CLOSE_POLICY, "")
                    throw RemoteProtocolException("hello refused: ${r.reason}")
                }
                is RemoteHello.Result.Ok -> {
                    val shared = RemoteCrypto.sharedSecret(ephemeral.private, r.serverEcdhSpki)
                    val sessionKeys = RemoteCrypto.sessionKeys(shared, agentNonce, sessionId)
                    java.util.Arrays.fill(shared, 0)
                    return RemoteChannel(ws, sessionKeys, sessionId, consentedMode.min(r.mode))
                }
            }
        }

        /** SHA-256 of streamToken ‖ nonce ‖ ECDH key (§4.4): the body hash of the signed attach request. */
        fun attachBodySha256(streamToken: ByteArray, agentNonce: ByteArray, agentEcdhSpki: ByteArray): String {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(streamToken)
            md.update(agentNonce)
            md.update(agentEcdhSpki)
            return Hex.encode(md.digest())
        }
    }
}
