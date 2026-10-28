package tools.obli.obligarth.agent.core

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

// =============================================================================
// RFC 6455 client of the remote assistance stream (P0-15 §8, T7a). Written from
// the RFC, not copied from Oblireach's websocket.go (no certificate check there,
// no Sec-WebSocket-Accept check, FIN and continuation ignored, no size cap).
// No dependency: a plain socket under TLS (SSLSocket), the same API on Android
// and in JVM tests.
// =============================================================================

/** A protocol failure: the connection is closed with [closeCode] (RFC 6455 §7.4.1). */
class WebSocketException(message: String, val closeCode: Int = WebSocket.CLOSE_PROTOCOL_ERROR) : IOException(message)

/** The server refused the upgrade (a status other than 101) or answered it wrongly. [status] is 101 for a bad 101. */
class WebSocketHandshakeException(message: String, val status: Int) : IOException(message)

/** A message received, or the end of the connection. */
sealed class WsMessage {
    class Text(val text: String) : WsMessage()
    class Binary(val bytes: ByteArray) : WsMessage()
    /** The server closed (code 1005 when its close frame carried none). */
    data class Closed(val code: Int, val reason: String) : WsMessage()
}

class WebSocketLimits(
    /** One frame from the server (spec §8: 64 KiB). Control frames: 125 bytes, by the RFC. */
    val maxFramePayload: Int = 64 * 1024,
    /** One message reassembled from its frames (2 MiB). */
    val maxMessageBytes: Int = 2 * 1024 * 1024,
    /** One message sent (a key frame of the encoder; the relay buffers 2 MiB per end). */
    val maxOutgoingBytes: Int = 2 * 1024 * 1024,
    /** The HTTP answer to the upgrade, headers included. */
    val maxHandshakeBytes: Int = 16 * 1024,
    val connectTimeoutMs: Int = 15_000,
    /** Silence tolerated on a read: the server pings every 25 s (§4.4). */
    val readTimeoutMs: Int = 60_000,
    /** Our own ping (under the 60 s of Nginx Proxy Manager), and the pong awaited after it. */
    val pingIntervalMs: Long = 25_000,
    val pongTimeoutMs: Long = 20_000,
    /** Wait for the server's close frame after ours. */
    val closeWaitMs: Long = 2_000,
)

/** Opens the TCP connection, and TLS over it when [secure]. */
interface SocketConnector {
    @Throws(IOException::class)
    fun connect(host: String, port: Int, secure: Boolean, connectTimeoutMs: Int): Socket
}

/**
 * TLS only (§8): the trust manager given (system store plus ISRG Root X1 and X2, see [AgentTls]), SNI, the host name
 * checked during the handshake (endpoint identification) and again by [hostnameVerifier] when given (Android: an
 * SSLSocket checks no name by itself), and the optional SPKI pins of the build (TLS_PINS, like UrlConnectionTransport).
 */
class TlsSocketConnector(
    trustManager: X509TrustManager,
    private val hostnameVerifier: HostnameVerifier? = null,
    private val tlsPins: Set<String> = emptySet(),
) : SocketConnector {
    private val factory: SSLSocketFactory =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), SecureRandom()) }.socketFactory

    override fun connect(host: String, port: Int, secure: Boolean, connectTimeoutMs: Int): Socket {
        if (!secure) throw IOException("cleartext refused")
        val raw = Socket()
        try {
            raw.connect(InetSocketAddress(host, port), connectTimeoutMs)
            raw.soTimeout = connectTimeoutMs // the TLS handshake is bounded too
            val ssl = factory.createSocket(raw, host, port, true) as SSLSocket
            val params = ssl.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            if (!isIpLiteral(host)) params.serverNames = listOf(SNIHostName(host))
            ssl.sslParameters = params
            ssl.startHandshake()
            val session = ssl.session
            if (hostnameVerifier != null && !hostnameVerifier.verify(host, session)) {
                throw SSLPeerUnverifiedException("host name not verified: $host")
            }
            if (tlsPins.isNotEmpty() && session.peerCertificates.none { Sha256.hex(it.publicKey.encoded) in tlsPins }) {
                throw SSLPeerUnverifiedException("TLS pin mismatch")
            }
            return ssl
        } catch (e: IOException) {
            closeQuietly(raw)
            throw e
        } catch (e: RuntimeException) {
            closeQuietly(raw)
            throw IOException("TLS: ${e.message}", e)
        }
    }

    private fun isIpLiteral(host: String) = host.contains(':') || host.all { it.isDigit() || it == '.' }
}

/** Trust of the raw sockets (§8): network_security_config.xml does not check host names on a socket. */
object AgentTls {
    /** The certificates of a PEM or DER resource (res/raw/isrg_root_x1, isrg_root_x2). */
    fun certificates(input: InputStream): List<X509Certificate> =
        CertificateFactory.getInstance("X.509").generateCertificates(input).filterIsInstance<X509Certificate>()

    /** Trusts these anchors only. */
    fun anchors(certificates: List<X509Certificate>): X509TrustManager {
        require(certificates.isNotEmpty()) { "no anchor" }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null, null)
        certificates.forEachIndexed { i, c -> ks.setCertificateEntry("anchor$i", c) }
        return trustManagerOf(ks)
    }

    /** The platform's default trust (on Android, the one of the network security configuration). */
    fun system(): X509TrustManager = trustManagerOf(null)

    /** The system store plus [extra] (Android 7.0 does not know ISRG Root X1). */
    fun agent(extra: List<X509Certificate>): X509TrustManager =
        if (extra.isEmpty()) system() else CompositeTrustManager(listOf(system(), anchors(extra)))

    private fun trustManagerOf(ks: KeyStore?): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(ks)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }
}

/** Trusted when one of [delegates] trusts the chain; never a client. */
class CompositeTrustManager(private val delegates: List<X509TrustManager>) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        throw CertificateException("no client is trusted")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        var first: CertificateException? = null
        for (d in delegates) {
            try {
                d.checkServerTrusted(chain, authType)
                return
            } catch (e: CertificateException) {
                if (first == null) first = e
            }
        }
        throw first ?: CertificateException("no trust manager")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegates.flatMap { it.acceptedIssuers.toList() }.toTypedArray()
}

/**
 * One WebSocket connection, client side. [receive] is called by one reader thread; the senders may be other threads
 * (each frame is written whole under a lock). Protocol errors close the connection with their code and throw
 * [WebSocketException]: a masked server frame, reserved bits, an unknown opcode, a control frame over 125 bytes or
 * fragmented, a continuation out of place, a frame over [WebSocketLimits.maxFramePayload], a message over
 * [WebSocketLimits.maxMessageBytes], a text that is not UTF-8.
 */
class WebSocket private constructor(
    private val socket: Socket,
    private val input: InputStream,
    private val output: OutputStream,
    private val limits: WebSocketLimits,
    private val random: SecureRandom,
    /** The clock of the keep-alive and of [deadlineMs]. */
    internal val nowMs: () -> Long,
) {
    private val writeLock = Any()
    private val closeSent = AtomicBoolean(false)
    private val socketClosed = AtomicBoolean(false)
    private val closedLatch = CountDownLatch(1)
    @Volatile private var reading = false
    @Volatile private var finished = false

    // Reassembly of a fragmented message (reader thread only).
    private var fragmentOpcode = -1
    private val fragments = ByteArrayOutputStream()

    // Keep-alive (§4.4).
    @Volatile var lastReceivedAtMs: Long = nowMs(); private set
    @Volatile private var lastPingAtMs: Long = nowMs()
    @Volatile private var pendingPing: ByteArray? = null
    @Volatile private var pendingPingAtMs: Long = 0

    val isOpen: Boolean get() = !finished && !socketClosed.get()

    /** The read time-out of the next reads (the hello is awaited shorter than the stream). */
    var readTimeoutMs: Int
        get() = socket.soTimeout
        set(value) { socket.soTimeout = value }

    /** Back to [WebSocketLimits.readTimeoutMs]. */
    fun restoreReadTimeout() {
        socket.soTimeout = limits.readTimeoutMs
    }

    /**
     * When set (above 0, on [nowMs]'s clock): [receive] gives up then with a [SocketTimeoutException], the connection
     * dropped, however many pings or pongs arrived meanwhile (each one would otherwise start the read time-out again).
     */
    @Volatile var deadlineMs: Long = 0

    // ------------------------------------------------------------------
    // Receiving
    // ------------------------------------------------------------------

    /**
     * The next data message, or [WsMessage.Closed] once when the server closes. Pings are answered and pongs taken
     * here. Throws [WebSocketException] on a protocol error (the connection is then closed), an IOException on a
     * network error or a read time-out.
     */
    @Throws(IOException::class)
    fun receive(): WsMessage {
        if (finished) throw WebSocketException("closed", CLOSE_NORMAL)
        reading = true
        try {
            while (true) {
                val deadline = deadlineMs
                if (deadline > 0) {
                    val left = deadline - nowMs()
                    if (left <= 0) throw SocketTimeoutException("deadline passed")
                    socket.soTimeout = Math.min(left, Int.MAX_VALUE.toLong()).toInt()
                }
                val b0 = input.read()
                if (b0 < 0) {
                    shutdown()
                    throw WebSocketException("connection lost", CLOSE_ABNORMAL)
                }
                val b1 = readByte()
                val fin = b0 and 0x80 != 0
                val opcode = b0 and 0x0f
                if (b0 and 0x70 != 0) fail(CLOSE_PROTOCOL_ERROR, "reserved bits set")
                if (b1 and 0x80 != 0) fail(CLOSE_PROTOCOL_ERROR, "masked server frame")
                val len = payloadLength(b1 and 0x7f)
                val control = opcode and 0x08 != 0
                if (control) {
                    if (!fin) fail(CLOSE_PROTOCOL_ERROR, "fragmented control frame")
                    if (len > MAX_CONTROL_PAYLOAD) fail(CLOSE_PROTOCOL_ERROR, "control frame over 125 bytes")
                } else if (len > limits.maxFramePayload) {
                    fail(CLOSE_TOO_BIG, "frame of $len bytes")
                }
                val payload = readFully(len.toInt())
                lastReceivedAtMs = nowMs()
                when (opcode) {
                    OP_PING -> if (!closeSent.get()) writeFrame(OP_PONG, payload)
                    OP_PONG -> pongReceived(payload)
                    OP_CLOSE -> return closeReceived(payload)
                    OP_TEXT, OP_BINARY -> {
                        if (fragmentOpcode != -1) fail(CLOSE_PROTOCOL_ERROR, "new message inside a fragmented one")
                        if (fin) return deliver(opcode, payload)
                        fragmentOpcode = opcode
                        fragments.reset()
                        fragments.write(payload)
                    }
                    OP_CONTINUATION -> {
                        if (fragmentOpcode == -1) fail(CLOSE_PROTOCOL_ERROR, "continuation without a message")
                        if (fragments.size().toLong() + payload.size > limits.maxMessageBytes) fail(CLOSE_TOO_BIG, "message too large")
                        fragments.write(payload)
                        if (fin) {
                            val op = fragmentOpcode
                            fragmentOpcode = -1
                            val whole = fragments.toByteArray()
                            fragments.reset()
                            return deliver(op, whole)
                        }
                    }
                    else -> fail(CLOSE_PROTOCOL_ERROR, "unknown opcode $opcode")
                }
            }
            @Suppress("UNREACHABLE_CODE")
            throw IllegalStateException()
        } catch (e: IOException) {
            if (e !is WebSocketException) shutdown()
            throw e
        } finally {
            reading = false
        }
    }

    private fun payloadLength(len7: Int): Long = when (len7) {
        126 -> {
            val n = (readByte() shl 8) or readByte()
            if (n < 126) fail(CLOSE_PROTOCOL_ERROR, "length not minimal")
            n.toLong()
        }
        127 -> {
            var n = 0L
            repeat(8) { n = (n shl 8) or readByte().toLong() }
            if (n < 0) fail(CLOSE_PROTOCOL_ERROR, "64-bit length with its high bit set")
            if (n <= 0xffff) fail(CLOSE_PROTOCOL_ERROR, "length not minimal")
            // Checked against the caps by the caller before anything is allocated.
            n
        }
        else -> len7.toLong()
    }

    private fun deliver(opcode: Int, payload: ByteArray): WsMessage {
        if (payload.size > limits.maxMessageBytes) fail(CLOSE_TOO_BIG, "message too large")
        if (opcode == OP_BINARY) return WsMessage.Binary(payload)
        val text = decodeUtf8(payload) ?: fail(CLOSE_INVALID_DATA, "text frame not UTF-8")
        return WsMessage.Text(text)
    }

    private fun closeReceived(payload: ByteArray): WsMessage.Closed {
        if (payload.size == 1) fail(CLOSE_PROTOCOL_ERROR, "close frame of one byte")
        var code = CLOSE_NO_STATUS
        var reason = ""
        if (payload.size >= 2) {
            code = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
            if (!validReceivedCloseCode(code)) fail(CLOSE_PROTOCOL_ERROR, "close code $code")
            reason = decodeUtf8(payload.copyOfRange(2, payload.size)) ?: fail(CLOSE_INVALID_DATA, "close reason not UTF-8")
        }
        // Echo it (RFC 6455 §5.5.1), then the TCP connection goes.
        if (closeSent.compareAndSet(false, true)) {
            try {
                writeFrame(OP_CLOSE, closePayload(if (code == CLOSE_NO_STATUS) CLOSE_NORMAL else code, ""))
            } catch (e: IOException) {
                // The peer may already be gone.
            }
        }
        shutdown()
        return WsMessage.Closed(code, reason)
    }

    private fun pongReceived(payload: ByteArray) {
        val expected = pendingPing
        if (expected != null && expected.contentEquals(payload)) pendingPing = null
    }

    // ------------------------------------------------------------------
    // Sending (masked, one frame per message, FIN set)
    // ------------------------------------------------------------------

    @Throws(IOException::class)
    fun sendText(text: String) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        if (bytes.size > limits.maxOutgoingBytes) throw IOException("message too large")
        sendFrame(OP_TEXT, bytes)
    }

    @Throws(IOException::class)
    fun sendBinary(bytes: ByteArray) {
        if (bytes.size > limits.maxOutgoingBytes) throw IOException("message too large")
        sendFrame(OP_BINARY, bytes)
    }

    @Throws(IOException::class)
    fun ping(payload: ByteArray = randomBytes(8)) {
        require(payload.size <= MAX_CONTROL_PAYLOAD) { "ping payload over 125 bytes" }
        pendingPing = payload
        pendingPingAtMs = nowMs()
        lastPingAtMs = pendingPingAtMs
        sendFrame(OP_PING, payload)
    }

    /**
     * Keep-alive, called about every second by the session: a ping every [WebSocketLimits.pingIntervalMs]; a pong
     * missing after [WebSocketLimits.pongTimeoutMs] closes the connection (dead 4G link held by a proxy).
     */
    @Throws(IOException::class)
    fun tick(now: Long = nowMs()) {
        if (finished) throw WebSocketException("closed", CLOSE_NORMAL)
        if (pendingPing != null && now - pendingPingAtMs > limits.pongTimeoutMs) {
            fail(CLOSE_GOING_AWAY, "no pong")
        }
        if (pendingPing == null && now - lastPingAtMs >= limits.pingIntervalMs) ping()
    }

    private fun sendFrame(opcode: Int, payload: ByteArray) {
        if (closeSent.get()) throw WebSocketException("closing", CLOSE_NORMAL)
        writeFrame(opcode, payload)
    }

    private fun writeFrame(opcode: Int, payload: ByteArray) {
        val n = payload.size
        val headerLen = 2 + (if (n < 126) 0 else if (n <= 0xffff) 2 else 8) + 4
        val frame = ByteArray(headerLen + n)
        frame[0] = (0x80 or opcode).toByte()
        var i: Int
        when {
            n < 126 -> { frame[1] = (0x80 or n).toByte(); i = 2 }
            n <= 0xffff -> {
                frame[1] = (0x80 or 126).toByte()
                frame[2] = (n ushr 8).toByte(); frame[3] = n.toByte(); i = 4
            }
            else -> {
                frame[1] = (0x80 or 127).toByte()
                for (k in 0 until 8) frame[2 + k] = (n.toLong() ushr (56 - 8 * k)).toByte()
                i = 10
            }
        }
        val mask = randomBytes(4)
        System.arraycopy(mask, 0, frame, i, 4)
        i += 4
        for (k in 0 until n) frame[i + k] = (payload[k].toInt() xor mask[k and 3].toInt()).toByte()
        synchronized(writeLock) {
            if (socketClosed.get()) throw WebSocketException("closed", CLOSE_ABNORMAL)
            try {
                output.write(frame)
                output.flush()
            } catch (e: IOException) {
                shutdown()
                throw e
            }
        }
    }

    // ------------------------------------------------------------------
    // Closing
    // ------------------------------------------------------------------

    /**
     * Clean close (RFC 6455 §7.1.2): our close frame, the server's awaited [WebSocketLimits.closeWaitMs] at most (by
     * the reader thread if one is reading, else here), then the TCP connection.
     */
    fun close(code: Int = CLOSE_NORMAL, reason: String = "") {
        if (finished) return
        if (closeSent.compareAndSet(false, true)) {
            try {
                writeFrame(OP_CLOSE, closePayload(code, reason))
            } catch (e: IOException) {
                shutdown()
                return
            }
        }
        if (reading) {
            closedLatch.await(limits.closeWaitMs, TimeUnit.MILLISECONDS)
        } else {
            try {
                socket.soTimeout = limits.closeWaitMs.toInt().coerceAtLeast(1)
                val deadline = nowMs() + limits.closeWaitMs
                while (!finished && nowMs() < deadline) {
                    if (receive() is WsMessage.Closed) break
                }
            } catch (e: IOException) {
                // Time-out or error: the connection goes anyway.
            }
        }
        shutdown()
    }

    /** Drops the connection at once (no close frame). */
    fun abort() = shutdown()

    private fun shutdown() {
        finished = true
        if (socketClosed.compareAndSet(false, true)) closeQuietly(socket)
        closedLatch.countDown()
    }

    /** Closes with [code] and throws. */
    private fun fail(code: Int, message: String): Nothing {
        if (closeSent.compareAndSet(false, true)) {
            try {
                writeFrame(OP_CLOSE, closePayload(code, ""))
            } catch (e: IOException) {
                // Best effort.
            }
        }
        shutdown()
        throw WebSocketException(message, code)
    }

    private fun closePayload(code: Int, reason: String): ByteArray {
        val r = reason.toByteArray(Charsets.UTF_8).let { if (it.size > MAX_CONTROL_PAYLOAD - 2) it.copyOf(MAX_CONTROL_PAYLOAD - 2) else it }
        val out = ByteArray(2 + r.size)
        out[0] = (code ushr 8).toByte()
        out[1] = code.toByte()
        System.arraycopy(r, 0, out, 2, r.size)
        return out
    }

    // ------------------------------------------------------------------

    private fun readByte(): Int {
        val b = input.read()
        if (b < 0) {
            shutdown()
            throw WebSocketException("connection lost", CLOSE_ABNORMAL)
        }
        return b
    }

    private fun readFully(n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(out, off, n - off)
            if (r < 0) {
                shutdown()
                throw WebSocketException("connection lost", CLOSE_ABNORMAL)
            }
            off += r
        }
        return out
    }

    private fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    companion object {
        const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        const val MAX_CONTROL_PAYLOAD = 125

        const val OP_CONTINUATION = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        const val CLOSE_NORMAL = 1000
        const val CLOSE_GOING_AWAY = 1001
        const val CLOSE_PROTOCOL_ERROR = 1002
        const val CLOSE_NO_STATUS = 1005
        const val CLOSE_ABNORMAL = 1006
        const val CLOSE_INVALID_DATA = 1007
        const val CLOSE_POLICY = 1008
        const val CLOSE_TOO_BIG = 1009

        /** The Sec-WebSocket-Accept expected for [key] (RFC 6455 §4.2.2). */
        fun acceptFor(key: String): String =
            B64.encodeStd(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))

        /** Codes a peer may send (RFC 6455 §7.4): 1004, 1005, 1006 and 1015 never travel. */
        fun validReceivedCloseCode(code: Int): Boolean =
            code in 1000..1003 || code in 1007..1014 || code in 3000..4999

        /**
         * Opens [url] (wss://host[:port]/path; ws:// only through a connector that admits it, in tests), sends the
         * upgrade with [headers] and checks the answer: status 101, Upgrade: websocket, Connection: Upgrade, the exact
         * Sec-WebSocket-Accept, no extension nor subprotocol (none asked). [onSocket] gets the connection once open,
         * before the upgrade: closing it from another thread gives up at once.
         */
        @Throws(IOException::class)
        fun connect(
            url: String,
            headers: Map<String, String>,
            connector: SocketConnector,
            limits: WebSocketLimits = WebSocketLimits(),
            random: SecureRandom = SecureRandom(),
            nowMs: () -> Long = { System.currentTimeMillis() },
            onSocket: (Socket) -> Unit = {},
        ): WebSocket {
            val uri = try { URI(url) } catch (e: Exception) { throw IOException("bad url") }
            val secure = when (uri.scheme?.lowercase()) {
                "wss" -> true
                "ws" -> false
                else -> throw IOException("bad scheme")
            }
            val host = uri.host ?: throw IOException("bad url")
            if (uri.rawUserInfo != null || uri.rawFragment != null || uri.rawQuery != null) throw IOException("bad url")
            val port = if (uri.port == -1) (if (secure) 443 else 80) else uri.port
            val path = uri.rawPath?.takeIf { it.startsWith("/") } ?: throw IOException("bad url")
            for ((k, v) in headers) {
                if (!HEADER_NAME.matches(k) || v.any { it == '\r' || it == '\n' || it.code > 0x7e }) throw IOException("bad header $k")
            }

            val socket = connector.connect(host, port, secure, limits.connectTimeoutMs)
            try {
                onSocket(socket)
                socket.soTimeout = limits.readTimeoutMs
                socket.tcpNoDelay = true
                val input = BufferedInputStream(socket.getInputStream(), 16 * 1024)
                val output = socket.getOutputStream()
                val key = B64.encodeStd(ByteArray(16).also { random.nextBytes(it) })
                val hostHeader = if (port == (if (secure) 443 else 80)) host else "$host:$port"
                val request = StringBuilder()
                    .append("GET ").append(path).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(hostHeader).append("\r\n")
                    .append("Upgrade: websocket\r\n")
                    .append("Connection: Upgrade\r\n")
                    .append("Sec-WebSocket-Key: ").append(key).append("\r\n")
                    .append("Sec-WebSocket-Version: 13\r\n")
                for ((k, v) in headers) request.append(k).append(": ").append(v).append("\r\n")
                request.append("\r\n")
                output.write(request.toString().toByteArray(Charsets.US_ASCII))
                output.flush()

                checkHandshake(readHead(input, limits.maxHandshakeBytes), key)
                return WebSocket(socket, input, output, limits, random, nowMs)
            } catch (e: IOException) {
                closeQuietly(socket)
                throw e
            } catch (e: RuntimeException) {
                closeQuietly(socket)
                throw IOException("handshake: ${e.message}", e)
            }
        }

        private val HEADER_NAME = Regex("^[A-Za-z0-9-]{1,64}$")

        /** The status line and headers, up to the empty line; the bytes after it stay in [input] (a first frame). */
        private fun readHead(input: InputStream, max: Int): String {
            val buf = ByteArrayOutputStream()
            var last4 = 0
            while (true) {
                val b = input.read()
                if (b < 0) throw WebSocketHandshakeException("connection closed during the handshake", 0)
                buf.write(b)
                if (buf.size() > max) throw WebSocketHandshakeException("handshake answer too large", 0)
                last4 = (last4 shl 8) or b
                if (last4 == 0x0d0a0d0a) break
            }
            return String(buf.toByteArray(), Charsets.ISO_8859_1)
        }

        private fun checkHandshake(head: String, key: String) {
            val lines = head.split("\r\n")
            val status = Regex("^HTTP/1\\.1 (\\d{3})(?: .*)?$").matchEntire(lines[0])?.groupValues?.get(1)?.toInt()
                ?: throw WebSocketHandshakeException("bad status line", 0)
            if (status != 101) throw WebSocketHandshakeException("upgrade refused: $status", status)
            val fields = HashMap<String, MutableList<String>>()
            for (line in lines.drop(1)) {
                if (line.isEmpty()) continue
                val colon = line.indexOf(':')
                if (colon <= 0) throw WebSocketHandshakeException("bad header line", 101)
                fields.getOrPut(line.substring(0, colon).trim().lowercase()) { ArrayList() } += line.substring(colon + 1).trim()
            }
            fun single(name: String): String? {
                val v = fields[name] ?: return null
                if (v.size != 1) throw WebSocketHandshakeException("repeated $name", 101)
                return v[0]
            }
            if (!single("upgrade").equals("websocket", ignoreCase = true)) throw WebSocketHandshakeException("Upgrade is not websocket", 101)
            val connection = fields["connection"].orEmpty().flatMap { it.split(',') }.map { it.trim().lowercase() }
            if ("upgrade" !in connection) throw WebSocketHandshakeException("Connection lacks Upgrade", 101)
            val accept = single("sec-websocket-accept") ?: throw WebSocketHandshakeException("no Sec-WebSocket-Accept", 101)
            if (!MessageDigest.isEqual(accept.toByteArray(Charsets.US_ASCII), acceptFor(key).toByteArray(Charsets.US_ASCII))) {
                throw WebSocketHandshakeException("wrong Sec-WebSocket-Accept", 101)
            }
            if (fields.containsKey("sec-websocket-extensions")) throw WebSocketHandshakeException("extension not asked for", 101)
            if (fields.containsKey("sec-websocket-protocol")) throw WebSocketHandshakeException("subprotocol not asked for", 101)
        }

        private fun decodeUtf8(bytes: ByteArray): String? = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: CharacterCodingException) {
            null
        }
    }
}

internal fun closeQuietly(socket: Socket) {
    try {
        socket.close()
    } catch (e: IOException) {
        // Nothing more to do.
    }
}
