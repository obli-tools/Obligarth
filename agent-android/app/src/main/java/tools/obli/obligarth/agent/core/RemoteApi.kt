package tools.obli.obligarth.agent.core

import java.io.IOException
import java.net.Socket
import java.security.SecureRandom

// =============================================================================
// Remote assistance, agent side of the queue and of the stream (P0-15 §4.3, §4.4,
// T7a): the remote part of the signed configuration, the signed routes /accept and
// /end (through AgentClient: seq consumed, answers verified), and the attach of the
// stream (Obl-Seq 0, single-use stream token, nonce and ephemeral ECDH key bound
// to the signature, hello checked before anything flows).
// =============================================================================

/** config.remote of /enroll and /poll (§4.3), absent: disabled. */
data class RemoteConfig(
    /** The corporate privacy profile of the tenant allows remote assistance. */
    val enabled: Boolean,
    /** Permanent /wait (tenant option, false by default, D9). */
    val waitChannel: Boolean,
    /** Server time (Unix seconds) until which /wait is held, at most 15 min after it was received. */
    val armedUntil: Long?,
    val minAgentVersion: String?,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "enabled" to enabled, "waitChannel" to waitChannel, "armedUntil" to armedUntil, "minAgentVersion" to minAgentVersion,
    )

    companion object {
        val DISABLED = RemoteConfig(false, false, null, null)

        /** The stored form. */
        fun fromJson(m: Map<String, Any?>): RemoteConfig =
            RemoteConfig(m.bool("enabled") == true, m.bool("waitChannel") == true, m.long("armedUntil"), m.str("minAgentVersion"))

        /**
         * The server's form, read at [serverNow]: a missing or malformed object disables; armedUntil is cut to
         * [WaitWindow.ARMED_SECONDS] after now (a server that arms the device for a day would hold its radio a day).
         */
        fun fromServer(m: Map<String, Any?>?, serverNow: Long): RemoteConfig {
            if (m == null) return DISABLED
            val armed = m.long("armedUntil")?.takeIf { it > serverNow }?.coerceAtMost(serverNow + WaitWindow.ARMED_SECONDS)
            val min = m.str("minAgentVersion")?.takeIf { it.length <= 16 }
            return RemoteConfig(m.bool("enabled") == true, m.bool("waitChannel") == true, armed, min)
        }
    }
}

/** What the agent measured when it took the session (§4.3 /accept, agent_capabilities of the session). */
data class RemoteCapabilities(
    val inject: Boolean,
    val remoteInject: Boolean,
    val codecs: List<String>,
    val width: Int,
    val height: Int,
    /** Informative since §0.1: the notifications of the agent blocked stop nothing. */
    val notificationsEnabled: Boolean,
    val overlay: Boolean,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "inject" to inject, "remoteInject" to remoteInject, "codecs" to codecs, "width" to width, "height" to height,
        "notificationsEnabled" to notificationsEnabled, "overlay" to overlay,
    )
}

/** The signed answer of /accept. */
class RemoteAccepted(
    /** base64url, as the server gave it (it goes back in Obl-Stream-Token). */
    val streamToken: String,
    val streamTokenBytes: ByteArray,
    /** /agent/v1/remote/<sessionId>/stream, nothing else. */
    val streamPath: String,
    val expiresIn: Long,
    /** Server time (Unix seconds) of the end of the session at the latest. */
    val maxEndsAt: Long?,
    val idleSeconds: Long?,
    val bitrateMax: Long?,
)

sealed class AcceptOutcome {
    class Accepted(val accepted: RemoteAccepted) : AcceptOutcome()
    /** Refused by the server (signed): 400 consentExceedsRequest, 409 indicatorUnavailable, 404, 409 state, 429... */
    class Refused(val status: Int, val code: String?) : AcceptOutcome() {
        /**
         * The server closed the session with this refusal, or does not know it: nothing more to tell it (session_gone).
         * Any other refusal (rateLimited, clockSkew or seqReplay still refused after the client's one retry, a body
         * not taken) leaves it waiting for /accept there: the session ends agent_error, told to /end.
         */
        val closesSession: Boolean get() = status == 404 || code in SESSION_CLOSING_CODES

        companion object {
            /** server/src/remote/sessions.ts onAccepted: the refusals of /accept that end the session (or find it ended). */
            val SESSION_CLOSING_CODES = setOf("remoteSessionState", "consentExceedsRequest", "indicatorUnavailable", "remoteUnavailable")
        }
    }
    /** No usable answer (unsigned, malformed, 5xx): the session is to be given up. */
    class Failed(val reason: String) : AcceptOutcome()
}

class RemoteApi(
    private val state: AgentState,
    private val client: AgentClient,
    private val signer: AgentSigner,
    private val connector: SocketConnector,
    private val random: SecureRandom = SecureRandom(),
    private val limits: WebSocketLimits = WebSocketLimits(),
    private val log: AgentLog = AgentLog.None,
    /** The hello awaited this long at most after the upgrade, pings or not (shorter in tests). */
    private val helloTimeoutMs: Int = RemoteLimits.HELLO_TIMEOUT_MS,
) {
    /**
     * POST /agent/v1/remote/<id>/accept (signed, seq consumed): consentedMode is the mode asked and consentedAt the time the
     * agent takes the session (§0.1: nobody on the device answers; the field names are those of the contract).
     */
    @Throws(IOException::class)
    fun accept(sessionId: String, consentedMode: RemoteMode, capabilities: RemoteCapabilities): AcceptOutcome {
        require(Uuids.isLower(sessionId)) { "session id" }
        val body = linkedMapOf<String, Any?>(
            "consentedAt" to client.correctedNow(), "consentedMode" to consentedMode.wire, "capabilities" to capabilities.toJson(),
        )
        val reply = client.call("POST", "/agent/v1/remote/$sessionId/accept", Json.bytes(body))
        if (!reply.signed) return AcceptOutcome.Failed("unsigned")
        if (reply.status != 200) return if (reply.status in 400..499) AcceptOutcome.Refused(reply.status, reply.code) else AcceptOutcome.Failed("http ${reply.status}")
        val j = reply.json ?: return AcceptOutcome.Failed("malformed")
        val token = j.str("streamToken")
        val tokenBytes = token?.let { B64.decode(it) }
        val path = j.str("streamPath")
        val expiresIn = j.long("expiresIn")
        if (token == null || tokenBytes == null || tokenBytes.size != 32 || token.any { it == '+' || it == '/' || it == '=' } ||
            path != streamPath(sessionId) || expiresIn == null || expiresIn !in 1..300
        ) {
            log.warn("remote accept answer malformed")
            return AcceptOutcome.Failed("malformed")
        }
        return AcceptOutcome.Accepted(RemoteAccepted(token, tokenBytes, path, expiresIn, j.long("maxEndsAt"), j.long("idleSeconds"), j.long("bitrateMax")))
    }

    /** POST /agent/v1/remote/<id>/end (signed, seq consumed). True when the server took it (signed 2xx). */
    @Throws(IOException::class)
    fun end(sessionId: String, reason: String): Boolean {
        require(Uuids.isLower(sessionId)) { "session id" }
        require(reason in END_REASONS) { "end reason $reason" }
        val reply = client.call("POST", "/agent/v1/remote/$sessionId/end", Json.bytes(linkedMapOf("reason" to reason)))
        return reply.signed && reply.ok
    }

    /**
     * GET /agent/v1/remote/<id>/stream with the upgrade (§4.4): signed with seq 0 over SHA-256(streamToken ‖ nonce ‖
     * ECDH key), then the hello checked against the trusted instance keys. The channel's mode is the lower of
     * [consentedMode] and the hello's. [onSocket] gets the connection as soon as it is open: closing it gives up the
     * attach at once, wherever it waits (the upgrade's answer, the hello).
     */
    @Throws(IOException::class)
    fun attach(sessionId: String, accepted: RemoteAccepted, consentedMode: RemoteMode, onSocket: (Socket) -> Unit = {}): RemoteChannel {
        require(Uuids.isLower(sessionId) && accepted.streamPath == streamPath(sessionId)) { "stream path" }
        val base = state.config?.serverBase ?: throw IOException("not configured")
        val agentId = state.agentId ?: throw IOException("not enrolled")
        val keys = state.serverKeys
        if (keys.isEmpty()) throw IOException("no server key")
        val nonce = ByteArray(RemoteCrypto.NONCE_BYTES).also { random.nextBytes(it) }
        val ephemeral = RemoteCrypto.ephemeralKeyPair(random)
        val ecdh = ephemeral.public.encoded
        val ts = client.correctedNow()
        val bodySha = RemoteChannel.attachBodySha256(accepted.streamTokenBytes, nonce, ecdh)
        val canonical = Canonical.request("GET", accepted.streamPath, agentId, 0, ts, bodySha)
        val headers = linkedMapOf(
            "Obl-Agent-Id" to agentId,
            "Obl-Seq" to "0",
            "Obl-Ts" to ts.toString(),
            "Obl-Stream-Token" to accepted.streamToken,
            "Obl-Nonce" to B64.encodeUrl(nonce),
            "Obl-Ecdh" to B64.encodeUrl(ecdh),
            "Obl-Signature" to B64.encodeUrl(signer.sign(canonical.toByteArray(Charsets.UTF_8))),
        )
        val url = "wss://" + base.removePrefix("https://") + accepted.streamPath
        val ws = WebSocket.connect(url, headers, connector, limits, random, onSocket = onSocket)
        return RemoteChannel.afterHello(ws, sessionId, consentedMode, nonce, ephemeral, keys, client.correctedNow(), helloTimeoutMs)
    }

    companion object {
        /**
         * The reasons the agent gives to /end (§4.3, §0.1): user_stopped, user_refused, consent_timeout and indicator_lost
         * are no longer produced (no answer nor Stop on the device, the indicator is not watched).
         */
        val END_REASONS = setOf("projection_denied", "screen_off_timeout", "agent_error")

        fun streamPath(sessionId: String) = "/agent/v1/remote/$sessionId/stream"
    }
}
