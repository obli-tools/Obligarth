package tools.obli.obligarth.agent.core

import java.io.IOException
import java.security.SecureRandom

// =============================================================================
// Fast wake-up of the bridge agent (P0-15 §4.3 B, D9, T7a): POST /agent/v1/wait,
// held by the server 50 s at most, answered { wake, nonce } signed by the instance
// key. Outside AgentClient on purpose: its process lock would block /poll,
// /accept, /inventory and the downloads for 50 s. Signed with Obl-Seq 0 (the
// server neither reads nor consumes last_seq for this route, so no race with
// /poll), never moves the clock (a 401 clockSkew is ignored: the next /poll sets
// it), its own connection (its own transport instance).
// =============================================================================

sealed class WaitOutcome {
    /** The server has something for the agent: interrogate now. */
    object Wake : WaitOutcome()
    /** The wait ended without anything (or was replaced by a newer one): wait again while the window is open. */
    object Idle : WaitOutcome()
    class Failed(val reason: String, val retryAfterSeconds: Long? = null) : WaitOutcome()
}

class WaitClient(
    private val state: AgentState,
    private val signer: AgentSigner,
    /** A transport of its own (UrlConnectionTransport with the same trust as the one of AgentClient). */
    private val transport: Transport,
    /** Local wall clock, Unix seconds. */
    private val clock: () -> Long,
    private val log: AgentLog = AgentLog.None,
    private val random: SecureRandom = SecureRandom(),
) {
    @Throws(IOException::class)
    fun waitOnce(timeoutMs: Int = TIMEOUT_MS): WaitOutcome {
        val base = state.config?.serverBase ?: return WaitOutcome.Failed("not_configured")
        val agentId = state.agentId ?: return WaitOutcome.Failed("not_enrolled")
        val nonce = B64.encodeUrl(ByteArray(NONCE_BYTES).also { random.nextBytes(it) })
        val body = Json.bytes(linkedMapOf("nonce" to nonce))
        val bodySha = Sha256.hex(body)
        // The offset is read, never written here.
        val ts = clock() + state.clockOffset
        val canonical = Canonical.request("POST", PATH, agentId, 0, ts, bodySha)
        val headers = linkedMapOf(
            "Accept" to "application/json",
            "Content-Type" to "application/json",
            "Obl-Agent-Id" to agentId,
            "Obl-Seq" to "0",
            "Obl-Ts" to ts.toString(),
            "Obl-Signature" to B64.encodeUrl(signer.sign(canonical.toByteArray(Charsets.UTF_8))),
        )
        val response = transport.exchange(HttpRequest("POST", base + PATH, headers, body, timeoutMs = timeoutMs))
        val signed = ResponseVerifier.verify(
            state.serverKeys, response.header("Obl-Server-Key-Id"), response.header("Obl-Server-Signature"),
            response.status, agentId, 0, bodySha, response.body,
        )
        val json = Json.parseObjectOrNull(String(response.body, Charsets.UTF_8))
        val retryAfter = response.header("Retry-After")?.trim()?.toLongOrNull()?.coerceIn(1, 3_600)
        if (response.status != 200) {
            val code = json?.str("code") ?: "http_${response.status}"
            // clockSkew: no correction here, signed or not (the next /poll sets the clock).
            return WaitOutcome.Failed(code, retryAfter)
        }
        if (!signed) {
            log.warn("unsigned /wait answer ignored")
            return WaitOutcome.Failed("unsigned")
        }
        if (json == null || json.str("nonce") != nonce) return WaitOutcome.Failed("nonce")
        return when (json.bool("wake")) {
            true -> WaitOutcome.Wake
            false -> WaitOutcome.Idle
            null -> WaitOutcome.Failed("malformed")
        }
    }

    companion object {
        const val PATH = "/agent/v1/wait"
        const val NONCE_BYTES = 16
        /** Connect and read each: the server answers within 50 s (under the 60 s of Nginx Proxy Manager). */
        const val TIMEOUT_MS = 65_000

        /** Pause before the next wait: none after an answer, else the server's Retry-After, else 30 s. */
        fun delayAfter(outcome: WaitOutcome): Long = when (outcome) {
            WaitOutcome.Wake, WaitOutcome.Idle -> 0
            is WaitOutcome.Failed -> outcome.retryAfterSeconds ?: FAILURE_DELAY_S
        }

        const val FAILURE_DELAY_S = 30L
    }
}

/**
 * When the agent holds /wait (§4.3 B, D9): only while remote assistance is enabled, and then during an armed window
 * (15 min after the "Ask for help" button, or until remote.armedUntil of the server), or always when the tenant chose
 * the permanent wait (remote.waitChannel, false by default). Outside it, no wait: no 4G radio held all day.
 */
object WaitWindow {
    const val ARMED_SECONDS = 15 * 60L

    /** [localNow]: local seconds; [serverNow]: corrected seconds (armedUntil is a server time). */
    fun open(state: AgentState, localNow: Long, serverNow: Long): Boolean {
        val remote = state.remote
        if (!remote.enabled) return false
        if (remote.waitChannel) return true
        val armed = remote.armedUntil
        if (armed != null && serverNow < armed && armed - serverNow <= ARMED_SECONDS) return true
        val help = state.helpArmedUntil
        // A window never exceeds 15 min: beyond that, the local clock was moved back since it was armed.
        return localNow < help && help - localNow <= ARMED_SECONDS
    }

    /** The user pressed "Ask for help" (T8): the window opens for 15 min. */
    fun armForHelp(state: AgentState, localNow: Long) {
        state.helpArmedUntil = localNow + ARMED_SECONDS
    }
}
