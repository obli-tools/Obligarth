package tools.obli.obligarth.agent.core

import java.io.File
import java.io.IOException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** One answer of the server, after signature verification. */
class Reply(
    val status: Int,
    /** The server signature verified against a pinned key (§4.3). */
    val signed: Boolean,
    val json: Map<String, Any?>?,
    val code: String?,
    val retryAfterSeconds: Long?,
    val downloadedSha256: String? = null,
) {
    val ok get() = status in 200..299
}

/**
 * Signed, serialised requests (spec §4.2), verified responses (§4.3), clock skew
 * and seq recovery (§4.8, RC-6). One request at a time per process.
 */
class AgentClient(
    private val state: AgentState,
    private val signer: AgentSigner,
    private val transport: Transport,
    /** Local wall clock, Unix seconds. */
    private val clock: () -> Long,
    private val log: AgentLog = AgentLog.None,
) {
    /** Process-wide serialisation of requests (an interrogation waits for a download, F-7). */
    val lock = ReentrantLock()

    fun correctedNow(): Long = clock() + state.clockOffset

    /** Signs and sends; recovers once from clockSkew and once from seqReplay. */
    @Throws(IOException::class)
    fun call(
        method: String,
        path: String,
        body: ByteArray?,
        enrollKeys: ((Map<String, Any?>?) -> List<ServerKey>)? = null,
        downloadTo: File? = null,
        maxDownloadBytes: Long = 0,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
        /** For a package download: the SHA-256 announced by the command, which the server signature covers (§4.7). */
        expectedDownloadSha256: String? = null,
        /** Enrollment only: enrollKeys keeps the keys pinned by the configuration or the build (never trust on first contact). */
        enrollKeysPinned: Boolean = false,
    ): Reply = lock.withLock {
        var skewRetried = false
        var seqRetried = false
        while (true) {
            val reply = once(method, path, body, enrollKeys, downloadTo, maxDownloadBytes, timeoutMs, expectedDownloadSha256)
            if (reply.status == 401 && reply.code == "clockSkew" && !skewRetried) {
                val serverTime = reply.json?.long("serverTime")
                // RC-6: only a signed body sets the clock. During enrollment, only an answer verified against a key
                // pinned by the configuration or the build (PONT-S review): an unsigned answer, or one verified
                // against a key the answer itself announces (debug trust on first contact), never moves the clock
                // that decides the expiry of orders.
                if (serverTime != null && reply.signed && (enrollKeys == null || enrollKeysPinned)) {
                    skewRetried = true
                    setClock(serverTime)
                    continue
                }
            }
            if (reply.status == 409 && reply.code == "seqReplay" && reply.signed && !seqRetried) {
                val last = reply.json?.long("lastSeq")
                if (last != null && last >= 0) {
                    seqRetried = true
                    state.seq = last
                    continue
                }
            }
            return reply
        }
        @Suppress("UNREACHABLE_CODE")
        throw IllegalStateException()
    }

    /** Called with the change (seconds) each time the clock offset is set from a server time. */
    var onClockCorrected: ((Long) -> Unit)? = null

    fun setClock(serverTime: Long): Long {
        val before = state.clockOffset
        val offset = serverTime - clock()
        state.clockOffset = offset
        val delta = offset - before
        onClockCorrected?.invoke(delta)
        return delta
    }

    private fun once(
        method: String,
        path: String,
        body: ByteArray?,
        enrollKeys: ((Map<String, Any?>?) -> List<ServerKey>)?,
        downloadTo: File?,
        maxDownloadBytes: Long,
        timeoutMs: Int,
        expectedDownloadSha256: String?,
    ): Reply {
        val base = state.config?.serverBase ?: throw IOException("not configured")
        val enroll = enrollKeys != null
        val agentId = if (enroll) null else state.agentId ?: throw IOException("not enrolled")
        val seq: Long = if (enroll) 0 else (state.seq + 1).also { state.seq = it } // persisted before sending (RC-6)
        val ts = correctedNow()
        val bodyHash = if (body == null || body.isEmpty()) Sha256.EMPTY else Sha256.hex(body)
        val canonical = Canonical.request(method, path, agentId, seq, ts, bodyHash)
        val signature = B64.encodeUrl(signer.sign(canonical.toByteArray(Charsets.UTF_8)))
        val headers = linkedMapOf(
            "Accept" to "application/json",
            "Obl-Agent-Id" to (agentId ?: Canonical.NO_AGENT),
            "Obl-Seq" to seq.toString(),
            "Obl-Ts" to ts.toString(),
            "Obl-Signature" to signature,
        )
        if (body != null) headers["Content-Type"] = "application/json"
        val response = transport.exchange(HttpRequest(method, base + path, headers, body, downloadTo, maxDownloadBytes, timeoutMs))

        val json = if (response.downloadedSha256 == null) Json.parseObjectOrNull(String(response.body, Charsets.UTF_8)) else null
        val keys = if (enroll) enrollKeys!!(json) else state.serverKeys
        // A download is signed over the known (announced) SHA-256; the file itself is checked against it afterwards (hash_mismatch).
        val responseHash = if (response.downloadedSha256 != null) expectedDownloadSha256 ?: response.downloadedSha256 else Sha256.hex(response.body)
        val signed = ResponseVerifier.verifyHash(
            keys, response.header("Obl-Server-Key-Id"), response.header("Obl-Server-Signature"),
            response.status, agentId, seq, bodyHash, responseHash,
        )
        if (!signed) log.warn("unsigned or badly signed answer ${response.status} to $method $path")
        val retryAfter = response.header("Retry-After")?.trim()?.toLongOrNull()?.coerceIn(1, 86_400)
        return Reply(response.status, signed, json, json?.str("code"), retryAfter, response.downloadedSha256)
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 30_000
    }
}
