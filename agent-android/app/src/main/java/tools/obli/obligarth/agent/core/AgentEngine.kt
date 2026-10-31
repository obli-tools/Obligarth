package tools.obli.obligarth.agent.core

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import kotlin.random.Random

/** What a cycle asks the scheduler for. */
data class CycleReport(
    /** Seconds until the next interrogation. */
    val nextDelaySeconds: Long,
    val commandsReceived: Int = 0,
    /** The install queue has work (downloads run in a dedicated job, F-7). */
    val installWork: Boolean = false,
)

/**
 * The agent logic, independent from Android: configuration, enrollment,
 * interrogation, inventory, command execution, install queue (spec §4, §5.3,
 * §8.3, §8.6, revisions RS-2, RS-4 to RS-8, F-7, F-8).
 */
class AgentEngine(
    private val state: AgentState,
    private val client: AgentClient,
    private val signer: AgentSigner,
    private val facts: DeviceFacts,
    private val actions: DeviceActions,
    private val policy: TrustPolicy,
    private val ownPackage: String,
    private val versionCode: Long,
    /** SHA-256 of the signing certificates admitted for an agent update (PINNED_SIGNERS). */
    private val pinnedSigners: Set<String>,
    private val updatesDir: File,
    private val clock: () -> Long,
    private val log: AgentLog = AgentLog.None,
    private val random: Random = Random.Default,
    /** Remote assistance sessions (1.1.0, P0-15); none: remote.open is refused. */
    private val remoteHost: RemoteHost = RemoteHost.None,
    /** 1.3.0: seals the secrets of the stored policy (AndroidKeyStore on the device); none: they are never stored. */
    private val sealer: SecretSealer = SecretSealer.None,
    /** 1.3.0: the policy files (blobs/<sha>): filesDir/policy on the device. */
    policyDir: File = File(updatesDir.path + "-policy"),
) {
    /** Called when a delivered configuration changes (Knox licence, keep-alive...). */
    var onConfigChanged: (() -> Unit)? = null
    /** Called when the identity was erased after a signed agentRevoked (or an agent.release, 1.4.0). */
    var onRevoked: (() -> Unit)? = null
    /** 1.4.0 (lot BANC §7.3): the owner role changed (true: the agent became the owner). Called inside the engine lock. */
    var onRoleChanged: ((Boolean) -> Unit)? = null
    /**
     * 1.3.0: the policy changed (new policy, kiosk suspended, re-apply asked): the host reconciles soon. Called inside
     * the engine lock: the host only schedules the work.
     */
    var onPolicyChanged: (() -> Unit)? = null

    /** The policy files downloaded and the inline files staged (1.3.0). */
    val blobCache = DirBlobCache(File(policyDir, "blobs"))
    /** When a blob was last refused (local seconds): retried after REFUSED_RETRY_S. */
    private val refusedAt = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /** The last policy read, secrets included when they came with this process (a sealing failure keeps them here). */
    @Volatile private var livePolicy: Policy? = null

    private val now get() = client.correctedNow()

    init {
        client.onClockCorrected = { delta ->
            // Enrollment sets the first offset: only later corrections are events.
            if (state.phase == Phase.ENROLLED && Math.abs(delta) > CLOCK_EVENT_S) {
                state.addEvent("clock_corrected", now, mapOf("deltaSeconds" to delta))
            }
        }
    }

    // ------------------------------------------------------------------
    // Configuration (§4.9)
    // ------------------------------------------------------------------

    /** Returns null when accepted, else the refusal reason. */
    @Synchronized
    fun importConfig(raw: String?, source: String): String? {
        val parsed = AgentConfig.parse(raw, policy)
        val t = EnrollmentMachine.next(state.phase, EnrollEvent.ConfigImported(parsed is ConfigResult.Valid))
        if (!t.acceptConfig) {
            val reason = t.refusal ?: (parsed as? ConfigResult.Invalid)?.reason ?: "refused"
            log.warn("configuration from $source refused: $reason")
            return if (parsed is ConfigResult.Invalid && t.refusal == "invalid") parsed.reason else reason
        }
        // 1.4.0 (lot BANC §7.1): an owner of the device not enrolled takes its configuration from the bench channel only.
        if (!BenchRules.configSourceAllowed(source, deviceOwner(), state.phase)) {
            log.warn("configuration from $source refused: $OWNER_BENCH_ONLY")
            return OWNER_BENCH_ONLY
        }
        val cfg = (parsed as ConfigResult.Valid).config
        state.config = cfg
        state.phase = t.next
        state.notBefore = 0
        state.backoffStep = 0
        state.lastStatus = "configured"
        state.addEvent("config_imported", now, mapOf("source" to source))
        log.info("configuration from $source accepted for ${cfg.host}")
        return null
    }

    // ------------------------------------------------------------------
    // One cycle: enroll or poll, then inventory when due.
    // ------------------------------------------------------------------

    @Synchronized
    fun runCycle(force: Boolean = false): CycleReport {
        val local = clock()
        // A wait never exceeds a day: beyond that, the local clock was moved back since it was set
        // (store clocks corrected late, F-6) and the agent would stay silent for as long.
        if (state.notBefore - local > MAX_WAIT_S) state.notBefore = 0
        if (!force && local < state.notBefore) return CycleReport(state.notBefore - local, installWork = state.installQueue.isNotEmpty())
        settleLocalState()
        return try {
            when (state.phase) {
                Phase.CONFIGURED -> enroll()
                Phase.ENROLLED -> pollAndExecute()
                else -> CycleReport(state.pollSeconds.toLong())
            }
        } catch (e: IOException) {
            log.warn("network: ${e.message}")
            state.lastStatus = "network_error"
            backoff(null)
        }
    }

    /** Self-update completion, prompt time-outs, old files (run before each cycle). */
    private fun settleLocalState() {
        val journal = state.journal.toMutableList()
        var changed = false
        val awaiting = state.awaitingUser.toMutableMap()
        for ((i, e) in journal.withIndex()) {
            if (e.state == "self_update" && e.targetVersion != null && versionCode >= e.targetVersion) {
                val r = CommandResult(e.id, ResultStatus.ACKNOWLEDGED, Codes.UPDATE_INSTALLED, mapOf("versionCode" to versionCode), now)
                journal[i] = e.copy(state = "done", result = r)
                addResult(r)
                state.addEvent("update_installed", now, mapOf("versionCode" to versionCode))
                awaiting.remove(e.id)
                changed = true
            }
        }
        if (changed) state.journal = journal
        // Prompts waiting for a user: settled by the package state, else 24 h time-out.
        for ((id, a) in awaiting.toMap()) {
            val pkg = a.str("package") ?: continue
            val kind = a.str("kind")
            val target = a.long("versionCode")
            val since = a.long("since") ?: 0
            val installed = actions.installedVersion(pkg)
            val result = when {
                kind == "uninstall" && installed == null -> CommandResult(id, ResultStatus.ACKNOWLEDGED, Codes.UNINSTALLED, emptyMap(), now)
                kind == "install" && target != null && installed != null && installed >= target -> postInstallCheck(id, pkg, a.str("signer"))
                clock() - since > USER_TIMEOUT_S -> CommandResult(id, ResultStatus.ERROR, Codes.USER_TIMEOUT, emptyMap(), now)
                else -> null
            }
            if (result != null) {
                awaiting.remove(id)
                finish(id, result)
            }
        }
        state.awaitingUser = awaiting
        settleRemote()
        cleanUpdates()
    }

    /** A remote.open the host no longer runs (the process was killed during the session) gets an answer. */
    private fun settleRemote() {
        val active = remoteHost.activeCommand()
        for (e in state.journal) {
            if (e.type == CommandType.REMOTE_OPEN.wire && e.state == "awaiting_user" && e.id != active && now - e.at > REMOTE_ORPHAN_S) {
                finish(e.id, CommandResult(e.id, ResultStatus.ERROR, Codes.INTERNAL, mapOf("message" to "session lost by the agent"), now))
            }
        }
    }

    private fun cleanUpdates() {
        val files = updatesDir.listFiles() ?: return
        for (f in files) if (clock() * 1000 - f.lastModified() > 86_400_000L) f.delete()
    }

    // ------------------------------------------------------------------
    // Enrollment (§4.4)
    // ------------------------------------------------------------------

    /**
     * The body of /enroll. 1.4.0 (lot BANC §3.4, §7.2): capabilities.deviceOwner always, hints.provisioningId when the
     * configuration came from a bench station; [legacy]: the body of 1.3.0, without them.
     */
    private fun enrollBody(cfg: AgentConfig, legacy: Boolean): ByteArray {
        val capabilities = LinkedHashMap(facts.capabilities())
        if (!legacy) capabilities["deviceOwner"] = deviceOwner()
        val hints = linkedMapOf<String, Any?>("deviceName" to cfg.hints["deviceName"], "serial" to cfg.hints["serial"], "imei" to cfg.hints["imei"])
        if (!legacy) cfg.hints[AgentConfig.PROVISIONING_ID]?.let { hints[AgentConfig.PROVISIONING_ID] = it }
        return Json.bytes(linkedMapOf(
            "token" to cfg.token,
            "publicKey" to B64.encodeUrl(signer.spki()),
            "keyStorage" to signer.storage,
            "agent" to facts.agent(),
            "device" to facts.device(),
            "capabilities" to capabilities,
            "hints" to hints,
        ))
    }

    private fun enroll(): CycleReport {
        val cfg = state.config ?: return CycleReport(state.pollSeconds.toLong())
        fun send(legacy: Boolean) = client.call(
            "POST", "/agent/v1/enroll", enrollBody(cfg, legacy), enrollKeys = { json -> trustedEnrollKeys(cfg, json) },
            enrollKeysPinned = cfg.serverKeySha256 != null || policy.serverKeyPins.isNotEmpty(),
        )
        var reply = send(legacy = false)
        // A server without the fields of 1.4.0 (its strict schema refuses them): sent again at once as 1.3.0, once.
        if (legacyEnrollRetry(reply.status, reply.code, reply.json?.str("error"))) {
            log.warn("enrollment: the server does not know the 1.4.0 fields, sent again as 1.3.0")
            reply = send(legacy = true)
        }
        if ((reply.status == 200 || reply.status == 201) && reply.signed && reply.json != null) {
            val j = reply.json
            val agentId = j.str("agentId")
            val keys = trustedEnrollKeys(cfg, j)
            if (agentId == null || !Uuids.isLower(agentId) || keys.isEmpty()) {
                log.warn("enrollment answer malformed")
                return backoff(null)
            }
            state.agentId = agentId
            state.deviceUuid = j.str("deviceUuid")
            state.serverKeys = keys
            state.seq = 0
            j.long("serverTime")?.let { client.setClock(it) }
            j.int("pollSeconds")?.let { state.pollSeconds = it }
            j.obj("config")?.let { applyConfig(it) }
            state.phase = EnrollmentMachine.next(state.phase, EnrollEvent.EnrollSucceeded).next
            state.backoffStep = 0
            state.notBefore = 0
            state.authFailingSince = 0
            state.inventoryRequested = true
            state.lastStatus = "enrolled"
            // The role told at the enrollment: no device_owner_gained at the first poll.
            state.lastOwner = deviceOwner()
            log.info("enrolled as $agentId")
            return pollAndExecute()
        }
        if (reply.status == 403 && reply.code == "tokenInvalid") {
            // Not destructive: the configuration stays, a new one is awaited (§4.8).
            state.phase = EnrollmentMachine.next(state.phase, EnrollEvent.TokenRejected).next
            state.lastStatus = "token_invalid"
            log.warn("enrollment refused: tokenInvalid")
            return CycleReport(DAY_S)
        }
        if (reply.status == 400) {
            state.lastStatus = "enroll_${reply.code ?: "badRequest"}"
            log.warn("enrollment refused: ${reply.code}")
            return slow(DAY_S)
        }
        state.lastStatus = "enroll_failed_${reply.status}"
        return backoff(reply)
    }

    /** Keys of the enrollment answer the agent may trust: matching the configured pin, else the compiled pins, else (debug) all. */
    private fun trustedEnrollKeys(cfg: AgentConfig, json: Map<String, Any?>?): List<ServerKey> {
        val listed = json?.list("serverKeys").orEmpty().mapNotNull { k ->
            @Suppress("UNCHECKED_CAST") val m = k as? Map<String, Any?> ?: return@mapNotNull null
            val spki = m.str("spki")?.let { B64.decode(it) } ?: return@mapNotNull null
            val key = ServerKey(spki)
            if (key.publicKey == null || m.str("keyId") != key.keyId) null else key
        }
        return when {
            cfg.serverKeySha256 != null -> listed.filter { it.sha256 == cfg.serverKeySha256 }
            policy.serverKeyPins.isNotEmpty() -> listed.filter { it.sha256 in policy.serverKeyPins }
            policy.requireServerKeyPin -> emptyList()
            else -> listed // debug only: trust on first contact (PB11)
        }
    }

    private fun applyConfig(c: Map<String, Any?>) {
        val rebuilt = c.long("version").let { it != null && it != state.configVersion }
        c.long("version")?.let { state.configVersion = it }
        state.configAgentVersion = versionCode
        c.long("inventorySeconds")?.let { if (it in 3600..30L * 86_400) state.inventorySeconds = it }
        c.bool("keepAlive")?.let { state.keepAlive = it }
        c.long("minAgentVersionCode")?.let { state.minAgentVersionCode = it }
        if (c.containsKey("knoxLicenseKey")) state.serverKnoxLicenseKey = c.str("knoxLicenseKey")?.takeIf { it.isNotBlank() }
        // The whole configuration travels each time: no remote object (a server before P0-15) disables it.
        state.remote = RemoteConfig.fromServer(c.obj("remote"), now)
        // 1.3.0: a server that delivers policies always sends the key (null: no policy); an older one never does, and the
        // policy held stays in place. Reports and the 1.3.0 events go to a policy server only.
        state.serverPolicyV1 = c.containsKey("policy")
        // 1.4.0 (lot BANC §3.4): the features of the server travel with each full configuration (absent: an older server).
        state.serverFeatures = c.list("features").orEmpty().filterIsInstance<String>().filter { it.length in 1..64 }.take(MAX_FEATURES)
        if (c.containsKey("policy")) receivePolicy(c["policy"], rebuilt)
        onConfigChanged?.invoke()
    }

    // ------------------------------------------------------------------
    // Owner of the device (1.4.0, lot BANC §3.4, §7.2)
    // ------------------------------------------------------------------

    /** The agent owns the device (false when it cannot be read). */
    private fun deviceOwner(): Boolean = try { facts.deviceOwner() } catch (e: Throwable) { false }

    /** The server announced device_owner_v1: status.deviceOwner, status.adbEnabled and the device_owner_* events go. */
    fun ownerFeature(): Boolean = OwnerMode.FEATURE_DEVICE_OWNER_V1 in state.serverFeatures

    /** An event of the owner role, to a server announcing device_owner_v1 only (an older one would refuse the poll). */
    private fun addOwnerEvent(type: String, detail: Map<String, Any?> = emptyMap()) {
        if (ownerFeature()) state.addEvent(type, now, detail) else log.info("event $type kept local (server without device_owner_v1)")
    }

    /**
     * 1.4.0 (lot BANC §7.4): the shell opened a bench window (the Knox lock of the administrator lifted). Always told to
     * the server at the next poll (its audit, protective). Before the enrollment the server is not known yet: queued all
     * the same (the configuration came from a bench station, so from a server of 1.4.0); poll() leaves the owner events
     * out of the body for a server without device_owner_v1.
     */
    fun benchWindowOpened(phase: Phase, uid: Int) {
        val detail = linkedMapOf<String, Any?>("phase" to phase.name, "uid" to uid)
        if (phase == Phase.ENROLLED) addOwnerEvent(EventTypes.BENCH_WINDOW_OPENED, detail) else state.addEvent(EventTypes.BENCH_WINDOW_OPENED, now, detail)
    }

    /** The server allows this ENROLLED agent to open a bench window now (benchConvert of its last poll reply). */
    fun benchConvertAllowed(): Boolean = state.phase == Phase.ENROLLED && state.benchConvertUntil > clock()

    /** The owner role read at each cycle: a change becomes an event (T389) and tells the host (its protections). */
    private fun trackRole() {
        val owner = deviceOwner()
        val previous = state.lastOwner
        if (previous == owner) return
        state.lastOwner = owner
        if (previous == null && !owner) return
        log.info("owner role: ${previous ?: "unknown"} -> $owner")
        for (e in RoleTransitions.events(previous, owner, releasing = false)) addOwnerEvent(e)
        try { onRoleChanged?.invoke(owner) } catch (e: Throwable) { log.warn("owner role change: ${e.javaClass.simpleName}") }
    }

    /**
     * 1.4.0 (lot BANC §6.5): what the device held for the policy was lost (an administrator restored by the bench after a
     * failed `set-device-owner`: its Knox licence and policies gone). As policy.reapply: every item applied again from a
     * full configuration, the report sent anew.
     */
    @Synchronized
    fun policyLost() {
        state.policyLedger = state.policyLedger.forget()
        state.configVersion = 0
        state.policyReportSentDigest = null
        log.info("policy applied again: the device lost what it held")
        onPolicyChanged?.invoke()
    }

    /** The bench gave the device back before any enrollment (§7.5): the configuration and the identity forgotten. */
    @Synchronized
    fun forgetAfterBenchRelease() {
        livePolicy = null
        state.eraseIdentity()
        state.phase = Phase.NEW
        state.lastStatus = "released"
        log.info("released by the bench: configuration erased")
    }

    /** agent.release (§7.5): the policy undone, the device given back (owner, then administrator), the identity erased. */
    private fun releaseDevice() {
        log.warn("agent.release: the device is given back")
        undoPolicyBeforeErase()
        val outcome = try { actions.releaseOwnership() } catch (e: Throwable) { log.warn("release: ${e.javaClass.simpleName}"); null }
        if (outcome == null) log.warn("release: not supported here, only the identity is erased")
        state.phase = EnrollmentMachine.next(state.phase, EnrollEvent.RevokedSigned).next
        state.eraseIdentity()
        try { signer.erase() } catch (e: Exception) { log.warn("key erase: ${e.message}") }
        state.lastStatus = "released"
        onRevoked?.invoke()
    }

    // ------------------------------------------------------------------
    // Policy (1.3.0, lot PONT-POL §8.1, §8.4, §10.3)
    // ------------------------------------------------------------------

    /** [rebuilt]: the configuration carries a new version (the server built it again: marked delivering on its side). */
    private fun receivePolicy(raw: Any?, rebuilt: Boolean) {
        if (raw == null) {
            if (state.policyHash != null || state.policyRejected != null) {
                log.info("policy removed by the server")
                state.policyJson = null
                state.policyHash = null
                state.policyRejected = null
                livePolicy = null
                onPolicyChanged?.invoke()
            }
            return
        }
        @Suppress("UNCHECKED_CAST") val m = raw as? Map<String, Any?>
        // The server keeps the policy held (its desired body could not be compiled): nothing changes, the report goes on.
        if (m != null && m.bool("keep") == true && m["hash"] == null) {
            log.info("policy kept as is (server side compilation refused)")
            return
        }
        when (val r = if (m == null) Policy.ParseResult.Malformed else Policy.parse(m)) {
            is Policy.ParseResult.Ok -> {
                // A kiosk withheld by the server (its PIN unreadable) or unreadable here: the one applied stays readable.
                val p = r.policy.keepingKioskOf(policySnapshot().policy)
                // A new policy: the PIN failures of the previous one are forgotten (D7).
                if (p.hash != state.policyHash) state.kioskPin = KioskModel.onSuccess()
                state.policyJson = Json.write(p.toJson(sealer))
                state.policyHash = p.hash
                state.policyRejected = null
                // Delivered again (a configuration of a new version: freeze, Knox key, settings…): the report goes at the
                // next poll, even unchanged, so the server, which may have marked it delivering, learns the outcome again.
                // A degraded answer repeated under the same version does not resend it at every poll.
                if (rebuilt) state.policyReportSentDigest = null
                livePolicy = p
                log.info("policy ${p.hash.take(8)} received: ${p.itemKeys.size} items, ${p.invalidKeys.size + p.invalidUnkeyed} unreadable")
                onPolicyChanged?.invoke()
            }
            is Policy.ParseResult.Unsupported -> {
                // A format this agent does not know: the current policy kept, the refusal reported (A10).
                log.warn("policy of an unsupported format kept aside")
                state.policyRejected = r.hash ?: "unknown"
                onPolicyChanged?.invoke()
            }
            Policy.ParseResult.Malformed -> log.warn("policy malformed: ignored, the current one kept")
        }
    }

    /** What a reconciliation needs, read at once. */
    class PolicySnapshot(val policy: Policy?, val ledger: Ledger, val rejected: String?, val kioskSuspendedUntil: Long, val report: PolicyReport?)

    @Synchronized
    fun policySnapshot(): PolicySnapshot {
        val hash = state.policyHash
        val p = if (hash == null) null else livePolicy?.takeIf { it.hash == hash } ?: state.policyJson?.let { Json.parseObjectOrNull(it) }
            ?.let { (Policy.parse(it, stored = true, sealer = sealer) as? Policy.ParseResult.Ok)?.policy }?.also { livePolicy = it }
        return PolicySnapshot(p, state.policyLedger, state.policyRejected, state.kioskSuspendedUntil, state.policyReport)
    }

    /** Keeps the outcome of a reconciliation; true when the report changed (a poll soon carries it). */
    @Synchronized
    fun commitReconcile(r: ReconcileResult): Boolean {
        val before = state.policyReport?.digest()
        state.policyLedger = r.ledger
        state.policyReport = r.report
        if (r.needFullConfig && state.configVersion != 0L) {
            // A Wi-Fi secret is needed and none is held: the next poll asks for the full configuration (§10.6).
            log.warn("policy secrets missing: full configuration asked")
            state.configVersion = 0
        }
        return before != r.report.digest()
    }

    /** A 1.3.0 event, to a server that delivers policies only (an older one would refuse the poll). */
    @Synchronized
    fun addPolicyEvent(type: String, detail: Map<String, Any?>) {
        if (state.serverPolicyV1) state.addEvent(type, now, detail) else log.info("event $type kept local (server without policies)")
    }

    /** The outcome of [runPolicy]: the report changed (a poll should carry it soon). */
    class PolicyRun(val reportChanged: Boolean, val report: PolicyReport)

    /**
     * Downloads what the policy is missing until [downloadUntil], then reconciles until [deadlineLocal] (local seconds),
     * outside the engine lock (snapshot and commit only take it).
     */
    fun runPolicy(deadlineLocal: Long, downloadUntil: Long = deadlineLocal): PolicyRun {
        val snap = policySnapshot()
        snap.policy?.let { downloadPolicyBlobs(it, downloadUntil) }
        val host = actions.policyHost()
        val local = clock()
        val result = PolicyReconciler(host, blobCache, clock, log).reconcile(
            snap.policy, snap.ledger, local, deadlineLocal, now, snap.rejected, KioskModel.suspended(snap.kioskSuspendedUntil, local),
        )
        val changed = commitReconcile(result)
        cleanBlobs(snap.policy)
        return PolicyRun(changed, result.report)
    }

    /** The blobs the policy needs and does not hold, by SHA-256 with their size. */
    fun missingBlobs(p: Policy): Map<String, Long> {
        val sizes = LinkedHashMap<String, Long>()
        for (f in p.files) f.blob?.let { sizes[it.sha256] = it.size }
        p.kiosk?.logo?.let { sizes[it.sha256] = it.size }
        p.kiosk?.tiles?.forEach { t -> t.image?.let { sizes[it.sha256] = it.size } }
        return sizes.filterKeys { it in p.blobs && !blobCache.has(it) }
    }

    /**
     * Downloads the missing blobs until [deadlineLocal]; true when one is worth another try soon (a 429, a network
     * failure or a 5xx, or the deadline). A 429 stops the round (C10). A refused blob (download_failed, hash_mismatch)
     * is not: it is tried again by the next reconciliation, never by the job's backoff, which would otherwise grow to
     * hours and hold the install queue behind it (30/10, on a pilot device: an agent.update never ran).
     */
    fun downloadPolicyBlobs(p: Policy, deadlineLocal: Long): Boolean {
        for ((sha, size) in missingBlobs(p)) {
            if (clock() >= deadlineLocal) return true
            // A refused blob waits REFUSED_RETRY_S before another try (each reconciliation schedules the job).
            refusedAt[sha]?.let { if (clock() - it in 0 until REFUSED_RETRY_S) continue }
            val dir = blobCache.dir
            dir.mkdirs()
            if (dir.usableSpace in 1..(size * 2 + FREE_MARGIN_BYTES)) { blobCache.setFailure(sha, PolicyCodes.STORAGE_UNAVAILABLE); continue }
            when (val r = downloadBlob(sha, size)) {
                is BlobResult.Ok -> { blobCache.setFailure(sha, null); refusedAt.remove(sha) }
                is BlobResult.Limited -> { blobCache.setFailure(sha, PolicyCodes.DOWNLOAD_LIMITED, r.detail); return true }
                is BlobResult.Failed -> {
                    blobCache.setFailure(sha, r.code, r.detail)
                    refusedAt[sha] = clock()
                    log.warn("policy file ${sha.take(12)}: ${r.code} ${r.detail ?: ""}")
                }
            }
        }
        return false
    }

    sealed class BlobResult {
        object Ok : BlobResult()
        /** 429, a network failure or a 5xx: tried again later (pending/download_limited, never an error). */
        class Limited(val retryAfter: Long?, val detail: String? = null) : BlobResult()
        /** [detail]: what was seen (the HTTP status and the server code), reported with the item. */
        class Failed(val code: String, val detail: String? = null) : BlobResult()
    }

    /** GET /agent/v1/files/<sha> into blobs/<sha>.part, size and SHA-256 checked, then renamed (never under the engine lock). */
    fun downloadBlob(sha: String, size: Long): BlobResult {
        if (!Hex.isSha256(sha) || size !in 1..Policy.STORE_FILE_BYTES) return BlobResult.Failed(PolicyCodes.DOWNLOAD_FAILED, "size $size")
        val dir = blobCache.dir
        val part = File(dir, "$sha.part")
        val target = File(dir, sha)
        val reply = try {
            client.call("GET", "/agent/v1/files/$sha", null, downloadTo = part, maxDownloadBytes = size, timeoutMs = 60_000, expectedDownloadSha256 = sha)
        } catch (e: IOException) {
            part.delete()
            log.warn("policy file download: ${e.message}")
            return BlobResult.Limited(null, "io ${e.javaClass.simpleName}")
        }
        val seen = "http ${reply.status}${reply.code?.let { " $it" } ?: ""}"
        if (reply.status == 429) { part.delete(); return BlobResult.Limited(reply.retryAfterSeconds, seen) }
        if (reply.status != 200) {
            part.delete()
            return if (reply.status in 400..499) BlobResult.Failed(PolicyCodes.DOWNLOAD_FAILED, seen) else BlobResult.Limited(reply.retryAfterSeconds, seen)
        }
        if (!reply.signed) { part.delete(); return BlobResult.Failed(PolicyCodes.DOWNLOAD_FAILED, "$seen unsigned") }
        if (reply.downloadedSha256 != sha || part.length() != size) {
            val got = part.length()
            part.delete()
            return BlobResult.Failed(PolicyCodes.HASH_MISMATCH, "$seen got $got bytes ${reply.downloadedSha256?.take(12)}")
        }
        if (!part.renameTo(target)) { part.delete(); return BlobResult.Failed(PolicyCodes.DOWNLOAD_FAILED, "rename") }
        return BlobResult.Ok
    }

    /** Removes the blobs the policy no longer names (cleanUpdates never touches them). */
    private fun cleanBlobs(p: Policy?) {
        val keep = HashSet<String>()
        if (p != null) {
            keep += p.blobs
            for (f in p.files) keep += f.sha256
        }
        try { blobCache.clean(keep) } catch (e: Exception) { log.warn("policy files clean-up: ${e.message}") }
    }

    /** The report is due: changed since the last one accepted, or [Policy.reportSeconds] passed, and not refused lately. */
    private fun reportDue(r: PolicyReport): Boolean {
        val local = clock()
        val refused = state.policyReportRefusedUntil
        if (local < refused && refused - local <= DAY_S) return false
        if (r.digest() != state.policyReportSentDigest) return true
        val sentAt = state.policyReportSentAt
        val period = livePolicy?.reportSeconds ?: Policy.REPORT_SECONDS_DEFAULT
        return local - sentAt >= period || sentAt > local
    }

    /** kiosk.suspend: the kiosk left for [Params.KioskSuspend.minutes]; kiosk_inactive when no kiosk is enabled. */
    private fun suspendKiosk(c: Command): CommandResult {
        val minutes = (c.params as Params.KioskSuspend).minutes
        if (policySnapshot().policy?.kiosk?.enabled != true) return err(c, Codes.KIOSK_INACTIVE)
        state.kioskSuspendedUntil = clock() + minutes * 60L
        addPolicyEvent(EventTypes.KIOSK_EXIT, linkedMapOf("via" to "command", "minutes" to minutes))
        onPolicyChanged?.invoke()
        return CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.KIOSK_SUSPENDED, mapOf("until" to now + minutes * 60L), now)
    }

    /** policy.reapply: the ledger digests forgotten, the full configuration asked (secrets again), the report sent anew. */
    private fun reapplyPolicy(c: Command): CommandResult {
        state.policyLedger = state.policyLedger.forget()
        state.configVersion = 0
        state.policyReportSentDigest = null
        onPolicyChanged?.invoke()
        return ack(c, Codes.DONE)
    }

    /** The result of a typed exit PIN. */
    sealed class PinCheck {
        object Ok : PinCheck()
        class Wrong(val left: Int) : PinCheck()
        class Locked(val seconds: Long) : PinCheck()
        object NoKiosk : PinCheck()
    }

    /** Checks a typed exit PIN (D7): PBKDF2 outside the lock, failures counted, 5 lock the dialog (event kiosk_pin_lockout). */
    fun checkKioskPin(pin: String): PinCheck {
        val (record, attempts) = synchronized(this) { policySnapshot().policy?.kiosk?.exitPin to state.kioskPin }
        if (record == null) return PinCheck.NoKiosk
        val locked = KioskModel.lockedFor(attempts, clock())
        if (locked > 0) return PinCheck.Locked(locked)
        val ok = try { record.verify(pin) } catch (e: Exception) { false }
        return synchronized(this) {
            if (ok) {
                state.kioskPin = KioskModel.onSuccess()
                PinCheck.Ok
            } else {
                val (next, lockedOut) = KioskModel.onFailure(state.kioskPin, clock())
                state.kioskPin = next
                if (lockedOut) {
                    addPolicyEvent(EventTypes.KIOSK_PIN_LOCKOUT, linkedMapOf("failures" to KioskModel.MAX_FAILURES))
                    PinCheck.Locked(KioskModel.lockedFor(next, clock()))
                } else PinCheck.Wrong(KioskModel.MAX_FAILURES - next.failures)
            }
        }
    }

    /** The kiosk left from the device (the PIN panel): suspended for [minutes], event kiosk_exit {via: pin}. */
    @Synchronized
    fun suspendKioskByPin(minutes: Int) {
        state.kioskSuspendedUntil = clock() + minutes * 60L
        addPolicyEvent(EventTypes.KIOSK_EXIT, linkedMapOf("via" to "pin", "minutes" to minutes))
        onPolicyChanged?.invoke()
    }

    /** The undo of the policy before the identity erase (A9): bounded, what is left goes to the local log only. */
    private fun undoPolicyBeforeErase() {
        val ledger = state.policyLedger
        if (ledger.entries.isNotEmpty()) {
            try {
                val host = actions.policyHost()
                try { host.kioskApply(null, false) } catch (e: Throwable) { log.warn("kiosk removal: ${e.javaClass.simpleName}") }
                val r = PolicyReconciler(host, blobCache, clock, log).reconcile(null, ledger, clock(), clock() + REVOKE_UNDO_S, now)
                if (r.undoLeft > 0) log.warn("policy undo before the erase unfinished: done=${r.undoDone} left=${r.undoLeft}")
                else log.info("policy undone before the erase: ${r.undoDone} items")
            } catch (e: Throwable) {
                log.warn("policy undo before the erase: ${e.javaClass.simpleName}")
            }
        }
        livePolicy = null
        try { blobCache.clean(emptySet(), Long.MAX_VALUE) } catch (e: Exception) { log.warn("policy files erase: ${e.message}") }
        try { sealer.erase() } catch (e: Exception) { log.warn("policy key erase: ${e.javaClass.simpleName}") }
    }

    // ------------------------------------------------------------------
    // Interrogation (§4.5) and execution (§5.3, RS-2)
    // ------------------------------------------------------------------

    private fun pollAndExecute(): CycleReport {
        val first = poll()
        if (first.report != null) return first.report
        var received = first.commands.size
        val terminal = execute(first.commands)
        if (terminal != null) {
            runTerminal(terminal)
            return CycleReport(state.pollSeconds.toLong(), received, state.installQueue.isNotEmpty())
        }
        // Results of what just ran leave at once (the server waits for them).
        if (state.outbox.isNotEmpty() || state.inventoryRequested || inventoryDue()) {
            if (inventoryDue() || state.inventoryRequested) sendInventory()
            if (state.outbox.isNotEmpty()) {
                val second = poll()
                if (second.report == null) {
                    received += second.commands.size
                    val t2 = execute(second.commands)
                    if (t2 != null) runTerminal(t2)
                }
            }
        }
        // The icons the server asked for (1.0.2): never a back-off nor an authentication failure of their own.
        if (state.serverAppsV2 && state.iconsWanted.isNotEmpty() && iconsAllowed()) {
            try {
                sendIcons(clock() + Icons.SEND_SECONDS)
            } catch (e: IOException) {
                log.warn("icons: ${e.message}")
            }
        }
        val next = if (received > 0) FOLLOW_UP_S else jitter(state.pollSeconds.toLong(), 0.10)
        return CycleReport(next, received, state.installQueue.isNotEmpty())
    }

    private class PollResult(val report: CycleReport?, val commands: List<Any?>)

    private fun poll(timeoutMs: Int = AgentClient.DEFAULT_TIMEOUT_MS): PollResult {
        trackRole()
        val outbox = state.outbox.take(MAX_RESULTS)
        val events = state.events.take(MAX_EVENTS)
        // The owner events go to a server announcing device_owner_v1 only (an older one would answer 400); dropped otherwise.
        val sentEvents = if (ownerFeature()) events else events.filter { it["type"] !in EventTypes.OWNER_ONLY }
        // 1.4.0: the owner role and ADB, to a server announcing device_owner_v1 only; otherwise the body of 1.3.0 as is.
        val status = facts.status().let { s ->
            if (!ownerFeature()) s else LinkedHashMap(s).also {
                it["deviceOwner"] = deviceOwner()
                it["adbEnabled"] = try { facts.adbEnabled() } catch (e: Throwable) { null }
            }
        }
        val body = linkedMapOf<String, Any?>(
            // The server sends the configuration only when the version announced differs, and its version hashes the
            // content alone: a configuration read by another version of the agent (1.0.x ignored config.remote) is
            // asked again whole, once, by announcing none.
            "agent" to linkedMapOf(
                "versionCode" to versionCode,
                "configVersion" to if (state.configAgentVersion == versionCode) state.configVersion else 0L,
            ),
            "status" to status,
            "results" to outbox.map { it.toJson() },
            "events" to sentEvents,
        )
        // 1.3.0: the policy report, to a server that delivers policies, when it changed or its period passed (§8.4).
        val report = if (state.serverPolicyV1) state.policyReport?.takeIf { reportDue(it) } else null
        if (report != null) body["policy"] = report.toJson()
        val reply = client.call("POST", "/agent/v1/poll", Json.bytes(body), timeoutMs = timeoutMs)
        state.lastPollAt = clock()
        val j = reply.json
        val usable = reply.signed && j != null && (reply.status == 200 || (reply.status == 426 && j.containsKey("commands")))
        if (usable) {
            state.authFailingSince = 0
            state.backoffStep = 0
            state.notBefore = 0
            state.lastStatus = if (reply.status == 426) "agent_too_old" else "ok"
            j!!.long("serverTime")?.let { client.setClock(it) }
            j.int("pollSeconds")?.let { state.pollSeconds = it }
            // Results accepted leave the outbox; the events sent leave their queue.
            val accepted = j.list("resultsAccepted").orEmpty().filterIsInstance<String>().toSet()
            state.outbox = state.outbox.filter { it.commandId !in accepted }
            if (events.isNotEmpty()) state.dropEvents(events.size)
            if (j.bool("inventoryDue") == true) state.inventoryRequested = true
            // 1.4.0 (lot BANC §6.5): an open conversion of this device on a bench station allows prepare_owner for 30 min.
            state.benchConvertUntil = if (reply.status == 200 && j.bool("benchConvert") == true) clock() + BenchRules.WINDOW_S else 0
            if (report != null) when (j.str("policyReport")) {
                "accepted" -> {
                    state.policyReportSentDigest = report.digest()
                    state.policyReportSentAt = clock()
                }
                // Refused (never the poll itself): no report for a day, the rest of the poll went through.
                "rejected" -> {
                    log.warn("policy report refused by the server: paused for a day")
                    state.policyReportRefusedUntil = clock() + DAY_S
                }
            }
            j.obj("config")?.let { applyConfig(it) }
            return PollResult(null, j.list("commands").orEmpty())
        }
        if (reply.status == 403 && reply.code == "agentRevoked") {
            if (reply.signed) {
                revoke()
                return PollResult(CycleReport(DAY_S), emptyList())
            }
            log.warn("unsigned agentRevoked ignored (RS-8)")
            return PollResult(backoff(reply), emptyList())
        }
        if (reply.status == 401 && (reply.code == "badSignature" || reply.code == "unknownAgent")) {
            if (state.authFailingSince == 0L) state.authFailingSince = clock()
            if (clock() - state.authFailingSince > DAY_S) {
                state.lastStatus = "link_lost"
                return PollResult(slow(DAY_S), emptyList())
            }
            state.lastStatus = "auth_failed"
            return PollResult(backoff(reply), emptyList())
        }
        if (reply.status == 400) {
            // Never resend the same request: the oldest outbox entries go to the local log.
            log.warn("poll refused: ${reply.code}; outbox kept=${state.outbox.size}")
            state.lastStatus = "bad_request"
            if (outbox.isNotEmpty()) state.outbox = state.outbox.drop(outbox.size)
            if (events.isNotEmpty()) state.dropEvents(events.size)
            return PollResult(CycleReport(state.pollSeconds.toLong()), emptyList())
        }
        if (reply.status == 426) {
            state.lastStatus = "agent_too_old"
            return PollResult(CycleReport(state.pollSeconds.toLong()), emptyList())
        }
        state.lastStatus = "poll_failed_${reply.status}"
        return PollResult(backoff(reply), emptyList())
    }

    private fun revoke() {
        log.warn("signed agentRevoked: identity erased")
        // 1.3.0 (A9): what the policy set is undone first (30 s at most), then the identity erased.
        undoPolicyBeforeErase()
        // 1.4.0 (lot BANC §3.8, §7.5): an owner of the device gives it back on its signed revocation (its protections, the
        // owner, then the administrator), as agent.release does: a revoked agent never stays an orphaned owner.
        if (deviceOwner()) {
            val outcome = try { actions.releaseOwnership() } catch (e: Throwable) { log.warn("release: ${e.javaClass.simpleName}"); null }
            if (outcome == null) log.warn("release on revocation: not supported here")
        }
        state.phase = EnrollmentMachine.next(state.phase, EnrollEvent.RevokedSigned).next
        state.eraseIdentity()
        try { signer.erase() } catch (e: Exception) { log.warn("key erase: ${e.message}") }
        state.lastStatus = "revoked"
        onRevoked?.invoke()
    }

    private sealed class Terminal {
        data class Wipe(val id: String, val external: Boolean) : Terminal()
        data class Reboot(val id: String) : Terminal()
        /** 1.4.0: agent.release, after a reboot and before a wipe in priority. */
        data class Release(val id: String) : Terminal()
    }

    /** Executes immediate commands now, queues installs (RS-2). Returns a wipe or reboot to run last. */
    private fun execute(raw: List<Any?>): Terminal? {
        var terminal: Terminal? = null
        val journal = state.journal.associateBy { it.id }
        val outboxIds = state.outbox.map { it.commandId }.toSet()
        for (item in raw) {
            when (val p = CommandParser.parse(item)) {
                ParsedCommand.Dropped -> log.warn("command without id dropped")
                is ParsedCommand.Refused -> {
                    val known = journal[p.id]
                    if (known == null) finish(p.id, CommandResult(p.id, ResultStatus.REJECTED, p.code, emptyMap(), now), "?")
                    else resendKnown(known, outboxIds)
                }
                is ParsedCommand.Ok -> {
                    val c = p.command
                    val known = journal[c.id]
                    if (known != null) {
                        // Already executed: send the known result again; in progress: ignore (F-8).
                        resendKnown(known, outboxIds)
                        continue
                    }
                    if (c.expiresAt <= now) {
                        finish(c.id, CommandResult(c.id, ResultStatus.REJECTED, Codes.EXPIRED_ON_DEVICE, emptyMap(), now), c.type.wire)
                        continue
                    }
                    if (!c.type.immediate) {
                        record(JournalEntry(c.id, c.type.wire, "running", null, now))
                        state.installQueue = state.installQueue + listOf(c.raw)
                        continue
                    }
                    when (c.type) {
                        CommandType.DEVICE_WIPE -> {
                            record(JournalEntry(c.id, c.type.wire, "running", null, now)) // before the acknowledgement (RS-4)
                            if (!actions.isAdminActive()) {
                                finish(c.id, CommandResult(c.id, ResultStatus.ERROR, Codes.ADMIN_INACTIVE, emptyMap(), now))
                            } else if (terminal !is Terminal.Wipe) {
                                terminal?.let { supersede(it) }
                                terminal = Terminal.Wipe(c.id, (c.params as Params.Wipe).wipeExternal)
                            } else {
                                finish(c.id, CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.WIPE_STARTED, emptyMap(), now))
                            }
                        }
                        CommandType.AGENT_RELEASE -> {
                            record(JournalEntry(c.id, c.type.wire, "running", null, now))
                            when (terminal) {
                                is Terminal.Wipe -> finish(c.id, CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.DONE, mapOf("supersededByWipe" to true), now))
                                is Terminal.Release -> finish(c.id, CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.DONE, emptyMap(), now))
                                else -> {
                                    terminal?.let { supersede(it) }
                                    terminal = Terminal.Release(c.id)
                                }
                            }
                        }
                        CommandType.DEVICE_REBOOT -> {
                            record(JournalEntry(c.id, c.type.wire, "running", null, now))
                            if (!actions.canReboot()) {
                                finish(c.id, CommandResult(c.id, ResultStatus.REJECTED, Codes.KNOX_REQUIRED, emptyMap(), now))
                            } else if (terminal == null) {
                                terminal = Terminal.Reboot(c.id)
                            } else {
                                finish(c.id, CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.REBOOT_STARTED, emptyMap(), now))
                            }
                        }
                        else -> runImmediate(c)
                    }
                }
            }
        }
        return terminal
    }

    /** A reboot displaced by a wipe is answered as started (the wipe restarts the device anyway). */
    private fun supersede(t: Terminal) {
        if (t is Terminal.Reboot) finish(t.id, CommandResult(t.id, ResultStatus.ACKNOWLEDGED, Codes.REBOOT_STARTED, mapOf("supersededByWipe" to true), now))
        if (t is Terminal.Release) finish(t.id, CommandResult(t.id, ResultStatus.ACKNOWLEDGED, Codes.DONE, mapOf("supersededByWipe" to true), now))
    }

    private fun resendKnown(known: JournalEntry, outboxIds: Set<String>) {
        if (known.state == "done" && known.result != null && known.id !in outboxIds) addResult(known.result)
    }

    private fun runImmediate(c: Command) {
        record(JournalEntry(c.id, c.type.wire, "running", null, now))
        val result: CommandResult? = try {
            when (c.type) {
                CommandType.DEVICE_LOCK -> {
                    if (!actions.isAdminActive()) err(c, Codes.ADMIN_INACTIVE)
                    else actions.lockNow()?.let { err(c, it) } ?: ack(c, Codes.LOCK_DONE)
                }
                CommandType.DEVICE_MESSAGE -> {
                    val m = c.params as Params.Message
                    actions.showMessage(c.id, m.title, m.text, m.fullscreen)?.let { err(c, it) } ?: ack(c, Codes.MESSAGE_SHOWN)
                }
                CommandType.INVENTORY_REFRESH -> {
                    // Answered once the inventory is accepted (see sendInventory).
                    state.inventoryRequested = true
                    null
                }
                CommandType.REMOTE_OPEN -> openRemote(c)
                CommandType.KIOSK_SUSPEND -> suspendKiosk(c)
                CommandType.POLICY_REAPPLY -> reapplyPolicy(c)
                else -> err(c, Codes.INTERNAL)
            }
        } catch (e: Exception) {
            log.warn("${c.type.wire} failed: ${e.message}")
            err(c, Codes.INTERNAL)
        }
        if (result != null) finish(c.id, result)
    }

    /**
     * remote.open (P0-15 §0.1, §4.3, §8): refused without showing anything unless the signed configuration enables
     * remote assistance; one session at a time (agent_busy); otherwise the host opens it (the opening told, the system
     * dialog of MediaProjection) and the result comes with [onRemoteOutcome].
     */
    private fun openRemote(c: Command): CommandResult? {
        val p = c.params as Params.RemoteOpen
        if (!state.remote.enabled) return rej(c, Codes.UNSUPPORTED)
        if (remoteHost.activeCommand() != null) return rej(c, Codes.AGENT_BUSY)
        val refusal = remoteHost.open(c.id, p)
        if (refusal != null) return if (refusal == Codes.UNSUPPORTED || refusal == Codes.AGENT_BUSY) rej(c, refusal) else err(c, refusal)
        record(JournalEntry(c.id, c.type.wire, "awaiting_user", null, now))
        return null
    }

    /**
     * The outcome of a remote.open handed to the host: projection_denied, session_gone, internal... or acknowledged
     * once /accept was taken. Ignored for another command or one already answered.
     */
    @Synchronized
    fun onRemoteOutcome(commandId: String, status: ResultStatus, code: String) {
        val e = state.journal.firstOrNull { it.id == commandId } ?: return
        if (e.type != CommandType.REMOTE_OPEN.wire || e.state == "done") return
        finish(commandId, CommandResult(commandId, status, code, emptyMap(), now))
    }

    private fun runTerminal(t: Terminal) {
        when (t) {
            is Terminal.Wipe -> {
                finish(t.id, CommandResult(t.id, ResultStatus.ACKNOWLEDGED, Codes.WIPE_STARTED, emptyMap(), now))
                flushBeforeTerminal()
                log.warn("wiping the device (command ${t.id})")
                val error = try { actions.wipe(t.external) } catch (e: Exception) { e.message ?: Codes.INTERNAL }
                if (error != null) log.warn("wipe failed after acknowledgement: $error")
            }
            is Terminal.Reboot -> {
                finish(t.id, CommandResult(t.id, ResultStatus.ACKNOWLEDGED, Codes.REBOOT_STARTED, emptyMap(), now))
                flushBeforeTerminal()
                val error = try { actions.reboot() } catch (e: Exception) { e.message ?: Codes.INTERNAL }
                if (error != null) log.warn("reboot failed after acknowledgement: $error")
            }
            is Terminal.Release -> {
                // §7.5: device_owner_released and the acknowledgement leave before anything is removed.
                addOwnerEvent(EventTypes.DEVICE_OWNER_RELEASED)
                finish(t.id, CommandResult(t.id, ResultStatus.ACKNOWLEDGED, Codes.DONE, emptyMap(), now))
                flushBeforeTerminal()
                releaseDevice()
            }
        }
    }

    /** Sends the acknowledgement first (15 s at most, by the transport time-outs), then acts whatever happens. */
    private fun flushBeforeTerminal() {
        try {
            poll(timeoutMs = ACK_TIMEOUT_MS)
        } catch (e: Exception) {
            log.warn("acknowledgement not sent: ${e.message}")
        }
    }

    // ------------------------------------------------------------------
    // Inventory (§4.6)
    // ------------------------------------------------------------------

    private fun inventoryDue(): Boolean = clock() - state.lastInventoryAt >= state.inventorySeconds

    fun sendInventory(): Boolean {
        var withSystem = true
        repeat(2) {
            val body = LinkedHashMap<String, Any?>()
            body["collectedAt"] = now
            // launchable only to a server known to take it (an older one refuses an unknown key).
            val inventory = facts.inventory(withSystem)
            body.putAll(if (state.serverAppsV2) inventory else Icons.withoutLaunchable(inventory))
            val reply = client.call("POST", "/agent/v1/inventory", Json.bytes(body))
            if (reply.status == 200 && reply.signed) {
                state.lastInventoryAt = clock()
                state.inventoryRequested = false
                Icons.parseWanted(reply.json)?.let { wanted ->
                    if (!state.serverAppsV2) {
                        // Learnt now: the next cycle sends the inventory again, with launchable.
                        state.serverAppsV2 = true
                        state.inventoryRequested = true
                    }
                    if (wanted.isNotEmpty()) state.iconsWanted = Icons.merge(state.iconsWanted, wanted)
                }
                // inventory.refresh commands waiting for this inventory.
                for (e in state.journal) if (e.state == "running" && e.type == CommandType.INVENTORY_REFRESH.wire) {
                    finish(e.id, CommandResult(e.id, ResultStatus.ACKNOWLEDGED, Codes.DONE, emptyMap(), now))
                }
                return true
            }
            if ((reply.status == 413 || reply.status == 415) && withSystem) {
                withSystem = false
                return@repeat
            }
            log.warn("inventory refused: ${reply.status} ${reply.code}")
            // A server that refuses the body may no longer know launchable (moved back to an older version): asked again.
            if (reply.status == 400 && reply.signed && state.serverAppsV2) state.serverAppsV2 = false
            return false
        }
        return false
    }

    // ------------------------------------------------------------------
    // Icons (1.0.2, §4.6): rendered one at a time, sent by batches
    // ------------------------------------------------------------------

    private fun iconsAllowed(): Boolean {
        val local = clock()
        // A block never exceeds its week: beyond that, the local clock was moved back since it was set.
        if (state.iconsBlockedUntil - local > Icons.BLOCK_SECONDS) state.iconsBlockedUntil = 0
        return local >= state.iconsBlockedUntil
    }

    /**
     * Sends the queue until empty or [deadlineLocal] (local seconds). 200 signed: the batch leaves the queue (accepted
     * or rejected alike); 404, signed or not (a server without the route): the queue is emptied and the icons wait a
     * week; 429: until the next cycle; 413: half the batch; anything else: the queue is kept. Never the back-off nor
     * authFailingSince of the interrogation. An icon that cannot be rendered is sent as failed: the server ends its
     * lease and asks another device.
     */
    fun sendIcons(deadlineLocal: Long) {
        var maxPerRequest = Icons.MAX_PER_REQUEST
        while (clock() < deadlineLocal) {
            val queue = state.iconsWanted
            if (queue.isEmpty()) return
            val batch = ArrayList<Map<String, Any?>>()
            val sentPackages = HashSet<String>()
            var size = Icons.EMPTY_BODY_BYTES
            for (w in queue) {
                if (batch.size >= maxPerRequest || clock() >= deadlineLocal) break
                val render = try { facts.icon(w.packageName, Icons.SIZE_PX) } catch (e: Throwable) { null }
                val entry = Icons.entry(w, render)
                val n = Icons.sizeOf(entry)
                if (!Icons.fits(batch.size, size, n, maxPerRequest)) break
                batch += entry
                sentPackages += w.packageName
                size += n
            }
            if (batch.isEmpty()) return
            val reply = client.call("POST", "/agent/v1/icons", Json.bytes(linkedMapOf("icons" to batch)))
            when {
                reply.status == 200 && reply.signed -> state.iconsWanted = state.iconsWanted.filter { it.packageName !in sentPackages }
                reply.status == 404 -> {
                    log.warn("icons: the server has no /icons, paused for a week")
                    state.iconsWanted = emptyList()
                    state.iconsBlockedUntil = clock() + Icons.BLOCK_SECONDS
                    return
                }
                reply.status == 429 -> return
                reply.status == 413 -> {
                    if (batch.size == 1) {
                        state.iconsWanted = state.iconsWanted.filter { it.packageName !in sentPackages }
                    } else {
                        maxPerRequest = (batch.size / 2).coerceAtLeast(1)
                    }
                }
                else -> {
                    log.warn("icons refused: ${reply.status} ${reply.code}")
                    return
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Install queue (§8.6, RS-2, RS-6, F-7): one item at a time, a pending
    // prompt never blocks the queue.
    // ------------------------------------------------------------------

    /** Runs the queue until empty or [deadlineLocal] (local seconds) is passed. Returns true when work remains. */
    fun runInstallQueue(deadlineLocal: Long): Boolean {
        while (clock() < deadlineLocal) {
            val head = synchronized(this) { state.installQueue.firstOrNull() } ?: return false
            val outcome = try {
                processInstall(head)
            } catch (e: IOException) {
                log.warn("download interrupted: ${e.message}")
                return true // kept for the next job
            }
            synchronized(this) { state.installQueue = state.installQueue.drop(1) }
            if (outcome != null) finish(outcome.commandId, outcome)
        }
        return synchronized(this) { state.installQueue.isNotEmpty() }
    }

    /** null = no result yet (prompt pending or self update launched). */
    private fun processInstall(raw: Map<String, Any?>): CommandResult? {
        val c = (CommandParser.parse(raw) as? ParsedCommand.Ok)?.command
            ?: return CommandResult(raw.str("id") ?: "", ResultStatus.REJECTED, Codes.BAD_PARAMS, emptyMap(), now)
        if (c.expiresAt <= now) return rej(c, Codes.EXPIRED_ON_DEVICE)
        return when (val p = c.params) {
            is Params.Uninstall -> uninstall(c, p)
            is Params.Install -> installApp(c, p)
            is Params.AgentUpdate -> updateSelf(c, p)
            is Params.Pull -> pullApp(c, p)
            else -> rej(c, Codes.BAD_PARAMS)
        }
    }

    /**
     * app.pull (1.2.0): the installed APK sent by chunks of [PULL_CHUNK] bytes to POST /agent/v1/pull/<id>, each one
     * signed; the server answers how much it holds and the agent goes on from there (a new attempt starts at 0). A
     * network failure keeps the item for the next job (IOException); a refusal of the server ends it (upload_failed).
     */
    private fun pullApp(c: Command, p: Params.Pull): CommandResult {
        if (p.packageName == ownPackage) return rej(c, Codes.FORBIDDEN_PACKAGE)
        val apk = actions.installedApk(p.packageName) ?: return err(c, Codes.NOT_INSTALLED)
        val size = apk.file.length()
        if (size <= 0 || size > CommandParser.MAX_APK_SIZE) return err(c, Codes.UPLOAD_FAILED, "size $size")
        val sha = ApkChecks.sha256(apk.file)
        val signer = apk.signers.singleOrNull()
        val buf = ByteArray(PULL_CHUNK)
        var offset = 0L
        var requests = 0
        RandomAccessFile(apk.file, "r").use { raf ->
            while (true) {
                if (++requests > 4 * (size / PULL_CHUNK + 2)) return err(c, Codes.UPLOAD_FAILED, "too many requests")
                raf.seek(offset)
                val n = raf.read(buf, 0, minOf(PULL_CHUNK.toLong(), size - offset).toInt())
                if (n <= 0) return err(c, Codes.UPLOAD_FAILED, "read")
                val body = Json.bytes(linkedMapOf(
                    "offset" to offset, "total" to size, "sha256" to sha, "versionCode" to apk.versionCode,
                    "versionName" to apk.versionName?.take(64), "signerSha256" to signer, "data" to B64.encodeStd(buf.copyOf(n)),
                ))
                val reply = client.call("POST", "/agent/v1/pull/${c.id}", body, timeoutMs = 60_000)
                if (reply.status == 429) {
                    Thread.sleep((reply.retryAfterSeconds ?: 2L).coerceAtMost(30) * 1000)
                    continue
                }
                if (reply.status != 200 || !reply.signed) {
                    if (reply.status in 400..499) return err(c, Codes.UPLOAD_FAILED, "http ${reply.status} ${reply.code ?: ""}".trim())
                    throw IOException("pull ${reply.status}")
                }
                val json = reply.json ?: return err(c, Codes.UPLOAD_FAILED, "no body")
                if (json["complete"] == true) {
                    return CommandResult(c.id, ResultStatus.ACKNOWLEDGED, Codes.PULLED,
                        mapOf("sha256" to sha, "size" to size, "versionCode" to apk.versionCode, "packageId" to json.str("packageId")), now)
                }
                val received = json.long("received") ?: return err(c, Codes.UPLOAD_FAILED, "no received")
                if (received < 0 || received > size) return err(c, Codes.UPLOAD_FAILED, "received $received")
                offset = received
            }
        }
        @Suppress("UNREACHABLE_CODE")
        return err(c, Codes.UPLOAD_FAILED)
    }

    private fun uninstall(c: Command, p: Params.Uninstall): CommandResult? {
        if (ApkChecks.uninstallForbidden(p.packageName, ownPackage, actions.isSystemPackage(p.packageName))) return rej(c, Codes.FORBIDDEN_PACKAGE)
        if (actions.installedVersion(p.packageName) == null) return ack(c, Codes.UNINSTALLED)
        return when (val o = actions.uninstall(c.id, p.packageName)) {
            InstallOutcome.Done -> ack(c, Codes.UNINSTALLED)
            InstallOutcome.Pending -> { awaitUser(c, "uninstall", p.packageName, null, null); null }
            is InstallOutcome.Failed -> err(c, o.code, o.detail)
        }
    }

    private fun download(c: Command, sha: String, size: Long): Pair<File?, CommandResult?> {
        updatesDir.mkdirs()
        val part = File(updatesDir, "$sha.part")
        val file = File(updatesDir, "$sha.apk")
        file.delete()
        val reply = client.call("GET", "/agent/v1/packages/$sha", null, downloadTo = part, maxDownloadBytes = size, timeoutMs = 60_000, expectedDownloadSha256 = sha)
        if (reply.status != 200) {
            part.delete()
            if (reply.status == 404 || reply.status in 400..499) return null to err(c, Codes.DOWNLOAD_FAILED, "http ${reply.status}")
            throw IOException("download ${reply.status}")
        }
        if (!reply.signed) {
            part.delete()
            return null to err(c, Codes.DOWNLOAD_FAILED, "unsigned")
        }
        if (!part.renameTo(file)) {
            part.delete()
            return null to err(c, Codes.DOWNLOAD_FAILED, "rename")
        }
        ApkChecks.checkFile(file, size, sha)?.let { file.delete(); return null to err(c, it) }
        return file to null
    }

    private fun installApp(c: Command, p: Params.Install): CommandResult? {
        if (p.packageName == ownPackage) return rej(c, Codes.FORBIDDEN_PACKAGE)
        val (file, failure) = download(c, p.sha256, p.size)
        if (failure != null) return failure
        try {
            ApkChecks.checkAppInstall(actions.inspectArchive(file!!), ownPackage, p.packageName, p.versionCode, p.signerSha256)
                ?.let { return if (it == Codes.FORBIDDEN_PACKAGE) rej(c, it) else err(c, it) }
            // RS-6: checked again right before the call.
            ApkChecks.checkFile(file, p.size, p.sha256)?.let { return err(c, it) }
            return when (val o = actions.install(c.id, file, p.packageName, false)) {
                InstallOutcome.Done -> postInstallCheck(c.id, p.packageName, p.signerSha256)
                InstallOutcome.Pending -> { awaitUser(c, "install", p.packageName, p.versionCode, p.signerSha256); null }
                is InstallOutcome.Failed -> err(c, o.code, o.detail)
            }
        } finally {
            file?.delete()
        }
    }

    /** RS-6: after installation, the installed signer must be the announced one; otherwise uninstalled. */
    private fun postInstallCheck(id: String, pkg: String, signer: String?): CommandResult {
        if (signer != null) {
            val installed = actions.installedSigners(pkg)
            if (installed == null || installed.size != 1 || installed[0].lowercase() != signer) {
                actions.uninstall(id, pkg)
                return CommandResult(id, ResultStatus.ERROR, Codes.SIGNER_MISMATCH, emptyMap(), now)
            }
        }
        return CommandResult(id, ResultStatus.ACKNOWLEDGED, Codes.INSTALLED, emptyMap(), now)
    }

    private fun updateSelf(c: Command, p: Params.AgentUpdate): CommandResult? {
        if (p.versionCode <= versionCode) return rej(c, Codes.VERSION_NOT_HIGHER)
        val (file, failure) = download(c, p.sha256, p.size)
        if (failure != null) return failure
        ApkChecks.checkAgentUpdate(actions.inspectArchive(file!!), ownPackage, versionCode, p.versionCode, pinnedSigners)
            ?.let { file.delete(); return err(c, it) }
        ApkChecks.checkFile(file, p.size, p.sha256)?.let { file.delete(); return err(c, it) }
        // §8.6 step 4: persisted before the installation; the new version sends update_installed.
        record(JournalEntry(c.id, c.type.wire, "self_update", null, now, targetVersion = p.versionCode))
        log.info("installing agent ${p.versionCode}")
        return when (val o = actions.install(c.id, file, ownPackage, true)) {
            InstallOutcome.Done, InstallOutcome.Pending -> {
                awaitUser(c, "self", ownPackage, p.versionCode, null)
                null
            }
            is InstallOutcome.Failed -> { file.delete(); err(c, o.code, o.detail) }
        }
    }

    @Synchronized
    private fun awaitUser(c: Command, kind: String, pkg: String, versionCode: Long?, signer: String?) {
        state.awaitingUser = state.awaitingUser + (c.id to linkedMapOf(
            "kind" to kind, "package" to pkg, "versionCode" to versionCode, "signer" to signer, "since" to clock(),
        ))
        if (kind != "self") record(JournalEntry(c.id, c.type.wire, "awaiting_user", null, now))
    }

    /** Status of a system installer session (PackageInstaller callback). */
    @Synchronized
    fun onInstallerStatus(commandId: String, success: Boolean, aborted: Boolean, message: String?) {
        val a = state.awaitingUser[commandId] ?: return
        val kind = a.str("kind")
        val result = when {
            success && kind == "uninstall" -> CommandResult(commandId, ResultStatus.ACKNOWLEDGED, Codes.UNINSTALLED, emptyMap(), now)
            success && kind == "install" -> postInstallCheck(commandId, a.str("package") ?: return, a.str("signer"))
            success -> return // self update: the new version reports it
            aborted -> CommandResult(commandId, ResultStatus.ERROR, Codes.USER_DECLINED, emptyMap(), now)
            else -> CommandResult(commandId, ResultStatus.ERROR, Codes.INSTALL_FAILED, mapOf("message" to message?.take(200)), now)
        }
        state.awaitingUser = state.awaitingUser - commandId
        finish(commandId, result)
    }

    // ------------------------------------------------------------------
    // Journal and outbox
    // ------------------------------------------------------------------

    @Synchronized
    private fun record(e: JournalEntry) {
        state.journal = state.journal.filter { it.id != e.id } + e
    }

    @Synchronized
    private fun finish(id: String, r: CommandResult, type: String? = null) {
        val existing = state.journal.firstOrNull { it.id == id }
        record(JournalEntry(id, existing?.type ?: type ?: "?", "done", r, now))
        addResult(r)
    }

    @Synchronized
    private fun addResult(r: CommandResult) {
        state.outbox = state.outbox.filter { it.commandId != r.commandId } + r
    }

    private fun ack(c: Command, code: String) = CommandResult(c.id, ResultStatus.ACKNOWLEDGED, code, emptyMap(), now)
    private fun rej(c: Command, code: String) = CommandResult(c.id, ResultStatus.REJECTED, code, emptyMap(), now)
    private fun err(c: Command, code: String, detail: String? = null) =
        CommandResult(c.id, ResultStatus.ERROR, code, if (detail == null) emptyMap() else mapOf("message" to detail.take(200)), now)

    // ------------------------------------------------------------------
    // Back-off (§4.8)
    // ------------------------------------------------------------------

    private fun backoff(reply: Reply?): CycleReport {
        val delay = reply?.retryAfterSeconds ?: run {
            val step = state.backoffStep
            state.backoffStep = (step + 1).coerceAtMost(10)
            jitter(Math.min(BACKOFF_MIN_S shl step.coerceAtMost(6), BACKOFF_MAX_S), 0.20)
        }
        state.notBefore = clock() + delay
        return CycleReport(delay, installWork = state.installQueue.isNotEmpty())
    }

    private fun slow(seconds: Long): CycleReport {
        state.notBefore = clock() + seconds
        return CycleReport(seconds)
    }

    private fun jitter(base: Long, ratio: Double): Long {
        val span = (base * ratio).toLong()
        return if (span <= 0) base else base - span + random.nextLong(2 * span + 1)
    }

    companion object {
        /** Connect + read: the acknowledgement of a wipe or reboot waits 15 s at most (§5.3). */
        const val ACK_TIMEOUT_MS = 7_500
        /** app.pull: raw bytes per request (shared LEGACY_AGENT_PULL_CHUNK_BYTES). */
        const val PULL_CHUNK = 1_048_576
        const val MAX_RESULTS = 100
        const val MAX_EVENTS = 20
        const val FOLLOW_UP_S = 10L
        const val DAY_S = 86_400L
        /** Longest legitimate wait: slow(DAY_S), Retry-After (1 day at most), back-off (36 min). */
        const val MAX_WAIT_S = DAY_S + 3_600L
        const val USER_TIMEOUT_S = 86_400L
        /** A remote.open the host does not run any more is answered after this (corrected seconds since handed over). */
        const val REMOTE_ORPHAN_S = 60L
        const val CLOCK_EVENT_S = 120L
        const val BACKOFF_MIN_S = 30L
        const val BACKOFF_MAX_S = 1_800L
        /** 1.3.0: the undo of the policy before a revocation's erase (A9). */
        const val REVOKE_UNDO_S = 30L
        /** 1.3.0: the free space a policy file download leaves (usable > size * 2 + this, else storage_unavailable). */
        const val FREE_MARGIN_BYTES = 50L * 1024 * 1024
        const val REFUSED_RETRY_S = 600L
        /** 1.4.0: the refusal of a configuration that did not come from the bench, while the agent owns the device. */
        const val OWNER_BENCH_ONLY = "owner_bench_only"
        const val MAX_FEATURES = 16

        /**
         * The messages of a 400 badRequest that name a field of 1.4.0 (§3.4): the server's strict schema reports an unknown
         * key at the path of its object (zod unrecognized_keys), a wrong value at its own path.
         */
        private val LEGACY_RETRY_MESSAGES = setOf(
            "Invalid body: capabilities", "Invalid body: capabilities.deviceOwner",
            "Invalid body: hints", "Invalid body: hints.provisioningId",
        )

        /** An enrollment refused for a field of 1.4.0 only: sent again at once with the body of 1.3.0 (T381). */
        fun legacyEnrollRetry(status: Int, code: String?, message: String?): Boolean =
            status == 400 && code == "badRequest" && message?.trim() in LEGACY_RETRY_MESSAGES
    }
}
