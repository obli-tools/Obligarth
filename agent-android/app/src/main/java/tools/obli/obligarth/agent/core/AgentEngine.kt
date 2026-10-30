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
) {
    /** Called when a delivered configuration changes (Knox licence, keep-alive...). */
    var onConfigChanged: (() -> Unit)? = null
    /** Called when the identity was erased after a signed agentRevoked. */
    var onRevoked: (() -> Unit)? = null

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

    private fun enroll(): CycleReport {
        val cfg = state.config ?: return CycleReport(state.pollSeconds.toLong())
        val body = linkedMapOf<String, Any?>(
            "token" to cfg.token,
            "publicKey" to B64.encodeUrl(signer.spki()),
            "keyStorage" to signer.storage,
            "agent" to facts.agent(),
            "device" to facts.device(),
            "capabilities" to facts.capabilities(),
            "hints" to linkedMapOf("deviceName" to cfg.hints["deviceName"], "serial" to cfg.hints["serial"], "imei" to cfg.hints["imei"]),
        )
        val reply = client.call(
            "POST", "/agent/v1/enroll", Json.bytes(body), enrollKeys = { json -> trustedEnrollKeys(cfg, json) },
            enrollKeysPinned = cfg.serverKeySha256 != null || policy.serverKeyPins.isNotEmpty(),
        )
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
        c.long("version")?.let { state.configVersion = it }
        state.configAgentVersion = versionCode
        c.long("inventorySeconds")?.let { if (it in 3600..30L * 86_400) state.inventorySeconds = it }
        c.bool("keepAlive")?.let { state.keepAlive = it }
        c.long("minAgentVersionCode")?.let { state.minAgentVersionCode = it }
        if (c.containsKey("knoxLicenseKey")) state.serverKnoxLicenseKey = c.str("knoxLicenseKey")?.takeIf { it.isNotBlank() }
        // The whole configuration travels each time: no remote object (a server before P0-15) disables it.
        state.remote = RemoteConfig.fromServer(c.obj("remote"), now)
        onConfigChanged?.invoke()
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
        val outbox = state.outbox.take(MAX_RESULTS)
        val events = state.events.take(MAX_EVENTS)
        val body = linkedMapOf<String, Any?>(
            // The server sends the configuration only when the version announced differs, and its version hashes the
            // content alone: a configuration read by another version of the agent (1.0.x ignored config.remote) is
            // asked again whole, once, by announcing none.
            "agent" to linkedMapOf(
                "versionCode" to versionCode,
                "configVersion" to if (state.configAgentVersion == versionCode) state.configVersion else 0L,
            ),
            "status" to facts.status(),
            "results" to outbox.map { it.toJson() },
            "events" to events,
        )
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
        state.phase = EnrollmentMachine.next(state.phase, EnrollEvent.RevokedSigned).next
        state.eraseIdentity()
        try { signer.erase() } catch (e: Exception) { log.warn("key erase: ${e.message}") }
        state.lastStatus = "revoked"
        onRevoked?.invoke()
    }

    private sealed class Terminal {
        data class Wipe(val id: String, val external: Boolean) : Terminal()
        data class Reboot(val id: String) : Terminal()
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
    }
}
