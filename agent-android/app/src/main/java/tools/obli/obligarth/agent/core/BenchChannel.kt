package tools.obli.obligarth.agent.core

/** What the bench channel needs from the device (Android: BenchProvider through AgentRuntime). */
interface BenchDevice {
    fun role(): AgentRole
    /** The Knox state of KnoxLicence (absent, present, licensed, license_error). */
    fun knoxState(): String
    /**
     * prepare_owner: opens the bench window until [until] (local seconds) and lifts the Knox lock of the administrator
     * only when it is really set (licensed, not removable, and an administrator allowed to hold it: never on Android 15+),
     * in one critical section with the Knox upkeep of the cycle. False when Knox refused: the window is closed again.
     */
    fun openBenchWindow(until: Long): Boolean
    /** A cycle soon (the job scheduler), never on the calling thread. */
    fun requestCycle()
    /** Gives the device back (§7.5). */
    fun release(): ReleaseOutcome
}

/**
 * The channel of the bench station (1.4.0, lot BANC §7.4, §7.5): `content call --uri content://<package>.bench --method
 * <m> [--arg <a>]`, from the shell only. Answers carry simple values only: never a token, a configuration, a full URL
 * or a hardware identifier. Pure (T382, T383): BenchProvider turns the answer into a Bundle.
 */
class BenchChannel(
    private val engine: AgentEngine,
    private val state: AgentState,
    private val device: BenchDevice,
    private val versionCode: Long,
    /** Local wall clock, seconds. */
    private val clock: () -> Long,
    private val log: AgentLog = AgentLog.None,
    /** The diagnostic line written after each call (Log.i ObligarthBench on the device). */
    private val onLine: (String) -> Unit = {},
) {
    @Volatile private var lastPoll = Long.MIN_VALUE

    /** Throws SecurityException for any caller but the shell or root (logged without the content). */
    fun call(uid: Int, method: String?, arg: String?): Map<String, Any?> {
        if (!BenchRules.callerAllowed(uid)) {
            log.warn("bench channel refused to uid $uid (${BenchLog.code(method)})")
            throw SecurityException("bench channel: shell only")
        }
        val answer = try {
            when (method) {
                "state" -> base()
                "import" -> import(arg)
                "poll" -> poll()
                "prepare_owner" -> prepareOwner(uid)
                "release" -> release()
                else -> base(false, "unknown_method")
            }
        } catch (e: SecurityException) {
            throw e
        } catch (e: Exception) {
            log.warn("bench ${BenchLog.code(method)} failed: ${e.javaClass.simpleName}")
            base(false, "internal")
        }
        onLine(BenchLog.line(state.phase, roleOrNone(), state.lastStatus))
        return answer
    }

    private fun roleOrNone(): AgentRole = try { device.role() } catch (e: Exception) { AgentRole.NONE }

    private fun knoxWire(): String = when (try { device.knoxState() } catch (e: Exception) { KnoxLicence.ABSENT }) {
        KnoxLicence.LICENSED -> "licensed"
        KnoxLicence.ABSENT -> "absent"
        else -> "unlicensed"
    }

    private fun base(ok: Boolean = true, code: String? = null): LinkedHashMap<String, Any?> = linkedMapOf(
        "ok" to ok, "code" to code, "phase" to state.phase.name, "role" to roleOrNone().wire,
        "last" to BenchLog.code(state.lastStatus), "knox" to knoxWire(), "versionCode" to versionCode,
    )

    private fun import(arg: String?): Map<String, Any?> {
        if (state.phase == Phase.ENROLLED) return base(false, "already_enrolled")
        val refusal = engine.importConfig(arg, BenchRules.SOURCE)
        if (refusal != null) {
            log.warn("bench import refused: ${BenchLog.code(refusal)}")
            return base(false, BenchLog.code(refusal))
        }
        lastPoll = clock()
        device.requestCycle()
        log.info("bench import accepted")
        return base(true, "configured")
    }

    private fun poll(): Map<String, Any?> {
        val phase = state.phase
        if (phase != Phase.CONFIGURED && phase != Phase.ENROLLED) return base(false, "not_configured")
        val now = clock()
        if (lastPoll != Long.MIN_VALUE && now - lastPoll in 0 until BenchRules.POLL_MIN_S) return base(false, "too_soon")
        lastPoll = now
        device.requestCycle()
        return base(true, "poll_requested")
    }

    /**
     * An enrolled agent is managed: its administrator lock is lifted only while the server allows it (an open conversion
     * of this device, benchConvert of the signed poll reply, §6.5); otherwise the shell is refused (not_authorized).
     * Before the enrollment the device is not managed yet: the window opens. Every window opened is told to the server
     * (event bench_window_opened, its audit).
     */
    private fun prepareOwner(uid: Int): Map<String, Any?> {
        val phase = state.phase
        if (!BenchRules.windowAllowed(phase, engine.benchConvertAllowed())) {
            log.warn("bench prepare_owner refused in phase ${phase.name}: no conversion allowed by the server")
            return base(false, "not_authorized")
        }
        if (!device.openBenchWindow(clock() + BenchRules.WINDOW_S)) {
            log.warn("bench prepare_owner: Knox refused setAdminRemovable(true)")
            return base(false, "knox_error")
        }
        engine.benchWindowOpened(phase, uid)
        log.info("bench window opened for ${BenchRules.WINDOW_S / 60} min")
        return base(true, "window_open").also { it["windowSeconds"] = BenchRules.WINDOW_S }
    }

    private fun release(): Map<String, Any?> {
        val phase = state.phase
        if (!BenchRules.releaseAllowed(phase)) {
            log.warn("bench release refused in phase ${phase.name}")
            return base(false, "release_refused")
        }
        val outcome = device.release()
        engine.forgetAfterBenchRelease()
        return base(outcome.complete, if (outcome.complete) "released" else "release_partial").also {
            it["ownerCleared"] = outcome.ownerCleared
            it["adminActive"] = outcome.adminActive
        }
    }
}
