package tools.obli.obligarth.agent

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Log
import tools.obli.obligarth.agent.core.AgentClient
import tools.obli.obligarth.agent.core.AgentEngine
import tools.obli.obligarth.agent.core.AgentRole
import tools.obli.obligarth.agent.core.BenchChannel
import tools.obli.obligarth.agent.core.BenchDevice
import tools.obli.obligarth.agent.core.BenchLog
import tools.obli.obligarth.agent.core.OwnerMode
import tools.obli.obligarth.agent.core.ReleaseOutcome
import tools.obli.obligarth.agent.core.AgentState
import tools.obli.obligarth.agent.core.AgentTls
import tools.obli.obligarth.agent.core.CycleReport
import tools.obli.obligarth.agent.core.Phase
import tools.obli.obligarth.agent.core.PolicyCodes
import tools.obli.obligarth.agent.core.RemoteApi
import tools.obli.obligarth.agent.core.RemoteSessions
import tools.obli.obligarth.agent.core.TlsSocketConnector
import tools.obli.obligarth.agent.core.TrustPolicy
import tools.obli.obligarth.agent.core.UrlConnectionTransport
import tools.obli.obligarth.agent.core.WaitClient
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection

/** Wires the pure engine to the Android implementations; one per process. */
class AgentRuntime private constructor(context: Context) {
    val app: Context = context.applicationContext
    val log = LocalLog(app)
    val state = AgentState(PrefsStore(app))
    val knox = KnoxBridge(app, log)
    val facts = AndroidFacts(app, knox)
    val actions = AndroidActions(app, facts, knox, log)
    val key = AgentKey(app, log)
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 }

    val policy = TrustPolicy.fromBuild(BuildConfig.ALLOWED_SERVER_HOSTS, BuildConfig.SERVER_KEY_PINS, BuildConfig.REQUIRE_SERVER_KEY_PIN)

    /** PINNED_SIGNERS, plus in debug the key that signed this very build (the local debug key). */
    val pinnedSigners: Set<String> = buildSet {
        BuildConfig.PINNED_SIGNERS.split(',').map { it.trim().lowercase() }.filter { it.length == 64 }.forEach { add(it) }
        if (BuildConfig.PIN_OWN_SIGNER) addAll(facts.ownSignerSha256())
    }

    private val tlsPins = BuildConfig.TLS_PINS.split(',').map { it.trim() }.filter { it.length == 64 }.toSet()
    private val transport = UrlConnectionTransport(tlsPins = tlsPins)
    val client = AgentClient(state, key, transport, clock, log)

    /**
     * Remote assistance (1.1.0, P0-15): the stream socket trusts the system store plus ISRG Root X1 and X2 (the network
     * security configuration does not check host names on a raw socket), with the host name checked again.
     */
    val remoteApi: RemoteApi by lazy {
        val isrg = listOf(R.raw.isrg_root_x1, R.raw.isrg_root_x2).flatMap { id -> app.resources.openRawResource(id).use { AgentTls.certificates(it) } }
        val connector = TlsSocketConnector(AgentTls.agent(isrg), HttpsURLConnection.getDefaultHostnameVerifier(), tlsPins)
        RemoteApi(state, client, key, connector, log = log)
    }

    /** /agent/v1/wait on a transport of its own, outside the lock of [client] (§4.3 B). */
    val waitClient: WaitClient by lazy { WaitClient(state, key, UrlConnectionTransport(tlsPins = tlsPins), clock, log) }

    /** What a remote assistance session shows on the device, and the sessions themselves (one at a time, P0-15). */
    val remoteUi = AndroidRemoteUi(app, log)
    val remoteSessions = RemoteSessions({ remoteApi }, remoteUi, { client.correctedNow() }, log, clockMs = { SystemClock.elapsedRealtime() })

    /** 1.3.0 (lot PONT-POL): the device side of the policy, and the key that seals its secrets at rest. */
    val policyApplier = PolicyApplier(app, facts, knox, log).also { actions.policyApplier = it }
    private val sealer = KeystoreSealer(log)

    /** 1.4.0 (lot BANC §7.3, §7.5): the owner of the device (its protections, policy items, release). */
    val owner = OwnerApplier(app, facts, knox, policyApplier.kiosk, policyApplier.wifi, log).also {
        actions.owner = it
        policyApplier.owner = it
    }

    val engine = AgentEngine(
        state, client, key, facts, actions, policy, app.packageName, facts.versionCode(), pinnedSigners,
        File(app.filesDir, "updates"), clock, log, remoteHost = remoteSessions, sealer = sealer, policyDir = File(app.filesDir, "policy"),
    ).also { e ->
        remoteSessions.report = { id, status, code -> e.onRemoteOutcome(id, status, code) }
        e.onConfigChanged = { applyKnoxAndKeepAlive() }
        e.onRevoked = {
            Notifications.status(app, app.getString(R.string.status_revoked))
            KeepAliveService.stop(app)
            for (need in listOf(Notifications.NEED_STORAGE, Notifications.NEED_HOME, Notifications.NEED_ADMIN_POLICIES)) Notifications.cancelPolicy(app, need)
        }
        e.onPolicyChanged = { requestReconcile() }
        // 1.4.0: a new owner takes its protections at once and applies the items of the owner; a lost role is reported
        // by the engine (device_owner_lost) and the policy reconciled again (its owner items go back to pending).
        e.onRoleChanged = { gained ->
            Thread({
                if (gained) owner.upkeep()
                applyKnoxAndKeepAlive()
            }, "obligarth-owner").start()
            requestReconcile()
        }
    }

    /**
     * The bench channel (1.4.0, lot BANC §7.4): BenchProvider hands it the calls of `content call`, from the shell only.
     * Each call writes the diagnostic line ObligarthBench (codes only).
     */
    val bench: BenchChannel by lazy {
        BenchChannel(engine, state, object : BenchDevice {
            override fun role(): AgentRole = facts.role()
            override fun knoxState(): String = knox.state()
            override fun openBenchWindow(until: Long): Boolean = this@AgentRuntime.openBenchWindow(until)
            override fun requestCycle() = PollScheduler.pollNow(app)
            override fun release(): ReleaseOutcome = actions.releaseOwnership() ?: ReleaseOutcome(false, facts.adminActive(), emptyList())
        }, facts.versionCode(), clock, log) { line -> Log.i(BenchLog.TAG, line) }
    }

    /** The diagnostic line of the bench after a cycle (§7.4): codes only. */
    private fun benchLine() {
        try { Log.i(BenchLog.TAG, BenchLog.line(state.phase, facts.role(), state.lastStatus)) } catch (e: Exception) { /* logcat only */ }
    }

    private val reconciling = AtomicBoolean(false)
    /** A reconciliation was asked while one ran (a PIN exit, kiosk.suspend, a new policy): the running one goes again. */
    private val reconcileAgain = AtomicBoolean(false)

    /**
     * Reconciles the policy (1.3.0, §10.4): the missing files downloaded for 90 s at most, then every item applied until
     * [deadlineLocal]; the rest of the downloads goes to the install job. A changed report asks a poll in 15 s. One run
     * at a time; never inside the engine lock. A request that comes while one runs is never lost: the running one takes
     * a fresh snapshot and goes again (a few times at most), and a request made just as it ends starts it again here.
     */
    fun reconcile(deadlineLocal: Long): AgentEngine.PolicyRun? {
        if (state.phase != Phase.ENROLLED) return null
        reconcileAgain.set(true)
        var last: AgentEngine.PolicyRun? = null
        while (reconcileAgain.get()) {
            // Another thread runs: it sees the flag and goes again.
            if (!reconciling.compareAndSet(false, true)) return last
            try {
                var runs = 0
                while (reconcileAgain.getAndSet(false) && runs < MAX_RECONCILE_RUNS) {
                    last = reconcileOnce(if (runs == 0) deadlineLocal else maxOf(deadlineLocal, clock() + RERUN_S)) ?: last
                    runs++
                }
            } finally {
                reconciling.set(false)
            }
        }
        return last
    }

    private fun reconcileOnce(deadlineLocal: Long): AgentEngine.PolicyRun? = try {
        val local = clock()
        val run = engine.runPolicy(deadlineLocal, downloadUntil = minOf(deadlineLocal, local + DOWNLOAD_IN_CYCLE_S))
        val snap = engine.policySnapshot()
        snap.policy?.let { if (engine.missingBlobs(it).isNotEmpty()) PollScheduler.scheduleInstall(app) }
        notifyNeeds(run.report)
        if (run.reportChanged && state.serverPolicyV1) PollScheduler.scheduleNext(app, REPORT_FOLLOW_UP_S)
        // A suspended kiosk is restored at its expiry (§10.5), not at the next cycle only.
        val now = clock()
        if (snap.kioskSuspendedUntil > now && snap.policy?.kiosk != null) PollScheduler.scheduleKioskResume(app, snap.kioskSuspendedUntil - now + 2)
        run
    } catch (e: Throwable) {
        log.warn("policy reconciliation failed: ${e.javaClass.simpleName}")
        null
    }

    /** Downloads the missing policy files (install job); true when some remain. */
    fun downloadPolicyBlobs(deadlineLocal: Long): Boolean {
        val p = engine.policySnapshot().policy ?: return false
        return engine.downloadPolicyBlobs(p, deadlineLocal)
    }

    fun policyBlobsMissing(): Boolean = engine.policySnapshot().policy?.let { engine.missingBlobs(it).isNotEmpty() } == true

    /** A reconciliation soon, on a worker thread (a new policy, a suspension, a permission granted). */
    fun requestReconcile() {
        Thread({ reconcile(clock() + RECONCILE_S) }, "obligarth-policy").start()
    }

    /** The notifications of what the policy needs from the person holding the device (they open the status screen). */
    private fun notifyNeeds(report: tools.obli.obligarth.agent.core.PolicyReport) {
        val codes = report.items.filter { it.state != "compliant" }.map { it.code }.toSet()
        fun need(id: Int, on: Boolean, text: Int) = if (on) Notifications.policy(app, id, text) else Notifications.cancelPolicy(app, id)
        need(Notifications.NEED_STORAGE, PolicyCodes.PERMISSION_MISSING in codes, R.string.policy_need_storage)
        need(Notifications.NEED_ADMIN_POLICIES, PolicyCodes.ADMIN_POLICY_MISSING in codes, R.string.policy_need_admin_policies)
    }

    /** Imports a configuration then starts the enrollment at once. Null when accepted. */
    fun importConfig(raw: String?, source: String): String? {
        val refusal = engine.importConfig(raw, source)
        if (refusal == null) {
            applyKnoxAndKeepAlive()
            PollScheduler.pollNow(app)
            benchLine()
        }
        return refusal
    }

    /** One interrogation cycle (job thread). */
    fun cycle(force: Boolean = false): CycleReport {
        applyKnoxAndKeepAlive()
        val report = engine.runCycle(force)
        PollScheduler.scheduleNext(app, report.nextDelaySeconds)
        if (report.installWork) PollScheduler.scheduleInstall(app)
        refreshStatusNotification()
        benchLine()
        return report
    }

    /**
     * §8.3: with the administrator active and Knox present, activate the licence;
     * once licensed, the administrator can no longer be removed by the staff.
     *
     * 1.4.0 (lot BANC §6.5, §7.3): that lock is for an administrator only, never while a bench window is open
     * (prepare_owner), never on Android 15+ (refused there to an administrator); the owner of the device lifts it (and
     * keeps its own protections: OwnerApplier.upkeep).
     */
    @Synchronized
    fun applyKnoxAndKeepAlive() {
        if (state.phase == Phase.ENROLLED && state.keepAlive) KeepAliveService.start(app) else if (!state.keepAlive) KeepAliveService.stop(app)
        val role = facts.role()
        if (role == AgentRole.OWNER) owner.upkeep()
        if (!knox.present || role == AgentRole.NONE) return
        val licence = state.serverKnoxLicenseKey ?: state.config?.knoxLicenseKey
        // A new key, or the current one refused (or never answered) a while ago and still not licensed.
        if (licence != null && knox.activationDue(licence)) {
            if (knox.activateLicense(licence)) log.info("Knox licence activation requested")
        }
        val windowOpen = state.benchWindowUntil > clock()
        if (role == AgentRole.ADMIN && !windowOpen && !OwnerMode.knoxRestricted(role, Build.VERSION.SDK_INT) &&
            knox.state() == "licensed" && knox.adminRemovable()) {
            if (knox.setAdminRemovable(false)) log.info("administrator made non-removable (Knox)")
        }
    }

    /**
     * prepare_owner (lot BANC §6.5, §7.4): the bench window opened and the Knox lock of the administrator lifted, under the
     * same monitor as [applyKnoxAndKeepAlive], so that a cycle running meanwhile (MY_PACKAGE_REPLACED right after
     * the update by adb install -r) never sets the lock again between the two. Knox is called only when the lock of 1.3.0 is really
     * there: licensed, not removable, and an administrator allowed to hold it (never on Android 15+, where Knox refuses
     * the call to an administrator and no lock was ever set). False when Knox refused: the window closed again.
     */
    @Synchronized
    fun openBenchWindow(until: Long): Boolean {
        state.benchWindowUntil = until
        val role = facts.role()
        val locked = knox.present && knox.state() == "licensed" && !OwnerMode.knoxRestricted(role, Build.VERSION.SDK_INT) && !knox.adminRemovable()
        if (!locked) return true
        if (knox.setAdminRemovable(true)) return true
        state.benchWindowUntil = 0
        return false
    }

    fun refreshStatusNotification() {
        if (!facts.adminActive() && state.phase != Phase.REVOKED) Notifications.adminRequired(app)
        else Notifications.cancelAdminRequired(app)
    }

    companion object {
        @SuppressLint("StaticFieldLeak") // holds the application context only
        @Volatile private var instance: AgentRuntime? = null
        /** Downloads inside a cycle (§10.6): the rest goes to the install job. */
        private const val DOWNLOAD_IN_CYCLE_S = 90L
        /** A reconciliation outside a cycle (new policy, permission granted). */
        const val RECONCILE_S = 120L
        private const val REPORT_FOLLOW_UP_S = 15L
        /** The runs of one reconciliation when requests keep coming meanwhile, and the time each further run gets. */
        private const val MAX_RECONCILE_RUNS = 4
        private const val RERUN_S = 60L

        fun get(context: Context): AgentRuntime =
            instance ?: synchronized(this) { instance ?: AgentRuntime(context).also { instance = it } }
    }
}
