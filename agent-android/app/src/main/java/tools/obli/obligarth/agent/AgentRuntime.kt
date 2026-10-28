package tools.obli.obligarth.agent

import android.annotation.SuppressLint
import android.content.Context
import android.os.SystemClock
import tools.obli.obligarth.agent.core.AgentClient
import tools.obli.obligarth.agent.core.AgentEngine
import tools.obli.obligarth.agent.core.AgentState
import tools.obli.obligarth.agent.core.AgentTls
import tools.obli.obligarth.agent.core.CycleReport
import tools.obli.obligarth.agent.core.Phase
import tools.obli.obligarth.agent.core.RemoteApi
import tools.obli.obligarth.agent.core.RemoteSessions
import tools.obli.obligarth.agent.core.TlsSocketConnector
import tools.obli.obligarth.agent.core.TrustPolicy
import tools.obli.obligarth.agent.core.UrlConnectionTransport
import tools.obli.obligarth.agent.core.WaitClient
import java.io.File
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

    val engine = AgentEngine(
        state, client, key, facts, actions, policy, app.packageName, facts.versionCode(), pinnedSigners,
        File(app.filesDir, "updates"), clock, log, remoteHost = remoteSessions,
    ).also { e ->
        remoteSessions.report = { id, status, code -> e.onRemoteOutcome(id, status, code) }
        e.onConfigChanged = { applyKnoxAndKeepAlive() }
        e.onRevoked = {
            Notifications.status(app, app.getString(R.string.status_revoked))
            KeepAliveService.stop(app)
        }
    }

    /** Imports a configuration then starts the enrollment at once. Null when accepted. */
    fun importConfig(raw: String?, source: String): String? {
        val refusal = engine.importConfig(raw, source)
        if (refusal == null) {
            applyKnoxAndKeepAlive()
            PollScheduler.pollNow(app)
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
        return report
    }

    /**
     * §8.3: with the administrator active and Knox present, activate the licence;
     * once licensed, the administrator can no longer be removed by the staff.
     */
    @Synchronized
    fun applyKnoxAndKeepAlive() {
        if (state.phase == Phase.ENROLLED && state.keepAlive) KeepAliveService.start(app) else if (!state.keepAlive) KeepAliveService.stop(app)
        if (!knox.present || !facts.adminActive()) return
        val licence = state.serverKnoxLicenseKey ?: state.config?.knoxLicenseKey
        // A new key, or the current one refused (or never answered) a while ago and still not licensed.
        if (licence != null && knox.activationDue(licence)) {
            if (knox.activateLicense(licence)) log.info("Knox licence activation requested")
        }
        if (knox.state() == "licensed" && knox.adminRemovable()) {
            if (knox.setAdminRemovable(false)) log.info("administrator made non-removable (Knox)")
        }
    }

    fun refreshStatusNotification() {
        if (!facts.adminActive() && state.phase != Phase.REVOKED) Notifications.adminRequired(app)
        else Notifications.cancelAdminRequired(app)
    }

    companion object {
        @SuppressLint("StaticFieldLeak") // holds the application context only
        @Volatile private var instance: AgentRuntime? = null

        fun get(context: Context): AgentRuntime =
            instance ?: synchronized(this) { instance ?: AgentRuntime(context).also { instance = it } }
    }
}
