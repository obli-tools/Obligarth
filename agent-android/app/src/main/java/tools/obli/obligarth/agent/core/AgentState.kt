package tools.obli.obligarth.agent.core

/** Persistent key-value storage (SharedPreferences on the device, a map in tests). Writes are synchronous. */
interface KeyValueStore {
    fun get(key: String): String?
    /** Applies all changes at once; a null value removes the key. */
    fun put(changes: Map<String, String?>)
}

class MemoryStore : KeyValueStore {
    private val map = HashMap<String, String>()
    @Synchronized override fun get(key: String): String? = map[key]
    @Synchronized override fun put(changes: Map<String, String?>) {
        for ((k, v) in changes) if (v == null) map.remove(k) else map[k] = v
    }
    @Synchronized fun snapshot(): Map<String, String> = HashMap(map)
}

/** One entry of the persistent command journal (dedup over the last 1000 ids, §5.3). */
data class JournalEntry(
    val id: String,
    val type: String,
    /** running | awaiting_user | self_update | done */
    val state: String,
    val result: CommandResult?,
    val at: Long,
    /** agent.update: target versionCode, checked at the next start (§8.6 step 4). */
    val targetVersion: Long? = null,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "id" to id, "type" to type, "state" to state, "result" to result?.toJson(), "at" to at, "targetVersion" to targetVersion,
    )

    companion object {
        fun fromJson(m: Map<String, Any?>): JournalEntry? {
            val id = m.str("id") ?: return null
            val state = m.str("state") ?: return null
            return JournalEntry(id, m.str("type") ?: "", state, m.obj("result")?.let { CommandResult.fromJson(it) }, m.long("at") ?: 0, m.long("targetVersion"))
        }
    }
}

/**
 * Typed view of everything the agent keeps (spec §8.2 storage). Every mutation is
 * written at once; [seq] is persisted before each request (RC-6).
 */
class AgentState(private val store: KeyValueStore) {
    private fun s(key: String) = store.get(key)
    private fun set(vararg pairs: Pair<String, String?>) = store.put(mapOf(*pairs))

    var phase: Phase
        get() = s(K_PHASE)?.let { runCatching { Phase.valueOf(it) }.getOrNull() } ?: Phase.NEW
        set(v) = set(K_PHASE to v.name)

    var config: AgentConfig?
        get() = s(K_CONFIG)?.let { Json.parseObjectOrNull(it) }?.let { configFromStored(it) }
        set(v) = set(K_CONFIG to v?.let { Json.write(it.toJson()) })

    var agentId: String? get() = s(K_AGENT_ID); set(v) = set(K_AGENT_ID to v)
    var deviceUuid: String? get() = s(K_DEVICE_UUID); set(v) = set(K_DEVICE_UUID to v)
    var seq: Long get() = s(K_SEQ)?.toLongOrNull() ?: 0; set(v) = set(K_SEQ to v.toString())
    /** serverTime - local time, seconds. */
    var clockOffset: Long get() = s(K_CLOCK)?.toLongOrNull() ?: 0; set(v) = set(K_CLOCK to v.toString())

    var serverKeys: List<ServerKey>
        get() = (s(K_SERVER_KEYS)?.let { Json.parse(it) } as? List<*>).orEmpty()
            .mapNotNull { (it as? String)?.let { b -> B64.decode(b) } }.map { ServerKey(it) }
        set(v) = set(K_SERVER_KEYS to Json.write(v.map { B64.encodeUrl(it.spki) }))

    var pollSeconds: Int get() = s(K_POLL)?.toIntOrNull() ?: 300; set(v) = set(K_POLL to v.coerceIn(60, 3600).toString())
    var inventorySeconds: Long get() = s(K_INV_SECONDS)?.toLongOrNull() ?: 86_400; set(v) = set(K_INV_SECONDS to v.toString())
    var keepAlive: Boolean get() = s(K_KEEPALIVE)?.toBoolean() ?: true; set(v) = set(K_KEEPALIVE to v.toString())
    var configVersion: Long get() = s(K_CONFIG_VERSION)?.toLongOrNull() ?: 0; set(v) = set(K_CONFIG_VERSION to v.toString())
    var minAgentVersionCode: Long get() = s(K_MIN_VERSION)?.toLongOrNull() ?: 0; set(v) = set(K_MIN_VERSION to v.toString())
    /** Licence key delivered by the server (config.knoxLicenseKey), else the one of the dropped configuration. */
    var serverKnoxLicenseKey: String? get() = s(K_KNOX_KEY); set(v) = set(K_KNOX_KEY to v)
    var knoxActivatedKeySha: String? get() = s(K_KNOX_DONE); set(v) = set(K_KNOX_DONE to v)

    var lastInventoryAt: Long get() = s(K_LAST_INV)?.toLongOrNull() ?: 0; set(v) = set(K_LAST_INV to v.toString())
    var inventoryRequested: Boolean get() = s(K_INV_REQ)?.toBoolean() ?: false; set(v) = set(K_INV_REQ to v.toString())
    /** First moment of an uninterrupted series of 401 (badSignature, unknownAgent); 0 when none. */
    var authFailingSince: Long get() = s(K_AUTH_FAIL)?.toLongOrNull() ?: 0; set(v) = set(K_AUTH_FAIL to v.toString())
    var lastStatus: String? get() = s(K_STATUS); set(v) = set(K_STATUS to v)
    var lastPollAt: Long get() = s(K_LAST_POLL)?.toLongOrNull() ?: 0; set(v) = set(K_LAST_POLL to v.toString())
    /** Earliest time of the next request (Retry-After, back-off), local seconds. */
    var notBefore: Long get() = s(K_NOT_BEFORE)?.toLongOrNull() ?: 0; set(v) = set(K_NOT_BEFORE to v.toString())
    var backoffStep: Int get() = s(K_BACKOFF)?.toIntOrNull() ?: 0; set(v) = set(K_BACKOFF to v.toString())

    // ---- Outbox (results), events, journal, install queue ----

    var outbox: List<CommandResult>
        get() = jsonList(K_OUTBOX).mapNotNull { CommandResult.fromJson(it) }
        set(v) = set(K_OUTBOX to Json.write(v.map { it.toJson() }))

    var events: List<Map<String, Any?>>
        get() = jsonList(K_EVENTS)
        set(v) = set(K_EVENTS to Json.write(v.takeLast(MAX_EVENTS_KEPT)))

    var journal: List<JournalEntry>
        get() = jsonList(K_JOURNAL).mapNotNull { JournalEntry.fromJson(it) }
        set(v) = set(K_JOURNAL to Json.write(v.takeLast(JOURNAL_SIZE).map { it.toJson() }))

    var installQueue: List<Map<String, Any?>>
        get() = jsonList(K_INSTALL_QUEUE)
        set(v) = set(K_INSTALL_QUEUE to Json.write(v))

    /** Install launched with a user prompt pending: commandId -> {startedAt, package, kind}. */
    var awaitingUser: Map<String, Map<String, Any?>>
        get() = (s(K_AWAITING)?.let { Json.parseObjectOrNull(it) } ?: emptyMap()).mapNotNull { (k, v) ->
            @Suppress("UNCHECKED_CAST") (v as? Map<String, Any?>)?.let { k to it }
        }.toMap()
        set(v) = set(K_AWAITING to Json.write(v))

    @Suppress("UNCHECKED_CAST")
    private fun jsonList(key: String): List<Map<String, Any?>> =
        (s(key)?.let { runCatching { Json.parse(it) }.getOrNull() } as? List<*>).orEmpty().mapNotNull { it as? Map<String, Any?> }

    /** Receivers add events from other threads than the engine: event queue changes go through this lock. */
    @Synchronized
    fun addEvent(type: String, at: Long, detail: Map<String, Any?> = emptyMap()) {
        events = events + linkedMapOf("type" to type, "at" to at, "detail" to detail)
    }

    @Synchronized
    fun dropEvents(count: Int) {
        events = events.drop(count)
    }

    /** Erases identity and configuration (signed agentRevoked only, RS-8). The local log survives. */
    fun eraseIdentity() {
        store.put(ALL_IDENTITY_KEYS.associateWith { null })
    }

    companion object {
        const val JOURNAL_SIZE = 1000
        const val MAX_EVENTS_KEPT = 200
        const val K_PHASE = "phase"
        const val K_CONFIG = "config"
        const val K_AGENT_ID = "agentId"
        const val K_DEVICE_UUID = "deviceUuid"
        const val K_SEQ = "seq"
        const val K_CLOCK = "clockOffset"
        const val K_SERVER_KEYS = "serverKeys"
        const val K_POLL = "pollSeconds"
        const val K_INV_SECONDS = "inventorySeconds"
        const val K_KEEPALIVE = "keepAlive"
        const val K_CONFIG_VERSION = "configVersion"
        const val K_MIN_VERSION = "minAgentVersionCode"
        const val K_KNOX_KEY = "knoxLicenseKey"
        const val K_KNOX_DONE = "knoxActivatedKeySha"
        const val K_LAST_INV = "lastInventoryAt"
        const val K_INV_REQ = "inventoryRequested"
        const val K_AUTH_FAIL = "authFailingSince"
        const val K_STATUS = "lastStatus"
        const val K_LAST_POLL = "lastPollAt"
        const val K_NOT_BEFORE = "notBefore"
        const val K_BACKOFF = "backoffStep"
        const val K_OUTBOX = "outbox"
        const val K_EVENTS = "events"
        const val K_JOURNAL = "journal"
        const val K_INSTALL_QUEUE = "installQueue"
        const val K_AWAITING = "awaitingUser"

        private val ALL_IDENTITY_KEYS = listOf(
            K_CONFIG, K_AGENT_ID, K_DEVICE_UUID, K_SEQ, K_CLOCK, K_SERVER_KEYS, K_POLL, K_INV_SECONDS, K_KEEPALIVE,
            K_CONFIG_VERSION, K_MIN_VERSION, K_KNOX_KEY, K_LAST_INV, K_INV_REQ, K_AUTH_FAIL, K_NOT_BEFORE, K_BACKOFF,
            K_OUTBOX, K_EVENTS, K_JOURNAL, K_INSTALL_QUEUE, K_AWAITING,
        )

        private fun configFromStored(m: Map<String, Any?>): AgentConfig? {
            val server = m.str("server") ?: return null
            val host = try { java.net.URI(server).host ?: return null } catch (e: Exception) { return null }
            @Suppress("UNCHECKED_CAST")
            return AgentConfig(server, host, m.str("token") ?: return null, m.str("serverKeySha256"), m.str("knoxLicenseKey"),
                (m["hints"] as? Map<String, Any?>) ?: emptyMap())
        }
    }
}
