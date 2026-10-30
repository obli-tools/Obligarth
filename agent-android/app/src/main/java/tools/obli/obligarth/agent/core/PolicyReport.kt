package tools.obli.obligarth.agent.core

/** One item of the compliance report: its key, a state of [PolicyStates.ITEM], a code of [PolicyCodes], a short detail. */
data class ReportItem(val key: String, val state: String, val code: String, val detail: String? = null) {
    fun toJson(): Map<String, Any?> = linkedMapOf<String, Any?>("key" to key, "state" to state, "code" to code).also { if (detail != null) it["detail"] = detail }

    companion object {
        fun fromJson(m: Map<String, Any?>): ReportItem? {
            val key = m.str("key") ?: return null
            return ReportItem(key, m.str("state") ?: return null, m.str("code") ?: return null, m.str("detail"))
        }
    }
}

/**
 * The compliance report of the policy (1.3.0, lot PONT-POL §8.4), sent in the body of a poll (key `policy`): the hash
 * of the policy held (null: none), the state computed from the items as the server does, the Knox state, the items
 * sorted by key (200 at most). Details are clipped to 160 printable characters and never carry a secret.
 */
class PolicyReport(
    val hash: String?,
    val state: String,
    val appliedAt: Long,
    val knoxState: String,
    val items: List<ReportItem>,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "hash" to hash, "state" to state, "appliedAt" to appliedAt, "knoxState" to knoxState, "items" to items.map { it.toJson() },
    )

    /** What changes the report: everything but appliedAt (a report re-sent only for its time would be noise). */
    fun digest(): String = Canon.sha256(linkedMapOf("hash" to hash, "state" to state, "knoxState" to knoxState, "items" to items.map { it.toJson() }))

    override fun toString() = "PolicyReport(${hash?.take(8)}, $state, ${items.size} items)"

    companion object {
        const val MAX_ITEMS = 200
        const val MAX_DETAIL = 160
        const val MAX_KEY = 160
        private val KNOX_STATES = setOf("absent", "present", "licensed", "license_error")

        /** The report state from its items (shared agentReportStateOf). */
        fun stateOf(items: List<ReportItem>, hasPolicy: Boolean): String = when {
            !hasPolicy -> "none"
            items.any { it.state == PolicyStates.ERROR } -> "error"
            items.any { it.state == PolicyStates.NON_COMPLIANT } -> "partial"
            items.any { it.state == PolicyStates.PENDING } -> "pending"
            else -> "applied"
        }

        /** Printable characters only (no control, no line break), [MAX_DETAIL] at most. */
        fun clipDetail(s: String?): String? =
            s?.filter { it >= ' ' && it != '\u007f' && !(it in '\u0080'..'\u009f') }?.take(MAX_DETAIL)?.ifEmpty { null }

        fun build(hash: String?, knoxState: String, items: List<ReportItem>, appliedAt: Long): PolicyReport {
            val clean = items.asSequence()
                .filter { Policy.isKey(it.key.take(MAX_KEY)) && it.state in PolicyStates.ITEM && it.code.matches(Regex("^[a-z_]{1,48}$")) }
                .map { it.copy(key = it.key.take(MAX_KEY), detail = clipDetail(it.detail)) }
                .associateBy { it.key }.values
                .sortedBy { it.key }
                .take(MAX_ITEMS)
                .toList()
            val knox = if (knoxState in KNOX_STATES) knoxState else "absent"
            return PolicyReport(hash, stateOf(clean, hash != null), appliedAt, knox, clean)
        }

        fun fromJson(m: Map<String, Any?>?): PolicyReport? {
            if (m == null) return null
            val items = m.list("items").orEmpty().mapNotNull { @Suppress("UNCHECKED_CAST") (it as? Map<String, Any?>)?.let { o -> ReportItem.fromJson(o) } }
            return PolicyReport(m.str("hash"), m.str("state") ?: return null, m.long("appliedAt") ?: 0, m.str("knoxState") ?: "absent", items)
        }
    }
}
