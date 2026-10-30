package tools.obli.obligarth.agent.core

/** What the agent last did for one path of a deposited file (C9): only a file it wrote may be deleted on undo. */
data class FileMark(val sha: String?, val writtenByAgent: Boolean, val size: Long, val mtime: Long, val checkedAt: Long) {
    fun toJson(): Map<String, Any?> = linkedMapOf("sha" to sha, "written" to writtenByAgent, "size" to size, "mtime" to mtime, "checkedAt" to checkedAt)

    companion object {
        fun fromJson(m: Map<String, Any?>): FileMark =
            FileMark(m.str("sha"), m.bool("written") ?: false, m.long("size") ?: -1, m.long("mtime") ?: -1, m.long("checkedAt") ?: 0)
    }
}

/**
 * What the agent applied for one key: the digest of the value applied ("" when forgotten by policy.reapply or never
 * settled), when it was last applied or read back, the last outcome, and what an undo needs (file marks and onRemove,
 * the Knox list applied, the certificate name, the last preferOver switch).
 */
data class LedgerEntry(
    val digest: String,
    val checkedAt: Long,
    val state: String,
    val code: String,
    val detail: String? = null,
    val files: Map<String, FileMark> = emptyMap(),
    val onRemove: String? = null,
    val value: Any? = null,
    val preferAt: Long = 0,
) {
    fun toJson(): Map<String, Any?> = linkedMapOf(
        "digest" to digest, "checkedAt" to checkedAt, "state" to state, "code" to code, "detail" to detail,
        "files" to files.mapValues { it.value.toJson() }, "onRemove" to onRemove, "value" to value, "preferAt" to preferAt,
    )

    companion object {
        fun fromJson(m: Map<String, Any?>): LedgerEntry? {
            @Suppress("UNCHECKED_CAST")
            val files = (m.obj("files") ?: emptyMap()).mapNotNull { (k, v) -> (v as? Map<String, Any?>)?.let { k to FileMark.fromJson(it) } }.toMap()
            return LedgerEntry(
                m.str("digest") ?: "", m.long("checkedAt") ?: 0, m.str("state") ?: return null, m.str("code") ?: return null,
                m.str("detail"), files, m.str("onRemove"), m["value"], m.long("preferAt") ?: 0,
            )
        }
    }
}

/** The ledger of the policy (state K_POLICY_LEDGER): per key, what was applied. Never a secret (digests only). */
class Ledger(val entries: Map<String, LedgerEntry> = emptyMap()) {
    fun toJson(): Map<String, Any?> = linkedMapOf("entries" to entries.mapValues { it.value.toJson() })

    /** policy.reapply: every digest forgotten (each item applied again), what an undo needs kept. */
    fun forget(): Ledger = Ledger(entries.mapValues { it.value.copy(digest = "", checkedAt = 0) })

    companion object {
        fun fromJson(m: Map<String, Any?>?): Ledger {
            @Suppress("UNCHECKED_CAST")
            val e = (m?.obj("entries") ?: emptyMap()).mapNotNull { (k, v) -> (v as? Map<String, Any?>)?.let { o -> LedgerEntry.fromJson(o)?.let { k to it } } }
            return Ledger(e.toMap())
        }
    }
}

/** The result of one reconciliation. */
class ReconcileResult(
    val ledger: Ledger,
    val report: PolicyReport,
    /** A Wi-Fi item needs its secrets again (sealed copy lost): the agent announces configVersion 0 at its next poll. */
    val needFullConfig: Boolean,
    /** Keys left in the ledger that the policy no longer names (undo not finished). */
    val undoLeft: Int,
    val undoDone: Int,
)

/**
 * Applies a policy to the device through [host] (1.3.0, lot PONT-POL §10.2): pure orchestration, no Android import.
 *
 * Order (C5): device administrator, Knox (but settingsChanges), certificates, Wi-Fi, Wi-Fi removals, inline files,
 * downloaded files, kiosk, then Knox settingsChanges = false last (only once the storage is writable and, with a kiosk,
 * the agent is the default home), then the undo of the ledger keys the policy no longer names. An item whose ledger
 * digest equals the desired one and whose read-back confirms it is compliant/unchanged without any call; otherwise it
 * is applied. Every item runs alone (a failure never stops the others); items not reached before [deadline] report
 * pending with their previous outcome kept. Dropped, undeliverable, withheld and unreadable items are reported, and an
 * undeliverable, withheld or unreadable key keeps what the device holds (never undone).
 */
class PolicyReconciler(
    private val host: PolicyHost,
    private val blobs: BlobCache,
    /** Local wall clock (seconds) for the deadline. */
    private val clock: () -> Long,
    private val log: AgentLog = AgentLog.None,
) {
    /**
     * [now]: local seconds of the ledger times; [appliedAt]: the corrected time of the report; [rejectedHash]: the hash
     * of a policy of an unknown format received (reported policy_version_unsupported); [kioskSuspended]: the kiosk left.
     * A null [policy] undoes every key of the ledger (removal, revocation).
     */
    fun reconcile(
        policy: Policy?, ledger: Ledger, now: Long, deadline: Long, appliedAt: Long = now,
        rejectedHash: String? = null, kioskSuspended: Boolean = false,
    ): ReconcileResult {
        val run = Run(policy, ledger, now, deadline)
        if (policy != null) run.apply(policy, kioskSuspended)
        run.undo(policy)
        if (rejectedHash != null) run.items += ReportItem(POLICY_KEY, PolicyStates.ERROR, PolicyCodes.POLICY_VERSION_UNSUPPORTED)
        val report = PolicyReport.build(policy?.hash, run.knox, run.items, appliedAt)
        return ReconcileResult(Ledger(run.entries.toMap()), report, run.needFull, run.undoLeft, run.undoDone)
    }

    private inner class Run(val policy: Policy?, ledger: Ledger, val now: Long, val deadline: Long) {
        val entries = LinkedHashMap(ledger.entries)
        val items = ArrayList<ReportItem>()
        val knox: String = try { host.knoxState() } catch (e: Throwable) { "absent" }
        var needFull = false
        /** The SSIDs of the policy's networks in place this pass (a removal never leaves the device without one). */
        val wifiSettled = HashSet<String>()
        var undoLeft = 0
        var undoDone = 0

        fun timeUp() = clock() >= deadline

        /** Not reached in time: pending, the previous outcome kept. */
        fun skip(key: String) {
            val prev = entries[key]
            items += ReportItem(key, PolicyStates.PENDING, prev?.code ?: PolicyCodes.OK, prev?.detail)
        }

        fun report(key: String, o: ItemOutcome) {
            items += ReportItem(key, o.state, o.code, o.detail)
        }

        /** Runs one item, its failures mapped (SecurityException: [onSecurity]; anything else: error/internal). */
        inline fun guarded(onSecurity: ItemOutcome, block: () -> ItemOutcome): ItemOutcome = try {
            block()
        } catch (e: SecurityException) {
            onSecurity
        } catch (e: Throwable) {
            log.warn("policy item failed: ${e.javaClass.simpleName}")
            ItemOutcome.error(PolicyCodes.INTERNAL, e.javaClass.simpleName)
        }

        /**
         * Keeps the outcome in the ledger: a settled item keeps its digest (and [checked] its time). [keepDigest] false:
         * the digest is forgotten even so (an outcome that must be tried again, such as a foreign Wi-Fi profile).
         */
        fun record(key: String, digest: String, o: ItemOutcome, checked: Boolean, keepDigest: Boolean = o.settled,
            update: (LedgerEntry) -> LedgerEntry = { it }) {
            val prev = entries[key]
            val base = prev ?: LedgerEntry("", 0, o.state, o.code)
            val next = base.copy(
                digest = if (keepDigest) digest else if (o.settled) "" else base.digest.takeIf { it == digest } ?: "",
                checkedAt = if (keepDigest && checked) now else base.checkedAt,
                state = o.state, code = o.code, detail = o.detail,
            )
            entries[key] = update(next)
            report(key, o)
        }

        fun knoxGate(): ItemOutcome? = when (knox) {
            KnoxLicence.LICENSED -> null
            KnoxLicence.ABSENT -> ItemOutcome.unsupported()
            else -> ItemOutcome.pendingLicence()
        }

        /** The ledger already holds [digest] for [key] and was checked less than a day ago. */
        fun fresh(key: String, digest: String): Boolean {
            val e = entries[key] ?: return false
            return e.digest.isNotEmpty() && e.digest == digest && now - e.checkedAt in 0 until DAY_S
        }

        fun same(key: String, digest: String): Boolean = entries[key]?.digest?.let { it.isNotEmpty() && it == digest } == true

        // ------------------------------------------------------------------

        fun apply(p: Policy, kioskSuspended: Boolean) {
            for (s in p.dpm) if (timeUp()) skip(s.key) else dpm(s)
            val settings = p.knox.filter { it.field != SETTINGS_CHANGES }
            for (s in settings) if (timeUp()) skip(s.key) else knoxSetting(s, p)
            for (c in p.certs) if (timeUp()) skip(c.key) else cert(c)
            for (w in p.wifi) if (timeUp()) skip(w.key) else wifi(w)
            for (r in p.wifiRemove) if (timeUp()) skip(r.key) else wifiRemove(r)
            for (f in p.files.sortedBy { if (it.inline != null) 0 else 1 }) if (timeUp()) skip(f.key) else file(f)
            // A kiosk kept from the previous policy (its key withheld: Policy.keepingKioskOf) stays as applied and follows a
            // suspension, without a ledger change; the key is reported below as undeliverable or unreadable.
            p.kiosk?.let { k ->
                when {
                    p.kioskWithheld -> guarded(ItemOutcome.error(PolicyCodes.INTERNAL)) { host.kioskApply(k, kioskSuspended) }
                    timeUp() -> skip(k.key)
                    else -> kiosk(k, kioskSuspended)
                }
            }
            p.knox.firstOrNull { it.field == SETTINGS_CHANGES }?.let { s -> if (timeUp()) skip(s.key) else knoxSetting(s, p) }
            for (d in p.dropped) items += ReportItem(d.key, PolicyStates.ERROR, d.code)
            for (k in p.undeliverable) items += ReportItem(k, PolicyStates.ERROR, PolicyCodes.UNDELIVERABLE)
            for (k in p.withheld) items += ReportItem(k, PolicyStates.PENDING, PolicyCodes.WIPE_WITHHELD)
            for (k in p.invalidKeys) items += ReportItem(k, PolicyStates.ERROR, PolicyCodes.INVALID_ITEM)
            val invalid = p.invalidKeys.size + p.invalidUnkeyed
            if (invalid > 0) items += ReportItem(POLICY_KEY, PolicyStates.ERROR, PolicyCodes.INVALID_ITEM, "$invalid")
        }

        fun dpm(s: Policy.Setting) {
            val spec = Policy.DPM_FIELDS[s.field] ?: return report(s.key, ItemOutcome.error(PolicyCodes.INVALID_ITEM))
            var read = false
            var o = guarded(ItemOutcome.pending(PolicyCodes.ADMIN_POLICY_MISSING)) {
                when {
                    !host.adminActive() -> ItemOutcome.error(PolicyCodes.ADMIN_INACTIVE)
                    !host.dpmGranted(s.field) -> ItemOutcome.pending(PolicyCodes.ADMIN_POLICY_MISSING)
                    spec.checkOnly -> host.dpmApply(s.field, s.value).also { read = true }
                    same(s.key, s.digest) && host.dpmRead(s.field).let { v -> v != null && sameValue(v, s.value) }.also { read = it } ->
                        ItemOutcome.compliant(PolicyCodes.UNCHANGED)
                    fresh(s.key, s.digest) && host.dpmRead(s.field) == null -> ItemOutcome.compliant(PolicyCodes.UNCHANGED)
                    else -> host.dpmApply(s.field, s.value).also { read = true }
                }
            }
            if (s.field == "passwordQuality" && o.settled && s.value != "unspecified" && guardedBool { host.passwordSufficient() } == false) {
                o = ItemOutcome.nonCompliant(PolicyCodes.PASSWORD_INSUFFICIENT)
            }
            record(s.key, s.digest, o, read)
        }

        fun knoxSetting(s: Policy.Setting, p: Policy) {
            var called = false
            val o = knoxGate() ?: reservedPackage(s, p) ?: run {
                if (s.field == SETTINGS_CHANGES && s.value == false) {
                    val homeOk = p.kiosk?.enabled != true || guardedBool { host.homeIsAgent() } == true
                    if (guardedBool { host.storageWritable() } != true || !homeOk) return@run ItemOutcome.pending(PolicyCodes.BLOCKED_BY_ORDER)
                }
                guarded(ItemOutcome.error(PolicyCodes.KNOX_REFUSED)) {
                    val v = if (same(s.key, s.digest)) host.knoxRead(s.field) else null
                    when {
                        v != null && sameValue(v, s.value) -> ItemOutcome.compliant(PolicyCodes.UNCHANGED)
                        v == null && fresh(s.key, s.digest) -> ItemOutcome.compliant(PolicyCodes.UNCHANGED)
                        else -> { called = true; host.knoxApply(s.field, s.value, entries[s.key]?.value) }
                    }
                }
            }
            val applied = o.settled && o.code != PolicyCodes.UNCHANGED
            record(s.key, s.digest, o, checked = applied) { e ->
                when {
                    s.field !in Policy.KNOX_LISTS -> e
                    o.settled -> e.copy(value = s.value)
                    // A list applied in part (one package refused): the packages before it are blocked already, so the
                    // value keeps everything this apply may have touched, and the undo (or the next apply) releases them.
                    called -> e.copy(value = packageUnion(e.value, s.value))
                    else -> e
                }
            }
        }

        fun packageUnion(a: Any?, b: Any?): List<String> =
            ((a as? List<*>).orEmpty() + (b as? List<*>).orEmpty()).filterIsInstance<String>().distinct()

        /** B9, defence in depth: a Knox list never names the agent, the system, Knox, Settings outside a kiosk, a tile. */
        fun reservedPackage(s: Policy.Setting, p: Policy): ItemOutcome? {
            if (s.field !in Policy.KNOX_LISTS) return null
            val kioskOn = p.kiosk?.enabled == true
            val tiles = p.kiosk?.tiles.orEmpty().mapNotNull { it.action.pkg?.lowercase() }.toSet()
            val bad = (s.value as? List<*>).orEmpty().filterIsInstance<String>().firstOrNull { pkg ->
                val l = pkg.lowercase()
                PathRules.isOwnPackage(l) || l == "android" || l.startsWith("com.sec.enterprise.knox") || l.startsWith("com.samsung.android.knox") ||
                    (l == "com.android.settings" && !kioskOn) || (s.field == "disabledApps" && l in tiles)
            } ?: return null
            return ItemOutcome.error(PolicyCodes.INVALID_ITEM, "package_reserved $bad")
        }

        fun cert(c: Policy.Cert) {
            val o = knoxGate() ?: if (fresh(c.key, c.digest)) ItemOutcome.compliant(PolicyCodes.UNCHANGED)
            else guarded(ItemOutcome.error(PolicyCodes.KNOX_REFUSED)) { host.knoxCertInstall(c.id, c.name, c.pem) }
            record(c.key, c.digest, o, checked = o.code != PolicyCodes.UNCHANGED) { e -> if (o.settled) e.copy(value = c.name) else e }
        }

        fun wifi(w: Policy.Wifi) {
            var checked = false
            var applied = false
            // C4: a network the agent created through WifiManager before the licence is created again through Knox once
            // it is licensed (once: the ledger then says how it went).
            val via = entries[w.key]?.value as? String
            val knoxRedo = knox == KnoxLicence.LICENSED && entries[w.key] != null && via != WIFI_VIA_KNOX && via != WIFI_VIA_LICENSED_FALLBACK
            var o = guarded(ItemOutcome.error(PolicyCodes.INTERNAL, "SecurityException")) {
                val present = if (same(w.key, w.digest) && !knoxRedo) host.wifiPresent(w) else false
                when {
                    present == true -> ItemOutcome.compliant(PolicyCodes.UNCHANGED).also { checked = true }
                    present == null && !knoxRedo && fresh(w.key, w.digest) -> ItemOutcome.compliant(PolicyCodes.UNCHANGED)
                    !w.hasSecrets -> {
                        // The sealed copy is lost (key store): the secret comes again with a full configuration.
                        needFull = true
                        ItemOutcome.pending(PolicyCodes.UNDELIVERABLE, "secrets_missing")
                    }
                    else -> host.wifiApply(w).also { checked = true; applied = true }
                }
            }
            if (o.state == PolicyStates.COMPLIANT) wifiSettled += w.ssid
            val method = when {
                !applied || !o.settled -> via
                o.detail == WIFI_VIA_KNOX -> WIFI_VIA_KNOX
                knox == KnoxLicence.LICENSED -> WIFI_VIA_LICENSED_FALLBACK
                else -> WIFI_VIA_MANAGER
            }
            var preferAt = entries[w.key]?.preferAt ?: 0
            if (o.settled && w.autoConnect && w.preferOver.isNotEmpty() && (now - preferAt >= PREFER_INTERVAL_S || preferAt > now)) {
                val p = try { host.wifiPrefer(w) } catch (e: Throwable) { null }
                if (p?.code == PolicyCodes.WIFI_PREFERRED) {
                    preferAt = now
                    o = o.copy(detail = PolicyCodes.WIFI_PREFERRED)
                } else if (p?.detail != null) {
                    // The scan cannot be read (location permission, location off): said, so the status screen asks.
                    o = o.copy(detail = p.detail)
                }
            }
            // A foreign profile (a same-SSID network of another app) is never taken as applied: the next pass looks again,
            // since the read-back cannot tell it from the agent's own network.
            record(w.key, w.digest, o, checked, keepDigest = o.settled && o.code != PolicyCodes.WIFI_FOREIGN_PROFILE) {
                it.copy(preferAt = preferAt, value = method)
            }
        }

        fun wifiRemove(r: Policy.WifiRemove) {
            val o = knoxGate() ?: if (same(r.key, r.digest)) ItemOutcome.compliant(PolicyCodes.UNCHANGED)
            else guarded(ItemOutcome.error(PolicyCodes.KNOX_REFUSED)) {
                // Never the network in use while no managed network of the policy is in place (it may be the device's
                // only way to the server): tried again at the next pass.
                val connected = host.wifiConnectedSsid()
                if (connected != null && connected == r.ssid && wifiSettled.isEmpty()) ItemOutcome.pending(PolicyCodes.BLOCKED_BY_ORDER, "kept_connected")
                else host.knoxWifiRemove(r.ssid)
            }
            record(r.key, r.digest, o, checked = true, keepDigest = o.state == PolicyStates.COMPLIANT)
        }

        fun file(f: Policy.FileItem) {
            val prev = entries[f.key]
            if (guardedBool { host.storageWritable() } != true) {
                return record(f.key, f.digest, ItemOutcome.pending(PolicyCodes.PERMISSION_MISSING), false)
            }
            val src = if (f.inline != null) {
                if (Sha256.hex(f.inline) != f.inlineSha256) return record(f.key, f.digest, ItemOutcome.error(PolicyCodes.HASH_MISMATCH), false)
                blobs.put(f.sha256, f.inline) ?: return record(f.key, f.digest, ItemOutcome.pending(PolicyCodes.STORAGE_UNAVAILABLE), false)
            } else {
                blobs.file(f.sha256) ?: run {
                    val failure = blobs.failure(f.sha256) ?: PolicyCodes.DOWNLOAD_LIMITED
                    val o = if (failure == PolicyCodes.DOWNLOAD_FAILED || failure == PolicyCodes.HASH_MISMATCH) ItemOutcome.error(failure)
                    else ItemOutcome.pending(failure)
                    return record(f.key, f.digest, o, false)
                }
            }
            val marks = LinkedHashMap<String, FileMark>()
            var worst: ItemOutcome? = null
            var worstIndex = -1
            var anyWritten = false
            for ((i, rel) in f.paths.withIndex()) {
                val mark = prev?.files?.get(rel)
                val o = guarded(ItemOutcome.pending(PolicyCodes.PERMISSION_MISSING)) {
                    if (!PathRules.isAllowed(rel, f.allowAppDataDir)) return@guarded ItemOutcome.error(PolicyCodes.PATH_FORBIDDEN)
                    val stat = host.fileState(rel)
                    if (f.overwrite == "if_absent" && stat != null) {
                        // Present before (or written by the agent once): never compared, never overwritten (C9).
                        marks[rel] = mark ?: FileMark(null, false, stat.size, stat.mtime, now)
                        return@guarded ItemOutcome.compliant(PolicyCodes.FILE_PRESENT)
                    }
                    if (stat != null && mark != null && mark.sha == f.sha256 && stat.size == mark.size && stat.mtime == mark.mtime &&
                        now - mark.checkedAt in 0 until DAY_S) {
                        marks[rel] = mark
                        return@guarded ItemOutcome.compliant(PolicyCodes.FILE_UNCHANGED)
                    }
                    if (stat != null && stat.size == f.size && host.fileSha(rel) == f.sha256) {
                        // Found identical: only a write of the agent makes it the agent's (C9), never this finding.
                        marks[rel] = FileMark(f.sha256, mark?.writtenByAgent ?: false, stat.size, stat.mtime, now)
                        return@guarded ItemOutcome.compliant(PolicyCodes.FILE_UNCHANGED)
                    }
                    val w = host.writeFile(rel, src, f.sha256, f.mediaScan)
                    if (w.settled) {
                        val after = host.fileState(rel)
                        marks[rel] = FileMark(f.sha256, true, after?.size ?: f.size, after?.mtime ?: -1, now)
                        anyWritten = true
                    } else if (mark != null) marks[rel] = mark
                    w
                }
                if (worst == null || rank(o) > rank(worst)) { worst = o; worstIndex = i }
            }
            // Paths the item no longer names: the item's onRemove applies to them.
            for ((rel, mark) in prev?.files.orEmpty()) if (rel !in f.paths) {
                if (!undoPath(rel, mark, f.onRemove)) marks[rel] = mark
            }
            val w = worst!!
            val o = when {
                w.state != PolicyStates.COMPLIANT -> w.copy(detail = listOfNotNull("path ${worstIndex + 1}", w.detail).joinToString(" "))
                anyWritten -> ItemOutcome.compliant(PolicyCodes.FILE_WRITTEN)
                else -> w
            }
            record(f.key, f.digest, o, checked = true) { it.copy(files = marks, onRemove = f.onRemove) }
        }

        fun kiosk(k: Policy.Kiosk, suspended: Boolean) {
            var tileIssue: ItemOutcome? = null
            for (t in k.tiles) {
                val refusal = KioskModel.actionRefusal(t.action)
                val issue = when {
                    refusal != null -> ItemOutcome.nonCompliant(refusal, t.id)
                    t.action.type == "app" && guardedBool { host.appLaunchable(t.action.pkg!!) } == false -> ItemOutcome.nonCompliant(PolicyCodes.APP_MISSING, t.id)
                    else -> null
                }
                if (issue != null && tileIssue == null) tileIssue = issue
            }
            val applied = guarded(ItemOutcome.error(PolicyCodes.INTERNAL, "SecurityException")) { host.kioskApply(k, suspended) }
            val o = if (k.enabled && tileIssue != null && rank(tileIssue) > rank(applied)) tileIssue else applied
            record(k.key, k.digest, o, checked = true)
        }

        // ---- Undo ----

        fun undo(p: Policy?) {
            val keep = if (p == null) emptySet() else (p.itemKeys + p.undeliverable + p.withheld + p.invalidKeys).toSet()
            for ((key, e) in entries.toList()) {
                if (key in keep) continue
                if (timeUp()) { undoLeft++; continue }
                val o = undoKey(key, e, p)
                // Only a compliant outcome is an undo done: anything else (a network another uid owns that removeNetwork
                // refuses, a file the storage cannot reach…) keeps the entry, tried again at the next pass.
                if (o.state != PolicyStates.COMPLIANT && o.state != PolicyStates.UNSUPPORTED) {
                    entries[key] = e.copy(state = o.state, code = o.code, detail = o.detail)
                    undoLeft++
                    report(key, o)
                } else {
                    entries.remove(key)
                    undoDone++
                    report(key, ItemOutcome.compliant(if (o.code == PolicyCodes.FILE_DELETED || o.code == PolicyCodes.WIFI_REMOVED) o.code else PolicyCodes.UNDONE, o.detail))
                }
            }
        }

        fun undoKey(key: String, e: LedgerEntry, p: Policy?): ItemOutcome = when {
            key.startsWith("agent:dpm.") -> {
                val field = key.removePrefix("agent:dpm.")
                val spec = Policy.DPM_FIELDS[field]
                when {
                    spec == null || spec.checkOnly -> ItemOutcome.compliant(PolicyCodes.UNDONE)
                    // Without the administrator its policies are void already.
                    guardedBool { host.adminActive() } == false -> ItemOutcome.compliant(PolicyCodes.UNDONE, PolicyCodes.ADMIN_INACTIVE)
                    else -> guarded(ItemOutcome.pending(PolicyCodes.ADMIN_POLICY_MISSING)) { host.dpmApply(field, spec.undo) }
                }
            }
            key.startsWith("agent:knox.") -> {
                val field = key.removePrefix("agent:knox.")
                knoxUndoGate() ?: guarded(ItemOutcome.error(PolicyCodes.KNOX_REFUSED)) { host.knoxApply(field, Policy.knoxUndo(field), e.value) }
            }
            key.startsWith("agent:cert[") -> {
                val id = key.removePrefix("agent:cert[").removeSuffix("]")
                knoxUndoGate() ?: guarded(ItemOutcome.error(PolicyCodes.KNOX_REFUSED)) { host.knoxCertRemove(id, e.value as? String ?: id) }
            }
            key.startsWith("agent:wifi.remove[") -> ItemOutcome.compliant(PolicyCodes.UNDONE)
            key.startsWith("agent:wifi[") -> guarded(ItemOutcome.error(PolicyCodes.INTERNAL, "SecurityException")) {
                // The other managed networks: those of the policy in place (§10.5: kept when it is the one in use and
                // no other managed network is configured).
                val managed = p?.wifi.orEmpty().filter { w -> entries[w.key]?.state == PolicyStates.COMPLIANT }.map { it.ssid }.toSet()
                host.wifiRemoveOwn(key.removePrefix("agent:wifi[").removeSuffix("]"), managed, e.value == WIFI_VIA_KNOX)
            }
            key.startsWith("agent:file[") -> {
                val due = e.onRemove == "delete" && e.files.values.any { it.writtenByAgent && it.sha != null }
                // A deletion due while the storage cannot be reached: kept for later (never taken for "changed by the user").
                if (due && guardedBool { host.storageWritable() } != true) ItemOutcome.pending(PolicyCodes.PERMISSION_MISSING)
                else {
                    var deleted = 0
                    var failed = false
                    for ((rel, mark) in e.files) {
                        if (undoPath(rel, mark, e.onRemove ?: "keep")) { if (e.onRemove == "delete" && mark.writtenByAgent) deleted++ } else failed = true
                    }
                    when {
                        failed -> ItemOutcome.error(PolicyCodes.IO_ERROR)
                        deleted > 0 -> ItemOutcome.compliant(PolicyCodes.FILE_DELETED)
                        else -> ItemOutcome.compliant(PolicyCodes.UNDONE)
                    }
                }
            }
            key == KIOSK_KEY -> guarded(ItemOutcome.error(PolicyCodes.INTERNAL, "SecurityException")) { host.kioskApply(null, false) }
            else -> ItemOutcome.compliant(PolicyCodes.UNDONE)
        }

        /** Knox gone (absent): nothing to undo any more; present without a licence: kept until it comes back. */
        fun knoxUndoGate(): ItemOutcome? = when (knox) {
            KnoxLicence.LICENSED -> null
            KnoxLicence.ABSENT -> ItemOutcome.compliant(PolicyCodes.UNDONE, PolicyCodes.KNOX_REQUIRED)
            else -> ItemOutcome.pendingLicence()
        }

        /**
         * The undo of one deposited path: deleted only with onRemove delete, written by the agent, and still holding
         * what it wrote (C9). False when a deletion was due and failed, or when the file is there but cannot be read
         * (tried again: an unreadable file is not a file the user changed).
         */
        fun undoPath(rel: String, mark: FileMark, onRemove: String): Boolean {
            if (onRemove != "delete" || !mark.writtenByAgent || mark.sha == null) return true
            return try {
                if (host.fileState(rel) == null) return true
                val sha = host.fileSha(rel) ?: return false
                if (sha != mark.sha) true else host.deleteFile(rel).state != PolicyStates.ERROR
            } catch (e: Throwable) {
                false
            }
        }

        inline fun guardedBool(block: () -> Boolean?): Boolean? = try { block() } catch (e: Throwable) { null }
    }

    companion object {
        const val POLICY_KEY = "agent:policy"
        const val KIOSK_KEY = "agent:kiosk"
        const val SETTINGS_CHANGES = "settingsChanges"
        const val DAY_S = 86_400L
        /** preferOver (C2): one switch per SSID every 6 hours at most. */
        const val PREFER_INTERVAL_S = 6 * 3_600L
        /** How a Wi-Fi item was last applied (its ledger value): through Knox WifiPolicy (C4), through WifiManager before
         *  the licence, or through WifiManager although licensed (the Knox path declined it: not tried again). */
        const val WIFI_VIA_KNOX = "knox"
        const val WIFI_VIA_MANAGER = "wifimanager"
        const val WIFI_VIA_LICENSED_FALLBACK = "wifimanager_licensed"

        /** Severity of an outcome: the worst path decides a file item, the worst of tiles and kiosk the kiosk. */
        fun rank(o: ItemOutcome): Int = when (o.state) {
            PolicyStates.COMPLIANT -> 0
            PolicyStates.UNSUPPORTED, PolicyStates.PENDING_LICENCE -> 1
            PolicyStates.PENDING -> 2
            PolicyStates.NON_COMPLIANT -> 3
            else -> 4
        }

        /** Two values of the wire (Boolean, Long or Int, String, lists compared as sets). */
        fun sameValue(a: Any?, b: Any?): Boolean = when {
            a is Number && b is Number -> a.toLong() == b.toLong()
            a is List<*> && b is List<*> -> a.map { it.toString() }.toSet() == b.map { it.toString() }.toSet()
            else -> a == b
        }
    }
}
