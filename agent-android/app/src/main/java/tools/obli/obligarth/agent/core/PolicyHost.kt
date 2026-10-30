package tools.obli.obligarth.agent.core

import java.io.File

/** The outcome of one item: a state of [PolicyStates.ITEM], a code of [PolicyCodes], a short detail (never a secret). */
data class ItemOutcome(val state: String, val code: String, val detail: String? = null) {
    companion object {
        fun compliant(code: String, detail: String? = null) = ItemOutcome(PolicyStates.COMPLIANT, code, detail)
        fun nonCompliant(code: String, detail: String? = null) = ItemOutcome(PolicyStates.NON_COMPLIANT, code, detail)
        fun pending(code: String, detail: String? = null) = ItemOutcome(PolicyStates.PENDING, code, detail)
        fun error(code: String, detail: String? = null) = ItemOutcome(PolicyStates.ERROR, code, detail)
        fun pendingLicence() = ItemOutcome(PolicyStates.PENDING_LICENCE, PolicyCodes.KNOX_REQUIRED)
        fun unsupported(code: String = PolicyCodes.KNOX_REQUIRED) = ItemOutcome(PolicyStates.UNSUPPORTED, code)
    }

    /** Applied or confirmed: the ledger keeps the item's digest. */
    val settled: Boolean get() = state == PolicyStates.COMPLIANT || state == PolicyStates.NON_COMPLIANT
}

/** Size and modification time of a deposited file (the cheap check between two full SHA-256 reads). */
data class FileStat(val size: Long, val mtime: Long)

/**
 * What the policy needs from the device (1.3.0, lot PONT-POL §10.2): the Android side (PolicyApplier) implements it,
 * the JVM tests use a fake. Every method has a default body (unsupported), so the existing fakes compile. Values read
 * back use the wire shapes: Boolean, Long, String, List<String>.
 */
interface PolicyHost {
    /** absent | present | licensed | license_error */
    fun knoxState(): String = "absent"

    // ---- Device administrator ----
    fun adminActive(): Boolean = true
    /** hasGrantedPolicy(admin, USES_POLICY_*) for the field (C1): an active admin does not hold newly declared policies. */
    fun dpmGranted(field: String): Boolean = true
    /** The value in force (null: cannot be read). */
    fun dpmRead(field: String): Any? = null
    fun dpmApply(field: String, value: Any?): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)
    /** isActivePasswordSufficient (null: unknown). */
    fun passwordSufficient(): Boolean? = null

    // ---- Knox (licensed only; the reconciler checks the licence first) ----
    /** The value in force (null: no getter known, the ledger decides). */
    fun knoxRead(field: String): Any? = null
    /** [previous]: the list the agent applied before for a list field (packages to enable again). */
    fun knoxApply(field: String, value: Any?, previous: Any? = null): ItemOutcome = ItemOutcome.unsupported()
    fun knoxCertInstall(id: String, name: String, pem: String): ItemOutcome = ItemOutcome.unsupported()
    fun knoxCertRemove(id: String, name: String): ItemOutcome = ItemOutcome.unsupported()
    fun knoxWifiRemove(ssid: String): ItemOutcome = ItemOutcome.unsupported()

    // ---- Wi-Fi ----
    /** The network is configured (by SSID and key management); null: cannot be read. */
    fun wifiPresent(w: Policy.Wifi): Boolean? = null
    fun wifiApply(w: Policy.Wifi): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)
    /** preferOver (C2): connected to one of them, the managed network seen, a switch asked; null when nothing done. */
    fun wifiPrefer(w: Policy.Wifi): ItemOutcome? = null
    /**
     * The undo of a network of the agent. [managed]: the SSIDs of the other managed networks in place (the one in use is
     * kept when none is configured); [viaKnox]: it was created through Knox WifiPolicy (removed through Knox).
     */
    fun wifiRemoveOwn(ssid: String, managed: Set<String> = emptySet(), viaKnox: Boolean = false): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)
    /** The SSID of the network in use, null when none or unreadable. */
    fun wifiConnectedSsid(): String? = null

    // ---- Files ----
    fun storageWritable(): Boolean = false
    fun fileState(rel: String): FileStat? = null
    fun fileSha(rel: String): String? = null
    fun writeFile(rel: String, src: File, sha: String, mediaScan: Boolean): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)
    fun deleteFile(rel: String): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)

    // ---- Kiosk ----
    fun homeIsAgent(): Boolean = false
    fun appLaunchable(pkg: String): Boolean = true
    /** null: the kiosk removed (alias disabled, Knox kiosk mode off). */
    fun kioskApply(k: Policy.Kiosk?, suspended: Boolean): ItemOutcome = ItemOutcome.unsupported(PolicyCodes.OK)
}

/** The policy files downloaded (GET /agent/v1/files/<sha>) and the inline files staged: by SHA-256. */
interface BlobCache {
    fun has(sha: String): Boolean
    fun file(sha: String): File?
    /** Stages inline bytes under their SHA-256 (the depositor copies from a file); null when it cannot be written. */
    fun put(sha: String, bytes: ByteArray): File?
    /** The last download failure of [sha] (download_limited, download_failed, hash_mismatch, storage_unavailable). */
    fun failure(sha: String): String? = null
}

/** A [BlobCache] in a directory (filesDir/policy/blobs on the device, a temporary directory in tests). */
class DirBlobCache(val dir: File) : BlobCache {
    private val failures = java.util.concurrent.ConcurrentHashMap<String, String>()

    override fun has(sha: String): Boolean = Hex.isSha256(sha) && File(dir, sha).isFile
    override fun file(sha: String): File? = if (has(sha)) File(dir, sha) else null

    override fun put(sha: String, bytes: ByteArray): File? {
        if (!Hex.isSha256(sha)) return null
        val target = File(dir, sha)
        if (target.isFile && target.length() == bytes.size.toLong()) return target
        return try {
            dir.mkdirs()
            val part = File(dir, "$sha.part")
            java.io.FileOutputStream(part).use { it.write(bytes); it.fd.sync() }
            if (!part.renameTo(target)) { part.delete(); null } else target
        } catch (e: java.io.IOException) {
            null
        }
    }

    override fun failure(sha: String): String? = failures[sha]
    fun setFailure(sha: String, code: String?) { if (code == null) failures.remove(sha) else failures[sha] = code }

    /** Removes what no SHA of [keep] names, and the .part files left for an hour (a download may be writing one). */
    fun clean(keep: Set<String>, nowMs: Long = System.currentTimeMillis()) {
        for (f in dir.listFiles().orEmpty()) {
            if (f.name.endsWith(".part")) { if (nowMs - f.lastModified() > 3_600_000L) f.delete() }
            else if (f.name !in keep) f.delete()
        }
    }
}
