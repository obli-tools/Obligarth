package tools.obli.obligarth.agent

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.MediaScannerConnection
import android.os.Environment
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.FileStat
import tools.obli.obligarth.agent.core.Hex
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.PolicyCodes
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest

/**
 * The files of the policy deposited in the external storage (1.3.0, lot PONT-POL §10.5). A device administrator
 * cannot grant itself WRITE_EXTERNAL_STORAGE (D1): asked once from the status screen, or granted by Knox when licensed.
 * Each write goes to <target>.obl-part, synced, then renamed; the canonical path must stay under the storage root
 * (the reconciler checked PathRules before).
 */
class FileDepositor(private val context: Context, private val knox: KnoxBridge, private val log: AgentLog) {
    private val root: File get() = Environment.getExternalStorageDirectory()
    @Volatile private var knoxGrantTriedAt = 0L

    fun permissionGranted(): Boolean =
        context.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    /** The permission held and the storage mounted; with Knox licensed, the permission granted first (once an hour). */
    fun writable(): Boolean {
        if (!permissionGranted() && knox.state() == "licensed" && System.currentTimeMillis() - knoxGrantTriedAt > 3_600_000L) {
            knoxGrantTriedAt = System.currentTimeMillis()
            if (knox.grantRuntimePermissions(listOf(Manifest.permission.WRITE_EXTERNAL_STORAGE, Manifest.permission.READ_EXTERNAL_STORAGE))) {
                log.info("storage permission granted by Knox")
            }
        }
        return permissionGranted() && Environment.getExternalStorageState() == Environment.MEDIA_MOUNTED
    }

    /** The file of [rel], null when its canonical path leaves the storage root. */
    private fun target(rel: String): File? = try {
        val base = root.canonicalFile
        val f = File(base, rel).canonicalFile
        if (f.path.startsWith(base.path + File.separator)) f else null
    } catch (e: IOException) {
        null
    }

    fun state(rel: String): FileStat? = target(rel)?.takeIf { it.isFile }?.let { FileStat(it.length(), it.lastModified()) }

    fun sha(rel: String): String? {
        val f = target(rel)?.takeIf { it.isFile } ?: return null
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(f).use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    md.update(buf, 0, n)
                }
            }
            Hex.encode(md.digest())
        } catch (e: IOException) {
            null
        }
    }

    fun write(rel: String, src: File, sha: String, mediaScan: Boolean): ItemOutcome {
        if (Environment.getExternalStorageState() != Environment.MEDIA_MOUNTED) return ItemOutcome.pending(PolicyCodes.STORAGE_UNAVAILABLE)
        val dest = target(rel) ?: return ItemOutcome.error(PolicyCodes.PATH_FORBIDDEN)
        val part = File(dest.path + ".obl-part")
        return try {
            dest.parentFile?.mkdirs()
            val md = MessageDigest.getInstance("SHA-256")
            FileInputStream(src).use { input ->
                FileOutputStream(part).use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        md.update(buf, 0, n)
                    }
                    out.fd.sync()
                }
            }
            if (Hex.encode(md.digest()) != sha) {
                part.delete()
                return ItemOutcome.error(PolicyCodes.HASH_MISMATCH)
            }
            if (!part.renameTo(dest)) {
                dest.delete()
                if (!part.renameTo(dest)) { part.delete(); return ItemOutcome.error(PolicyCodes.IO_ERROR, "rename") }
            }
            if (mediaScan) {
                try { MediaScannerConnection.scanFile(context, arrayOf(dest.path), null, null) } catch (e: Exception) { }
            }
            ItemOutcome.compliant(PolicyCodes.FILE_WRITTEN)
        } catch (e: IOException) {
            part.delete()
            log.warn("policy file write: ${e.javaClass.simpleName}")
            ItemOutcome.error(PolicyCodes.IO_ERROR)
        }
    }

    fun delete(rel: String): ItemOutcome {
        val f = target(rel) ?: return ItemOutcome.error(PolicyCodes.PATH_FORBIDDEN)
        if (!f.exists()) return ItemOutcome.compliant(PolicyCodes.FILE_DELETED)
        return if (f.delete()) {
            try { MediaScannerConnection.scanFile(context, arrayOf(f.path), null, null) } catch (e: Exception) { }
            ItemOutcome.compliant(PolicyCodes.FILE_DELETED)
        } else ItemOutcome.error(PolicyCodes.IO_ERROR)
    }
}
