package tools.obli.obligarth.agent.core

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/** What the platform reads from an archive (PackageManager.getPackageArchiveInfo on the device). */
data class ArchiveInfo(
    val packageName: String,
    val versionCode: Long,
    /** SHA-256 (hex) of the DER of each signing certificate. */
    val signerSha256: List<String>,
)

/**
 * Checks of a downloaded APK before installation (spec §8.6, RS-6). Pure: the
 * caller supplies the archive information read by the platform.
 */
object ApkChecks {
    /** Size and SHA-256 announced by the server; null when they match. */
    fun checkFile(file: File, expectedSize: Long, expectedSha256: String): String? {
        if (!file.isFile || file.length() != expectedSize) return Codes.HASH_MISMATCH
        return if (sha256(file) == expectedSha256.lowercase()) null else Codes.HASH_MISMATCH
    }

    fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return Hex.encode(md.digest())
    }

    /** Self update: own package, announced versionCode, strictly higher, single pinned signer. */
    fun checkAgentUpdate(
        info: ArchiveInfo?,
        ownPackage: String,
        currentVersionCode: Long,
        announcedVersionCode: Long,
        pinnedSigners: Set<String>,
    ): String? {
        if (info == null) return Codes.INSTALL_FAILED
        if (info.packageName != ownPackage) return Codes.PACKAGE_MISMATCH
        if (info.versionCode != announcedVersionCode) return Codes.PACKAGE_MISMATCH
        if (info.versionCode <= currentVersionCode) return Codes.VERSION_NOT_HIGHER
        if (info.signerSha256.size != 1) return Codes.SIGNER_MISMATCH
        if (info.signerSha256[0].lowercase() !in pinnedSigners) return Codes.SIGNER_MISMATCH
        return null
    }

    /** Client APK: announced package and versionCode, signer if declared, never the agent itself. */
    fun checkAppInstall(
        info: ArchiveInfo?,
        ownPackage: String,
        announcedPackage: String,
        announcedVersionCode: Long,
        announcedSigner: String?,
    ): String? {
        if (announcedPackage == ownPackage) return Codes.FORBIDDEN_PACKAGE
        if (info == null) return Codes.INSTALL_FAILED
        if (info.packageName == ownPackage) return Codes.FORBIDDEN_PACKAGE
        if (info.packageName != announcedPackage) return Codes.PACKAGE_MISMATCH
        if (info.versionCode != announcedVersionCode) return Codes.PACKAGE_MISMATCH
        if (announcedSigner != null) {
            if (info.signerSha256.size != 1 || info.signerSha256[0].lowercase() != announcedSigner.lowercase()) {
                return Codes.SIGNER_MISMATCH
            }
        }
        return null
    }

    private val KNOX_PREFIXES = listOf("com.samsung.android.knox", "com.sec.enterprise")

    /** RS-5: the agent, any system app, Samsung Knox packages are never uninstalled. */
    fun uninstallForbidden(packageName: String, ownPackage: String, isSystem: Boolean): Boolean =
        packageName == ownPackage || isSystem || KNOX_PREFIXES.any { packageName.startsWith(it) }
}
