package tools.obli.obligarth.agent

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.AgentRole
import tools.obli.obligarth.agent.core.ArchiveInfo
import tools.obli.obligarth.agent.core.InstallPath
import tools.obli.obligarth.agent.core.OwnerMode
import tools.obli.obligarth.agent.core.OwnerRelease
import tools.obli.obligarth.agent.core.ReleaseOutcome
import tools.obli.obligarth.agent.core.Codes
import tools.obli.obligarth.agent.core.DeviceActions
import tools.obli.obligarth.agent.core.InstallOutcome
import tools.obli.obligarth.agent.core.InstalledApk
import tools.obli.obligarth.agent.core.JarSigners
import tools.obli.obligarth.agent.core.PolicyHost
import tools.obli.obligarth.agent.core.Sha256
import java.io.File
import java.io.FileInputStream

/**
 * Device actions (spec §5.1, §8.5, §8.6, RS-4, RS-6): device administrator
 * first, Knox when licensed, the system installer prompt otherwise. Every
 * fallback without Knox is written to the local log.
 */
class AndroidActions(
    private val context: Context,
    private val facts: AndroidFacts,
    private val knox: KnoxBridge,
    private val log: AgentLog,
) : DeviceActions {
    private val pm: PackageManager = context.packageManager
    private val dpm get() = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    private fun knoxLicensed() = knox.state() == "licensed"

    /** 1.3.0 (lot PONT-POL): the device side of the policy, set once by AgentRuntime. */
    @Volatile var policyApplier: PolicyHost? = null

    override fun policyHost(): PolicyHost = policyApplier ?: super.policyHost()

    override fun isAdminActive(): Boolean = facts.adminActive()

    override fun lockNow(): String? {
        if (!isAdminActive()) return Codes.ADMIN_INACTIVE
        return try {
            dpm.lockNow()
            null
        } catch (e: SecurityException) {
            Codes.ADMIN_INACTIVE
        }
    }

    override fun wipe(external: Boolean): String? {
        if (knoxLicensed()) {
            val err = knox.wipe(external)
            if (err == null) return null
            log.warn("Knox wipe failed ($err), device administrator fallback")
        }
        if (!isAdminActive()) return Codes.ADMIN_INACTIVE
        return try {
            // Never WIPE_RESET_PROTECTION_DATA: device owner only (RS-4).
            dpm.wipeData(if (external) DevicePolicyManager.WIPE_EXTERNAL_STORAGE else 0)
            null
        } catch (e: SecurityException) {
            Codes.ADMIN_INACTIVE
        }
    }

    /** 1.4.0 (lot BANC §7.3): the owner of the device, set once by AgentRuntime. */
    @Volatile var owner: OwnerApplier? = null

    private fun role(): AgentRole = facts.role()

    /** §3.8: the owner restarts the device itself (API 24), Knox otherwise. */
    override fun canReboot(): Boolean = OwnerMode.canReboot(role(), Build.VERSION.SDK_INT, knoxLicensed())

    override fun reboot(): String? {
        if (role() == AgentRole.OWNER && owner?.reboot() == true) return null
        if (!knoxLicensed()) return Codes.KNOX_REQUIRED
        return knox.reboot("Obligarth")
    }

    override fun releaseOwnership(): ReleaseOutcome? = owner?.let { OwnerRelease.run(it, log) }

    override fun showMessage(commandId: String, title: String, text: String, fullscreen: Boolean): String? {
        Notifications.message(context, commandId, title, text)
        if (fullscreen) {
            // Allowed from the background under API 24 / targetSdk 25 (§5.1).
            context.startActivity(MessageActivity.intent(context, title, text).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
        return null
    }

    @SuppressLint("SetWorldReadable") // PAR-3: the Knox service reads the verified private file
    override fun install(commandId: String, apk: File, packageName: String, self: Boolean): InstallOutcome {
        // 1.4.0 (lot BANC §7.3): the owner commits the session without a prompt; an administrator on Android 15+ never
        // tries Knox (refused there, knox_restricted); otherwise the order of 1.3.0.
        val plan = OwnerMode.installPath(role(), Build.VERSION.SDK_INT, knoxLicensed())
        if (plan.path == InstallPath.OWNER_SESSION) {
            return try {
                sessionInstall(commandId, apk, packageName)
                log.info("owner: silent install of $packageName")
                InstallOutcome.Pending
            } catch (e: Exception) {
                log.warn("owner installer session: ${e.javaClass.simpleName}: ${e.message}")
                InstallOutcome.Failed(Codes.INSTALL_FAILED, e.message)
            }
        }
        plan.note?.let { log.info("install of $packageName: $it, installer prompt") }
        if (plan.path == InstallPath.KNOX) {
            // The system service reads the file: made readable, directory included (PAR-3).
            apk.setReadable(true, false)
            apk.parentFile?.setReadable(true, false)
            apk.parentFile?.setExecutable(true, false)
            val update = self || installedVersion(packageName) != null
            val err = knox.install(apk.absolutePath, update)
            if (err == null) return InstallOutcome.Done
            log.warn("Knox install failed ($err): installer prompt fallback")
        } else if (plan.note == null) {
            log.info("no Knox licence: installer prompt for $packageName")
        }
        return try {
            sessionInstall(commandId, apk, packageName)
            InstallOutcome.Pending
        } catch (e: Exception) {
            log.warn("installer session: ${e.javaClass.simpleName}: ${e.message}")
            InstallOutcome.Failed(Codes.INSTALL_FAILED, e.message)
        }
    }

    private fun sessionInstall(commandId: String, apk: File, packageName: String) {
        val installer = pm.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(packageName)
        params.setSize(apk.length())
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("base.apk", 0, apk.length()).use { out ->
                FileInputStream(apk).use { it.copyTo(out, 64 * 1024) }
                session.fsync(out)
            }
            session.commit(InstallStatusReceiver.sender(context, commandId))
        }
    }

    override fun uninstall(commandId: String, packageName: String): InstallOutcome {
        // Same paths as install: the owner's request is silent, Knox only where it is allowed.
        val plan = OwnerMode.installPath(role(), Build.VERSION.SDK_INT, knoxLicensed())
        if (plan.path == InstallPath.KNOX) {
            val err = knox.uninstall(packageName)
            if (err == null) return InstallOutcome.Done
            log.warn("Knox uninstall failed ($err): prompt fallback")
        }
        return try {
            pm.packageInstaller.uninstall(packageName, InstallStatusReceiver.sender(context, commandId))
            InstallOutcome.Pending
        } catch (e: Exception) {
            InstallOutcome.Failed(Codes.INSTALL_FAILED, e.message)
        }
    }

    @Suppress("DEPRECATION")
    override fun installedVersion(packageName: String): Long? = try {
        val p = pm.getPackageInfo(packageName, 0)
        if (Build.VERSION.SDK_INT >= 28) p.longVersionCode else p.versionCode.toLong()
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    override fun isSystemPackage(packageName: String): Boolean = try {
        val flags = pm.getApplicationInfo(packageName, 0).flags
        (flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    override fun installedSigners(packageName: String): List<String>? = try {
        pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures?.map { Sha256.hex(it.toByteArray()) }
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    @Suppress("DEPRECATION")
    override fun inspectArchive(apk: File): ArchiveInfo? {
        val info = pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNATURES) ?: return null
        val versionCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
        var signers = info.signatures?.map { Sha256.hex(it.toByteArray()) }.orEmpty()
        if (signers.isEmpty()) {
            // Some Android 7 builds return no signature for an archive: read the v1 signature (RS-10).
            signers = JarSigners.signerSha256(apk) ?: emptyList()
        }
        return ArchiveInfo(info.packageName, versionCode, signers)
    }

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    override fun installedApk(packageName: String): InstalledApk? = try {
        val p = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        val ai = p.applicationInfo
        val file = ai?.sourceDir?.let { File(it) }
        if (ai == null || file == null || !file.isFile || !file.canRead() || !ai.splitSourceDirs.isNullOrEmpty()) null
        else InstalledApk(
            file,
            if (Build.VERSION.SDK_INT >= 28) p.longVersionCode else p.versionCode.toLong(),
            p.versionName,
            p.signatures?.map { Sha256.hex(it.toByteArray()) }.orEmpty(),
        )
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    companion object {
        fun mutableFlag(): Int = if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
    }
}
