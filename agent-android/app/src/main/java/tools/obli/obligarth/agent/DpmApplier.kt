@file:Suppress("DEPRECATION") // the device-administrator and Wi-Fi APIs of Android 7 (targetSdk 25)

package tools.obli.obligarth.agent

import android.app.admin.DeviceAdminInfo
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.PolicyCodes

/**
 * The device-administrator settings of the policy (1.3.0, lot PONT-POL §2.4, §10.5) on API 24. A policy declared by a
 * newer version is not held by an administrator activated before it (C1): hasGrantedPolicy says so, the item stays
 * pending (admin_policy_missing) and the status screen offers to grant it (D12). Never setStorageEncryption, never
 * resetPassword (D11).
 */
class DpmApplier(private val context: Context, private val log: AgentLog) {
    private val dpm get() = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val admin = ComponentName(context, AgentAdminReceiver::class.java)
    private val prefs = context.getSharedPreferences("policy", Context.MODE_PRIVATE)

    fun active(): Boolean = try { dpm.isAdminActive(admin) } catch (e: Exception) { false }

    /** The USES_POLICY_* a field needs (null: none). */
    private fun usesPolicies(field: String): List<Int> = when (field) {
        "cameraDisabled" -> listOf(DeviceAdminInfo.USES_POLICY_DISABLE_CAMERA)
        "passwordQuality", "passwordMinLength", "passwordMinLetters", "passwordMinNumeric", "passwordMinSymbols",
        "passwordHistoryLength" -> listOf(DeviceAdminInfo.USES_POLICY_LIMIT_PASSWORD)
        "passwordExpirationDays" -> listOf(DeviceAdminInfo.USES_POLICY_EXPIRE_PASSWORD)
        "keyguardDisabledFeatures" -> listOf(DeviceAdminInfo.USES_POLICY_DISABLE_KEYGUARD_FEATURES)
        "maxTimeToLockSeconds" -> listOf(DeviceAdminInfo.USES_POLICY_FORCE_LOCK)
        "maxFailedPasswordsForWipe" -> listOf(DeviceAdminInfo.USES_POLICY_WATCH_LOGIN, DeviceAdminInfo.USES_POLICY_WIPE_DATA)
        "requireEncryption" -> listOf(USES_POLICY_ENCRYPTED_STORAGE)
        else -> emptyList()
    }

    fun granted(field: String): Boolean = try {
        usesPolicies(field).all { dpm.hasGrantedPolicy(admin, it) }
    } catch (e: Exception) {
        false
    }

    /** True when some field of the catalogue is declared but not held (the "Grant the new permissions" card). */
    fun anyPolicyMissing(fields: Collection<String>): Boolean = active() && fields.any { !granted(it) }

    fun read(field: String): Any? = try {
        when (field) {
            "cameraDisabled" -> dpm.getCameraDisabled(admin)
            "passwordQuality" -> QUALITIES.entries.firstOrNull { it.value == dpm.getPasswordQuality(admin) }?.key
            "passwordMinLength" -> dpm.getPasswordMinimumLength(admin).toLong()
            "passwordMinLetters" -> dpm.getPasswordMinimumLetters(admin).toLong()
            "passwordMinNumeric" -> dpm.getPasswordMinimumNumeric(admin).toLong()
            "passwordMinSymbols" -> dpm.getPasswordMinimumSymbols(admin).toLong()
            "passwordHistoryLength" -> dpm.getPasswordHistoryLength(admin).toLong()
            "passwordExpirationDays" -> dpm.getPasswordExpirationTimeout(admin) / DAY_MS
            "keyguardDisabledFeatures" -> dpm.getKeyguardDisabledFeatures(admin).let { flags -> KEYGUARD.filter { (flags and it.value) != 0 }.keys.sorted() }
            "maxTimeToLockSeconds" -> dpm.getMaximumTimeToLock(admin) / 1000
            "maxFailedPasswordsForWipe" -> dpm.getMaximumFailedPasswordsForWipe(admin).toLong()
            else -> null
        }
    } catch (e: SecurityException) {
        null
    }

    fun apply(field: String, value: Any?): ItemOutcome {
        if (!active()) return ItemOutcome.error(PolicyCodes.ADMIN_INACTIVE)
        val n = (value as? Number)?.toLong() ?: 0L
        when (field) {
            "cameraDisabled" -> dpm.setCameraDisabled(admin, value == true)
            "passwordQuality" -> dpm.setPasswordQuality(admin, QUALITIES[value as? String] ?: DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED)
            "passwordMinLength" -> dpm.setPasswordMinimumLength(admin, n.toInt())
            "passwordMinLetters" -> dpm.setPasswordMinimumLetters(admin, n.toInt())
            "passwordMinNumeric" -> dpm.setPasswordMinimumNumeric(admin, n.toInt())
            "passwordMinSymbols" -> dpm.setPasswordMinimumSymbols(admin, n.toInt())
            "passwordHistoryLength" -> dpm.setPasswordHistoryLength(admin, n.toInt())
            "passwordExpirationDays" -> dpm.setPasswordExpirationTimeout(admin, n * DAY_MS)
            "keyguardDisabledFeatures" -> dpm.setKeyguardDisabledFeatures(admin,
                (value as? List<*>).orEmpty().fold(0) { acc, f -> acc or (KEYGUARD[f as? String] ?: 0) })
            "maxTimeToLockSeconds" -> dpm.setMaximumTimeToLock(admin, n * 1000)
            "maxFailedPasswordsForWipe" -> dpm.setMaximumFailedPasswordsForWipe(admin, n.toInt())
            "requireEncryption" -> return encryption(value == true)
            "promptPasswordChange" -> return promptPasswordChange(value == true)
            else -> return ItemOutcome.error(PolicyCodes.INVALID_ITEM)
        }
        return ItemOutcome.compliant(PolicyCodes.APPLIED)
    }

    /** isActivePasswordSufficient: null when it cannot be asked (limit-password not held yet). */
    fun passwordSufficient(): Boolean? = try { dpm.isActivePasswordSufficient } catch (e: Exception) { null }

    /** Checked only (never set): ENCRYPTION_STATUS_ACTIVE or ACTIVE_PER_USER. */
    private fun encryption(required: Boolean): ItemOutcome {
        if (!required) return ItemOutcome.compliant(PolicyCodes.OK)
        val s = dpm.storageEncryptionStatus
        val ok = s == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || s == ENCRYPTION_STATUS_ACTIVE_PER_USER
        return if (ok) ItemOutcome.compliant(PolicyCodes.OK) else ItemOutcome.nonCompliant(PolicyCodes.ENCRYPTION_MISSING)
    }

    /** A notification that opens ACTION_SET_NEW_PASSWORD while the password is insufficient, once every 6 hours at most. */
    private fun promptPasswordChange(on: Boolean): ItemOutcome {
        if (!on || passwordSufficient() != false) return ItemOutcome.compliant(PolicyCodes.OK)
        val now = System.currentTimeMillis()
        val last = prefs.getLong(K_PROMPT_AT, 0L)
        if (last > now || now - last >= PROMPT_INTERVAL_MS) {
            prefs.edit().putLong(K_PROMPT_AT, now).apply()
            Notifications.passwordChange(context)
            log.info("password change prompted")
        }
        return ItemOutcome.nonCompliant(PolicyCodes.PASSWORD_INSUFFICIENT)
    }

    companion object {
        private const val DAY_MS = 86_400_000L
        private const val PROMPT_INTERVAL_MS = 6 * 3_600_000L
        private const val K_PROMPT_AT = "passwordPromptAt"
        /** DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER (API 24). */
        private const val ENCRYPTION_STATUS_ACTIVE_PER_USER = 5
        /** DeviceAdminInfo.USES_POLICY_ENCRYPTED_STORAGE (hidden in the SDK; the <encrypted-storage/> tag). */
        private const val USES_POLICY_ENCRYPTED_STORAGE = 7

        val QUALITIES = linkedMapOf(
            "unspecified" to DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED,
            "something" to DevicePolicyManager.PASSWORD_QUALITY_SOMETHING,
            "numeric" to DevicePolicyManager.PASSWORD_QUALITY_NUMERIC,
            "numeric_complex" to DevicePolicyManager.PASSWORD_QUALITY_NUMERIC_COMPLEX,
            "alphabetic" to DevicePolicyManager.PASSWORD_QUALITY_ALPHABETIC,
            "alphanumeric" to DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC,
            "complex" to DevicePolicyManager.PASSWORD_QUALITY_COMPLEX,
        )

        val KEYGUARD = linkedMapOf(
            "camera" to DevicePolicyManager.KEYGUARD_DISABLE_SECURE_CAMERA,
            "notifications" to DevicePolicyManager.KEYGUARD_DISABLE_SECURE_NOTIFICATIONS,
            "unredacted_notifications" to DevicePolicyManager.KEYGUARD_DISABLE_UNREDACTED_NOTIFICATIONS,
            "trust_agents" to DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS,
            "fingerprint" to DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT,
        )
    }
}
