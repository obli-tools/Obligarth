package tools.obli.obligarth.agent

import android.Manifest
import android.annotation.SuppressLint
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import android.telephony.TelephonyManager
import tools.obli.obligarth.agent.core.DeviceFacts
import tools.obli.obligarth.agent.core.Sha256
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Identity, status and inventory read from the device (spec §4.4 to §4.6, §8.7).
 * Every unreadable value is null, never an error. No personal data: no
 * accounts, contacts or location.
 */
class AndroidFacts(private val context: Context, private val knox: KnoxBridge) : DeviceFacts {
    private val pm: PackageManager = context.packageManager

    fun adminComponent() = ComponentName(context, AgentAdminReceiver::class.java)

    fun adminActive(): Boolean = try {
        (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).isAdminActive(adminComponent())
    } catch (e: Exception) {
        false
    }

    @Suppress("DEPRECATION")
    fun ownPackageInfo(flags: Int = 0): PackageInfo = pm.getPackageInfo(context.packageName, flags)

    @Suppress("DEPRECATION")
    fun versionCode(): Long = ownPackageInfo().versionCode.toLong()

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    fun ownSignerSha256(): List<String> = try {
        ownPackageInfo(PackageManager.GET_SIGNATURES).signatures.orEmpty().map { Sha256.hex(it.toByteArray()) }
    } catch (e: Exception) {
        emptyList()
    }

    override fun agent(): Map<String, Any?> {
        val info = ownPackageInfo()
        return linkedMapOf(
            "package" to context.packageName,
            "versionCode" to versionCode(),
            "versionName" to (info.versionName ?: ""),
            "signerSha256" to ownSignerSha256().firstOrNull(),
        )
    }

    @SuppressLint("HardwareIds")
    @Suppress("DEPRECATION")
    override fun device(): Map<String, Any?> = linkedMapOf(
        "manufacturer" to Build.MANUFACTURER,
        "brand" to Build.BRAND,
        "model" to Build.MODEL,
        "device" to Build.DEVICE,
        "androidId" to safe { Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) },
        // Readable under targetSdk 25 (PB8).
        "serial" to Build.SERIAL?.takeIf { it.isNotBlank() && it != Build.UNKNOWN },
        "samsungSerial" to (systemProperty("ril.serialnumber") ?: knox.serialNumber()),
        "imeis" to imeis(),
        "apiLevel" to Build.VERSION.SDK_INT,
        "osVersion" to Build.VERSION.RELEASE,
        "securityPatch" to Build.VERSION.SECURITY_PATCH?.takeIf { it.isNotBlank() },
        "build" to Build.DISPLAY,
        "deviceName" to deviceName(),
    )

    override fun capabilities(): Map<String, Any?> {
        val (version, level) = knox.versionInfo()
        return linkedMapOf(
            "adminActive" to adminActive(),
            "knox" to linkedMapOf("state" to knox.state(), "version" to version, "mdmApiLevel" to level),
        )
    }

    override fun status(): Map<String, Any?> {
        val battery = battery()
        return linkedMapOf(
            "adminActive" to adminActive(),
            "knoxState" to knox.state(),
            "batteryLevel" to battery["level"],
            "charging" to battery["charging"],
            "storageFreeBytes" to storage().second,
            "network" to network().let { linkedMapOf("type" to it["type"], "ip" to it["ip"]) },
            "uptimeSeconds" to SystemClock.elapsedRealtime() / 1000,
        )
    }

    override fun inventory(withSystemApps: Boolean): Map<String, Any?> {
        val (version, level) = knox.versionInfo()
        val (total, free) = storage()
        return linkedMapOf(
            "device" to device(),
            "storage" to linkedMapOf("totalBytes" to total, "freeBytes" to free),
            "battery" to battery(),
            "network" to network(),
            "knox" to linkedMapOf("state" to knox.state(), "version" to version, "mdmApiLevel" to level, "error" to knox.lastError()),
            "admin" to linkedMapOf("active" to adminActive(), "removable" to knox.adminRemovable()),
            "install" to linkedMapOf("unknownSources" to unknownSources()),
            "apps" to apps(withSystemApps),
        )
    }

    /** RC-7: Settings.Secure.INSTALL_NON_MARKET_APPS, null when unreadable. */
    @Suppress("DEPRECATION")
    private fun unknownSources(): Boolean? = try {
        Settings.Secure.getInt(context.contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS) == 1
    } catch (e: Exception) {
        null
    }

    @Suppress("DEPRECATION")
    private fun apps(withSystem: Boolean): List<Map<String, Any?>> {
        val list = try { pm.getInstalledPackages(0) } catch (e: Exception) { emptyList<PackageInfo>() }
        return list.asSequence().mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            val system = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            if (system && !withSystem) return@mapNotNull null
            linkedMapOf(
                "package" to p.packageName,
                "label" to safe { ai.loadLabel(pm).toString().take(200) },
                "versionName" to p.versionName?.take(64),
                "versionCode" to (if (Build.VERSION.SDK_INT >= 28) p.longVersionCode else p.versionCode.toLong()),
                "system" to system,
                "installer" to safe { pm.getInstallerPackageName(p.packageName) },
                "firstInstallAt" to p.firstInstallTime / 1000,
                "lastUpdateAt" to p.lastUpdateTime / 1000,
            )
        }.take(2000).toList()
    }

    private fun storage(): Pair<Long?, Long?> = try {
        val s = StatFs(Environment.getDataDirectory().path)
        s.totalBytes to s.availableBytes
    } catch (e: Exception) {
        null to null
    }

    private fun battery(): Map<String, Any?> {
        val i: Intent? = try { context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) } catch (e: Exception) { null }
        if (i == null) return linkedMapOf("level" to null, "charging" to null, "health" to null)
        val level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val status = i.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val health = when (i.getIntExtra(BatteryManager.EXTRA_HEALTH, -1)) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
            BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over_voltage"
            BatteryManager.BATTERY_HEALTH_COLD -> "cold"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
            else -> null
        }
        return linkedMapOf(
            "level" to (if (level >= 0 && scale > 0) level * 100 / scale else null),
            "charging" to (status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL),
            "health" to health,
        )
    }

    @Suppress("DEPRECATION")
    private fun network(): Map<String, Any?> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val info = try { cm?.activeNetworkInfo } catch (e: Exception) { null }
        val type = when {
            info == null || !info.isConnected -> "none"
            info.type == ConnectivityManager.TYPE_WIFI -> "wifi"
            info.type == ConnectivityManager.TYPE_MOBILE -> "cellular"
            info.type == ConnectivityManager.TYPE_ETHERNET -> "ethernet"
            else -> "other"
        }
        val operator = safe { (context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager)?.networkOperatorName?.takeIf { it.isNotBlank() } }
        return linkedMapOf("type" to type, "ip" to ipv4(), "mac" to null, "ssid" to null, "operator" to operator)
    }

    private fun ipv4(): String? = try {
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }?.hostAddress
    } catch (e: Exception) {
        null
    }

    @SuppressLint("MissingPermission", "HardwareIds")
    @Suppress("DEPRECATION")
    private fun imeis(): List<String> {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) return emptyList()
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return emptyList()
        val count = safe { tm.phoneCount } ?: 1
        return (0 until count).mapNotNull { slot -> safe { tm.getDeviceId(slot) }?.takeIf { it.isNotBlank() } }.distinct()
    }

    private fun deviceName(): String? =
        safe { Settings.Global.getString(context.contentResolver, "device_name") }?.takeIf { it.isNotBlank() }?.take(100)

    @SuppressLint("PrivateApi") // ril.serialnumber (Samsung serial, §8.7), null when unavailable
    private fun systemProperty(name: String): String? = try {
        Class.forName("android.os.SystemProperties").getMethod("get", String::class.java)
            .invoke(null, name)?.toString()?.trim()?.takeIf { it.isNotEmpty() && it != "unknown" }
    } catch (e: Throwable) {
        null
    }

    private inline fun <T> safe(block: () -> T?): T? = try { block() } catch (e: Throwable) { null }
}
