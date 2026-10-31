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
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.net.ConnectivityManager
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.SystemClock
import android.provider.Settings
import android.telephony.TelephonyManager
import tools.obli.obligarth.agent.core.AgentRole
import tools.obli.obligarth.agent.core.Bounds
import tools.obli.obligarth.agent.core.OwnerMode
import tools.obli.obligarth.agent.core.DeviceFacts
import tools.obli.obligarth.agent.core.IconRender
import tools.obli.obligarth.agent.core.Icons
import tools.obli.obligarth.agent.core.clip
import tools.obli.obligarth.agent.core.Sha256
import java.io.ByteArrayOutputStream
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

    /** 1.4.0 (lot BANC §7.2): the agent is the owner of the device (set by `dpm set-device-owner` at the bench). */
    override fun deviceOwner(): Boolean = try {
        (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).isDeviceOwnerApp(context.packageName)
    } catch (e: Exception) {
        false
    }

    fun role(): AgentRole = OwnerMode.roleOf(adminActive(), deviceOwner())

    /** 1.4.0 (§7.4): ADB enabled on the device (readable by any app), null when unreadable. */
    override fun adbEnabled(): Boolean? = try {
        Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED) == 1
    } catch (e: Exception) {
        null
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
    // Every value is bounded and shaped like the server's strict schema (DeviceFacts): one value out of
    // it fails the whole /enroll or /inventory (400), and an enrollment refused that way waits a day.
    override fun device(): Map<String, Any?> = linkedMapOf(
        "manufacturer" to Build.MANUFACTURER?.clip(64),
        "brand" to Build.BRAND?.clip(64),
        "model" to Build.MODEL?.clip(64),
        "device" to Build.DEVICE?.clip(64),
        "androidId" to safe { Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) }
            ?.takeIf { ANDROID_ID_RE.matches(it) },
        // Readable under targetSdk 25 (PB8) up to Android 9; the owner reads Build.getSerial() (1.4.0, §7.3).
        "serial" to serial()?.clip(64),
        "samsungSerial" to (systemProperty("ril.serialnumber") ?: knox.serialNumber())?.clip(64),
        "imeis" to imeis(),
        "apiLevel" to Build.VERSION.SDK_INT,
        "osVersion" to Build.VERSION.RELEASE?.clip(32),
        "securityPatch" to Build.VERSION.SECURITY_PATCH?.takeIf { PATCH_RE.matches(it) },
        "build" to Build.DISPLAY?.clip(128),
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
        // One query for the whole set: the packages with an activity in the launcher (null when unreadable).
        val launchable: Set<String>? = try {
            pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
                .mapNotNull { it.activityInfo?.packageName }.toSet()
        } catch (e: Exception) {
            null
        }
        return list.asSequence().mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            val system = (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
            if (system && !withSystem) return@mapNotNull null
            linkedMapOf(
                "package" to p.packageName,
                "label" to safe { ai.loadLabel(pm).toString().take(200) },
                "versionName" to p.versionName?.take(64),
                "versionCode" to (if (Build.VERSION.SDK_INT >= 28) p.longVersionCode else p.versionCode.toLong()).coerceAtLeast(0),
                "system" to system,
                "launchable" to launchable?.contains(p.packageName),
                "installer" to safe { pm.getInstallerPackageName(p.packageName) },
                "firstInstallAt" to p.firstInstallTime / 1000,
                "lastUpdateAt" to p.lastUpdateTime / 1000,
            )
        }.take(2000).toList()
    }

    /**
     * The launcher icon of a package as a square PNG (§4.6, 1.0.2): drawn on an ARGB bitmap of [sizePx] (an adaptive
     * icon included), compressed, tried again at [Icons.FALLBACK_PX] when larger than [Icons.MAX_PNG_BYTES]. NoIcon
     * when the package declares no icon; null when it cannot be rendered (absent package, too large, any error,
     * out of memory included).
     */
    override fun icon(packageName: String, sizePx: Int): IconRender? = try {
        val ai = pm.getApplicationInfo(packageName, 0)
        if (ai.icon == 0) IconRender.NoIcon else {
            val drawable = pm.getApplicationIcon(ai)
            (render(drawable, sizePx) ?: render(drawable, Icons.FALLBACK_PX))?.let { IconRender.Png(it) }
        }
    } catch (e: Throwable) {
        null
    }

    private fun render(drawable: Drawable, px: Int): ByteArray? {
        val bitmap = Bitmap.createBitmap(px, px, Bitmap.Config.ARGB_8888)
        try {
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, px, px)
            drawable.draw(canvas)
            val out = ByteArrayOutputStream()
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) return null
            return out.toByteArray().takeIf { it.size <= Icons.MAX_PNG_BYTES }
        } finally {
            bitmap.recycle()
        }
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

    /**
     * The serial number of the device (ro.serialno, the series ADB shows): Build.SERIAL, "unknown" from Android 10 under
     * targetSdk 25; the owner of the device reads Build.getSerial() (API 26) instead (1.4.0, §7.3).
     */
    @SuppressLint("MissingPermission", "HardwareIds")
    @Suppress("DEPRECATION")
    private fun serial(): String? {
        val owned = if (Build.VERSION.SDK_INT >= 26 && deviceOwner()) safe { Build.getSerial() } else null
        return (owned ?: Build.SERIAL)?.takeIf { it.isNotBlank() && it != Build.UNKNOWN }
    }

    @SuppressLint("MissingPermission", "HardwareIds")
    @Suppress("DEPRECATION")
    private fun imeis(): List<String> {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) return emptyList()
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager ?: return emptyList()
        val count = safe { tm.phoneCount } ?: 1
        // The owner reads getImei (API 26), the only way from Android 10 (1.4.0, §7.3); getDeviceId otherwise.
        val owner = Build.VERSION.SDK_INT >= 26 && deviceOwner()
        // IMEI digits only (a CDMA MEID, hexadecimal, is left out: the server schema takes 14 to 16 digits).
        return Bounds.imeis((0 until count).map { slot -> safe { if (owner) tm.getImei(slot) else tm.getDeviceId(slot) } })
    }

    private companion object {
        val ANDROID_ID_RE = Regex("^[0-9a-fA-F]{1,32}$")
        val PATCH_RE = Regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    }

    private fun deviceName(): String? =
        safe { Settings.Global.getString(context.contentResolver, "device_name") }?.takeIf { it.isNotBlank() }?.clip(100)

    @SuppressLint("PrivateApi") // ril.serialnumber (Samsung serial, §8.7), null when unavailable
    private fun systemProperty(name: String): String? = try {
        Class.forName("android.os.SystemProperties").getMethod("get", String::class.java)
            .invoke(null, name)?.toString()?.trim()?.takeIf { it.isNotEmpty() && it != "unknown" }
    } catch (e: Throwable) {
        null
    }

    private inline fun <T> safe(block: () -> T?): T? = try { block() } catch (e: Throwable) { null }
}
