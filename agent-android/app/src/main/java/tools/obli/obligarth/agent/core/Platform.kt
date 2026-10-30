package tools.obli.obligarth.agent.core

import java.io.File
import java.io.IOException

/** The agent's own key (Keystore on the device, a software key in tests). */
interface AgentSigner {
    /** SPKI DER of the public key. */
    fun spki(): ByteArray
    fun sign(data: ByteArray): ByteArray
    /** hardware | software | unknown */
    val storage: String
    /** Erases the key (signed agentRevoked only). */
    fun erase()
}

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray?,
    /** When set, a 200 body is streamed into this file instead of memory. */
    val downloadTo: File? = null,
    val maxDownloadBytes: Long = 0,
    /** Connect and read time-out each, milliseconds. */
    val timeoutMs: Int = 30_000,
)

class HttpResponse(
    val status: Int,
    /** Header names in lower case. */
    val headers: Map<String, String>,
    val body: ByteArray,
    /** SHA-256 of the streamed file when [HttpRequest.downloadTo] was used and the status is 200. */
    val downloadedSha256: String? = null,
) {
    fun header(name: String): String? = headers[name.lowercase()]
}

interface Transport {
    @Throws(IOException::class)
    fun exchange(request: HttpRequest): HttpResponse
}

interface AgentLog {
    fun info(message: String)
    fun warn(message: String)

    object None : AgentLog {
        override fun info(message: String) {}
        override fun warn(message: String) {}
    }
}

/** Facts read from the device (spec §4.4, §4.5, §4.6, §8.7). Values are JSON-ready maps. */
interface DeviceFacts {
    /** The `device` object of /enroll and /inventory. */
    fun device(): Map<String, Any?>
    /** The `capabilities` object of /enroll. */
    fun capabilities(): Map<String, Any?>
    /** The `status` object of /poll. */
    fun status(): Map<String, Any?>
    /** The body of /inventory without collectedAt; [withSystemApps] false after a 413. */
    fun inventory(withSystemApps: Boolean): Map<String, Any?>
    /** Agent identity: package, versionCode, versionName, signerSha256. */
    fun agent(): Map<String, Any?>
    /**
     * The launcher icon of an installed package rendered as a square PNG of about [sizePx] pixels (iconsWanted of the
     * server, §4.6): [IconRender.NoIcon] when the package declares none, null when it cannot be rendered (absent,
     * too large, out of memory). The default renders nothing (fakes written before 1.0.2).
     */
    fun icon(packageName: String, sizePx: Int): IconRender? = null
}

/** The rendering of an app icon. */
sealed class IconRender {
    class Png(val bytes: ByteArray) : IconRender()
    object NoIcon : IconRender()
}

sealed class InstallOutcome {
    /** Done silently (Knox). */
    object Done : InstallOutcome()
    /** A system prompt waits for the user; the result arrives later. */
    object Pending : InstallOutcome()
    data class Failed(val code: String, val detail: String? = null) : InstallOutcome()
}

/**
 * A remote assistance session from its opening to its end (1.1.0, P0-15 §0.1, §8; Android: RemoteSessions).
 * [None] refuses every session (unsupported) and shows nothing.
 */
interface RemoteHost {
    /** The command id of the session in progress (system dialog, /accept or stream), null when none. */
    fun activeCommand(): String?

    /**
     * Opens [request] (one session at a time): the opening told, the system dialog asked. Null when started: the
     * outcome comes later through AgentEngine.onRemoteOutcome. Otherwise the result code of the refusal.
     */
    fun open(commandId: String, request: Params.RemoteOpen): String?

    object None : RemoteHost {
        override fun activeCommand(): String? = null
        override fun open(commandId: String, request: Params.RemoteOpen): String = Codes.UNSUPPORTED
    }
}

/** What the agent can do on the device (Android framework and Knox). */
interface DeviceActions {
    fun isAdminActive(): Boolean
    /** null when done, else an error code of §5.3. */
    fun lockNow(): String?
    /** Never returns when it worked (the device is erased); returns an error code otherwise. */
    fun wipe(external: Boolean): String?
    fun canReboot(): Boolean
    fun reboot(): String?
    fun showMessage(commandId: String, title: String, text: String, fullscreen: Boolean): String?
    fun install(commandId: String, apk: File, packageName: String, self: Boolean): InstallOutcome
    fun uninstall(commandId: String, packageName: String): InstallOutcome
    /** versionCode of an installed package, null when absent. */
    fun installedVersion(packageName: String): Long?
    fun isSystemPackage(packageName: String): Boolean
    /** SHA-256 of the signing certificates of an installed package. */
    fun installedSigners(packageName: String): List<String>?
    fun inspectArchive(apk: File): ArchiveInfo?
    /** 1.2.0 (app.pull): the base APK of an installed package, null when absent or split (several APKs). */
    fun installedApk(packageName: String): InstalledApk? = null
}

/** The installed APK of a package (app.pull): its file (readable by any app up to Android 10) and its identity. */
data class InstalledApk(val file: File, val versionCode: Long, val versionName: String?, val signers: List<String>)
