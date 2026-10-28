package tools.obli.obligarth.agent.core

import java.util.concurrent.TimeUnit

// =============================================================================
// Remote assistance, the session on the device (P0-15 §0.1, §2, §8): the MSP model
// of Oblireach. Nobody on the device answers anything: at remote.open the device
// tells who opens the session and asks the system dialog of MediaProjection (never
// answered by the agent; 60 s without an answer: projection_denied), then /accept
// with the mode asked, the permanent notification all along, the end told. Pure
// JVM: the machine decides, the Android side (Remote.kt) shows and captures.
// =============================================================================

/** The durations of a session on the device (D14); shorter in tests. */
data class RemoteTimings(
    /** The system dialog of MediaProjection not answered (nobody there, "Don't show again" never ticked). */
    val projectionMs: Long = 60_000,
    /** From the projection granted to a usable answer of /accept (its HTTP time-outs and retries): then agent_error. */
    val acceptMs: Long = 120_000,
    /** The attach given up this long after the stream token expired (expiresIn of /accept), whatever the peer sends. */
    val attachGraceMs: Long = 15_000,
    /** The period of the checks (screen, deadlines). */
    val tickMs: Long = 1_000,
    /** Screen off this long during a live session: screen_off_timeout. */
    val screenOffMs: Long = 300_000,
    /** inactivity_warning this long before the end for inactivity (stream_idle.go). */
    val idleWarningMs: Long = 30_000,
    /** No H.264 output this long after the encoder started: the JPEG fallback. */
    val codecStallMs: Long = 5_000,
    /** A keepalive to the viewer when nothing else left for this long. */
    val keepaliveMs: Long = 30_000,
    /** The device ends a session itself this long after its maximum end (the server ends it first). */
    val maxGraceMs: Long = 30_000,
    /** How long the stream keeps sending the last control messages before it closes. */
    val flushMs: Long = 1_000,
)

/** The text the server filled (operator, organisation), as the notifications show it. */
object RemoteText {
    /**
     * Neutralises what could change how a text reads: control, format (direction marks and overrides, zero width
     * characters), line and paragraph separators become a space; spaces are collapsed; [max] UTF-16 units at most.
     */
    fun display(s: String, max: Int = 200): String {
        val sb = StringBuilder(s.length)
        var space = false
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            val neutral = when (Character.getType(cp)) {
                Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.LINE_SEPARATOR.toInt(),
                Character.PARAGRAPH_SEPARATOR.toInt(), Character.SPACE_SEPARATOR.toInt(), Character.SURROGATE.toInt(),
                Character.UNASSIGNED.toInt(), Character.PRIVATE_USE.toInt() -> true
                else -> Character.isWhitespace(cp)
            }
            if (neutral) {
                space = sb.isNotEmpty()
                continue
            }
            if (space) sb.append(' ')
            space = false
            sb.appendCodePoint(cp)
        }
        if (sb.length <= max) return sb.toString()
        var end = max - 1
        if (Character.isHighSurrogate(sb[end - 1])) end--
        return sb.substring(0, end) + "…"
    }

    /** A duration as h:mm:ss or m:ss (logs and tests; the device shows [durationParts] with their units). */
    fun duration(seconds: Long): String {
        val s = seconds.coerceAtLeast(0)
        val h = s / 3600
        val m = (s % 3600) / 60
        val r = s % 60
        return if (h > 0) "%d:%02d:%02d".format(h, m, r) else "%d:%02d".format(m, r)
    }

    /**
     * A duration as the units shown on the device (§8, the end of a session): hours and minutes past an hour, else
     * minutes and seconds, the zero ones left out ("12 min 30 s", "1 h 5 min", "7 s"), never a clock-like 12:30.
     */
    fun durationParts(seconds: Long): List<Pair<TimeUnit, Long>> {
        val s = seconds.coerceAtLeast(0)
        val h = s / 3600
        val m = (s % 3600) / 60
        val r = s % 60
        val out = ArrayList<Pair<TimeUnit, Long>>()
        if (h > 0) {
            out += TimeUnit.HOURS to h
            if (m > 0) out += TimeUnit.MINUTES to m
            return out
        }
        if (m > 0) out += TimeUnit.MINUTES to m
        if (r > 0 || m == 0L) out += TimeUnit.SECONDS to r
        return out
    }
}

/** Where a session stands on the device. */
enum class RemotePhase {
    /** remote.open arrived: the opening told, the system dialog of MediaProjection asked (60 s). */
    PROJECTION,
    /** The projection granted, the session's notification up: /accept, then the attach of the stream. */
    CONNECTING,
    /** The stream flows. */
    LIVE,
    ENDED,
}

/**
 * Why a session ends on the device side, and what the agent tells the server: the result of remote.open when /accept
 * was not answered yet ([resultCode], shared/src/mdm/legacyAgent.ts, mapped by server/src/remote/sessions.ts
 * RESULT_ENDS), and the reason of POST /end ([endReason], null when the server already knows: it ended or refused the
 * session, or ends it by its own deadline). The user of the device never ends nor refuses a session (§0.1).
 */
enum class RemoteEndCause(val resultCode: String, val endReason: String?) {
    /** The system dialog refused, or not answered in 60 s. */
    PROJECTION_DENIED(Codes.PROJECTION_DENIED, "projection_denied"),
    /**
     * /accept refused by the server with a refusal that closes the session there (or a session it does not know:
     * [AcceptOutcome.Refused.closesSession]); any other signed 4xx is an [AGENT_ERROR], told to /end.
     */
    SESSION_GONE(Codes.SESSION_GONE, null),
    /**
     * The system stopped the projection during the stream (another capture took it, or the system's own control on
     * the versions that have one): the viewer gets error projection_stopped, the server agent_error.
     */
    PROJECTION_STOPPED(Codes.INTERNAL, "agent_error"),
    /** Screen off for 5 min. */
    SCREEN_OFF_TIMEOUT(Codes.INTERNAL, "screen_off_timeout"),
    /** No activity of the viewer (inactivity_timeout sent to it; 'idle' is not a reason of /end). */
    IDLE(Codes.INTERNAL, null),
    /** Past the maximum end of the session (the server ends it there). */
    MAX_DURATION(Codes.INTERNAL, null),
    /** session_end received from the server. */
    SERVER_ENDED(Codes.INTERNAL, null),
    /** The server closed the stream. */
    STREAM_CLOSED(Codes.INTERNAL, null),
    /** The network, the protocol, the capture, the service, or /accept without a usable answer. */
    AGENT_ERROR(Codes.INTERNAL, "agent_error"),
}

/** What the session asks of the device and of the network, in order. */
sealed class RemoteEffect {
    /** The notification of the opening, and the system dialog of MediaProjection. */
    object Open : RemoteEffect()
    object CloseProjection : RemoteEffect()
    /** The foreground service and its permanent notification (then /accept). */
    object StartService : RemoteEffect()
    object CallAccept : RemoteEffect()
    object Attach : RemoteEffect()
    /** The result of remote.open. */
    data class Report(val status: ResultStatus, val code: String) : RemoteEffect()
    /** POST /agent/v1/remote/<id>/end. */
    data class CallEnd(val reason: String) : RemoteEffect()
    /** Over: the service stops, the end is told on the device. */
    data class Finish(val cause: RemoteEndCause) : RemoteEffect()
}

/**
 * The life of one session on the device (P0-15 §0.1 and §2 seen from the agent): never an image before the system
 * dialog is granted, and the agent never answers it. Times are monotonic milliseconds. Not thread-safe: the controller
 * calls it under its lock.
 */
class RemoteSessionMachine(private val timings: RemoteTimings, private val requestedMode: RemoteMode) {
    var phase: RemotePhase = RemotePhase.PROJECTION
        private set
    var endCause: RemoteEndCause? = null
        private set
    /** The result of remote.open is sent (acknowledged after /accept, or the failure). */
    var resultSent = false
        private set
    var liveSinceMs: Long? = null
        private set
    /** The system dialog is given up here; 0 until [start]. */
    private var projectionDeadline = 0L
    /** CONNECTING ends here (agent_error); 0 until the first tick in that phase arms it. */
    private var connectDeadline = 0L
    /** /accept was sent and is not answered yet. */
    private var acceptInFlight = false

    /** The mode told to /accept: always the mode asked, nobody on the device answers (§0.1, rule 1). */
    val consentedMode: RemoteMode get() = requestedMode

    val isEnded get() = phase == RemotePhase.ENDED

    /** remote.open taken: the opening told and the system dialog asked at once, whoever is in front of the device. */
    fun start(now: Long): List<RemoteEffect> {
        check(phase == RemotePhase.PROJECTION && projectionDeadline == 0L) { "started twice" }
        projectionDeadline = now + timings.projectionMs
        return listOf(RemoteEffect.Open)
    }

    /** The deadlines, about every second. */
    fun tick(now: Long): List<RemoteEffect> = when (phase) {
        RemotePhase.PROJECTION -> if (now >= projectionDeadline) end(RemoteEndCause.PROJECTION_DENIED) else emptyList()
        // /accept and the attach are bounded as a whole: a server or a proxy that answers slowly, or pings without a
        // hello, never holds the session (nor its notification, nor the next remote.open) beyond this.
        RemotePhase.CONNECTING -> when {
            connectDeadline == 0L -> { connectDeadline = now + timings.acceptMs; emptyList() }
            now >= connectDeadline -> end(RemoteEndCause.AGENT_ERROR)
            else -> emptyList()
        }
        else -> emptyList()
    }

    /** /accept gave a stream token: the attach must hold by [deadline] (its expiry plus a margin). */
    fun connectBy(deadline: Long) {
        if (phase == RemotePhase.CONNECTING) connectDeadline = deadline
    }

    fun projection(granted: Boolean): List<RemoteEffect> {
        if (phase != RemotePhase.PROJECTION) return emptyList()
        if (!granted) return end(RemoteEndCause.PROJECTION_DENIED)
        phase = RemotePhase.CONNECTING
        return listOf(RemoteEffect.CloseProjection, RemoteEffect.StartService)
    }

    /** The service and its notification are up: /accept, once. Notifications blocked stop nothing (§0.1, rule 2). */
    fun serviceUp(): List<RemoteEffect> {
        if (phase != RemotePhase.CONNECTING || acceptInFlight || resultSent) return emptyList()
        acceptInFlight = true
        return listOf(RemoteEffect.CallAccept)
    }

    sealed class AcceptAnswer {
        object Accepted : AcceptAnswer()
        object Refused : AcceptAnswer()
        object Failed : AcceptAnswer()
    }

    fun accepted(answer: AcceptAnswer): List<RemoteEffect> {
        acceptInFlight = false
        if (phase != RemotePhase.CONNECTING) return emptyList()
        return when (answer) {
            AcceptAnswer.Accepted -> {
                resultSent = true
                // A control asked on a device that cannot inject yet (Knox RemoteInjection, T8): the code says so.
                val code = if (requestedMode == RemoteMode.CONTROL) Codes.REMOTE_INJECTION_UNAVAILABLE else Codes.DONE
                listOf(RemoteEffect.Report(ResultStatus.ACKNOWLEDGED, code), RemoteEffect.Attach)
            }
            AcceptAnswer.Refused -> end(RemoteEndCause.SESSION_GONE)
            AcceptAnswer.Failed -> end(RemoteEndCause.AGENT_ERROR)
        }
    }

    fun attached(now: Long): Boolean {
        if (phase != RemotePhase.CONNECTING || !resultSent) return false
        phase = RemotePhase.LIVE
        liveSinceMs = now
        return true
    }

    /** The end, whatever its cause; nothing once ended. */
    fun end(cause: RemoteEndCause): List<RemoteEffect> {
        if (phase == RemotePhase.ENDED) return emptyList()
        val from = phase
        phase = RemotePhase.ENDED
        endCause = cause
        val out = ArrayList<RemoteEffect>()
        if (from == RemotePhase.PROJECTION) out += RemoteEffect.CloseProjection
        if (!resultSent) {
            resultSent = true
            out += RemoteEffect.Report(ResultStatus.ERROR, cause.resultCode)
        }
        cause.endReason?.let { out += RemoteEffect.CallEnd(it) }
        out += RemoteEffect.Finish(cause)
        return out
    }
}

/** What /accept tells of the device's notifications (informative since §0.1: a blocked notification stops nothing). */
data class IndicatorReading(
    /** areNotificationsEnabled() and the channel of the session not blocked. */
    val notificationsEnabled: Boolean,
    /** The border is on screen. */
    val overlayShown: Boolean,
)

// -----------------------------------------------------------------------------
// The deadlines of a live session: inactivity (stream_idle.go: 10 min, warned 30 s
// before), screen off (5 min), maximum duration.
// -----------------------------------------------------------------------------

sealed class LiveEvent {
    data class IdleWarning(val seconds: Int) : LiveEvent()
    object IdleTimeout : LiveEvent()
    object ScreenOffTimeout : LiveEvent()
    object MaxDuration : LiveEvent()
}

class LiveMonitor(
    startMs: Long,
    private val idleMs: Long,
    private val warnMs: Long,
    private val screenOffMs: Long,
    /** Monotonic end of the session at the latest. */
    private val deadlineMs: Long,
) {
    private var lastActivity = startMs
    private var warned = false
    private var unavailableSince: Long? = null

    /** A message of the viewer (keepalive, key request, bitrate, codec, quality, an admitted input). */
    fun activity(now: Long) {
        lastActivity = now
        warned = false
    }

    /** At most one event per tick, the most final first. */
    fun tick(now: Long, screenAvailable: Boolean): LiveEvent? {
        if (now >= deadlineMs) return LiveEvent.MaxDuration
        if (screenAvailable) unavailableSince = null else if (unavailableSince == null) unavailableSince = now
        unavailableSince?.let { if (now - it >= screenOffMs) return LiveEvent.ScreenOffTimeout }
        val idle = now - lastActivity
        if (idle >= idleMs) return LiveEvent.IdleTimeout
        if (!warned && idle >= idleMs - warnMs) {
            warned = true
            return LiveEvent.IdleWarning(((idleMs - idle + 999) / 1000).toInt())
        }
        return null
    }
}
