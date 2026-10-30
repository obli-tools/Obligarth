package tools.obli.obligarth.agent.core

/**
 * The rules of the soft kiosk that need no Android (1.3.0, lot PONT-POL §10.2): the tile actions (mirror of the shared
 * normalizeIntentUri, isUnsafeIntentUri and isAgentTileUrl, B1), the exit PIN attempts and their lockout (D7), the
 * suspension.
 */
object KioskModel {
    const val MAX_FAILURES = 5
    const val LOCK_BASE_S = 300L
    const val LOCK_MAX_S = 3_600L
    const val PIN_EXIT_MINUTES = 15

    // ---- Tile actions ----

    /** An intent URI with its scheme in lower case ('Intent://' -> 'intent://'); null when it is not one. */
    fun normalizeIntentUri(uri: String?): String? {
        if (uri == null || uri.isEmpty() || uri.length > 2048) return null
        if (!uri.regionMatches(0, "intent:", 0, 7, ignoreCase = true)) return null
        return "intent:" + uri.substring(7)
    }

    /** intent:...#Intent;...;end without a control character. */
    fun isIntentWellFormed(uri: String?): Boolean {
        val n = normalizeIntentUri(uri) ?: return false
        return n.contains("#Intent;") && n.endsWith(";end") && n.none { it < ' ' || it == '\u007f' }
    }

    private val UNSAFE_SCHEME = Regex("[;#]scheme=(file|content)(;|$)")
    private val UNSAFE_DATA = Regex("^(//)?(file|content):")

    /**
     * Does an intent URI reach what a tile must never reach (case-insensitive)? The agent's package anywhere, a
     * selector, launch flags (set by the agent only), a browser fallback URL, a file or content data scheme.
     */
    fun isUnsafeIntentUri(uri: String): Boolean {
        val u = uri.lowercase()
        if (u.contains(PathRules.OWN_PACKAGE)) return true
        if (u.contains(";sel;") || u.contains("#intent;sel;")) return true
        if (u.contains("launchflags=")) return true
        if (u.contains("s.browser_fallback_url=")) return true
        if (UNSAFE_SCHEME.containsMatchIn(u)) return true
        val data = u.removePrefix("intent:").substringBefore('#')
        return UNSAFE_DATA.containsMatchIn(data)
    }

    private val TILE_URL = Regex("^https?://[^/\\s]+", RegexOption.IGNORE_CASE)

    /** An http or https URL of 2048 characters at most, without blank or control character. */
    fun isTileUrl(url: String?): Boolean =
        url != null && url.isNotEmpty() && url.length <= 2048 && url.none { it <= ' ' || it == '\u007f' } && TILE_URL.containsMatchIn(url)

    /** Null when the tile's action may run, else the report code (intent_invalid; app_missing is checked by the host). */
    fun actionRefusal(a: Policy.TileAction): String? = when (a.type) {
        "app" -> if (a.pkg == null || !CommandParser.isPackageName(a.pkg) || PathRules.isOwnPackage(a.pkg)) PolicyCodes.INTENT_INVALID else null
        "url" -> if (!isTileUrl(a.url) || (a.pkg != null && (PathRules.isOwnPackage(a.pkg) || !CommandParser.isPackageName(a.pkg)))) PolicyCodes.INTENT_INVALID else null
        "intent" -> {
            val n = normalizeIntentUri(a.uri)
            if (n == null || !isIntentWellFormed(n) || isUnsafeIntentUri(n)) PolicyCodes.INTENT_INVALID else null
        }
        else -> PolicyCodes.INTENT_INVALID
    }

    // ---- Exit PIN attempts (D7): 5 failures lock 5 min, each further lockout doubles it up to 60 min ----

    data class PinAttempts(val failures: Int = 0, val lockouts: Int = 0, val lockedUntil: Long = 0) {
        fun toJson(): Map<String, Any?> = linkedMapOf("failures" to failures, "lockouts" to lockouts, "lockedUntil" to lockedUntil)

        companion object {
            fun fromJson(m: Map<String, Any?>?): PinAttempts =
                if (m == null) PinAttempts() else PinAttempts(m.int("failures") ?: 0, m.int("lockouts") ?: 0, m.long("lockedUntil") ?: 0)
        }
    }

    /** Seconds the PIN dialog stays closed at [now] (a lockout longer than its maximum: the clock moved back, reset). */
    fun lockedFor(a: PinAttempts, now: Long): Long {
        val left = a.lockedUntil - now
        return if (left <= 0 || left > LOCK_MAX_S) 0 else left
    }

    /** A wrong PIN; [lockedOut] true when this failure started a lockout (the event kiosk_pin_lockout). */
    fun onFailure(a: PinAttempts, now: Long): Pair<PinAttempts, Boolean> {
        val failures = a.failures + 1
        if (failures < MAX_FAILURES) return a.copy(failures = failures) to false
        val seconds = minOf(LOCK_BASE_S shl a.lockouts.coerceAtMost(4), LOCK_MAX_S)
        return PinAttempts(0, a.lockouts + 1, now + seconds) to true
    }

    /** A right PIN, or a new policy hash: everything forgotten. */
    fun onSuccess(): PinAttempts = PinAttempts()

    /** The kiosk is suspended at [now] (local seconds); a suspension longer than its maximum is ignored (clock moved). */
    fun suspended(until: Long, now: Long): Boolean = until > now && until - now <= CommandParser.MAX_SUSPEND_MINUTES * 60L
}
