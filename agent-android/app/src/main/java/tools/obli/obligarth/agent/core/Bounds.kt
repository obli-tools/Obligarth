package tools.obli.obligarth.agent.core

/**
 * Values shaped like the server's strict schema (DeviceFacts of /enroll and
 * /inventory, spec §4.4, §4.6): one value out of it fails the whole request
 * with a 400 the agent does not retry before a day (§8.7: an unreadable value
 * is null, never an error).
 */
object Bounds {
    private val IMEI_RE = Regex("^[0-9]{14,16}$")

    /** The first [max] UTF-16 units (the server counts the same units), never half of a surrogate pair. */
    fun clip(value: String, max: Int): String {
        if (value.length <= max) return value
        val end = if (max > 0 && Character.isHighSurrogate(value[max - 1])) max - 1 else max
        return value.substring(0, end)
    }

    /** Decimal IMEIs only (14 to 16 digits): a CDMA MEID in hexadecimal or a placeholder is left out; 4 at most. */
    fun imeis(values: List<String?>): List<String> =
        values.mapNotNull { it?.trim()?.takeIf { v -> IMEI_RE.matches(v) } }.distinct().take(4)
}

fun String.clip(max: Int): String = Bounds.clip(this, max)
