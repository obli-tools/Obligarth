package tools.obli.obligarth.agent.core

/**
 * Target paths of the deposited files (1.3.0, lot PONT-POL §4.3), identical to the shared isAgentFilePath: relative to
 * the external storage, '/' separators, 1 to 8 segments, 240 characters at most, each segment a plain name (never '.',
 * '..', empty, ending with a dot or a space). Under Android/: the agent's own data folder always; another app's data
 * folder (Android/data/<package>/files/...) only with allowAppDataDir (D16); anything else under Android/ (obb, media)
 * refused. The depositor checks the canonical path again on the device.
 */
object PathRules {
    const val PATH_MAX = 240
    const val SEGMENTS_MAX = 8
    const val OWN_PACKAGE = "tools.obli.obligarth.agent"

    private val SEGMENT = Regex("^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}$")

    fun isAllowed(rel: String, allowAppDataDir: Boolean): Boolean {
        if (rel.isEmpty() || rel.length > PATH_MAX) return false
        val segs = rel.split('/')
        if (segs.size > SEGMENTS_MAX) return false
        if (!segs.all { SEGMENT.matches(it) && it != "." && it != ".." && !it.endsWith(".") && !it.endsWith(" ") }) return false
        if (!segs[0].equals("android", ignoreCase = true)) return true
        if (segs.size < 2 || !segs[1].equals("data", ignoreCase = true)) return false
        val pkg = segs.getOrNull(2) ?: return false
        if (!CommandParser.isPackageName(pkg)) return false
        if (isOwnPackage(pkg)) return segs.size >= 4
        return allowAppDataDir && segs.size >= 5 && segs[3] == "files"
    }

    /** The agent's package or one of its sub-names (the debug build is tools.obli.obligarth.agent.debug). */
    fun isOwnPackage(pkg: String): Boolean {
        val p = pkg.lowercase()
        return p == OWN_PACKAGE || p.startsWith("$OWN_PACKAGE.")
    }

    /** The key two paths collide on (the storage is case-insensitive). */
    fun key(rel: String): String = rel.lowercase()
}
