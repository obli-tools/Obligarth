package tools.obli.obligarth.agent.core

/**
 * The icons of the installed apps (1.0.2, spec §4.6): the server answers an
 * inventory with `iconsWanted` (the apps whose icon it lacks, a lease per app
 * so that one device of the fleet sends it); the agent keeps them in a queue
 * (deduplicated by package, [MAX_QUEUE] at most), renders them one at a time
 * and sends them to POST /agent/v1/icons by batches ([MAX_PER_REQUEST] icons,
 * about [BODY_BUDGET] bytes of body): a PNG, none (the app has no icon) or
 * failed (it cannot be rendered: the server ends the lease and asks another
 * device). The presence of `iconsWanted`, even
 * empty, tells the agent the server knows the icons and the `launchable` flag
 * of the apps: never sent to an older server, whose strict schema refuses an
 * unknown key.
 */
data class IconWanted(val packageName: String, val versionCode: Long?) {
    fun toJson(): Map<String, Any?> = linkedMapOf("package" to packageName, "versionCode" to versionCode)

    companion object {
        private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*$")

        fun fromJson(m: Map<String, Any?>): IconWanted? {
            val p = m.str("package") ?: return null
            if (p.length > 255 || !PACKAGE.matches(p)) return null
            return IconWanted(p, m.long("versionCode")?.takeIf { it >= 0 })
        }
    }
}

object Icons {
    const val MAX_QUEUE = 100
    const val MAX_PER_REQUEST = 16
    /** The body of one request (the server takes 512 KiB, the edge proxy 600 KiB). */
    const val BODY_BUDGET = 240 * 1024
    const val SIZE_PX = 96
    const val FALLBACK_PX = 72
    /** A rendering beyond this is tried again at [FALLBACK_PX], then given up (the server takes 32 KiB). */
    const val MAX_PNG_BYTES = 24 * 1024
    /** Seconds of a cycle spent on the icons at most. */
    const val SEND_SECONDS = 20L
    /** A 404 (a server without the route): no icon for a week. */
    const val BLOCK_SECONDS = 7 * 86_400L
    /** The JSON frame of a body: {"icons":[]}. */
    const val EMPTY_BODY_BYTES = 12

    /** iconsWanted of an inventory answer; null when the answer has none (an older server). */
    fun parseWanted(json: Map<String, Any?>?): List<IconWanted>? {
        val list = json?.list("iconsWanted") ?: return null
        @Suppress("UNCHECKED_CAST")
        return list.mapNotNull { (it as? Map<String, Any?>)?.let { m -> IconWanted.fromJson(m) } }
    }

    /** The queue with [incoming] added: one entry per package (its place kept, its versionCode the newest), capped. */
    fun merge(queue: List<IconWanted>, incoming: List<IconWanted>): List<IconWanted> {
        val byPackage = LinkedHashMap<String, IconWanted>()
        for (w in queue) byPackage[w.packageName] = w
        for (w in incoming) byPackage[w.packageName] = w
        return byPackage.values.take(MAX_QUEUE)
    }

    /** The entry of a request body for a rendering; null: the icon could not be rendered (failed). */
    fun entry(w: IconWanted, render: IconRender?): Map<String, Any?> = when (render) {
        is IconRender.Png -> linkedMapOf("package" to w.packageName, "versionCode" to (w.versionCode ?: 0L), "png" to B64.encodeStd(render.bytes))
        IconRender.NoIcon -> linkedMapOf("package" to w.packageName, "versionCode" to (w.versionCode ?: 0L), "none" to true)
        null -> linkedMapOf("package" to w.packageName, "versionCode" to (w.versionCode ?: 0L), "failed" to true)
    }

    /** Bytes an entry adds to a body (its JSON and a comma). */
    fun sizeOf(entry: Map<String, Any?>): Int = Json.bytes(entry).size + 1

    /** Whether an entry of [entrySize] bytes still fits a batch of [count] entries and [bodySize] bytes. */
    fun fits(count: Int, bodySize: Int, entrySize: Int, maxCount: Int = MAX_PER_REQUEST): Boolean =
        count < maxCount && (count == 0 || bodySize + entrySize <= BODY_BUDGET)

    /** An inventory without the `launchable` flag of its apps (for a server that does not know it). */
    @Suppress("UNCHECKED_CAST")
    fun withoutLaunchable(inventory: Map<String, Any?>): Map<String, Any?> {
        val apps = inventory["apps"] as? List<*> ?: return inventory
        val out = LinkedHashMap(inventory)
        out["apps"] = apps.map { a -> (a as? Map<String, Any?>)?.let { m -> LinkedHashMap(m).apply { remove("launchable") } } ?: a }
        return out
    }
}
