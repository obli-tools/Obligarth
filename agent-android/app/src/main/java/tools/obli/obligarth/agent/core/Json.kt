package tools.obli.obligarth.agent.core

/**
 * Minimal JSON (RFC 8259) reader and writer, identical on the device and in JVM
 * tests (Android's org.json differs from the Maven one, e.g. optString of a JSON
 * null returns "null" on Android).
 *
 * Values: Map<String, Any?> (insertion order kept), List<Any?>, String, Long
 * (integers that fit), Double, Boolean, null.
 */
object Json {
    class ParseException(message: String) : Exception(message)

    private const val MAX_DEPTH = 32

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.value(0)
        p.skipWs()
        if (p.i != text.length) throw ParseException("trailing data at ${p.i}")
        return v
    }

    fun parseObject(text: String): Map<String, Any?> =
        parse(text) as? Map<String, Any?> ?: throw ParseException("not an object")

    /** Null instead of an exception. */
    fun parseObjectOrNull(text: String?): Map<String, Any?>? =
        try { if (text == null) null else parseObject(text) } catch (e: ParseException) { null }

    fun write(value: Any?): String = StringBuilder().also { writeTo(it, value) }.toString()

    fun bytes(value: Any?): ByteArray = write(value).toByteArray(Charsets.UTF_8)

    private fun writeTo(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is String -> quote(sb, v)
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int, is Long, is Short, is Byte -> sb.append(v.toString())
            is Float, is Double -> {
                val d = (v as Number).toDouble()
                require(!d.isNaN() && !d.isInfinite()) { "non-finite number" }
                if (d == Math.floor(d) && Math.abs(d) < 1e15) sb.append(d.toLong()) else sb.append(d.toString())
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k.toString())
                    sb.append(':')
                    writeTo(sb, value)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('[')
                var first = true
                for (item in v) {
                    if (!first) sb.append(',')
                    first = false
                    writeTo(sb, item)
                }
                sb.append(']')
            }
            is Array<*> -> writeTo(sb, v.toList())
            else -> quote(sb, v.toString())
        }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000c' -> sb.append("\\f")
                else -> if (c < ' ' || c == ' ' || c == ' ') {
                    sb.append(String.format("\\u%04x", c.code))
                } else sb.append(c)
            }
        }
        sb.append('"')
    }

    private class Parser(val s: String) {
        var i = 0

        fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw ParseException("too deep")
            if (i >= s.length) throw ParseException("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else throw ParseException("unexpected '$c' at $i")
            }
        }

        fun literal(word: String, v: Any?): Any? {
            if (!s.startsWith(word, i)) throw ParseException("bad literal at $i")
            i += word.length
            return v
        }

        fun obj(depth: Int): Map<String, Any?> {
            val m = LinkedHashMap<String, Any?>()
            i++
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return m }
            while (true) {
                skipWs()
                if (i >= s.length || s[i] != '"') throw ParseException("key expected at $i")
                val k = str()
                skipWs()
                if (i >= s.length || s[i] != ':') throw ParseException("':' expected at $i")
                i++
                skipWs()
                if (m.containsKey(k)) throw ParseException("duplicate key '$k'")
                m[k] = value(depth + 1)
                skipWs()
                if (i >= s.length) throw ParseException("unexpected end")
                if (s[i] == ',') { i++; continue }
                if (s[i] == '}') { i++; return m }
                throw ParseException("',' or '}' expected at $i")
            }
        }

        fun arr(depth: Int): List<Any?> {
            val l = ArrayList<Any?>()
            i++
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return l }
            while (true) {
                skipWs()
                l.add(value(depth + 1))
                skipWs()
                if (i >= s.length) throw ParseException("unexpected end")
                if (s[i] == ',') { i++; continue }
                if (s[i] == ']') { i++; return l }
                throw ParseException("',' or ']' expected at $i")
            }
        }

        fun str(): String {
            i++
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw ParseException("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) throw ParseException("bad escape")
                        when (val e = s[i++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000c'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) throw ParseException("bad \\u escape")
                                val code = s.substring(i, i + 4).toIntOrNull(16) ?: throw ParseException("bad \\u escape")
                                sb.append(code.toChar())
                                i += 4
                            }
                            else -> throw ParseException("bad escape '\\$e'")
                        }
                    }
                    c < ' ' -> throw ParseException("control character in string")
                    else -> sb.append(c)
                }
            }
        }

        fun num(): Any {
            val start = i
            if (s[i] == '-') i++
            if (i >= s.length) throw ParseException("bad number")
            if (s[i] == '0') i++ else if (s[i] in '1'..'9') { while (i < s.length && s[i] in '0'..'9') i++ } else throw ParseException("bad number")
            var integral = true
            if (i < s.length && s[i] == '.') {
                integral = false
                i++
                if (i >= s.length || s[i] !in '0'..'9') throw ParseException("bad number")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                integral = false
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (i >= s.length || s[i] !in '0'..'9') throw ParseException("bad number")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            val text = s.substring(start, i)
            if (integral) text.toLongOrNull()?.let { return it }
            return text.toDouble()
        }
    }
}

// ---- Typed accessors: null when absent or of another type, never an exception ----

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.obj(key: String): Map<String, Any?>? = this[key] as? Map<String, Any?>
fun Map<String, Any?>.list(key: String): List<Any?>? = this[key] as? List<Any?>
fun Map<String, Any?>.str(key: String): String? = this[key] as? String
fun Map<String, Any?>.bool(key: String): Boolean? = this[key] as? Boolean
fun Map<String, Any?>.long(key: String): Long? = when (val v = this[key]) {
    is Long -> v
    is Int -> v.toLong()
    else -> null
}
fun Map<String, Any?>.int(key: String): Int? = long(key)?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
