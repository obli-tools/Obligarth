package tools.obli.obligarth.agent.core

import java.security.MessageDigest

/**
 * Encodings used by the contract (spec §4). Pure Kotlin: java.util.Base64 only
 * exists from API 26 and android.util.Base64 is not available to JVM tests.
 */
object Hex {
    private val DIGITS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[2 * i] = DIGITS[v ushr 4]
            out[2 * i + 1] = DIGITS[v and 0x0f]
        }
        return String(out)
    }

    fun isSha256(value: String?): Boolean = value != null && SHA256_HEX.matches(value)

    private val SHA256_HEX = Regex("^[0-9a-f]{64}$")
}

object Sha256 {
    fun of(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun hex(bytes: ByteArray): String = Hex.encode(of(bytes))
    fun hex(text: String): String = hex(text.toByteArray(Charsets.UTF_8))

    /** SHA-256 of the empty body. */
    const val EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

/** Base64 (RFC 4648), standard or URL-safe alphabet, padding optional on decode. */
object B64 {
    private const val STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun encodeUrl(bytes: ByteArray): String = encode(bytes, URL, pad = false)
    fun encodeStd(bytes: ByteArray): String = encode(bytes, STD, pad = true)

    private fun encode(bytes: ByteArray, alphabet: String, pad: Boolean): String {
        val sb = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i + 3 <= bytes.size) {
            val n = ((bytes[i].toInt() and 0xff) shl 16) or ((bytes[i + 1].toInt() and 0xff) shl 8) or (bytes[i + 2].toInt() and 0xff)
            sb.append(alphabet[(n ushr 18) and 63]).append(alphabet[(n ushr 12) and 63])
                .append(alphabet[(n ushr 6) and 63]).append(alphabet[n and 63])
            i += 3
        }
        val rest = bytes.size - i
        if (rest == 1) {
            val n = (bytes[i].toInt() and 0xff) shl 16
            sb.append(alphabet[(n ushr 18) and 63]).append(alphabet[(n ushr 12) and 63])
            if (pad) sb.append("==")
        } else if (rest == 2) {
            val n = ((bytes[i].toInt() and 0xff) shl 16) or ((bytes[i + 1].toInt() and 0xff) shl 8)
            sb.append(alphabet[(n ushr 18) and 63]).append(alphabet[(n ushr 12) and 63]).append(alphabet[(n ushr 6) and 63])
            if (pad) sb.append('=')
        }
        return sb.toString()
    }

    /**
     * Decodes either alphabet (never mixed), padding optional; returns null on
     * any malformed input instead of throwing.
     */
    fun decode(text: String): ByteArray? {
        var s = text.trim()
        while (s.endsWith("=")) s = s.dropLast(1)
        if (s.isEmpty()) return ByteArray(0)
        if (s.length % 4 == 1) return null
        val urlSafe = s.any { it == '-' || it == '_' }
        val std = s.any { it == '+' || it == '/' }
        if (urlSafe && std) return null
        val alphabet = if (urlSafe) URL else STD
        val out = java.io.ByteArrayOutputStream(s.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (c in s) {
            val v = alphabet.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer ushr bits) and 0xff)
            }
        }
        // Leftover bits must be zero (canonical encoding).
        if (bits > 0 && (buffer and ((1 shl bits) - 1)) != 0) return null
        return out.toByteArray()
    }
}

object Uuids {
    private val LOWER = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    fun isLower(value: String?): Boolean = value != null && LOWER.matches(value)
}
