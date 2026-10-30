package tools.obli.obligarth.agent.core

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * PBKDF2-HMAC-SHA256 (RFC 8018) on javax.crypto.Mac: SecretKeyFactory PBKDF2WithHmacSHA256 does not exist before
 * API 26. The kiosk exit PIN is checked against the record the server sends (§8.2): the clear PIN never reaches the
 * device.
 */
object Pbkdf2 {
    fun sha256(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        require(iterations >= 1 && dkLen >= 1) { "bad parameters" }
        val mac = Mac.getInstance("HmacSHA256")
        // An empty key is refused by SecretKeySpec: a PIN is never empty (8 to 12 digits).
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val hLen = mac.macLength
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(dkLen)
        for (i in 1..blocks) {
            mac.update(salt)
            mac.update(byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (n in 2..iterations) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            val off = (i - 1) * hLen
            System.arraycopy(t, 0, out, off, minOf(hLen, dkLen - off))
        }
        return out
    }

    /** Compares in a time that does not depend on where the arrays differ. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        var diff = a.size xor b.size
        for (i in 0 until minOf(a.size, b.size)) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}

/** The PBKDF2 record of a kiosk exit PIN ({alg, iterations, salt, hash}, base64). */
class PinRecord(val iterations: Int, val salt: ByteArray, val hash: ByteArray) {
    fun verify(pin: String): Boolean {
        if (pin.isEmpty() || pin.length > 64) return false
        val derived = Pbkdf2.sha256(pin.toByteArray(Charsets.UTF_8), salt, iterations, hash.size)
        return Pbkdf2.constantTimeEquals(derived, hash)
    }

    fun toJson(): Map<String, Any?> = linkedMapOf(
        "alg" to ALG, "iterations" to iterations, "salt" to B64.encodeStd(salt), "hash" to B64.encodeStd(hash),
    )

    override fun toString(): String = "PinRecord(redacted)"

    companion object {
        const val ALG = "pbkdf2-sha256"
        /** Bounds: a record outside them is an invalid item (never a slow loop on the device). */
        private val ITERATIONS = 1_000..200_000

        fun parse(m: Map<String, Any?>?): PinRecord? {
            if (m == null || m.str("alg") != ALG) return null
            val it = m.int("iterations")?.takeIf { it in ITERATIONS } ?: return null
            val salt = m.str("salt")?.let { B64.decode(it) }?.takeIf { it.size in 8..64 } ?: return null
            val hash = m.str("hash")?.let { B64.decode(it) }?.takeIf { it.size in 16..64 } ?: return null
            return PinRecord(it, salt, hash)
        }
    }
}
