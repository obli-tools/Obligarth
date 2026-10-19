package tools.obli.obligarth.agent.core

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/** Canonical strings of the frozen contract (spec §4.2 and §4.3, revision RC-1). */
object Canonical {
    const val REQUEST_TAG = "OBL-AGENT-1"
    const val RESPONSE_TAG = "OBL-SERVER-2"

    /** Agent id and seq used by /enroll. */
    const val NO_AGENT = "-"

    fun request(method: String, path: String, agentId: String?, seq: Long, ts: Long, bodySha256Hex: String): String =
        listOf(REQUEST_TAG, method.uppercase(), path, agentId ?: NO_AGENT, seq.toString(), ts.toString(), bodySha256Hex)
            .joinToString("\n")

    fun response(status: Int, agentId: String?, seq: Long, requestBodySha256Hex: String, responseBodySha256Hex: String): String =
        listOf(RESPONSE_TAG, status.toString(), agentId ?: NO_AGENT, seq.toString(), requestBodySha256Hex, responseBodySha256Hex)
            .joinToString("\n")
}

/** ECDSA P-256 / SHA-256 helpers (signatures DER, keys SPKI DER). */
object Ec {
    const val ALGORITHM = "SHA256withECDSA"

    /** Parses an SPKI and accepts EC P-256 only; null otherwise. */
    fun publicKeyFromSpki(spki: ByteArray): PublicKey? = try {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        if (key is ECPublicKey && key.params.curve.field.fieldSize == 256 &&
            key.params.order.toString(16) == P256_ORDER
        ) key else null
    } catch (e: Exception) {
        null
    }

    fun privateKeyFromPkcs8(der: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))

    fun sign(key: PrivateKey, data: ByteArray): ByteArray =
        Signature.getInstance(ALGORITHM).run {
            initSign(key)
            update(data)
            sign()
        }

    fun verify(key: PublicKey, data: ByteArray, signatureDer: ByteArray): Boolean = try {
        Signature.getInstance(ALGORITHM).run {
            initVerify(key)
            update(data)
            verify(signatureDer)
        }
    } catch (e: Exception) {
        false
    }

    /** keyId of the contract: the first 16 hex characters of SHA-256(SPKI). */
    fun keyId(spki: ByteArray): String = Sha256.hex(spki).substring(0, 16)

    private const val P256_ORDER = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
}

/** A server key the agent trusts (from the enrollment response, checked against the pins). */
class ServerKey(val spki: ByteArray) {
    val sha256: String = Sha256.hex(spki)
    val keyId: String = sha256.substring(0, 16)
    val publicKey: PublicKey? = Ec.publicKeyFromSpki(spki)
}

/** Verifies the server signature of a response (spec §4.3). */
object ResponseVerifier {
    fun verify(
        keys: Collection<ServerKey>,
        keyIdHeader: String?,
        signatureHeader: String?,
        status: Int,
        agentId: String?,
        seq: Long,
        requestBodySha256: String,
        responseBody: ByteArray,
    ): Boolean = verifyHash(keys, keyIdHeader, signatureHeader, status, agentId, seq, requestBodySha256, Sha256.hex(responseBody))

    fun verifyHash(
        keys: Collection<ServerKey>,
        keyIdHeader: String?,
        signatureHeader: String?,
        status: Int,
        agentId: String?,
        seq: Long,
        requestBodySha256: String,
        responseBodySha256: String,
    ): Boolean {
        if (keyIdHeader == null || signatureHeader == null) return false
        val key = keys.firstOrNull { it.keyId == keyIdHeader.trim().lowercase() } ?: return false
        val pub = key.publicKey ?: return false
        val sig = B64.decode(signatureHeader.trim()) ?: return false
        val text = Canonical.response(status, agentId, seq, requestBodySha256, responseBodySha256)
        return Ec.verify(pub, text.toByteArray(Charsets.UTF_8), sig)
    }
}
