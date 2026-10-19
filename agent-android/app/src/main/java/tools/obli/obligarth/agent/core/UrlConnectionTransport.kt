package tools.obli.obligarth.agent.core

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/**
 * HTTP transport on HttpURLConnection (the same API on Android and in JVM tests).
 * HTTPS only, except for loopback tests ([allowCleartextLoopback]); optional TLS
 * pinning on the SHA-256 of a certificate public key (SPKI) of the chain.
 */
class UrlConnectionTransport(
    private val tlsPins: Set<String> = emptySet(),
    private val allowCleartextLoopback: Boolean = false,
) : Transport {

    override fun exchange(request: HttpRequest): HttpResponse {
        val url = URL(request.url)
        val loopback = url.host == "127.0.0.1" || url.host == "localhost"
        if (url.protocol != "https" && !(allowCleartextLoopback && loopback && url.protocol == "http")) {
            throw IOException("cleartext refused")
        }
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.connectTimeout = request.timeoutMs
            conn.readTimeout = request.timeoutMs
            conn.requestMethod = request.method
            conn.setRequestProperty("Accept-Encoding", "identity")
            for ((k, v) in request.headers) conn.setRequestProperty(k, v)
            val body = request.body
            if (body != null) {
                conn.doOutput = true
                // No streaming mode: the JDK client would lose the body of a 401 (HttpRetryException); bodies are small.
            }
            conn.connect()
            if (conn is HttpsURLConnection && tlsPins.isNotEmpty()) checkPins(conn)
            if (body != null) conn.outputStream.use { it.write(body) }

            val status = conn.responseCode
            val headers = HashMap<String, String>()
            for ((k, v) in conn.headerFields) if (k != null && v != null && v.isNotEmpty()) headers[k.lowercase()] = v.first()
            val stream: InputStream? = if (status >= 400) conn.errorStream else conn.inputStream
            val target = request.downloadTo
            if (status == 200 && target != null) {
                val sha = stream?.use { streamToFile(it, target, request.maxDownloadBytes) } ?: Sha256.EMPTY
                return HttpResponse(status, headers, ByteArray(0), sha)
            }
            val bytes = stream?.use { readCapped(it, MAX_JSON_BYTES) } ?: ByteArray(0)
            return HttpResponse(status, headers, bytes)
        } finally {
            conn.disconnect()
        }
    }

    private fun checkPins(conn: HttpsURLConnection) {
        val chain = conn.serverCertificates
        val ok = chain.any { Sha256.hex(it.publicKey.encoded) in tlsPins }
        if (!ok) throw IOException("TLS pin mismatch")
    }

    /** Streams at most [max] + 1 bytes (a larger file then fails the size check: hash_mismatch). */
    private fun streamToFile(input: InputStream, file: File, max: Long): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.parentFile?.mkdirs()
        FileOutputStream(file).use { out ->
            val buf = ByteArray(64 * 1024)
            var total = 0L
            val limit = if (max > 0) max + 1 else Long.MAX_VALUE
            while (total < limit) {
                val n = input.read(buf, 0, Math.min(buf.size.toLong(), limit - total).toInt())
                if (n < 0) break
                out.write(buf, 0, n)
                md.update(buf, 0, n)
                total += n
            }
            out.fd.sync()
        }
        return Hex.encode(md.digest())
    }

    private fun readCapped(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > max) throw IOException("response too large")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    companion object {
        const val MAX_JSON_BYTES = 1 shl 20
    }
}
