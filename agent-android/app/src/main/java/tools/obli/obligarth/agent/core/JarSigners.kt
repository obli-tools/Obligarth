package tools.obli.obligarth.agent.core

import java.io.File
import java.security.cert.Certificate
import java.util.jar.JarFile

/**
 * Reads the signers of an APK from its v1 (JAR) signature, verifying every
 * entry. Fallback when PackageManager.getPackageArchiveInfo returns no
 * signature (seen on some Android 7 builds), and the JVM-side reader of the
 * tests. Returns null when the archive is unsigned, partly signed or tampered.
 */
object JarSigners {
    fun signerSha256(file: File): List<String>? = try {
        JarFile(file, true).use { jar ->
            var signers: List<Certificate>? = null
            val buf = ByteArray(16 * 1024)
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (e.isDirectory) continue
                // Reading the entry to the end makes JarFile verify its digest (SecurityException if altered).
                jar.getInputStream(e).use { input -> while (input.read(buf) >= 0) { /* drain */ } }
                val name = e.name.uppercase()
                if (name.startsWith("META-INF/")) continue
                val certs = e.certificates?.toList() ?: return@use null
                // Only the leaf certificate of each signer (a chain lists issuers after the leaf).
                val leaves = leafCertificates(certs)
                if (signers == null) signers = leaves
                else if (signers!!.map { it.encoded.toList() } != leaves.map { it.encoded.toList() }) return@use null
            }
            signers?.map { Sha256.hex(it.encoded) }
        }
    } catch (e: SecurityException) {
        null
    } catch (e: java.io.IOException) {
        null
    }

    private fun leafCertificates(certs: List<Certificate>): List<Certificate> {
        val out = ArrayList<Certificate>()
        var i = 0
        while (i < certs.size) {
            val leaf = certs[i] as? java.security.cert.X509Certificate ?: return certs
            out.add(leaf)
            i++
            var issuer = leaf.issuerX500Principal
            // Skip the issuer chain of this signer.
            while (i < certs.size) {
                val next = certs[i] as? java.security.cert.X509Certificate ?: break
                if (next.subjectX500Principal != issuer || next.subjectX500Principal == leaf.subjectX500Principal) break
                issuer = next.issuerX500Principal
                i++
            }
        }
        return out
    }
}
