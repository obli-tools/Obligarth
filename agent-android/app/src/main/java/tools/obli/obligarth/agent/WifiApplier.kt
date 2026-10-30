@file:Suppress("DEPRECATION") // the device-administrator and Wi-Fi APIs of Android 7 (targetSdk 25)

package tools.obli.obligarth.agent

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiEnterpriseConfig
import android.net.wifi.WifiManager
import android.provider.Settings
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.Policy
import tools.obli.obligarth.agent.core.PolicyCodes
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The Wi-Fi networks of the policy (1.3.0, lot PONT-POL §10.5): WPA2-PSK, and WPA2-Enterprise PEAP/MSCHAPv2 with its CA
 * as X509 objects (C3). Wi-Fi is never turned on by the agent (D5). A network found but not updatable was created by
 * another app (only Knox can change it); a network refused with its CA is never saved without it unless the policy says
 * allowNoCa. Secrets live in memory only while the configuration is built, and the logs carry the SSID and a code only.
 * With the licence, the network goes through Knox WifiPolicy first (C4: a Knox network survives wifiUserProfiles =
 * false), names to confirm on the J7; any failure there falls back to WifiManager.
 */
class WifiApplier(context: Context, private val knox: KnoxBridge, private val log: AgentLog) {
    private val context: Context = context.applicationContext
    private val wm = this.context.getSystemService(Context.WIFI_SERVICE) as WifiManager

    private fun quoted(ssid: String) = "\"$ssid\""

    private fun isEap(c: WifiConfiguration) = c.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_EAP)
    private fun isPsk(c: WifiConfiguration) = c.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_PSK)

    /** The configured network of [ssid] with the same key management (null when none or unreadable). */
    @SuppressLint("MissingPermission")
    private fun find(ssid: String, eap: Boolean?): WifiConfiguration? = try {
        wm.configuredNetworks?.firstOrNull { it.SSID == quoted(ssid) && (eap == null || (if (eap) isEap(it) else isPsk(it))) }
    } catch (e: SecurityException) {
        null
    }

    @SuppressLint("MissingPermission") // location only from Android 10; the agent targets 25 (a refusal reads as unknown)
    fun present(w: Policy.Wifi): Boolean? = try {
        wm.configuredNetworks?.any { it.SSID == quoted(w.ssid) && (if (w.security == Policy.PEAP) isEap(it) else isPsk(it)) }
    } catch (e: SecurityException) {
        null
    }

    fun apply(w: Policy.Wifi): ItemOutcome {
        if (!wm.isWifiEnabled) return ItemOutcome.pending(PolicyCodes.WIFI_DISABLED)
        val cas = w.eap?.caPem?.let { certificates(it) ?: return ItemOutcome.error(PolicyCodes.WIFI_ADD_FAILED, "ca_invalid") }
        if (knox.state() == "licensed") knoxProfile(w, cas)?.let { return it }
        val cfg = build(w, cas)
        val existing = find(w.ssid, w.security == Policy.PEAP)
        val outcome = if (existing != null) {
            cfg.networkId = existing.networkId
            val id = wm.updateNetwork(cfg)
            if (id == -1) return ItemOutcome.nonCompliant(PolicyCodes.WIFI_FOREIGN_PROFILE)
            enable(id, w.autoConnect)
            ItemOutcome.compliant(PolicyCodes.WIFI_UPDATED)
        } else {
            val id = wm.addNetwork(cfg)
            // Never retried without the CA (C3): with a CA, the refusal says so.
            if (id == -1) return ItemOutcome.error(PolicyCodes.WIFI_ADD_FAILED, if (cas != null) "ca_set" else null)
            enable(id, w.autoConnect)
            ItemOutcome.compliant(PolicyCodes.WIFI_ADDED)
        }
        wm.saveConfiguration()
        log.info("wifi ${w.ssid}: ${outcome.code}")
        return outcome
    }

    private fun enable(id: Int, autoConnect: Boolean) {
        if (autoConnect) wm.enableNetwork(id, false) else wm.disableNetwork(id)
    }

    private fun build(w: Policy.Wifi, cas: List<X509Certificate>?): WifiConfiguration = WifiConfiguration().apply {
        SSID = quoted(w.ssid)
        hiddenSSID = w.hidden
        priority = w.priority
        if (w.security == Policy.PSK) {
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK)
            val psk = w.psk!!
            preSharedKey = if (psk.length == 64 && psk.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) psk else "\"$psk\""
        } else {
            val e = w.eap!!
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP)
            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X)
            enterpriseConfig = WifiEnterpriseConfig().apply {
                eapMethod = WifiEnterpriseConfig.Eap.PEAP
                phase2Method = WifiEnterpriseConfig.Phase2.MSCHAPV2
                identity = e.identity
                anonymousIdentity = e.anonymousIdentity ?: ""
                password = e.password
                e.domainSuffixMatch?.let { domainSuffixMatch = it }
                when {
                    cas == null -> {}
                    cas.size == 1 -> caCertificate = cas[0]
                    else -> caCertificates = cas.toTypedArray()
                }
            }
        }
    }

    private fun certificates(pem: String): List<X509Certificate>? = try {
        CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream()).filterIsInstance<X509Certificate>().ifEmpty { null }
    } catch (e: Exception) {
        null
    }

    /**
     * Knox WifiPolicy.setWifiProfile(WifiAdminProfile) (C4): null when unavailable here (WifiManager then), else the
     * outcome. The profile's fields are set by name, and a field the profile lacks makes the Knox path give way to
     * WifiManager (never a network saved without one of its settings). Until the J7 confirms the profile's fields
     * (§13.4), the Knox path takes only what it is known to carry in full: a WPA2-PSK network, visible, joined
     * automatically. An enterprise network (its CA, C3: never saved without it; its domain), a hidden one or one not
     * joined automatically go through WifiManager.
     */
    private fun knoxProfile(w: Policy.Wifi, @Suppress("UNUSED_PARAMETER") cas: List<X509Certificate>?): ItemOutcome? {
        if (w.security != Policy.PSK || w.hidden || !w.autoConnect) return null
        val wifi = knox.policyObject(KnoxPolicies.WIFI) ?: return null
        return try {
            val cls = Class.forName(wifi.javaClass.`package`!!.name + ".WifiAdminProfile")
            val p = cls.getConstructor().newInstance()
            fun set(name: String, v: Any?): Boolean = try { cls.getField(name).set(p, v); true } catch (e: NoSuchFieldException) { false }
            val complete = set("ssid", w.ssid) && set("security", "PSK") && set("psk", w.psk)
            if (!complete) {
                log.warn("wifi ${w.ssid}: Knox profile without a required field, WifiManager used")
                return null
            }
            when (val r = knox.invoke(wifi, listOf("setWifiProfile"), p)) {
                KnoxBridge.KnoxCall.Missing -> null
                is KnoxBridge.KnoxCall.Ok -> if (r.value == false) null else ItemOutcome.compliant(PolicyCodes.WIFI_UPDATED, "knox")
            }
        } catch (e: Throwable) {
            log.warn("wifi ${w.ssid}: Knox profile unavailable (${e.javaClass.simpleName})")
            null
        }
    }

    /** The SSID of the network in use (null when none or unreadable). */
    fun connectedSsid(): String? = try {
        wm.connectionInfo?.takeIf { it.networkId != -1 }?.ssid?.removeSurrounding("\"")?.takeIf { it.isNotEmpty() && it != "<unknown ssid>" }
    } catch (e: Exception) {
        null
    }

    /** Scan results need a location permission from Android 6 (an app targeting 23+ gets an empty list without it,
     *  never an exception), and the location turned on. */
    private fun scanReadable(): String? {
        if (context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED &&
            !(knox.state() == "licensed" && knox.grantRuntimePermissions(listOf(Manifest.permission.ACCESS_COARSE_LOCATION)))) {
            return SCAN_UNAVAILABLE
        }
        val mode = try { Settings.Secure.getInt(context.contentResolver, Settings.Secure.LOCATION_MODE) } catch (e: Exception) { -1 }
        return if (mode == Settings.Secure.LOCATION_MODE_OFF) LOCATION_OFF else null
    }

    /**
     * preferOver (C2): connected to one of the listed SSIDs while the managed network is in the last scan, one switch
     * asked (Android 7 largely ignores priority). Null when nothing was done; a detail (scan_unavailable, location_off)
     * when the scan cannot be read, so the status screen asks for the location permission.
     */
    @SuppressLint("MissingPermission")
    fun prefer(w: Policy.Wifi): ItemOutcome? {
        val current = connectedSsid() ?: return null
        if (current !in w.preferOver) return null
        scanReadable()?.let { return ItemOutcome.compliant(PolicyCodes.OK, it) }
        val seen = try { wm.scanResults?.any { it.SSID == w.ssid } == true } catch (e: SecurityException) { false }
        if (!seen) return null
        val id = find(w.ssid, w.security == Policy.PEAP)?.networkId ?: return null
        return if (wm.enableNetwork(id, true)) ItemOutcome.compliant(PolicyCodes.WIFI_PREFERRED) else null
    }

    /**
     * The undo of a network of the agent: removed, unless it is the one in use and no other managed network ([managed]:
     * the SSIDs of the policy's networks in place) is configured (kept, compliant/undone kept_connected). Wi-Fi off:
     * pending (the configuration cannot change while the supplicant is down). A network created through Knox
     * ([viaKnox]), or one removeNetwork refuses (another uid owns it), goes through Knox when licensed; otherwise it
     * stays non-compliant, kept in the ledger and tried again.
     */
    @SuppressLint("MissingPermission")
    fun removeOwn(ssid: String, managed: Set<String>, viaKnox: Boolean): ItemOutcome {
        if (!wm.isWifiEnabled) return ItemOutcome.pending(PolicyCodes.WIFI_DISABLED)
        val cfg = find(ssid, null) ?: return ItemOutcome.compliant(PolicyCodes.WIFI_REMOVED, "absent")
        val connected = wm.connectionInfo?.networkId == cfg.networkId
        val others = try {
            wm.configuredNetworks?.count { c ->
                c.networkId != cfg.networkId && c.SSID?.removeSurrounding("\"")?.let { it != ssid && it in managed } == true
            } ?: 0
        } catch (e: SecurityException) {
            0
        }
        if (connected && others == 0) return ItemOutcome.compliant(PolicyCodes.UNDONE, "kept_connected")
        val removed = (!viaKnox && wm.removeNetwork(cfg.networkId)) || removeThroughKnox(ssid)
        if (!removed) return ItemOutcome.nonCompliant(PolicyCodes.WIFI_FOREIGN_PROFILE)
        wm.saveConfiguration()
        log.info("wifi $ssid: removed")
        return ItemOutcome.compliant(PolicyCodes.WIFI_REMOVED)
    }

    /** WifiPolicy.removeNetworkConfiguration(ssid), licensed only; false when unavailable or refused. */
    private fun removeThroughKnox(ssid: String): Boolean {
        if (knox.state() != "licensed") return false
        val wifi = knox.policyObject(KnoxPolicies.WIFI) ?: return false
        return try {
            (knox.invoke(wifi, listOf("removeNetworkConfiguration"), ssid) as? KnoxBridge.KnoxCall.Ok)?.value == true
        } catch (e: Exception) {
            log.warn("wifi $ssid: Knox removal (${e.javaClass.simpleName})")
            false
        }
    }

    companion object {
        const val SCAN_UNAVAILABLE = "scan_unavailable"
        const val LOCATION_OFF = "location_off"
    }
}
