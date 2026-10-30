package tools.obli.obligarth.agent

import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.PolicyCodes

/**
 * The Knox restrictions of the policy (1.3.0, lot PONT-POL §10.5), reached by reflection through [KnoxBridge]: per field,
 * the policy object, the setters (each group tried name after name; every group must work) and the getters. Candidates
 * to confirm on the J7 once the licence is active (§13.4, D13); a name that exists nowhere is knox_method_missing, a
 * false answer knox_refused. The reconciler calls this only when the licence is active.
 */
class KnoxPolicies(private val knox: KnoxBridge) {

    private class Field(val obj: String, val setters: List<List<String>>, val getters: List<String> = emptyList())

    private val table: Map<String, Field> = mapOf(
        "camera" to Field(RESTRICTION, listOf(listOf("setCameraState")), listOf("isCameraEnabled")),
        "microphone" to Field(RESTRICTION, listOf(listOf("setMicrophoneState")), listOf("isMicrophoneEnabled")),
        "bluetooth" to Field(RESTRICTION, listOf(listOf("setBluetooth", "allowBluetooth")), listOf("isBluetoothEnabled")),
        "nfc" to Field(RESTRICTION, listOf(listOf("allowNFC", "setEnableNFC")), listOf("isNFCEnabled")),
        "cellularData" to Field(RESTRICTION, listOf(listOf("setCellularData")), listOf("isCellularDataAllowed")),
        "tethering" to Field(RESTRICTION, listOf(listOf("setTethering")), listOf("isTetheringEnabled")),
        "unknownSources" to Field(RESTRICTION, listOf(listOf("setAllowNonMarketApps")), listOf("isNonMarketAppAllowed")),
        "clipboard" to Field(RESTRICTION, listOf(listOf("setClipboardEnabled")), listOf("isClipboardAllowed")),
        "screenCapture" to Field(RESTRICTION, listOf(listOf("setScreenCapture")), listOf("isScreenCaptureEnabled")),
        "usbDebugging" to Field(RESTRICTION, listOf(listOf("setUsbDebuggingEnabled")), listOf("isUsbDebuggingEnabled")),
        "usbMediaPlayer" to Field(RESTRICTION, listOf(listOf("setUsbMediaPlayerAvailability")), listOf("isUsbMediaPlayerAvailable")),
        "mockLocation" to Field(RESTRICTION, listOf(listOf("setMockLocation")), listOf("isMockLocationEnabled")),
        "factoryReset" to Field(RESTRICTION, listOf(listOf("allowFactoryReset")), listOf("isFactoryResetAllowed")),
        "airplaneMode" to Field(RESTRICTION, listOf(listOf("allowAirplaneMode")), listOf("isAirplaneModeAllowed")),
        "safeMode" to Field(RESTRICTION, listOf(listOf("allowSafeMode")), listOf("isSafeModeAllowed")),
        "statusBarExpansion" to Field(RESTRICTION, listOf(listOf("allowStatusBarExpansion")), listOf("isStatusBarExpansionAllowed")),
        "settingsChanges" to Field(RESTRICTION, listOf(listOf("allowSettingsChanges")), listOf("isSettingsChangesAllowed")),
        "multiWindow" to Field(RESTRICTION, listOf(listOf("allowMultiWindowMode")), listOf("isMultiWindowModeAllowed")),
        "sdCard" to Field(RESTRICTION, listOf(listOf("setSdCardState")), listOf("isSdCardEnabled")),
        "otaUpgrade" to Field(RESTRICTION, listOf(listOf("allowOTAUpgrade")), listOf("isOTAUpgradeAllowed")),
        "smsIncoming" to Field(PHONE, listOf(listOf("allowIncomingSms")), listOf("isIncomingSmsAllowed")),
        "smsOutgoing" to Field(PHONE, listOf(listOf("allowOutgoingSms")), listOf("isOutgoingSmsAllowed")),
        "mms" to Field(PHONE, listOf(listOf("allowIncomingMms"), listOf("allowOutgoingMms")), listOf("isIncomingMmsAllowed")),
        "wifiUserProfiles" to Field(WIFI, listOf(listOf("setAllowUserProfiles")), listOf("getAllowUserProfiles")),
        "appUninstall" to Field(APPLICATION, listOf(listOf("setApplicationUninstallationMode"))),
    )

    /** The value in force (true = allowed), null when no getter answers (the ledger decides then). */
    fun read(field: String): Any? {
        val f = table[field] ?: return null
        if (f.getters.isEmpty()) return null
        val obj = knox.policyObject(f.obj) ?: return null
        return try {
            // Some getters take a "show message" flag: tried with it first, then without.
            ((knox.invoke(obj, f.getters, false) as? KnoxBridge.KnoxCall.Ok) ?: (knox.invoke(obj, f.getters) as? KnoxBridge.KnoxCall.Ok))
                ?.value as? Boolean
        } catch (e: Exception) {
            null
        }
    }

    /** Applies [value]; [previous] is the list applied before for a list field (packages to enable again). */
    fun apply(field: String, value: Any?, previous: Any?): ItemOutcome {
        if (field == "disabledApps") return packages(value, previous, listOf("setDisableApplication"), listOf("setEnableApplication"))
        if (field == "uninstallBlocked") return packages(value, previous, listOf("setApplicationUninstallationDisabled"),
            listOf("setApplicationUninstallationEnabled"))
        val f = table[field] ?: return ItemOutcome.error(PolicyCodes.INVALID_ITEM)
        val allowed = value as? Boolean ?: return ItemOutcome.error(PolicyCodes.INVALID_ITEM)
        val obj = knox.policyObject(f.obj) ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, f.obj)
        for (group in f.setters) {
            var r = knox.invoke(obj, group, allowed)
            // appUninstall: some versions take a mode (0 allowed, 1 blocked) instead of a flag.
            if (r is KnoxBridge.KnoxCall.Missing && field == "appUninstall") r = knox.invoke(obj, group, if (allowed) 0 else 1)
            when (r) {
                KnoxBridge.KnoxCall.Missing -> return ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, group.first())
                is KnoxBridge.KnoxCall.Ok -> if (r.value == false) return ItemOutcome.error(PolicyCodes.KNOX_REFUSED, group.first())
            }
        }
        return ItemOutcome.compliant(PolicyCodes.APPLIED)
    }

    /** A package list: the new ones blocked, the ones that left it released. */
    private fun packages(value: Any?, previous: Any?, block: List<String>, release: List<String>): ItemOutcome {
        val now = (value as? List<*>).orEmpty().filterIsInstance<String>().toSet()
        val before = (previous as? List<*>).orEmpty().filterIsInstance<String>().toSet()
        val app = knox.policyObject(APPLICATION) ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, APPLICATION)
        for (pkg in now) {
            when (val r = knox.invoke(app, block, pkg)) {
                KnoxBridge.KnoxCall.Missing -> return ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, block.first())
                is KnoxBridge.KnoxCall.Ok -> if (r.value == false) return ItemOutcome.error(PolicyCodes.KNOX_REFUSED, pkg)
            }
        }
        for (pkg in before - now) {
            when (val r = knox.invoke(app, release, pkg)) {
                KnoxBridge.KnoxCall.Missing -> return ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, release.first())
                is KnoxBridge.KnoxCall.Ok -> if (r.value == false) return ItemOutcome.error(PolicyCodes.KNOX_REFUSED, pkg)
            }
        }
        return ItemOutcome.compliant(PolicyCodes.APPLIED)
    }

    /** A network created by another app (MobiControl) removed: WifiPolicy.removeNetworkConfiguration(ssid). */
    fun removeWifi(ssid: String): ItemOutcome {
        val wifi = knox.policyObject(WIFI) ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, WIFI)
        return when (val r = knox.invoke(wifi, listOf("removeNetworkConfiguration"), ssid)) {
            KnoxBridge.KnoxCall.Missing -> ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, "removeNetworkConfiguration")
            is KnoxBridge.KnoxCall.Ok -> if (r.value == false) ItemOutcome.compliant(PolicyCodes.WIFI_REMOVED, "absent")
            else ItemOutcome.compliant(PolicyCodes.WIFI_REMOVED)
        }
    }

    /** A CA in the system store: installCertificateToKeystore("CERT", der, name, null, KEYSTORE_DEFAULT). */
    fun installCert(name: String, pem: String): ItemOutcome {
        val cp = knox.certificateProvisioning() ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, "certificateProvisioning")
        val der = derOf(pem) ?: return ItemOutcome.error(PolicyCodes.INVALID_ITEM, "pem")
        val store = constant(cp.javaClass, "KEYSTORE_DEFAULT", 1)
        return when (val r = knox.invoke(cp, listOf("installCertificateToKeystore"), "CERT", der, name, null, store)) {
            KnoxBridge.KnoxCall.Missing -> ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, "installCertificateToKeystore")
            is KnoxBridge.KnoxCall.Ok -> if (r.value == false) ItemOutcome.error(PolicyCodes.KNOX_REFUSED) else ItemOutcome.compliant(PolicyCodes.CERT_INSTALLED)
        }
    }

    /**
     * The CA of [name] out of the system store. The Knox SDK deletes a CertificateInfo (deleteCertificateFromKeystore(
     * CertificateInfo, int)): the store is listed (getCertificatesFromKeystore(int)) and the entry whose alias is
     * [name] (the alias given at install) is passed. Listed without it: already gone. The String signatures stay a
     * fallback for firmwares that would offer them (to confirm on the J7, §13.4).
     */
    fun removeCert(name: String): ItemOutcome {
        val cp = knox.certificateProvisioning() ?: return ItemOutcome.error(PolicyCodes.KNOX_ERROR, "certificateProvisioning")
        val store = constant(cp.javaClass, "KEYSTORE_DEFAULT", 1)
        val listed = (knox.invoke(cp, listOf("getCertificatesFromKeystore"), store) as? KnoxBridge.KnoxCall.Ok)?.value as? List<*>
        // A listing whose aliases cannot be read proves nothing (never taken for "already gone").
        if (listed != null && (listed.isEmpty() || listed.any { it != null && aliasOf(it) != null })) {
            val info = listed.firstOrNull { it != null && aliasOf(it) == name }
                ?: return ItemOutcome.compliant(PolicyCodes.UNDONE, "absent")
            when (val r = knox.invoke(cp, listOf("deleteCertificateFromKeystore"), info, store)) {
                KnoxBridge.KnoxCall.Missing -> {}
                is KnoxBridge.KnoxCall.Ok ->
                    return if (r.value == false) ItemOutcome.error(PolicyCodes.KNOX_REFUSED) else ItemOutcome.compliant(PolicyCodes.UNDONE)
            }
        }
        val r = knox.invoke(cp, listOf("deleteCertificateFromKeystore", "removeCertificateFromKeystore"), name, store)
            .let { if (it is KnoxBridge.KnoxCall.Missing) knox.invoke(cp, listOf("deleteCertificateFromKeystore", "removeCertificateFromKeystore"), name) else it }
        return when (r) {
            KnoxBridge.KnoxCall.Missing -> ItemOutcome.error(PolicyCodes.KNOX_METHOD_MISSING, "deleteCertificateFromKeystore")
            is KnoxBridge.KnoxCall.Ok -> if (r.value == false) ItemOutcome.error(PolicyCodes.KNOX_REFUSED) else ItemOutcome.compliant(PolicyCodes.UNDONE)
        }
    }

    /** The alias of a Knox CertificateInfo (getAlias), null when it has none readable. */
    private fun aliasOf(info: Any): String? = try {
        info.javaClass.getMethod("getAlias").invoke(info) as? String
    } catch (e: Throwable) {
        null
    }

    private fun derOf(pem: String): ByteArray? = try {
        java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()).encoded
    } catch (e: Exception) {
        null
    }

    private fun constant(cls: Class<*>, name: String, fallback: Int): Int = try { cls.getField(name).getInt(null) } catch (e: Throwable) { fallback }

    companion object {
        const val RESTRICTION = "getRestrictionPolicy"
        const val PHONE = "getPhoneRestrictionPolicy"
        const val WIFI = "getWifiPolicy"
        const val APPLICATION = "getApplicationPolicy"
    }
}
