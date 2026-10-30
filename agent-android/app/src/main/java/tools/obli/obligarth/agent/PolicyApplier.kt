package tools.obli.obligarth.agent

import android.content.Context
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.FileStat
import tools.obli.obligarth.agent.core.ItemOutcome
import tools.obli.obligarth.agent.core.Policy
import tools.obli.obligarth.agent.core.PolicyCodes
import tools.obli.obligarth.agent.core.PolicyHost
import java.io.File

/**
 * The device side of the policy (1.3.0, lot PONT-POL §10.5): the PolicyHost of the reconciler, delegating to the
 * device administrator, Knox, Wi-Fi, file and kiosk appliers. One per process (AgentRuntime).
 */
class PolicyApplier(context: Context, private val facts: AndroidFacts, private val knox: KnoxBridge, log: AgentLog) : PolicyHost {
    val dpm = DpmApplier(context, log)
    val knoxPolicies = KnoxPolicies(knox)
    val wifi = WifiApplier(context, knox, log)
    val files = FileDepositor(context, knox, log)
    val kiosk = KioskController(context, knox, log)

    override fun knoxState(): String = knox.state()

    override fun adminActive(): Boolean = facts.adminActive()
    override fun dpmGranted(field: String): Boolean = dpm.granted(field)
    override fun dpmRead(field: String): Any? = dpm.read(field)
    override fun dpmApply(field: String, value: Any?): ItemOutcome = dpm.apply(field, value)
    override fun passwordSufficient(): Boolean? = dpm.passwordSufficient()

    override fun knoxRead(field: String): Any? = knoxPolicies.read(field)
    override fun knoxApply(field: String, value: Any?, previous: Any?): ItemOutcome = knoxPolicies.apply(field, value, previous)
    override fun knoxCertInstall(id: String, name: String, pem: String): ItemOutcome = knoxPolicies.installCert(name, pem)
    override fun knoxCertRemove(id: String, name: String): ItemOutcome = knoxPolicies.removeCert(name)
    override fun knoxWifiRemove(ssid: String): ItemOutcome = knoxPolicies.removeWifi(ssid)

    override fun wifiPresent(w: Policy.Wifi): Boolean? = wifi.present(w)
    override fun wifiApply(w: Policy.Wifi): ItemOutcome = wifi.apply(w)
    override fun wifiPrefer(w: Policy.Wifi): ItemOutcome? = wifi.prefer(w)
    override fun wifiRemoveOwn(ssid: String, managed: Set<String>, viaKnox: Boolean): ItemOutcome = wifi.removeOwn(ssid, managed, viaKnox)
    override fun wifiConnectedSsid(): String? = wifi.connectedSsid()

    override fun storageWritable(): Boolean = files.writable()
    override fun fileState(rel: String): FileStat? = files.state(rel)
    override fun fileSha(rel: String): String? = files.sha(rel)
    override fun writeFile(rel: String, src: File, sha: String, mediaScan: Boolean): ItemOutcome = files.write(rel, src, sha, mediaScan)
    override fun deleteFile(rel: String): ItemOutcome = files.delete(rel)

    override fun homeIsAgent(): Boolean = kiosk.homeIsAgent()
    override fun appLaunchable(pkg: String): Boolean = kiosk.appLaunchable(pkg)
    override fun kioskApply(k: Policy.Kiosk?, suspended: Boolean): ItemOutcome = kiosk.apply(k, suspended) { files.writable() }

    companion object {
        /** The codes that ask something of the person holding the device (the status screen shows the matching button). */
        val DEVICE_ACTIONS = setOf(PolicyCodes.PERMISSION_MISSING, PolicyCodes.HOME_NOT_DEFAULT, PolicyCodes.ADMIN_POLICY_MISSING,
            PolicyCodes.PASSWORD_INSUFFICIENT)
    }
}
