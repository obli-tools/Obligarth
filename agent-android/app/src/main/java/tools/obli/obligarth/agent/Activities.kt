package tools.obli.obligarth.agent

import android.Manifest
import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import tools.obli.obligarth.agent.core.KnoxLicence
import tools.obli.obligarth.agent.core.Phase
import tools.obli.obligarth.agent.core.PolicyCodes
import java.text.DateFormat
import java.util.Date

/**
 * Status and activation screen (spec §8.2 SetupActivity), exported with the
 * action ACTIVATE_ADMIN: "Enable administration" button, READ_PHONE_STATE
 * request, manual configuration as a last resort.
 */
class SetupActivity : Activity() {
    private lateinit var statusView: TextView
    private lateinit var policyView: TextView
    private lateinit var storageButton: Button
    private lateinit var locationButton: Button
    private lateinit var homeButton: Button
    private lateinit var grantButton: Button
    private lateinit var passwordButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val rt = AgentRuntime.get(this)
        PollScheduler.ensurePeriodic(this)
        rt.refreshStatusNotification()
        Thread { ConfigFile.importIfPresent(rt) }.start()
        importFromIntent(intent)
        // The MobiControl script runs again with each new version of the package: once the
        // administrator is on, the activation request ends here without showing anything.
        if (intent?.action == ACTION_ACTIVATE_ADMIN && rt.facts.adminActive()) {
            finish()
            return
        }

        val pad = dp(16)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        root.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
        })
        statusView = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(0, pad / 2, 0, pad)
        }
        root.addView(statusView)

        root.addView(button(R.string.action_activate_admin) { requestAdmin() })
        root.addView(button(R.string.action_phone_permission) {
            requestPermissions(arrayOf(Manifest.permission.READ_PHONE_STATE), 1)
        })
        root.addView(button(R.string.action_poll_now) {
            PollScheduler.pollNow(this)
            Toast.makeText(this, R.string.toast_poll_requested, Toast.LENGTH_SHORT).show()
        })

        // 1.3.0 (lot PONT-POL): the policy card, and what the policy needs from the person holding the device.
        policyView = TextView(this).apply {
            setTextIsSelectable(true)
            setPadding(0, pad, 0, pad / 2)
        }
        root.addView(policyView)
        storageButton = button(R.string.action_storage_permission) {
            requestPermissions(arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE, Manifest.permission.READ_EXTERNAL_STORAGE), REQUEST_STORAGE)
        }.also { root.addView(it) }
        // preferOver (C2): the Wi-Fi scan needs the location permission (and the location on).
        locationButton = button(R.string.action_location_permission) {
            if (checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION), REQUEST_STORAGE)
            } else try {
                startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
            } catch (e: Exception) {
                rt.log.warn("location settings: ${e.javaClass.simpleName}")
            }
        }.also { root.addView(it) }
        homeButton = button(R.string.action_set_home) { setAsHome() }.also { root.addView(it) }
        grantButton = button(R.string.action_grant_admin_policies) { grantAdminPolicies() }.also { root.addView(it) }
        passwordButton = button(R.string.action_change_password) {
            try {
                startActivity(Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD))
            } catch (e: Exception) {
                rt.log.warn("password change screen: ${e.javaClass.simpleName}")
            }
        }.also { root.addView(it) }

        root.addView(TextView(this).apply {
            text = getString(R.string.manual_config_label)
            setPadding(0, pad, 0, 0)
        })
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            minLines = 2
        }
        root.addView(input)
        root.addView(button(R.string.action_import_config) {
            val raw = input.text.toString()
            Thread {
                val refusal = rt.importConfig(raw, "manual")
                runOnUiThread {
                    val msg = if (refusal == null) getString(R.string.config_accepted) else getString(R.string.config_refused, refusal)
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
                    if (refusal == null) input.setText("")
                    render()
                }
            }.start()
        })

        setContentView(ScrollView(this).apply { addView(root) })
        if (intent?.action == ACTION_ACTIVATE_ADMIN && !rt.facts.adminActive()) requestAdmin()
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        importFromIntent(intent)
        if (intent.action == ACTION_ACTIVATE_ADMIN && !AgentRuntime.get(this).facts.adminActive()) requestAdmin()
    }

    /**
     * The activity also takes the "config" extra: an app never launched is in the
     * stopped state and may miss the CONFIGURE broadcast, whereas starting this
     * activity always works (one sendintent -a line configures and activates).
     */
    private fun importFromIntent(intent: Intent?) {
        val raw = intent?.getStringExtra("config") ?: return
        intent.removeExtra("config")
        val rt = AgentRuntime.get(this)
        Thread {
            val refusal = rt.importConfig(raw, "intent")
            if (refusal != null) rt.log.warn("configuration (activity) refused: $refusal")
            runOnUiThread { render() }
        }.start()
    }

    private fun requestAdmin() {
        val rt = AgentRuntime.get(this)
        if (rt.facts.adminActive()) {
            Toast.makeText(this, R.string.admin_already_active, Toast.LENGTH_SHORT).show()
            return
        }
        openAdminSettings()
    }

    /**
     * The list of administrators of the Settings first: the screen that opens under the
     * MobiControl lockdown, where the direct activation screen (ACTION_ADD_DEVICE_ADMIN)
     * is closed at once. One more tap ("Obligarth Agent", then ACTIVATE), but it opens.
     */
    private fun openAdminSettings() {
        val rt = AgentRuntime.get(this)
        val candidates = listOf(
            Intent().setComponent(ComponentName("com.android.settings", "com.android.settings.DeviceAdminSettings")),
            Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, rt.facts.adminComponent())
                .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, getString(R.string.admin_explanation)),
            Intent(Settings.ACTION_SECURITY_SETTINGS),
        )
        for (i in candidates) {
            try {
                startActivity(i)
                Toast.makeText(this, R.string.admin_settings_hint, Toast.LENGTH_LONG).show()
                return
            } catch (e: Exception) {
                rt.log.warn("administrator settings (${i.component ?: i.action}): ${e.javaClass.simpleName}")
            }
        }
    }

    private fun render() {
        if (!::statusView.isInitialized) return
        val rt = AgentRuntime.get(this)
        val s = rt.state
        val yes = getString(R.string.yes)
        val no = getString(R.string.no)
        val phase = when (s.phase) {
            Phase.NEW -> getString(R.string.phase_new)
            Phase.CONFIGURED -> getString(R.string.phase_configured)
            Phase.ENROLLED -> getString(R.string.phase_enrolled)
            Phase.TOKEN_REJECTED -> getString(R.string.phase_token_rejected)
            Phase.REVOKED -> getString(R.string.status_revoked)
        }
        val lastPoll = if (s.lastPollAt > 0) DateFormat.getDateTimeInstance().format(Date(s.lastPollAt * 1000)) else "-"
        val phonePerm = checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED
        statusView.text = listOf(
            getString(R.string.label_state) to phase,
            getString(R.string.label_server) to (s.config?.host ?: "-"),
            getString(R.string.label_agent) to (s.agentId ?: "-"),
            getString(R.string.label_admin) to (if (rt.facts.adminActive()) yes else no),
            getString(R.string.label_owner) to (if (rt.facts.deviceOwner()) yes else no),
            getString(R.string.label_knox) to knoxLabel(rt.knox.state()),
            getString(R.string.label_phone) to (if (phonePerm) yes else no),
            getString(R.string.label_last_poll) to lastPoll,
            getString(R.string.label_last_status) to (s.lastStatus ?: "-"),
            getString(R.string.label_version) to "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
        ).joinToString("\n") { (k, v) -> "$k : $v" }
        renderPolicy()
    }

    /** The policy card (1.3.0): hash, state and counts of the last report; the buttons of what it needs. */
    private fun renderPolicy() {
        if (!::policyView.isInitialized) return
        val rt = AgentRuntime.get(this)
        val s = rt.state
        val report = s.policyReport
        val hash = s.policyHash
        val codes = report?.items.orEmpty().filter { it.state != "compliant" }.map { it.code }.toSet()
        val counts = report?.items.orEmpty().groupingBy { it.state }.eachCount()
        policyView.text = if (hash == null) getString(R.string.policy_none) else listOf(
            getString(R.string.label_policy) to hash.take(8),
            getString(R.string.label_policy_state) to (report?.state ?: "-"),
            getString(R.string.label_policy_items) to listOf("compliant", "non_compliant", "pending", "pending_licence", "error")
                .joinToString(" / ") { "${counts[it] ?: 0}" },
        ).joinToString("\n") { (k, v) -> "$k : $v" }
        val storageMissing = checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED
        storageButton.visibility = if (hash != null && storageMissing) View.VISIBLE else View.GONE
        val scanBlocked = report?.items.orEmpty().any { it.detail == WifiApplier.SCAN_UNAVAILABLE || it.detail == WifiApplier.LOCATION_OFF }
        locationButton.visibility = if (hash != null && scanBlocked) View.VISIBLE else View.GONE
        homeButton.visibility = if (PolicyCodes.HOME_NOT_DEFAULT in codes) View.VISIBLE else View.GONE
        grantButton.visibility = if (PolicyCodes.ADMIN_POLICY_MISSING in codes) View.VISIBLE else View.GONE
        passwordButton.visibility = if (PolicyCodes.PASSWORD_INSUFFICIENT in codes) View.VISIBLE else View.GONE
    }

    @Deprecated("Activity result API of the platform")
    @Suppress("DEPRECATION")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_STORAGE) {
            AgentRuntime.get(this).requestReconcile()
            render()
        }
    }

    /**
     * The kiosk needs the agent as the default home: the system chooser ("Always"), or, when another launcher holds
     * the default, its app details so its defaults can be cleared first.
     */
    private fun setAsHome() {
        val rt = AgentRuntime.get(this)
        val current = rt.policyApplier.kiosk.defaultHome()
        val i = if (current != null && current != "android" && current != packageName) {
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", current, null))
        } else Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        try {
            startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: Exception) {
            rt.log.warn("set as home: ${e.javaClass.simpleName}")
        }
    }

    /** D12: the policies declared since the activation granted by the system's refresh screen (one tap). */
    private fun grantAdminPolicies() {
        val rt = AgentRuntime.get(this)
        try {
            startActivity(
                Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                    .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, rt.facts.adminComponent())
                    .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, getString(R.string.admin_policies_explanation)),
            )
        } catch (e: Exception) {
            rt.log.warn("grant admin policies: ${e.javaClass.simpleName}")
            openAdminSettings()
        }
    }

    /** The state shown, translated; the code itself goes to the server as is (AndroidFacts). */
    private fun knoxLabel(state: String): String = when (state) {
        KnoxLicence.ABSENT -> getString(R.string.knox_state_absent)
        KnoxLicence.PRESENT -> getString(R.string.knox_state_present)
        KnoxLicence.LICENSED -> getString(R.string.knox_state_licensed)
        KnoxLicence.LICENSE_ERROR -> getString(R.string.knox_state_license_error)
        else -> state
    }

    private fun button(label: Int, onClick: () -> Unit) = Button(this).apply {
        text = getString(label)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    companion object {
        const val ACTION_ACTIVATE_ADMIN = "tools.obli.obligarth.agent.action.ACTIVATE_ADMIN"
        private const val REQUEST_STORAGE = 2
    }
}

/** Full-screen message (device.message, mode fullscreen). */
class MessageActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        window.addFlags(
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
        )
        val pad = (24 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(pad, pad, pad, pad)
        }
        root.addView(TextView(this).apply {
            text = intent.getStringExtra(EXTRA_TITLE)?.ifEmpty { null } ?: getString(R.string.app_name)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 26f)
            gravity = Gravity.CENTER
        })
        root.addView(TextView(this).apply {
            text = intent.getStringExtra(EXTRA_TEXT) ?: ""
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            gravity = Gravity.CENTER
            setPadding(0, pad, 0, pad)
        })
        root.addView(Button(this).apply {
            text = getString(android.R.string.ok)
            setOnClickListener { finish() }
        })
        setContentView(root)
    }

    companion object {
        private const val EXTRA_TITLE = "title"
        private const val EXTRA_TEXT = "text"

        fun intent(ctx: Context, title: String, text: String): Intent =
            Intent(ctx, MessageActivity::class.java).putExtra(EXTRA_TITLE, title).putExtra(EXTRA_TEXT, text)
                .addFlags(Intent.FLAG_ACTIVITY_MULTIPLE_TASK or Intent.FLAG_ACTIVITY_NEW_DOCUMENT)
    }
}
