package tools.obli.obligarth.agent

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import tools.obli.obligarth.agent.core.AgentLog

/**
 * 1.4.0: the guided choice of the agent as the default home, for the person holding the device ("finish the update"):
 * one big button, then "Agent Obligarth" and "Always" in the system chooser. The choice another launcher holds is reset
 * first (KioskController.resetHomeChoice); when the system keeps it, the button opens the screen where it is changed
 * (the home settings, else the details of that launcher, "Clear defaults"). Back is ignored while the kiosk waits for
 * its home. Opened on unlock (UnlockReceiver), by the policy itself while the screen is on (KioskController, every
 * 20 min), by the notification of the policy, or by the action FINISH_SETUP (a MobiControl `sendintent`).
 */
class HomeSetupActivity : Activity() {
    private lateinit var title: TextView
    private lateinit var steps: TextView
    private lateinit var button: Button
    private var fallback = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val pad = dp(24)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(Color.WHITE)
        }
        root.addView(ImageView(this).apply { setImageResource(R.drawable.ic_agent) }, LinearLayout.LayoutParams(dp(96), dp(96)))
        title = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 30f)
            setTextColor(Color.BLACK)
            gravity = Gravity.CENTER
            setPadding(0, pad, 0, pad / 2)
        }
        root.addView(title)
        steps = TextView(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(Color.DKGRAY)
            setLineSpacing(0f, 1.3f)
            setPadding(0, 0, 0, pad)
        }
        root.addView(steps)
        button = Button(this).apply {
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply { setColor(GREEN); cornerRadius = dp(16).toFloat() }
            setPadding(pad, pad / 2, pad, pad / 2)
            setOnClickListener { go() }
        }
        root.addView(button, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(88)))
        setContentView(root)
    }

    override fun onResume() {
        super.onResume()
        val kiosk = AgentRuntime.get(this).policyApplier.kiosk
        when {
            // Nothing to choose: no kiosk of this agent (the alias off), or already its home.
            !kiosk.aliasEnabled() -> finish()
            kiosk.homeIsAgent() -> done()
            else -> render()
        }
    }

    private fun render() {
        title.text = getString(R.string.home_setup_title)
        steps.text = getString(if (fallback) R.string.home_setup_steps_clear else R.string.home_setup_steps, getString(R.string.app_name))
        button.text = getString(R.string.home_setup_button)
    }

    private fun done() {
        title.text = getString(R.string.home_setup_done)
        steps.text = ""
        button.text = getString(R.string.home_setup_open)
        button.setOnClickListener { openHome() }
        button.postDelayed({ if (!isFinishing) openHome() }, 1_500)
    }

    private fun go() {
        val rt = AgentRuntime.get(this)
        val kiosk = rt.policyApplier.kiosk
        if (kiosk.resetHomeChoice()) {
            fallback = false
            openHome()
            return
        }
        // The system keeps the other launcher: its choice is cleared by hand.
        fallback = true
        render()
        val current = kiosk.defaultHome()
        val home = Intent(Settings.ACTION_HOME_SETTINGS)
        val i = if (home.resolveActivity(packageManager) != null) home
        else Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", current, null))
        try {
            startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: Exception) {
            rt.log.warn("home setup: ${e.javaClass.simpleName}")
        }
    }

    private fun openHome() {
        try {
            startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: Exception) {
            AgentRuntime.get(this).log.warn("home setup: ${e.javaClass.simpleName}")
        }
        finish()
    }

    @Deprecated("Back is ignored: the kiosk waits for its home")
    override fun onBackPressed() = Unit

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    companion object {
        const val ACTION_FINISH_SETUP = "tools.obli.obligarth.agent.action.FINISH_SETUP"
        private val GREEN = Color.rgb(0x2E, 0x9E, 0x4F)

        fun intent(ctx: Context): Intent = Intent(ctx, HomeSetupActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)

        /**
         * Opens the screen by itself (no MobiControl needed), screen on, at most every [minIntervalMs] (one clock shared
         * by the unlock and the policy). Android 7 to 9 let a background app start an activity; from Android 10 it needs
         * "display over other apps", the notification remaining otherwise.
         */
        fun prompt(ctx: Context, minIntervalMs: Long, log: AgentLog): Boolean {
            val app = ctx.applicationContext
            if (!(app.getSystemService(Context.POWER_SERVICE) as PowerManager).isInteractive) return false
            val prefs = app.getSharedPreferences("unlock", Context.MODE_PRIVATE)
            val now = SystemClock.elapsedRealtime()
            val last = prefs.getLong("lastHomePrompt", 0L)
            if (last in 1..now && now - last < minIntervalMs) return false
            prefs.edit().putLong("lastHomePrompt", now).apply()
            return try {
                app.startActivity(intent(app))
                true
            } catch (e: Exception) {
                log.warn("home prompt: ${e.javaClass.simpleName}: ${e.message}")
                false
            }
        }
    }
}
