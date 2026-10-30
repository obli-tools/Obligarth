package tools.obli.obligarth.agent

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.GridView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import tools.obli.obligarth.agent.core.AgentEngine
import tools.obli.obligarth.agent.core.KioskModel
import tools.obli.obligarth.agent.core.Policy
import java.io.File
import java.text.DateFormat
import java.util.Date

/**
 * The soft kiosk (1.3.0, lot PONT-POL §10.5): the HOME screen of the agent while the policy enables a kiosk (alias
 * KioskHome). A header (logo or name, title, device name), a grid of tiles that launch an app, open an http(s) URL or
 * fire a sanitised intent (B1), never the agent itself. Five taps on the header within 3 s open the exit PIN dialog
 * (PBKDF2, lockout D7); the panel then leaves the kiosk for 15 minutes, opens the agent status or the Android settings.
 * While suspended, a banner shows the time left and Settings and All apps tiles are added. Back is ignored. All the UI
 * is built in code, and the model is read off the main thread (the engine lock may wait on the network).
 */
class KioskActivity : Activity() {
    private lateinit var root: LinearLayout
    private val taps = ArrayList<Long>()

    /** What the screen shows, read from the engine. */
    private class Model(val kiosk: Policy.Kiosk, val suspendedUntil: Long, val images: Map<String, File>)

    private sealed class Entry {
        class TileEntry(val tile: Policy.Tile) : Entry()
        object SettingsEntry : Entry()
        object AllAppsEntry : Entry()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
        }
        setContentView(root)
        lastModel?.let { render(it) }
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    @Deprecated("Back is ignored in the kiosk")
    @Suppress("DEPRECATION", "MissingSuperCall")
    override fun onBackPressed() {
        // Ignored: the kiosk is the home screen.
    }

    /**
     * Reads the model and draws it. Never a HOME that closes itself while the alias holds HOME (a loop with no exit):
     * without a kiosk to show, the last one shown stays while the alias is on, or, with none, the alias and the agent's
     * Knox kiosk are released (the stock launcher takes over) before the screen closes.
     */
    private fun load() {
        val app = applicationContext
        Thread({
            val rt = AgentRuntime.get(app)
            val snap = rt.engine.policySnapshot()
            val k = snap.policy?.kiosk
            var model = if (k == null || !k.enabled) null else {
                val shas = listOfNotNull(k.logo?.sha256) + k.tiles.mapNotNull { it.image?.sha256 }
                Model(k, snap.kioskSuspendedUntil, shas.mapNotNull { sha -> rt.engine.blobCache.file(sha)?.let { sha to it } }.toMap())
            }
            val kioskCtl = rt.policyApplier.kiosk
            if (model == null && kioskCtl.aliasEnabled()) {
                model = lastModel?.let { Model(it.kiosk, snap.kioskSuspendedUntil, it.images) }
                if (model == null) try { kioskCtl.releaseOrphanHome() } catch (e: Exception) { rt.log.warn("kiosk release: ${e.javaClass.simpleName}") }
            }
            lastModel = model
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                if (model == null) finish() else {
                    render(model)
                    launchOnStartOnce(model)
                }
            }
        }, "obligarth-kiosk").start()
    }

    /** The end of a suspension redraws the screen (the banner, the Settings and All apps tiles go). */
    private val expiry = Runnable { if (!isFinishing) load() }

    private fun suspended(m: Model) = KioskModel.suspended(m.suspendedUntil, System.currentTimeMillis() / 1000)

    private fun render(m: Model) {
        root.removeAllViews()
        root.removeCallbacks(expiry)
        if (suspended(m)) root.postDelayed(expiry, (m.suspendedUntil - System.currentTimeMillis() / 1000 + 1).coerceIn(1, 86_400) * 1000)
        val pad = dp(12)
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(pad, pad, pad, pad)
            setOnClickListener { headerTap() }
        }
        val logo = m.kiosk.logo?.let { m.images[it.sha256] }?.let { decodeSampled(it, dp(48)) }
        if (logo != null) header.addView(ImageView(this).apply { setImageBitmap(logo) }, LinearLayout.LayoutParams(dp(48), dp(48)))
        else header.addView(TextView(this).apply {
            text = getString(R.string.app_name)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
            setTypeface(typeface, Typeface.BOLD)
        })
        header.addView(TextView(this).apply {
            text = m.kiosk.title ?: ""
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            setPadding(pad, 0, pad, 0)
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        if (m.kiosk.showDeviceName && m.kiosk.deviceName != null) header.addView(TextView(this).apply {
            text = m.kiosk.deviceName
            setTextColor(Color.GRAY)
        })
        root.addView(header)
        if (suspended(m)) root.addView(TextView(this).apply {
            text = getString(R.string.kiosk_suspended_banner, DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(m.suspendedUntil * 1000)))
            setBackgroundColor(0xFFFFF3CD.toInt())
            setPadding(pad, pad / 2, pad, pad / 2)
        })
        val entries = m.kiosk.tiles.map { Entry.TileEntry(it) } + if (suspended(m)) listOf(Entry.SettingsEntry, Entry.AllAppsEntry) else emptyList()
        root.addView(GridView(this).apply {
            numColumns = m.kiosk.columns
            verticalSpacing = pad
            horizontalSpacing = pad
            setPadding(pad, pad, pad, pad)
            adapter = TileAdapter(entries, m)
            setOnItemClickListener { _, _, position, _ -> open(entries[position]) }
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    }

    private inner class TileAdapter(val entries: List<Entry>, val m: Model) : BaseAdapter() {
        override fun getCount() = entries.size
        override fun getItem(position: Int) = entries[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val e = entries[position]
            val size = dp(64)
            val cell = LinearLayout(this@KioskActivity).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
            }
            val image = ImageView(this@KioskActivity)
            val label: String
            when (e) {
                is Entry.TileEntry -> {
                    label = e.tile.label
                    // B13: decoded sampled; unreadable, the app icon, else a letter.
                    val bmp = e.tile.image?.let { m.images[it.sha256] }?.let { decodeSampled(it, size) }
                    if (bmp != null) image.setImageBitmap(bmp) else image.setImageDrawable(appIcon(e.tile))
                }
                Entry.SettingsEntry -> { label = getString(R.string.kiosk_tile_settings); image.setImageResource(android.R.drawable.ic_menu_preferences) }
                Entry.AllAppsEntry -> { label = getString(R.string.kiosk_tile_all_apps); image.setImageResource(android.R.drawable.ic_menu_more) }
            }
            if (image.drawable == null) cell.addView(TextView(this@KioskActivity).apply {
                text = label.take(1).uppercase()
                gravity = Gravity.CENTER
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 28f)
                setBackgroundColor(0xFFE0E0E0.toInt())
            }, LinearLayout.LayoutParams(size, size))
            else cell.addView(image, LinearLayout.LayoutParams(size, size))
            cell.addView(TextView(this@KioskActivity).apply {
                text = label
                maxLines = 2
                gravity = Gravity.CENTER
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTextColor(0xFF666666.toInt())
                setTypeface(typeface, Typeface.BOLD)
            })
            return cell
        }
    }

    private fun appIcon(t: Policy.Tile): Drawable? {
        val pkg = t.action.pkg ?: return null
        return try { packageManager.getApplicationIcon(pkg) } catch (e: PackageManager.NameNotFoundException) { null }
    }

    /** B13: the bounds first, then a power-of-two sample to fit [px]; any failure (out of memory included) gives null. */
    private fun decodeSampled(f: File, px: Int): Bitmap? = try {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(f.path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) null else {
            var sample = 1
            while (bounds.outWidth / (sample * 2) >= px && bounds.outHeight / (sample * 2) >= px) sample *= 2
            BitmapFactory.decodeFile(f.path, BitmapFactory.Options().apply { inSampleSize = sample })
        }
    } catch (e: Exception) {
        null
    } catch (e: OutOfMemoryError) {
        null
    }

    // ---- Tile actions (B1) ----

    private fun open(e: Entry) {
        // The suspension may have ended since the screen was drawn: its entries are refused then, and the screen redrawn.
        val m = lastModel
        if (e !is Entry.TileEntry && (m == null || !suspended(m))) { load(); return }
        when (e) {
            is Entry.TileEntry -> launch(e.tile)
            Entry.SettingsEntry -> start(Intent(Settings.ACTION_SETTINGS))
            Entry.AllAppsEntry -> allApps()
        }
    }

    private fun launch(t: Policy.Tile) {
        if (KioskModel.actionRefusal(t.action) != null) return toast(R.string.kiosk_tile_refused)
        val intent = when (t.action.type) {
            "app" -> packageManager.getLaunchIntentForPackage(t.action.pkg!!) ?: return toast(R.string.kiosk_app_missing)
            "url" -> Intent(Intent.ACTION_VIEW, Uri.parse(t.action.url)).apply {
                t.action.pkg?.takeIf { !tools.obli.obligarth.agent.core.PathRules.isOwnPackage(it) }?.let { setPackage(it) }
            }
            else -> sanitized(t.action.uri!!) ?: return toast(R.string.kiosk_tile_refused)
        }
        start(intent)
    }

    /**
     * An intent tile: parsed, its selector dropped, a component of the agent cleared, its flags reduced to NEW_TASK (no
     * grant of a URI permission), a file or content data refused, and it must resolve to another package than ours.
     */
    private fun sanitized(uri: String): Intent? = try {
        val i = Intent.parseUri(uri, Intent.URI_INTENT_SCHEME)
        i.selector = null
        if (i.component?.packageName == packageName) i.component = null
        if (i.`package` == packageName) i.`package` = null
        i.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        val scheme = i.data?.scheme?.lowercase()
        val target = packageManager.resolveActivity(i, 0)?.activityInfo?.packageName
        if (scheme == "file" || scheme == "content" || target == null || target == packageName) null else i
    } catch (e: Exception) {
        null
    }

    private fun start(i: Intent) {
        try {
            startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: Exception) {
            toast(R.string.kiosk_tile_failed)
        }
    }

    private fun toast(res: Int) = Toast.makeText(this, res, Toast.LENGTH_SHORT).show()

    private fun allApps() {
        val main = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = packageManager.queryIntentActivities(main, 0)
            .filter { it.activityInfo.packageName != packageName }
            .sortedBy { it.loadLabel(packageManager).toString().lowercase() }
        val labels = apps.map { it.loadLabel(packageManager).toString() }.toTypedArray()
        AlertDialog.Builder(this).setTitle(R.string.kiosk_tile_all_apps).setItems(labels) { _, which ->
            packageManager.getLaunchIntentForPackage(apps[which].activityInfo.packageName)?.let { start(it) }
        }.show()
    }

    /** launchOnStart: the tiles marked so are fired once after each boot. */
    private fun launchOnStartOnce(m: Model) {
        val prefs = getSharedPreferences("kiosk", Context.MODE_PRIVATE)
        val boot = (System.currentTimeMillis() - SystemClock.elapsedRealtime()) / 60_000
        val last = prefs.getLong("launchedBoot", 0L)
        if (Math.abs(last - boot) <= 1 || suspended(m)) return
        prefs.edit().putLong("launchedBoot", boot).apply()
        m.kiosk.tiles.firstOrNull { it.launchOnStart }?.let { launch(it) }
    }

    // ---- Admin exit (D7) ----

    private fun headerTap() {
        val now = SystemClock.elapsedRealtime()
        taps += now
        taps.removeAll { now - it > 3_000 }
        if (taps.size >= 5) {
            taps.clear()
            pinDialog()
        }
    }

    private fun pinDialog() {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.kiosk_pin_hint)
        }
        AlertDialog.Builder(this).setTitle(R.string.kiosk_pin_title).setView(input)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val pin = input.text.toString()
                input.setText("")
                val app = applicationContext
                Thread({
                    val r = AgentRuntime.get(app).engine.checkKioskPin(pin)
                    runOnUiThread { onPin(r) }
                }, "obligarth-kiosk-pin").start()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun onPin(r: AgentEngine.PinCheck) {
        if (isFinishing) return
        when (r) {
            AgentEngine.PinCheck.Ok -> adminPanel()
            is AgentEngine.PinCheck.Wrong -> Toast.makeText(this, getString(R.string.kiosk_pin_wrong, r.left), Toast.LENGTH_SHORT).show()
            is AgentEngine.PinCheck.Locked -> Toast.makeText(this, getString(R.string.kiosk_pin_locked, (r.seconds + 59) / 60), Toast.LENGTH_LONG).show()
            AgentEngine.PinCheck.NoKiosk -> load()
        }
    }

    private fun adminPanel() {
        val items = arrayOf(
            getString(R.string.kiosk_admin_leave, KioskModel.PIN_EXIT_MINUTES), getString(R.string.kiosk_admin_status),
            getString(R.string.kiosk_admin_settings),
        )
        AlertDialog.Builder(this).setTitle(R.string.kiosk_admin_title).setItems(items) { _, which ->
            when (which) {
                0 -> {
                    val app = applicationContext
                    Thread({
                        val rt = AgentRuntime.get(app)
                        rt.engine.suspendKioskByPin(KioskModel.PIN_EXIT_MINUTES)
                        runOnUiThread { load() }
                    }, "obligarth-kiosk-exit").start()
                }
                1 -> start(Intent(this, SetupActivity::class.java))
                else -> start(Intent(Settings.ACTION_SETTINGS))
            }
        }.show()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    companion object {
        /** The last model shown, so a recreated screen draws at once. */
        @Volatile private var lastModel: Model? = null
    }
}
