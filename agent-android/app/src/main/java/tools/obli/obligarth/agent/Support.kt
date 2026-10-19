package tools.obli.obligarth.agent

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import tools.obli.obligarth.agent.core.AgentLog
import tools.obli.obligarth.agent.core.KeyValueStore
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** SharedPreferences, private, written synchronously (commit). */
class PrefsStore(context: Context) : KeyValueStore {
    private val prefs = context.getSharedPreferences("agent", Context.MODE_PRIVATE)

    override fun get(key: String): String? = prefs.getString(key, null)

    @SuppressLint("ApplySharedPref") // synchronous on purpose: seq is persisted before each request (RC-6)
    @Synchronized
    override fun put(changes: Map<String, String?>) {
        val e = prefs.edit()
        for ((k, v) in changes) if (v == null) e.remove(k) else e.putString(k, v)
        e.commit()
    }
}

/**
 * Local journal (private file, about 256 KiB, the older half dropped past that)
 * plus logcat. Never holds a secret: no token, no key.
 */
class LocalLog(context: Context) : AgentLog {
    private val file = File(context.filesDir, "agent.log")
    private val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT)

    override fun info(message: String) = write("I", message)
    override fun warn(message: String) = write("W", message)

    @Synchronized
    private fun write(level: String, message: String) {
        if (level == "W") Log.w(TAG, message) else Log.i(TAG, message)
        try {
            if (file.length() > MAX_BYTES) {
                val text = file.readText()
                file.writeText(text.substring(text.length / 2))
            }
            file.appendText("${format.format(Date())} $level ${message.replace('\n', ' ').take(500)}\n")
        } catch (e: Exception) {
            Log.w(TAG, "log write failed", e)
        }
    }

    @Synchronized
    fun tail(lines: Int): String = try {
        file.readLines().takeLast(lines).joinToString("\n")
    } catch (e: Exception) {
        ""
    }

    companion object {
        const val TAG = "ObligarthAgent"
        private const val MAX_BYTES = 256 * 1024L
    }
}
