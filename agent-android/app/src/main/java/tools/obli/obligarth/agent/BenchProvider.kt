package tools.obli.obligarth.agent

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.util.Log
import tools.obli.obligarth.agent.core.BenchRules

/**
 * The channel of the bench station (1.4.0, lot BANC §7.1, §7.4): `adb shell content call --uri
 * content://tools.obli.obligarth.agent.bench --method state|import|poll|prepare_owner|release [--arg …]`.
 *
 * Exported without a declared permission on purpose: every call checks the uid of the caller, and only the shell (2000,
 * adb) or root passes. A broadcast cannot tell its sender before API 34, and a receiver behind a development permission
 * (DUMP, WRITE_SECURE_SETTINGS) stays grantable to another app by `pm grant`. No query, insert, update or delete: the
 * whole channel is call(). The answers carry simple values, never a token, a configuration, a URL or an identifier.
 */
class BenchProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val uid = Binder.getCallingUid()
        // Checked here first (no work for anyone else), then again by the channel itself.
        if (!BenchRules.callerAllowed(uid)) {
            Log.w(LocalLog.TAG, "bench channel refused to uid $uid")
            throw SecurityException("bench channel: shell only")
        }
        val ctx = context ?: throw IllegalStateException("no context")
        val rt = AgentRuntime.get(ctx)
        val answer = rt.bench.call(uid, method, arg)
        return Bundle().apply {
            for ((k, v) in answer) when (v) {
                is Boolean -> putBoolean(k, v)
                is Int -> putInt(k, v)
                is Long -> putLong(k, v)
                is String -> putString(k, v)
                null -> {}
                else -> putString(k, v.toString())
            }
        }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
