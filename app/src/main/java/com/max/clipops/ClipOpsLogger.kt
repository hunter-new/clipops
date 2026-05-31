package com.max.clipops

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ClipOpsLogger {
    private const val TAG = "ClipOpsLogger"
    private const val LOG_FILE = "clipops_debug.log"
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    private var logFile: File? = null

    fun init(ctx: Context) {
        logFile = File(ctx.filesDir, LOG_FILE)
        log(ctx, "=== ClipOps session started ===")
    }

    fun log(ctx: Context, message: String, level: String = "D") {
        val line = "${fmt.format(Date())} [$level] $message\n"
        Log.d(TAG, message)
        try {
            logFile?.let {
                if (!it.exists()) it.createNewFile()
                it.appendText(line)
                // Keep log under ~1MB — trim oldest half if too large
                if (it.length() > 1_000_000) {
                    val lines = it.readLines()
                    it.writeText(lines.drop(lines.size / 2).joinToString("\n") + "\n")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Logger write error", e)
        }
    }

    fun exportIntent(ctx: Context): Intent? {
        val file = logFile ?: return null
        if (!file.exists()) return null
        return try {
            val uri = FileProvider.getUriForFile(
                ctx,
                "${ctx.packageName}.fileprovider",
                file
            )
            Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "ClipOps Debug Log")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Export failed", e)
            null
        }
    }

    fun clearLog(ctx: Context) {
        logFile?.delete()
        log(ctx, "=== Log cleared ===")
    }
}
