package com.max.clipops

import android.content.Context
import android.util.Log
import com.cgutman.adblib.AdbBase64
import com.cgutman.adblib.AdbConnection
import com.cgutman.adblib.AdbCrypto
import com.sengab.adbpairing.AdbPairingClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.net.Socket
import java.util.Base64

object LocalAdbManager {
    private const val TAG = "LocalAdbManager"
    private const val PRIV_KEY = "adb_priv.key"
    private const val PUB_KEY  = "adb_pub.key"

    private var crypto: AdbCrypto? = null
    private var connection: AdbConnection? = null

    // ── Key management ───────────────────────────────────────────────────────

    fun initKeys(ctx: Context) {
        val privFile = File(ctx.filesDir, PRIV_KEY)
        val pubFile  = File(ctx.filesDir, PUB_KEY)
        val base64 = AdbBase64 { data -> Base64.getEncoder().encodeToString(data) }
        crypto = try {
            if (privFile.exists() && pubFile.exists()) {
                AdbCrypto.loadAdbKeyPair(base64, privFile, pubFile)
            } else {
                AdbCrypto.generateAdbKeyPair(base64).also {
                    it.saveAdbKeyPair(privFile, pubFile)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Key init failed", e)
            null
        }
    }

    // ── SPAKE2+ Pairing via JetBrains adblib ────────────────────────────────

    fun pairDevice(
        host: String,
        pairPort: Int,
        pairingCode: String,
        onResult: (success: Boolean, message: String) -> Unit
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val client = AdbPairingClient(host, pairPort, pairingCode)
                val success = client.pair()
                if (success) onResult(true, "Paired successfully")
                else onResult(false, "Pairing rejected by device")
            } catch (e: Exception) {
                Log.e(TAG, "Pairing error", e)
                onResult(false, e.message ?: "Unknown error")
            }
        }
    }

    // ── ADB Connect via vendored cgutman adblib ──────────────────────────────

    fun connect(
        host: String,
        port: Int,
        onResult: (success: Boolean) -> Unit
    ) {
        val keys = crypto ?: return onResult(false)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                disconnect()
                val socket = Socket(host, port)
                val conn = AdbConnection.create(socket, keys)
                conn.connect()
                connection = conn
                onResult(true)
            } catch (e: Exception) {
                Log.e(TAG, "Connect error", e)
                onResult(false)
            }
        }
    }

    fun disconnect() {
        try { connection?.close() } catch (_: Exception) {}
        connection = null
    }

    fun isConnected(): Boolean = connection != null

    // ── AppOps shell commands ────────────────────────────────────────────────

    fun setClipboardReadMode(packageName: String, isAllowed: Boolean, onResult: (Boolean) -> Unit) {
        val op = if (isAllowed) "allow" else "ignore"
        runShellCommand("cmd appops set $packageName READ_CLIPBOARD $op") { success, _ ->
            onResult(success)
        }
    }

    fun getClipboardReadMode(packageName: String, onResult: (Boolean) -> Unit) {
        runShellCommand("cmd appops get $packageName READ_CLIPBOARD") { success, output ->
            onResult(success && output.contains("allow"))
        }
    }

    private fun runShellCommand(cmd: String, callback: (Boolean, String) -> Unit) {
        val conn = connection ?: return callback(false, "Not connected")
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val stream = conn.open("shell:$cmd")
                val sb = StringBuilder()
                while (true) {
                    val data = stream.read() ?: break
                    sb.append(String(data))
                }
                stream.close()
                callback(true, sb.toString())
            } catch (e: Exception) {
                Log.e(TAG, "Shell error", e)
                callback(false, e.message ?: "")
            }
        }
    }
}
