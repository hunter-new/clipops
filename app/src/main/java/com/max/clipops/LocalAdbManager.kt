package com.max.clipops

import android.content.Context
import android.util.Base64
import android.util.Log
import com.cgutman.adblib.AdbBase64
import com.cgutman.adblib.AdbConnection
import com.cgutman.adblib.AdbCrypto
import com.cgutman.adblib.AdbStream
import java.io.File
import java.net.ConnectException
import java.net.Socket

object LocalAdbManager {
    private const val TAG = "LocalAdbManager"
    private var connection: AdbConnection? = null
    private var crypto: AdbCrypto? = null

    // AdbBase64 implementation using Android's Base64
    private val adbBase64 = AdbBase64 { bArr ->
        Base64.encodeToString(bArr, Base64.NO_WRAP)
    }

    /**
     * Initializes RSA keys for ADB authentication.
     * Keys are stored in the app's private files directory so the user only
     * needs to authorize once ("Always allow from this computer").
     */
    fun initKeys(context: Context) {
        val privKeyFile = File(context.filesDir, "adb_priv.key")
        val pubKeyFile  = File(context.filesDir, "adb_pub.key")

        try {
            crypto = if (privKeyFile.exists() && pubKeyFile.exists()) {
                Log.d(TAG, "Loading existing ADB keys")
                AdbCrypto.loadAdbKeyPair(adbBase64, privKeyFile, pubKeyFile)
            } else {
                Log.d(TAG, "Generating new ADB key pair")
                val newCrypto = AdbCrypto.generateAdbKeyPair(adbBase64)
                newCrypto.saveAdbKeyPair(privKeyFile, pubKeyFile)
                newCrypto
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize ADB keys", e)
        }
    }

    fun isConnected(): Boolean = connection != null && crypto != null

    /**
     * Connect to the local ADB daemon on the given Wireless Debugging port.
     */
    fun connectLocal(port: Int, onResult: (Boolean, String?) -> Unit) {
        val c = crypto
        if (c == null) {
            onResult(false, "Keys not initialized. Call initKeys() first.")
            return
        }

        Thread {
            try {
                val socket = Socket("127.0.0.1", port).apply { soTimeout = 5000 }
                val conn = AdbConnection.create(socket, c)
                conn.connect()
                connection = conn
                Log.d(TAG, "Connected to local ADB on port $port")
                onResult(true, null)
            } catch (e: ConnectException) {
                Log.e(TAG, "Connection refused on port $port", e)
                onResult(false, "Connection refused. Is Wireless Debugging active on port $port?")
            } catch (e: Exception) {
                Log.e(TAG, "ADB connection error", e)
                onResult(false, e.localizedMessage ?: "Unknown connection error")
            }
        }.start()
    }

    fun disconnect() {
        try { connection?.close() } catch (_: Exception) {}
        connection = null
    }

    /**
     * Run a shell command and return stdout.
     */
    fun runShellCommand(command: String, onResult: (Boolean, String) -> Unit) {
        val conn = connection
        if (conn == null) {
            onResult(false, "Not connected. Please connect to local ADB first.")
            return
        }

        Thread {
            try {
                val stream: AdbStream = conn.open("shell:$command")
                val output = StringBuilder()
                while (!stream.isClosed) {
                    val data = stream.read()        // returns ByteArray, no args
                    output.append(String(data))
                }
                onResult(true, output.toString().trim())
            } catch (e: Exception) {
                Log.e(TAG, "Shell command failed: $command", e)
                onResult(false, e.localizedMessage ?: "Shell transaction failed")
            }
        }.start()
    }

    fun getClipboardReadMode(packageName: String, onResult: (Int) -> Unit) {
        runShellCommand("cmd appops get $packageName READ_CLIPBOARD") { success, output ->
            if (!success) { onResult(3); return@runShellCommand }
            onResult(when {
                output.contains("allow")  -> 0  // MODE_ALLOWED
                output.contains("ignore") -> 1  // MODE_IGNORED
                output.contains("deny")   -> 2  // MODE_ERRORED
                else                      -> 3  // MODE_DEFAULT
            })
        }
    }

    fun setClipboardReadMode(packageName: String, isAllowed: Boolean, onResult: (Boolean) -> Unit) {
        val op = if (isAllowed) "allow" else "ignore"
        runShellCommand("cmd appops set $packageName READ_CLIPBOARD $op") { success, _ ->
            onResult(success)
        }
    }
}
