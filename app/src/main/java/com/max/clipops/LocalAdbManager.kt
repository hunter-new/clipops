package com.max.clipops

import android.content.Context
import android.util.Base64
import android.util.Log
import com.cgutman.adblib.AdbBase64
import com.cgutman.adblib.AdbConnection
import com.cgutman.adblib.AdbCrypto
import com.cgutman.adblib.AdbStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.ConnectException
import java.net.Socket
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

object LocalAdbManager {
    private const val TAG = "LocalAdbManager"
    private var connection: AdbConnection? = null
    private var crypto: AdbCrypto? = null

    // Implementing the AdbBase64 interface required by AdbLib
    private val adbBase64 = object : AdbBase64 {
        override fun encodeToString(bArr: ByteArray?): String {
            return Base64.encodeToString(bArr, Base64.NO_WRAP)
        }
    }

    /**
     * Initializes RSA keys for ADB authentication.
     * We generate and cache them in the app's internal cache directory so the user doesn't
     * have to re-authorize ADB debugging on every app start.
     */
    fun initKeys(context: Context) {
        val dir = context.filesDir
        val privKeyFile = File(dir, "adb_priv.key")
        val pubKeyFile = File(dir, "adb_pub.key")

        try {
            if (privKeyFile.exists() && pubKeyFile.exists()) {
                Log.d(TAG, "Loading existing ADB keys")
                val privBytes = FileInputStream(privKeyFile).use { it.readBytes() }
                val pubBytes = FileInputStream(pubKeyFile).use { it.readBytes() }
                
                crypto = AdbCrypto.loadAdbKeyPair(adbBase64, privBytes, pubBytes)
            } else {
                Log.d(TAG, "Generating new ADB key pair")
                crypto = AdbCrypto.generateAdbKeyPair(adbBase64)
                
                FileOutputStream(privKeyFile).use { it.write(crypto?.getAdbPrivateKey() ?: ByteArray(0)) }
                FileOutputStream(pubKeyFile).use { it.write(crypto?.getAdbPublicKey() ?: ByteArray(0)) }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize ADB keys", e)
        }
    }

    /**
     * Is connected and authenticated with the local ADB daemon
     */
    fun isConnected(): Boolean {
        return connection != null && crypto != null
    }

    /**
     * Connect to local ADB loopback port.
     * port: The dynamic Wireless Debugging port (typically found in Wireless Debugging page)
     */
    fun connectLocal(port: Int, onResult: (Boolean, String?) -> Unit) {
        if (crypto == null) {
            onResult(false, "Crypto keys not initialized. Call initKeys first.")
            return
        }

        try {
            val socket = Socket("127.0.0.1", port)
            // Timeout after 5 seconds to prevent hanging on incorrect ports
            socket.soTimeout = 5000 
            
            val conn = AdbConnection.create(socket, crypto)
            conn.connect()
            connection = conn
            Log.d(TAG, "Successfully connected to local ADB daemon on port $port")
            onResult(true, null)
        } catch (e: ConnectException) {
            Log.e(TAG, "Connection refused. Is Wireless Debugging on port $port running?", e)
            onResult(false, "Connection refused. Please check if wireless port $port is active.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish local ADB connection", e)
            onResult(false, e.localizedMessage ?: "Unknown connection error")
        }
    }

    /**
     * Disconnects active ADB connection
     */
    fun disconnect() {
        try {
            connection?.close()
        } catch (e: Exception) {
            // ignore
        } finally {
            connection = null
        }
    }

    /**
     * Runs a raw shell command asynchronously and returns stdout + stderr
     */
    fun runShellCommand(command: String, onResult: (Boolean, String) -> Unit) {
        val conn = connection
        if (conn == null) {
            onResult(false, "Not connected to local ADB server. Please pair and connect first.")
            return
        }

        try {
            val stream: AdbStream = conn.open("shell:$command")
            val output = StringBuilder()
            val buffer = ByteArray(1024)

            while (!stream.isClosed) {
                try {
                    val read = stream.read(buffer)
                    if (read > 0) {
                        output.append(String(buffer, 0, read))
                    }
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    break
                }
            }
            onResult(true, output.toString().trim())
        } catch (e: Exception) {
            Log.e(TAG, "Error executing shell command: $command", e)
            onResult(false, e.localizedMessage ?: "Shell transaction failed")
        }
    }

    /**
     * Specialized: Queries clipboard appops status for package
     */
    fun getClipboardReadMode(packageName: String, onResult: (Int) -> Unit) {
        // cmd appops get <package> READ_CLIPBOARD
        // Output format is usually: "READ_CLIPBOARD: allow; time=... " or "READ_CLIPBOARD: ignore; time=..."
        runShellCommand("cmd appops get $packageName READ_CLIPBOARD") { success, output ->
            if (success) {
                when {
                    output.contains("allow") -> onResult(0) // MODE_ALLOWED
                    output.contains("ignore") -> onResult(1) // MODE_IGNORED
                    output.contains("deny") -> onResult(2) // MODE_ERRORED
                    else -> onResult(3) // MODE_DEFAULT (not explicitly set, default is allow)
                }
            } else {
                onResult(3)
            }
        }
    }

    /**
     * Specialized: Sets clipboard appops mode for package
     */
    fun setClipboardReadMode(packageName: String, isAllowed: Boolean, onResult: (Boolean) -> Unit) {
        val op = if (isAllowed) "allow" else "ignore"
        runShellCommand("cmd appops set $packageName READ_CLIPBOARD $op") { success, _ ->
            onResult(success)
        }
    }
}
