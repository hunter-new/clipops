package com.max.clipops

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import android.widget.LinearLayout
import android.view.inputmethod.EditorInfo
import com.cgutman.adblib.AdbBase64
import com.cgutman.adblib.AdbCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.util.Base64

class PairingCodeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val port = intent.getIntExtra("discovered_pair_port", 0)
        val host = intent.getStringExtra("discovered_pair_host") ?: "127.0.0.1"

        ClipOpsLogger.log(this, "PairingCodeActivity: opened with host=$host port=$port")

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * resources.displayMetrics.density).toInt()
            setPadding(pad, 0, pad, 0)
        }

        val til = TextInputLayout(this).apply {
            hint = "Pairing code + port (e.g. 123456 40983)"
        }
        val input = TextInputEditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                        android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = EditorInfo.IME_ACTION_DONE
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        til.addView(input)
        container.addView(til)

        AlertDialog.Builder(this)
            .setTitle("Enter pairing code")
            .setMessage("Type the 6-digit code and port shown on the Wireless Debugging screen, separated by a space.")
            .setView(container)
            .setPositiveButton("Pair") { _, _ ->
                val parts = input.text.toString().trim().split("\\s+".toRegex())
                val code = parts.getOrNull(0) ?: ""
                val inputPort = parts.getOrNull(1)?.toIntOrNull() ?: 0
                val resolvedPort = if (inputPort > 0) inputPort else port

                if (code.length != 6 || !code.all { it.isDigit() }) {
                    Toast.makeText(this, "Code must be 6 digits", Toast.LENGTH_SHORT).show()
                    finish()
                    return@setPositiveButton
                }
                if (resolvedPort <= 0) {
                    Toast.makeText(this, "Please enter a valid port", Toast.LENGTH_SHORT).show()
                    finish()
                    return@setPositiveButton
                }

                ClipOpsLogger.log(this, "PairingCodeActivity: starting SPAKE2 pairing host=$host port=$resolvedPort")
                Toast.makeText(this, "Pairing…", Toast.LENGTH_SHORT).show()

                val ctx = this
                CoroutineScope(Dispatchers.IO).launch {
                    // Load / generate RSA key pair
                    val privFile = File(ctx.filesDir, "adb_priv.key")
                    val pubFile  = File(ctx.filesDir, "adb_pub.key")
                    val base64   = AdbBase64 { data -> Base64.getEncoder().encodeToString(data) }
                    val crypto   = try {
                        if (privFile.exists() && pubFile.exists()) {
                            AdbCrypto.loadAdbKeyPair(base64, privFile, pubFile)
                        } else {
                            AdbCrypto.generateAdbKeyPair(base64).also {
                                it.saveAdbKeyPair(privFile, pubFile)
                            }
                        }
                    } catch (e: Exception) {
                        ClipOpsLogger.log(ctx, "key init failed: ${e.message}", "E")
                        runOnUiThread {
                            Toast.makeText(ctx, "Key error: ${e.message}", Toast.LENGTH_LONG).show()
                            finish()
                        }
                        return@launch
                    }

                    val pubKeyPayload = try {
                        crypto.adbPublicKeyPayload
                    } catch (e: Exception) {
                        ClipOpsLogger.log(ctx, "pubkey encode failed: ${e.message}", "E")
                        runOnUiThread {
                            Toast.makeText(ctx, "Key encode error: ${e.message}", Toast.LENGTH_LONG).show()
                            finish()
                        }
                        return@launch
                    }

                    val errMsg = AdbSpake2Pairing.pair(
                        host         = host,
                        port         = resolvedPort,
                        pairingCode  = code,
                        rsaPubKeyPayload = pubKeyPayload
                    ) { msg -> ClipOpsLogger.log(ctx, "SPAKE2: $msg") }

                    runOnUiThread {
                        if (errMsg.isEmpty()) {
                            Toast.makeText(ctx, "Paired! Now search to connect.", Toast.LENGTH_LONG).show()
                        } else {
                            Toast.makeText(ctx, "Pairing failed: $errMsg", Toast.LENGTH_LONG).show()
                        }
                        finish()
                    }
                }
            }
            .setNegativeButton("Cancel") { _, _ -> finish() }
            .setOnDismissListener { finish() }
            .show()
            .window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
    }
}
