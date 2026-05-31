package com.max.clipops

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import android.widget.*
import androidx.appcompat.app.AlertDialog

class PairingCodeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val connPort = intent.getIntExtra("conn_port", 0)

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * resources.displayMetrics.density).toInt()
            setPadding(pad, 0, pad, 0)
        }

        // Instruction
        val instruction = TextView(this).apply {
            text = "1. Open Settings → Developer Options → Wireless Debugging\n" +
                   "2. Note the port shown (e.g. 192.168.4.x:XXXXX)\n" +
                   "3. Enter that port below and tap Connect\n" +
                   "4. ⚠️ Tap \"Always allow\" on the dialog that appears"
            setPadding(0, 0, 0, (16 * resources.displayMetrics.density).toInt())
        }
        container.addView(instruction)

        val til = com.google.android.material.textfield.TextInputLayout(this).apply {
            hint = "Connection port (e.g. 38247)"
        }
        val input = com.google.android.material.textfield.TextInputEditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            if (connPort > 0) setText(connPort.toString())
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        til.addView(input)
        container.addView(til)

        AlertDialog.Builder(this)
            .setTitle("Connect to Wireless Debugging")
            .setView(container)
            .setPositiveButton("Connect") { _, _ ->
                val port = input.text.toString().trim().toIntOrNull()
                if (port == null || port < 1024 || port > 65535) {
                    Toast.makeText(this, "Enter a valid port number", Toast.LENGTH_SHORT).show()
                    finish()
                    return@setPositiveButton
                }
                Toast.makeText(this, "Connecting… tap 'Always Allow' if prompted!", Toast.LENGTH_LONG).show()
                LocalAdbManager.initKeys(this)
                LocalAdbManager.connect("127.0.0.1", port) { success, msg ->
                    runOnUiThread {
                        if (success) {
                            Toast.makeText(this, "✓ Connected!", Toast.LENGTH_SHORT).show()
                            // Notify service
                            sendBroadcast(android.content.Intent(ClipOpsService.ACTION_CONNECTED)
                                .setPackage(packageName))
                        } else {
                            Toast.makeText(this, "Failed: $msg\n\nDid you tap Allow?", Toast.LENGTH_LONG).show()
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
