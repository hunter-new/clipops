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

class PairingCodeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val port = intent.getIntExtra("discovered_pair_port", 0)

        // Build inline input layout
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (24 * resources.displayMetrics.density).toInt()
            setPadding(pad, 0, pad, 0)
        }

        val til = TextInputLayout(this).apply {
            hint = "6-digit pairing code"
        }
        val input = TextInputEditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
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
            .setMessage("Type the 6-digit code shown on the Wireless Debugging screen.")
            .setView(container)
            .setPositiveButton("Pair") { _, _ ->
                val code = input.text.toString().trim()
                if (code.length != 6) {
                    Toast.makeText(this, "Code must be 6 digits", Toast.LENGTH_SHORT).show()
                    finish()
                    return@setPositiveButton
                }
                LocalAdbManager.initKeys(this)
                LocalAdbManager.connect("127.0.0.1", port) { success, msg ->
                    runOnUiThread {
                        if (success) {
                            Toast.makeText(this, "Connected!", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "Failed: $msg", Toast.LENGTH_LONG).show()
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
