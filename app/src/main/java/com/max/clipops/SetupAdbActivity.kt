package com.max.clipops

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.max.clipops.databinding.ActivitySetupAdbBinding

class SetupAdbActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySetupAdbBinding
    private val prefs by lazy { getSharedPreferences("clipops", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySetupAdbBinding.inflate(layoutInflater)
        setContentView(binding.root)

        LocalAdbManager.initKeys(this)

        // Pre-fill saved values so the user doesn't have to retype after switching apps
        val savedPairPort = intent.getIntExtra("discovered_pair_port",
            prefs.getInt("pair_port", 0))
        val savedConnPort = prefs.getInt("conn_port", 0)
        val savedCode     = prefs.getString("pair_code", "") ?: ""

        val autoDiscovered = intent.hasExtra("discovered_pair_port")

        if (savedPairPort > 0) binding.pairingPortEditText.setText(savedPairPort.toString())
        if (savedConnPort > 0) binding.portEditText.setText(savedConnPort.toString())
        if (savedCode.isNotEmpty()) binding.codeEditText.setText(savedCode)

        // If port was auto-discovered, hide pairing port field and focus code field
        if (autoDiscovered) {
            binding.pairingPortEditText.isEnabled = false
            binding.codeEditText.requestFocus()
        }

        binding.btnDevSettings.setOnClickListener {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            } catch (e: Exception) {
                startActivity(Intent(Settings.ACTION_SETTINGS))
                Toast.makeText(this, "Enable 'Developer Options' manually", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnConnect.setOnClickListener {
            val pairingPortStr = binding.pairingPortEditText.text.toString().trim()
            val connPortStr    = binding.portEditText.text.toString().trim()
            val code           = binding.codeEditText.text.toString().trim()

            val pairingPort = pairingPortStr.toIntOrNull()
            if (pairingPort == null || pairingPort <= 0 || pairingPort > 65535) {
                binding.pairingPortEditText.error = "Invalid pairing port"
                return@setOnClickListener
            }

            val connPort = connPortStr.toIntOrNull()
            if (connPort == null || connPort <= 0 || connPort > 65535) {
                binding.portEditText.error = "Invalid connection port"
                return@setOnClickListener
            }

            if (code.length != 6) {
                binding.codeEditText.error = "Must be 6 digits"
                return@setOnClickListener
            }

            // Save so fields survive app-switch
            prefs.edit()
                .putInt("pair_port", pairingPort)
                .putInt("conn_port", connPort)
                .putString("pair_code", code)
                .apply()

            binding.progressBar.visibility = View.VISIBLE
            binding.statusText.text = "Connecting to localhost:$connPort…"
            binding.btnConnect.isEnabled = false

            LocalAdbManager.pairAndConnect(this, pairingPort, code) { success, error ->
                runOnUiThread {
                    binding.progressBar.visibility = View.GONE
                    binding.btnConnect.isEnabled = true
                    if (success) {
                        Toast.makeText(this, "ClipOps connected!", Toast.LENGTH_LONG).show()
                        setResult(RESULT_OK)
                        finish()
                    } else {
                        binding.statusText.text = error ?: "Connection failed."
                    }
                }
            }
        }
    }
}
