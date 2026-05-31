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

        // Pre-fill: prefer mDNS-discovered port from intent, else saved prefs
        val autoDiscovered = intent.hasExtra("discovered_pair_port")
        val discoveredPairPort = intent.getIntExtra("discovered_pair_port",
            prefs.getInt("pair_port", 0))
        val savedConnPort = prefs.getInt("conn_port", 0)

        if (discoveredPairPort > 0) binding.pairingPortEditText.setText(discoveredPairPort.toString())
        if (savedConnPort > 0) binding.portEditText.setText(savedConnPort.toString())

        // If port was auto-discovered: lock the field, focus code input
        if (autoDiscovered) {
            binding.pairingPortEditText.isEnabled = false
            binding.codeEditText.requestFocus()
        }

        binding.btnDevSettings.setOnClickListener {
            // Save pairing port before leaving app so it's there when we come back
            val pairPort = binding.pairingPortEditText.text.toString().trim().toIntOrNull()
            if (pairPort != null) prefs.edit().putInt("pair_port", pairPort).apply()
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            } catch (e: Exception) {
                Toast.makeText(this, "Cannot open Developer Options", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnConnect.setOnClickListener {
            val pairPort = binding.pairingPortEditText.text.toString().trim().toIntOrNull()
            val connPort = binding.portEditText.text.toString().trim().toIntOrNull()
            val code     = binding.codeEditText.text.toString().trim()

            if (pairPort == null || connPort == null || code.isEmpty()) {
                Toast.makeText(this, "Please fill all fields", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Save for next time
            prefs.edit()
                .putInt("pair_port", pairPort)
                .putInt("conn_port", connPort)
                .putString("pair_code", code)
                .apply()

            binding.progressBar.visibility = View.VISIBLE
            binding.btnConnect.isEnabled = false

            // Step 1: SPAKE2+ Pair
            LocalAdbManager.pairDevice("127.0.0.1", pairPort, code) { paired, msg ->
                runOnUiThread {
                    if (!paired) {
                        binding.progressBar.visibility = View.GONE
                        binding.btnConnect.isEnabled = true
                        Toast.makeText(this, "Pairing failed: $msg", Toast.LENGTH_LONG).show()
                        return@runOnUiThread
                    }
                    Toast.makeText(this, "Paired! Connecting…", Toast.LENGTH_SHORT).show()
                    // Step 2: Connect on the main ADB port
                    LocalAdbManager.connect("127.0.0.1", connPort) { connected ->
                        runOnUiThread {
                            binding.progressBar.visibility = View.GONE
                            binding.btnConnect.isEnabled = true
                            if (connected) {
                                setResult(RESULT_OK)
                                finish()
                            } else {
                                Toast.makeText(this,
                                    "Connected to ADB daemon — if toggling fails, try connecting again",
                                    Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            }
        }
    }
}
