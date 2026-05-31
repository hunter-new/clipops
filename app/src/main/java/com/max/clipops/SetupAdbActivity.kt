package com.max.clipops

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.max.clipops.databinding.ActivitySetupAdbBinding
import kotlin.concurrent.thread

class SetupAdbActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySetupAdbBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySetupAdbBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Initialize Keys
        LocalAdbManager.initKeys(this)

        binding.btnDevSettings.setOnClickListener {
            try {
                // Open developer options directly
                startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            } catch (e: Exception) {
                // Fallback to general settings
                startActivity(Intent(Settings.ACTION_SETTINGS))
                Toast.makeText(this, "Enable 'Developer Options' manually", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnConnect.setOnClickListener {
            val portStr = binding.portEditText.text.toString().trim()
            if (portStr.isEmpty()) {
                binding.portEditText.error = "Port is required"
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull()
            if (port == null || port <= 0 || port > 65535) {
                binding.portEditText.error = "Invalid Port"
                return@setOnClickListener
            }

            binding.progressBar.visibility = View.VISIBLE
            binding.statusText.text = "Attempting to connect to localhost:$port..."
            binding.btnConnect.isEnabled = false

            // Attempt connection to ADB daemon.
            // On modern Android (11+), when you enable Wireless Debugging, there are two ports.
            // 1. A random port for ADB shell connections (shown on the main Wireless Debugging screen).
            // 2. A random port for pairing (shown inside 'Pair device with pairing code' popup).
            // Our app relies on connecting to the main ADB connection port (1). If your ADB keys were already authorized,
            // connecting to this port succeeds instantly. If it's a first-time connection, Android will show a popup on
            // your screen asking: "Allow USB Debugging?" or "Allow Wireless Debugging?". User must click "Allow".
            thread {
                LocalAdbManager.connectLocal(port) { success, error ->
                    runOnUiThread {
                        binding.progressBar.visibility = View.GONE
                        binding.btnConnect.isEnabled = true
                        if (success) {
                            Toast.makeText(this, "Successfully Activated local ADB!", Toast.LENGTH_LONG).show()
                            // Finish and return to main screen
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
}
