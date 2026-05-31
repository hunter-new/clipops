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

        // Pre-fill saved connection port
        val savedConnPort = prefs.getInt("conn_port", 0)
        if (savedConnPort > 0) binding.portEditText.setText(savedConnPort.toString())

        binding.btnDevSettings.setOnClickListener {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            } catch (e: Exception) {
                Toast.makeText(this, "Cannot open Developer Options", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnConnect.setOnClickListener {
            val connPort = binding.portEditText.text.toString().trim().toIntOrNull()
            if (connPort == null) {
                Toast.makeText(this, "Enter the port shown in Wireless Debugging", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            prefs.edit().putInt("conn_port", connPort).apply()

            binding.progressBar.visibility = View.VISIBLE
            binding.btnConnect.isEnabled = false

            LocalAdbManager.connect("127.0.0.1", connPort) { success, msg ->
                runOnUiThread {
                    binding.progressBar.visibility = View.GONE
                    binding.btnConnect.isEnabled = true
                    if (success) {
                        setResult(RESULT_OK)
                        finish()
                    } else {
                        Toast.makeText(this,
                            "Failed: $msg\n\nMake sure you tapped 'Always allow' on the device prompt.",
                            Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }
}
