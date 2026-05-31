package com.max.clipops

import android.annotation.SuppressLint
import android.app.Dialog
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.provider.Settings
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.view.LayoutInflater
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class ClipOpsTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (LocalAdbManager.isConnected()) {
            // Already connected — disconnect
            LocalAdbManager.disconnect()
            updateTile()
            Toast.makeText(this, "ClipOps disconnected", Toast.LENGTH_SHORT).show()
        } else {
            // Show pairing dialog over the lock screen / shade
            showPairingDialog()
        }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        if (LocalAdbManager.isConnected()) {
            tile.state = Tile.STATE_ACTIVE
            tile.label = "ClipOps: ON"
            tile.contentDescription = "ClipOps ADB connected — tap to disconnect"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.label = "ClipOps: Pair"
            tile.contentDescription = "ClipOps ADB disconnected — tap to pair"
        }
        tile.updateTile()
    }

    @SuppressLint("InflateParams")
    private fun showPairingDialog() {
        val prefs = getSharedPreferences("clipops", MODE_PRIVATE)
        val savedPort = prefs.getInt("pair_port", 0)
        val savedCode = prefs.getString("pair_code", "") ?: ""

        val view = LayoutInflater.from(this).inflate(R.layout.dialog_pairing, null)
        val portEdit = view.findViewById<EditText>(R.id.pairingPort)
        val codeEdit = view.findViewById<EditText>(R.id.pairingCode)
        val btnPair  = view.findViewById<Button>(R.id.btnPair)
        val btnOpen  = view.findViewById<Button>(R.id.btnOpenSettings)
        val status   = view.findViewById<TextView>(R.id.pairingStatus)

        if (savedPort > 0) portEdit.setText(savedPort.toString())
        if (savedCode.isNotEmpty()) codeEdit.setText(savedCode)

        val dialog = Dialog(this, android.R.style.Theme_DeviceDefault_Light_Dialog_NoActionBar_MinWidth)
        dialog.setContentView(view)
        dialog.window?.setType(WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY)

        btnOpen.setOnClickListener {
            try {
                val intent = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                startActivityAndCollapse(intent)
            } catch (e: Exception) {
                startActivityAndCollapse(Intent(Settings.ACTION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            }
        }

        btnPair.setOnClickListener {
            val portStr = portEdit.text.toString().trim()
            val code    = codeEdit.text.toString().trim()

            val port = portStr.toIntOrNull()
            if (port == null || port <= 0 || port > 65535) {
                status.text = "Invalid port"
                return@setOnClickListener
            }
            if (code.length != 6) {
                status.text = "Code must be 6 digits"
                return@setOnClickListener
            }

            status.text = "Pairing…"
            btnPair.isEnabled = false

            // Save for next time
            prefs.edit().putInt("pair_port", port).putString("pair_code", code).apply()

            LocalAdbManager.initKeys(this)
            LocalAdbManager.pairAndConnect(this, port, code) { success, error ->
                // TileService callbacks can come on any thread; post back
                mainLooper.run {
                    btnPair.isEnabled = true
                    if (success) {
                        updateTile()
                        dialog.dismiss()
                        Toast.makeText(this@ClipOpsTileService, "ClipOps connected!", Toast.LENGTH_SHORT).show()
                    } else {
                        status.text = error ?: "Pairing failed"
                    }
                }
            }
        }

        showDialog(dialog)
    }
}
