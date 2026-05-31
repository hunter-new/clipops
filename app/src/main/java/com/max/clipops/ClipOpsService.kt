package com.max.clipops

import android.app.*
import android.content.Intent
import android.content.IntentFilter
import android.content.BroadcastReceiver
import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

class ClipOpsService : Service() {

    companion object {
        const val CHANNEL_ID = "clipops_main"
        const val NOTIF_ID = 1
        const val ACTION_START_SEARCH  = "com.max.clipops.ACTION_START_SEARCH"
        const val ACTION_STOP_SEARCH   = "com.max.clipops.ACTION_STOP_SEARCH"
        const val ACTION_ENTER_CODE    = "com.max.clipops.ACTION_ENTER_CODE"
        const val ACTION_STOP_SERVICE  = "com.max.clipops.ACTION_STOP_SERVICE"
        private const val TAG = "ClipOpsService"
        private const val PAIRING_SERVICE_TYPE = "_adb-tls-pairing._tcp."
    }

    enum class State { IDLE, SEARCHING, FOUND, CONNECTED }

    private var state = State.IDLE
    private var discoveredPort = 0
    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null

    // ── Notification ─────────────────────────────────────────────────────────

    private fun ensureChannel() {
        val ch = NotificationChannel(CHANNEL_ID, "ClipOps Status",
            NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
    }

    private fun pb(action: String, req: Int) = PendingIntent.getBroadcast(
        this, req, Intent(action).setPackage(packageName),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun buildNotification(): Notification {
        ensureChannel()
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val b = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("ClipOps")
            .setOngoing(true)
            .setContentIntent(openApp)

        when (state) {
            State.IDLE -> {
                b.setContentText("Tap to search for pairing service")
                b.addAction(0, "Search for pairing service", pb(ACTION_START_SEARCH, 1))
            }
            State.SEARCHING -> {
                b.setContentText("Searching for pairing service…")
                b.addAction(0, "Stop searching", pb(ACTION_STOP_SEARCH, 2))
            }
            State.FOUND -> {
                b.setContentText("Pairing service found")
                b.addAction(0, "Enter pairing code", pb(ACTION_ENTER_CODE, 4))
                b.addAction(0, "Stop searching", pb(ACTION_STOP_SEARCH, 2))
            }
            State.CONNECTED -> {
                b.setContentText("Connected — managing clipboard access")
            }
        }
        b.addAction(0, "Stop", pb(ACTION_STOP_SERVICE, 3))
        return b.build()
    }

    private fun push() = getSystemService(NotificationManager::class.java)
        .notify(NOTIF_ID, buildNotification())

    // ── mDNS ────────────────────────────────────────────────────────────────

    private fun startSearch() {
        if (state == State.SEARCHING) return
        state = State.SEARCHING
        push()

        val nsd = getSystemService(NsdManager::class.java).also { nsdManager = it }

        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(t: String, c: Int) { stopSearch() }
            override fun onStopDiscoveryFailed(t: String, c: Int)  {}
            override fun onDiscoveryStarted(t: String)             {}
            override fun onDiscoveryStopped(t: String)             {}
            override fun onServiceLost(i: NsdServiceInfo)          {}
            override fun onServiceFound(info: NsdServiceInfo) {
                nsd.resolveService(info, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(i: NsdServiceInfo, c: Int) {
                        Log.w(TAG, "Resolve failed: $c")
                    }
                    override fun onServiceResolved(resolved: NsdServiceInfo) {
                        discoveredPort = resolved.port
                        Log.d(TAG, "Pairing service found on port $discoveredPort")
                        getSharedPreferences("clipops", MODE_PRIVATE)
                            .edit().putInt("pair_port", discoveredPort).apply()
                        // Stop discovery, switch to FOUND state
                        stopDiscoveryOnly()
                        state = State.FOUND
                        push()
                    }
                })
            }
        }
        discoveryListener = listener
        nsd.discoverServices(PAIRING_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
    }

    private fun stopDiscoveryOnly() {
        discoveryListener?.let {
            try { nsdManager?.stopServiceDiscovery(it) } catch (_: Exception) {}
        }
        discoveryListener = null
    }

    private fun stopSearch() {
        stopDiscoveryOnly()
        if (state == State.SEARCHING || state == State.FOUND) {
            state = State.IDLE
            push()
        }
    }

    // ── Receiver ────────────────────────────────────────────────────────────

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                ACTION_START_SEARCH -> startSearch()
                ACTION_STOP_SEARCH  -> stopSearch()
                ACTION_ENTER_CODE   -> {
                    // Open SetupAdbActivity with the discovered port pre-filled
                    startActivity(
                        Intent(this@ClipOpsService, SetupAdbActivity::class.java)
                            .putExtra("discovered_pair_port", discoveredPort)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
                ACTION_STOP_SERVICE -> stopSelf()
            }
        }
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        val filter = IntentFilter().apply {
            addAction(ACTION_START_SEARCH)
            addAction(ACTION_STOP_SEARCH)
            addAction(ACTION_ENTER_CODE)
            addAction(ACTION_STOP_SERVICE)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(receiver, filter)
        }
        state = if (LocalAdbManager.isConnected()) State.CONNECTED else State.IDLE
        startForeground(NOTIF_ID, buildNotification())
    }

    override fun onDestroy() {
        stopSearch()
        unregisterReceiver(receiver)
        super.onDestroy()
    }

    fun onConnected() {
        state = State.CONNECTED
        push()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
