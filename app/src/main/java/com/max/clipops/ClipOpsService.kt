package com.max.clipops

import android.app.*
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.RemoteInput

class ClipOpsService : Service() {

    companion object {
        const val CHANNEL_ID        = "clipops_main"       // low-priority persistent
        const val CHANNEL_ALERT_ID  = "clipops_alert"      // high-priority heads-up
        const val NOTIF_ID          = 1
        const val ACTION_START_SEARCH  = "com.max.clipops.ACTION_START_SEARCH"
        const val ACTION_STOP_SEARCH   = "com.max.clipops.ACTION_STOP_SEARCH"
        const val ACTION_ENTER_CODE    = "com.max.clipops.ACTION_ENTER_CODE"
        const val ACTION_SUBMIT_CODE   = "com.max.clipops.ACTION_SUBMIT_CODE"
        const val ACTION_STOP_SERVICE  = "com.max.clipops.ACTION_STOP_SERVICE"
        const val KEY_PAIRING_CODE     = "pairing_code"
        private const val TAG = "ClipOpsService"
        private const val PAIRING_SERVICE_TYPE = "_adb-tls-pairing._tcp."
        private const val SEARCH_TIMEOUT_MS = 2 * 60 * 1000L  // 2 minutes
    }

    enum class State { IDLE, SEARCHING, FOUND, CONNECTED }

    private var state = State.IDLE
    private var discoveredPort = 0
    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private val handler = Handler(Looper.getMainLooper())
    private val timeoutRunnable = Runnable { stopSearch() }

    // ── Channels ─────────────────────────────────────────────────────────────

    private fun ensureChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        // Persistent status — silent
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "ClipOps Status",
                NotificationManager.IMPORTANCE_LOW)
        )
        // Heads-up alerts — pops to top of screen
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERT_ID, "ClipOps Pairing",
                NotificationManager.IMPORTANCE_HIGH).apply {
                description = "Shown when a pairing service is found"
            }
        )
    }

    // ── Notification ─────────────────────────────────────────────────────────

    private fun pb(action: String, req: Int) = PendingIntent.getBroadcast(
        this, req, Intent(action).setPackage(packageName),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun openAppPI() = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun buildNotification(): Notification {
        ensureChannels()

        // Use high-priority channel for SEARCHING and FOUND so it pops up
        val channelId = when (state) {
            State.SEARCHING, State.FOUND -> CHANNEL_ALERT_ID
            else -> CHANNEL_ID
        }

        val b = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(openAppPI())

        when (state) {
            State.IDLE -> {
                b.setContentTitle("ClipOps")
                b.setContentText("Tap to search for pairing service")
                b.addAction(0, "Search for pairing service", pb(ACTION_START_SEARCH, 1))
            }
            State.SEARCHING -> {
                b.setContentTitle("ClipOps")
                b.setContentText("Searching for pairing service…")
                // Show progress spinner
                b.setProgress(0, 0, true)
                b.addAction(0, "Stop searching", pb(ACTION_STOP_SEARCH, 2))
            }
            State.FOUND -> {
                b.setContentTitle("Pairing service found")
                b.setContentText(null)
                // Heads-up: vibrate + pop up
                b.priority = NotificationCompat.PRIORITY_HIGH
                b.addAction(0, "Enter pairing code", pb(ACTION_ENTER_CODE, 4))
                b.addAction(0, "Stop searching",     pb(ACTION_STOP_SEARCH, 2))
            }
            State.CONNECTED -> {
                b.setContentTitle("ClipOps")
                b.setContentText("Connected — managing clipboard access")
            }
        }

        if (state != State.CONNECTED) {
            b.addAction(0, "Stop", pb(ACTION_STOP_SERVICE, 3))
        }

        return b.build()
    }

    private fun push() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification())

        // When pairing is found: post a SEPARATE non-ongoing heads-up notification
        // (foreground/ongoing notifications are suppressed from heads-up by the OS)
        if (state == State.FOUND) {
            val remoteInput = RemoteInput.Builder(KEY_PAIRING_CODE)
                .setLabel("Pairing code")
                .build()

            val submitIntent = pb(ACTION_SUBMIT_CODE, 55)
            val enterCodeAction = NotificationCompat.Action.Builder(
                0, "Enter pairing code", submitIntent
            ).addRemoteInput(remoteInput).build()

            val headsUp = NotificationCompat.Builder(this, CHANNEL_ALERT_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Pairing service found")
                .setAutoCancel(false)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .addAction(enterCodeAction)
                .addAction(0, "Stop searching", pb(ACTION_STOP_SEARCH, 22))
                .build()
            nm.notify(NOTIF_ID + 1, headsUp)
        } else {
            nm.cancel(NOTIF_ID + 1)
        }
    }

    // ── mDNS ────────────────────────────────────────────────────────────────

    private fun startSearch() {
        if (state == State.SEARCHING) return
        state = State.SEARCHING
        push()

        // Auto-stop after 2 minutes
        handler.removeCallbacks(timeoutRunnable)
        handler.postDelayed(timeoutRunnable, SEARCH_TIMEOUT_MS)

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
                        handler.removeCallbacks(timeoutRunnable)
                        stopDiscoveryOnly()
                        state = State.FOUND
                        push()   // ← heads-up notification pops up here
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
        handler.removeCallbacks(timeoutRunnable)
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
                    startActivity(
                        Intent(this@ClipOpsService, PairingCodeActivity::class.java)
                            .putExtra("discovered_pair_port", discoveredPort)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
                ACTION_SUBMIT_CODE  -> {
                    val code = RemoteInput.getResultsFromIntent(intent)
                        ?.getCharSequence(KEY_PAIRING_CODE)?.toString()?.trim() ?: return
                    if (code.isEmpty()) return
                    // Show "Connecting…" update on the notification
                    getSystemService(NotificationManager::class.java).notify(NOTIF_ID + 1,
                        NotificationCompat.Builder(this@ClipOpsService, CHANNEL_ALERT_ID)
                            .setSmallIcon(android.R.drawable.ic_dialog_info)
                            .setContentTitle("Connecting…")
                            .setProgress(0, 0, true)
                            .setOngoing(true)
                            .build()
                    )
                    LocalAdbManager.initKeys(this@ClipOpsService)
                    LocalAdbManager.connect("127.0.0.1", discoveredPort) { success, msg ->
                        if (success) {
                            state = State.CONNECTED
                            push()
                        } else {
                            // Show error back in notification
                            getSystemService(NotificationManager::class.java).notify(NOTIF_ID + 1,
                                NotificationCompat.Builder(this@ClipOpsService, CHANNEL_ALERT_ID)
                                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                                    .setContentTitle("Connection failed")
                                    .setContentText(msg)
                                    .setAutoCancel(true)
                                    .build()
                            )
                        }
                    }
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
            addAction(ACTION_SUBMIT_CODE)
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
        handler.removeCallbacks(timeoutRunnable)
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
