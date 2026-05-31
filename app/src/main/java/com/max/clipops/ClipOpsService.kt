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
        const val ACTION_CONNECTED     = "com.max.clipops.ACTION_CONNECTED"
        const val KEY_PAIRING_CODE     = "pairing_code"
        private const val TAG = "ClipOpsService"
        private const val PAIRING_SERVICE_TYPE = "_adb-tls-pairing._tcp."
        private const val SEARCH_TIMEOUT_MS = 2 * 60 * 1000L  // 2 minutes
    }

    enum class State { IDLE, SEARCHING, FOUND, CONNECTED }

    private var state = State.IDLE
    private var discoveredPairPort = 0
    private var discoveredConnPort = 0
    private var nsdManager: NsdManager? = null
    private var pairDiscoveryListener: NsdManager.DiscoveryListener? = null
    private var connDiscoveryListener: NsdManager.DiscoveryListener? = null
    private val handler = Handler(Looper.getMainLooper())
    private val timeoutRunnable = Runnable {
        // On timeout, restart search automatically instead of stopping
        Log.d(TAG, "Search timed out, restarting…")
        stopDiscoveryOnly()
        if (state == State.SEARCHING) {
            startSearch()  // restart
        }
    }

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

    // RemoteInput actions MUST use FLAG_MUTABLE (Android requirement)
    private fun pbMutable(action: String, req: Int) = PendingIntent.getBroadcast(
        this, req, Intent(action).setPackage(packageName),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
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
                val openActivity = PendingIntent.getActivity(
                    this,
                    10,
                    Intent(this, PairingCodeActivity::class.java)
                        .putExtra("conn_port", discoveredConnPort)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                b.setContentTitle("Pairing service found")
                b.setContentText("Tap to connect")
                b.addAction(0, "Connect", openActivity)
                b.addAction(0, "Stop searching", pb(ACTION_STOP_SEARCH, 2))
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
        // Cancel any leftover secondary notification
        nm.cancel(NOTIF_ID + 1)
    }

    // ── mDNS ────────────────────────────────────────────────────────────────

    private fun startSearch() {
        stopDiscoveryOnly()  // always clean up before restarting
        state = State.SEARCHING
        push()

        // Auto-stop after 2 minutes
        handler.removeCallbacks(timeoutRunnable)
        handler.postDelayed(timeoutRunnable, SEARCH_TIMEOUT_MS)

        val nsd = getSystemService(NsdManager::class.java).also { nsdManager = it }

        fun makeListener(isPair: Boolean) = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(t: String, c: Int) { handler.post { stopSearch() } }
            override fun onStopDiscoveryFailed(t: String, c: Int)  {}
            override fun onDiscoveryStarted(t: String)             {}
            override fun onDiscoveryStopped(t: String)             {}
            override fun onServiceLost(i: NsdServiceInfo)          {}
            override fun onServiceFound(info: NsdServiceInfo) {
                nsd.resolveService(info, object : NsdManager.ResolveListener {
                    override fun onResolveFailed(i: NsdServiceInfo, c: Int) {
                        Log.w(TAG, "Resolve failed ($isPair): $c")
                    }
                    override fun onServiceResolved(resolved: NsdServiceInfo) {
                        handler.post {
                            if (isPair) {
                                discoveredPairPort = resolved.port
                                Log.d(TAG, "Pair port: $discoveredPairPort")
                                getSharedPreferences("clipops", MODE_PRIVATE)
                                    .edit().putInt("pair_port", discoveredPairPort).apply()
                            } else {
                                discoveredConnPort = resolved.port
                                Log.d(TAG, "Conn port: $discoveredConnPort")
                                getSharedPreferences("clipops", MODE_PRIVATE)
                                    .edit().putInt("conn_port", discoveredConnPort).apply()
                            }
                            // Show FOUND as soon as we have the pair port
                            if (discoveredPairPort > 0 && state == State.SEARCHING) {
                                handler.removeCallbacks(timeoutRunnable)
                                stopDiscoveryOnly()
                                state = State.FOUND
                                push()
                            }
                        }
                    }
                })
            }
        }

        pairDiscoveryListener = makeListener(true)
        connDiscoveryListener = makeListener(false)
        nsd.discoverServices("_adb-tls-pairing._tcp.", NsdManager.PROTOCOL_DNS_SD, pairDiscoveryListener!!)
        nsd.discoverServices("_adb-tls-connect._tcp.", NsdManager.PROTOCOL_DNS_SD, connDiscoveryListener!!)
    }

    private fun stopDiscoveryOnly() {
        pairDiscoveryListener?.let {
            try { nsdManager?.stopServiceDiscovery(it) } catch (_: Exception) {}
        }
        pairDiscoveryListener = null
        connDiscoveryListener?.let {
            try { nsdManager?.stopServiceDiscovery(it) } catch (_: Exception) {}
        }
        connDiscoveryListener = null
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
                ACTION_CONNECTED    -> { state = State.CONNECTED; push() }
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
            addAction(ACTION_CONNECTED)
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Handle start actions passed directly via intent (e.g. from MainActivity)
        when (intent?.action) {
            ACTION_START_SEARCH -> startSearch()
        }
        return START_STICKY  // restart if killed by OS
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
