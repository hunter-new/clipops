package com.max.clipops

import android.app.*
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

class ClipOpsService : Service() {

    companion object {
        const val CHANNEL_ID = "clipops_main"
        const val NOTIF_ID = 1
        const val ACTION_PAIR = "com.max.clipops.ACTION_PAIR"
        const val ACTION_STOP = "com.max.clipops.ACTION_STOP"

        fun buildNotification(service: Service, connected: Boolean): Notification {
            val ctx = service.applicationContext
            val channel = NotificationChannel(
                CHANNEL_ID, "ClipOps Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "ClipOps ADB connection status" }
            ctx.getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)

            val pairIntent = PendingIntent.getBroadcast(
                ctx, 0,
                Intent(ACTION_PAIR).setPackage(ctx.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val stopIntent = PendingIntent.getBroadcast(
                ctx, 1,
                Intent(ACTION_STOP).setPackage(ctx.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val openIntent = PendingIntent.getActivity(
                ctx, 0,
                Intent(ctx, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            return NotificationCompat.Builder(ctx, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_menu_share)
                .setContentTitle("ClipOps")
                .setContentText(if (connected) "Connected — managing clipboard access" else "Waiting to connect via Wireless ADB")
                .setContentIntent(openIntent)
                .setOngoing(true)
                .apply {
                    if (!connected) {
                        addAction(NotificationCompat.Action(0, "Pair & Connect", pairIntent))
                    }
                    addAction(NotificationCompat.Action(0, "Stop", stopIntent))
                }
                .build()
        }
    }

    private val receiver = object : android.content.BroadcastReceiver() {
        override fun onReceive(ctx: android.content.Context, intent: Intent) {
            when (intent.action) {
                ACTION_PAIR -> {
                    // Open SetupAdbActivity from notification
                    startActivity(
                        Intent(ctx, SetupAdbActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
                ACTION_STOP -> stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        val filter = android.content.IntentFilter().apply {
            addAction(ACTION_PAIR)
            addAction(ACTION_STOP)
        }
        registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)
        startForeground(NOTIF_ID, buildNotification(this, LocalAdbManager.isConnected()))
    }

    override fun onDestroy() {
        unregisterReceiver(receiver)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    fun updateNotification(connected: Boolean) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(this, connected))
    }
}
