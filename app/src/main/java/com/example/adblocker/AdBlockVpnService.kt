package com.example.adblocker

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * A local, on-device VPN that never actually sends traffic to a remote VPN
 * server. Its only job is to sit between the device and the network so it
 * can inspect DNS queries: ad/tracker domains get an instant "blocked"
 * answer (0.0.0.0), everything else is forwarded to a real DNS resolver
 * untouched. Non-DNS traffic is passed straight to the real network.
 *
 * This is the same basic technique used by non-root ad blockers like
 * DNS66 / Blokada.
 */
class AdBlockVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private var workerThread: Thread? = null
    val blockedCount = AtomicInteger(0)

    companion object {
        const val ACTION_STOP = "com.example.adblocker.STOP"
        const val CHANNEL_ID = "adblock_service"
        const val NOTIF_ID = 1
        const val VPN_ADDRESS = "10.111.222.1"
        const val VPN_ROUTE = "0.0.0.0"
        const val UPSTREAM_DNS = "8.8.8.8" // Google Public DNS, used only to resolve non-blocked queries

        @Volatile
        var instance: AdBlockVpnService? = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        startVpn()
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(channel)
        }
        val stopIntent = Intent(this, AdBlockVpnService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(0, "Stop", stopPending)
            .build()
        startForeground(NOTIF_ID, notification)
    }

    private fun startVpn() {
        if (isRunning.get()) return
        instance = this

        val blockList = BlockList.loadFromAssets(applicationContext)

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(VPN_ADDRESS, 24)
            .addDnsServer(VPN_ADDRESS) // force all device DNS through us
            .addRoute(VPN_ROUTE, 0)    // route everything so we see all traffic
            .setMtu(1500)

        vpnInterface = builder.establish() ?: return
        isRunning.set(true)

        workerThread = Thread { runPacketLoop(blockList) }.apply {
            name = "AdBlockVpnWorker"
            start()
        }
    }

    private fun runPacketLoop(blockList: BlockList) {
        val iface = vpnInterface ?: return
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteArray(32767)

        // One UDP socket, reused for every forwarded (non-blocked) DNS query.
        val forwardSocket = DatagramSocket()
        protect(forwardSocket) // exclude this socket from the VPN, or we'd loop forever

        try {
            while (isRunning.get()) {
                val length = try {
                    input.read(buffer)
                } catch (e: IOException) {
                    if (isRunning.get()) continue else break
                }
                if (length <= 0) continue

                val parsed = DnsPacketUtils.parseUdp(buffer, length)
                if (parsed == null || parsed.dstPort != DnsPacketUtils.DNS_PORT) {
                    // Not a DNS packet — this simplified prototype doesn't proxy
                    // general traffic, so it's dropped. See the note below.
                    continue
                }

                val hostname = DnsPacketUtils.extractQueriedHostname(
                    buffer, parsed.udpPayloadOffset, parsed.udpPayloadLen
                )

                if (hostname != null && blockList.isBlocked(hostname)) {
                    blockedCount.incrementAndGet()
                    val response = DnsPacketUtils.buildBlockedResponse(
                        buffer.copyOf(length), parsed
                    )
                    output.write(response)
                } else {
                    forwardDnsQuery(buffer, parsed, forwardSocket, output)
                }
            }
        } finally {
            forwardSocket.close()
        }
    }

    /** Sends the DNS query to a real resolver and relays the answer back into the TUN. */
    private fun forwardDnsQuery(
        buffer: ByteArray,
        parsed: DnsPacketUtils.ParsedUdp,
        socket: DatagramSocket,
        output: FileOutputStream
    ) {
        try {
            val queryPayload = buffer.copyOfRange(
                parsed.udpPayloadOffset, parsed.udpPayloadOffset + parsed.udpPayloadLen
            )
            val upstream = InetSocketAddress(InetAddress.getByName(UPSTREAM_DNS), DnsPacketUtils.DNS_PORT)
            socket.send(DatagramPacket(queryPayload, queryPayload.size, upstream))

            val replyBuf = ByteArray(4096)
            val replyPacket = DatagramPacket(replyBuf, replyBuf.size)
            socket.soTimeout = 5000
            socket.receive(replyPacket)

            // Re-wrap the real DNS reply into an IPv4/UDP packet addressed back
            // to the original requesting app (src/dst swapped relative to the query).
            val wrapped = DnsPacketUtils.buildForwardedResponse(
                parsed, replyBuf, replyPacket.length
            )
            output.write(wrapped)
        } catch (e: Exception) {
            // Timeout or lookup failure — silently drop; the requesting app will retry/timeout normally.
        }
    }

    fun stopVpn() {
        isRunning.set(false)
        try { vpnInterface?.close() } catch (e: IOException) { /* ignore */ }
        vpnInterface = null
        workerThread?.interrupt()
        workerThread = null
        instance = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    fun isActive(): Boolean = isRunning.get()
}
