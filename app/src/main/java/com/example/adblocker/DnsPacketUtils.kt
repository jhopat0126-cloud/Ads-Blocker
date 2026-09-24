package com.example.adblocker

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal IPv4 + UDP + DNS packet parsing/building, just enough to:
 *  1. Recognize an outgoing UDP packet whose destination port is 53 (DNS).
 *  2. Read the queried hostname out of the DNS question section.
 *  3. Build a synthetic "blocked" DNS response (A record -> 0.0.0.0) sent
 *     straight back through the TUN interface, without ever hitting the
 *     real network.
 *
 * This is intentionally a simplified, best-effort parser (IPv4 only, no
 * IP options, single-question DNS packets) — plenty for a working
 * prototype, not a hardened production network stack.
 */
object DnsPacketUtils {

    private const val IPV4_HEADER_MIN_LEN = 20
    private const val UDP_HEADER_LEN = 8
    const val PROTOCOL_UDP = 17
    const val DNS_PORT = 53

    data class ParsedUdp(
        val ipHeaderLen: Int,
        val srcAddr: ByteArray,
        val dstAddr: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val udpPayloadOffset: Int,
        val udpPayloadLen: Int
    )

    fun getIpVersion(packet: ByteArray): Int = (packet[0].toInt() and 0xF0) ushr 4

    fun getProtocol(packet: ByteArray): Int = packet[9].toInt() and 0xFF

    /** Parses IPv4 + UDP headers. Returns null if this isn't a plain IPv4/UDP packet. */
    fun parseUdp(packet: ByteArray, length: Int): ParsedUdp? {
        if (length < IPV4_HEADER_MIN_LEN) return null
        if (getIpVersion(packet) != 4) return null
        if (getProtocol(packet) != PROTOCOL_UDP) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl + UDP_HEADER_LEN) return null

        val srcAddr = packet.copyOfRange(12, 16)
        val dstAddr = packet.copyOfRange(16, 20)

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)

        val payloadOffset = ihl + UDP_HEADER_LEN
        val payloadLen = udpLen - UDP_HEADER_LEN
        if (payloadLen < 0 || payloadOffset + payloadLen > length) return null

        return ParsedUdp(ihl, srcAddr, dstAddr, srcPort, dstPort, payloadOffset, payloadLen)
    }

    /** Extracts the queried hostname from a DNS question packet. Returns null on failure. */
    fun extractQueriedHostname(packet: ByteArray, dnsOffset: Int, dnsLen: Int): String? {
        if (dnsLen < 12) return null
        val qdCount = ((packet[dnsOffset + 4].toInt() and 0xFF) shl 8) or (packet[dnsOffset + 5].toInt() and 0xFF)
        if (qdCount < 1) return null

        var pos = dnsOffset + 12
        val end = dnsOffset + dnsLen
        val sb = StringBuilder()
        while (pos < end) {
            val len = packet[pos].toInt() and 0xFF
            if (len == 0) { pos += 1; break }
            pos += 1
            if (pos + len > end) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(packet, pos, len, Charsets.US_ASCII))
            pos += len
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /**
     * Builds a full IPv4/UDP/DNS response packet that answers the given
     * query with a single A record pointing at 0.0.0.0 (i.e. "blocked").
     * Source/destination are swapped relative to the original query so it
     * looks, from the requesting app's point of view, like a normal reply.
     */
    fun buildBlockedResponse(
        originalPacket: ByteArray,
        parsed: ParsedUdp
    ): ByteArray {
        val dnsQuery = originalPacket.copyOfRange(
            parsed.udpPayloadOffset,
            parsed.udpPayloadOffset + parsed.udpPayloadLen
        )

        val dnsResponse = buildDnsBlockedAnswer(dnsQuery)

        val udpLen = UDP_HEADER_LEN + dnsResponse.size
        val ipLen = IPV4_HEADER_MIN_LEN + udpLen
        val out = ByteArray(ipLen)
        val buf = ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN)

        // IPv4 header
        buf.put(0, (0x45).toByte())        // version 4, IHL 5
        buf.put(1, 0)                       // DSCP/ECN
        buf.putShort(2, ipLen.toShort())    // total length
        buf.putShort(4, 0)                  // identification
        buf.putShort(6, 0)                  // flags/fragment offset
        buf.put(8, 64.toByte())             // TTL
        buf.put(9, PROTOCOL_UDP.toByte())   // protocol
        buf.putShort(10, 0)                 // checksum placeholder
        // swap src/dst addresses
        System.arraycopy(parsed.dstAddr, 0, out, 12, 4)
        System.arraycopy(parsed.srcAddr, 0, out, 16, 4)

        val ipChecksum = checksum(out, 0, IPV4_HEADER_MIN_LEN)
        buf.putShort(10, ipChecksum.toShort())

        // UDP header (swap ports)
        val udpOffset = IPV4_HEADER_MIN_LEN
        buf.putShort(udpOffset, parsed.dstPort.toShort())
        buf.putShort(udpOffset + 2, parsed.srcPort.toShort())
        buf.putShort(udpOffset + 4, udpLen.toShort())
        buf.putShort(udpOffset + 6, 0) // UDP checksum optional over IPv4; 0 = not computed

        System.arraycopy(dnsResponse, 0, out, udpOffset + UDP_HEADER_LEN, dnsResponse.size)

        return out
    }

    /** Turns a raw DNS query into a DNS response with one A record = 0.0.0.0. */
    private fun buildDnsBlockedAnswer(query: ByteArray): ByteArray {
        // Header: copy transaction ID, set QR=1/RD/RA flags, ANCOUNT=1
        val header = ByteArray(12)
        header[0] = query[0]; header[1] = query[1] // transaction ID
        header[2] = 0x81.toByte() // QR=1, Opcode=0, AA=0, TC=0, RD=1
        header[3] = 0x80.toByte() // RA=1, Z=0, RCODE=0
        header[4] = query[4]; header[5] = query[5] // QDCOUNT (copy)
        header[6] = 0x00; header[7] = 0x01         // ANCOUNT = 1
        header[8] = 0x00; header[9] = 0x00         // NSCOUNT = 0
        header[10] = 0x00; header[11] = 0x00       // ARCOUNT = 0

        // Question section: copy verbatim from the query (everything after the 12-byte header)
        val question = query.copyOfRange(12, query.size)

        // Answer: pointer to question name (0xC00C), TYPE A (1), CLASS IN (1),
        // TTL, RDLENGTH=4, RDATA=0.0.0.0
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C,          // name = pointer to offset 12
            0x00, 0x01,                    // TYPE A
            0x00, 0x01,                    // CLASS IN
            0x00, 0x00, 0x00, 0x3C,        // TTL = 60s
            0x00, 0x04,                    // RDLENGTH = 4
            0x00, 0x00, 0x00, 0x00          // RDATA = 0.0.0.0
        )

        return header + question + answer
    }

    /**
     * Wraps a real DNS response (received from the upstream resolver) back
     * into an IPv4/UDP packet addressed to the original requesting app,
     * exactly like [buildBlockedResponse] does for synthetic answers.
     */
    fun buildForwardedResponse(
        parsed: ParsedUdp,
        dnsReply: ByteArray,
        dnsReplyLen: Int
    ): ByteArray {
        val dnsResponse = dnsReply.copyOf(dnsReplyLen)

        val udpLen = UDP_HEADER_LEN + dnsResponse.size
        val ipLen = IPV4_HEADER_MIN_LEN + udpLen
        val out = ByteArray(ipLen)
        val buf = ByteBuffer.wrap(out).order(ByteOrder.BIG_ENDIAN)

        buf.put(0, (0x45).toByte())
        buf.put(1, 0)
        buf.putShort(2, ipLen.toShort())
        buf.putShort(4, 0)
        buf.putShort(6, 0)
        buf.put(8, 64.toByte())
        buf.put(9, PROTOCOL_UDP.toByte())
        buf.putShort(10, 0)
        System.arraycopy(parsed.dstAddr, 0, out, 12, 4)
        System.arraycopy(parsed.srcAddr, 0, out, 16, 4)

        val ipChecksum = checksum(out, 0, IPV4_HEADER_MIN_LEN)
        buf.putShort(10, ipChecksum.toShort())

        val udpOffset = IPV4_HEADER_MIN_LEN
        buf.putShort(udpOffset, parsed.dstPort.toShort())
        buf.putShort(udpOffset + 2, parsed.srcPort.toShort())
        buf.putShort(udpOffset + 4, udpLen.toShort())
        buf.putShort(udpOffset + 6, 0)

        System.arraycopy(dnsResponse, 0, out, udpOffset + UDP_HEADER_LEN, dnsResponse.size)
        return out
    }

    /** Standard Internet checksum (RFC 1071) used by both IP and UDP headers. */
    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }
}
