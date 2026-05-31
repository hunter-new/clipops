package com.max.clipops

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * ADB SPAKE2+ pairing over TLS implementation.
 *
 * Protocol (from AOSP adb/pairing_connection/pairing_connection.cpp):
 *
 * 1. Connect TLS (server-side is the device — we verify nothing)
 * 2. Exchange SPAKE2 public messages (each 65 bytes = uncompressed P-256 point)
 * 3. Derive shared key via SHA-256 transcript hash
 * 4. Exchange AES-GCM encrypted "pairing data" (our RSA pub key)
 * 5. Device responds with its certificate / success indicator
 *
 * SPAKE2 key schedule (BoringSSL SPAKE2 / draft-irtf-cfrg-spake2):
 *   password  = HKDF-SHA512(pakeCode.toByteArray, "PAIR_SETUP_ENCRYPT_SALT",
 *                            "PAIR_SETUP_ENCRYPT_INFO")   (simplified: SHA-256 of code bytes)
 *   w         = password interpreted as big-endian scalar mod N
 *   x         = random scalar mod N
 *   X_msg     = x*G + w*M   (client role sends this)
 *   Y_msg     = y*G + w*N   (server role — device sends this)
 *   K_A       = x*(Y_msg - w*N)   = xy*G
 *   transcript= SHA-256( len(context) || context || X_msg || Y_msg || K_A || w )
 *   shared_key = SHA-256( transcript )
 *
 * The encrypted pairing-data frames are length-prefixed (4-byte LE) on the TLS stream.
 */
object AdbSpake2Pairing {

    private val random = SecureRandom()

    /**
     * Perform the full SPAKE2+ pairing handshake.
     * @param host       device IP
     * @param port       _adb-tls-pairing._tcp. discovered port
     * @param pairingCode  6-digit code shown on the device
     * @param rsaPubKeyPayload  AdbCrypto.getAdbPublicKeyPayload() bytes
     * @return Result message (empty string = success)
     */
    fun pair(
        host: String,
        port: Int,
        pairingCode: String,
        rsaPubKeyPayload: ByteArray,
        log: (String) -> Unit
    ): String {
        return try {
            val sslCtx = buildTrustAllSslContext()
            // Plain socket first with connect timeout, then layer TLS on top
            val plainSock = java.net.Socket()
            plainSock.connect(java.net.InetSocketAddress(host, port), 10_000)
            plainSock.soTimeout = 15_000   // read timeout for all subsequent ops
            val sock = sslCtx.socketFactory.createSocket(plainSock, host, port, true)
            val tlsSock = sock as javax.net.ssl.SSLSocket
            tlsSock.startHandshake()
            log("TLS handshake done")

            val inp = tlsSock.inputStream
            val out = tlsSock.outputStream

            // ── Step 1: password scalar w from code ──────────────────────────────
            val w = codeToScalar(pairingCode)
            log("w derived from code")

            // ── Step 2: generate ephemeral scalar x ──────────────────────────────
            val x = randomScalar()

            // ── Step 3: compute and send client message X_msg = x*G + w*M ────────
            val xG    = P256.mul(x, P256.G)
            val wM    = P256.mul(w, P256.M)
            val xMsg  = P256.add(xG, wM)
            val xBytes = P256.encodeUncompressed(xMsg)   // 65 bytes
            sendFrame(out, TYPE_SPAKE2_MSG, xBytes)
            log("sent X_msg (${xBytes.size} bytes)")

            // ── Step 4: read server message Y_msg ─────────────────────────────────
            val (_, yBytes) = recvFrame(inp)
            require(yBytes.size == 65) { "Expected 65-byte Y_msg, got ${yBytes.size}" }
            log("received Y_msg (${yBytes.size} bytes)")
            val yMsg = P256.decodePoint(yBytes)

            // ── Step 5: compute shared point K = x*(Y_msg - w*N) ─────────────────
            val wN = P256.mul(w, P256.Npoint)
            val wNneg = P256.ECPoint(wN.x, (P256.P - wN.y).mod(P256.P))
            val kPoint = P256.mul(x, P256.add(yMsg, wNneg))
            val kBytes = P256.encodeUncompressed(kPoint)
            log("K computed")

            // ── Step 6: derive shared key via SHA-256 transcript ──────────────────
            val context = "ADB PAIR_SETUP SPAKE2\u0000".toByteArray(Charsets.UTF_8)
            val sha = MessageDigest.getInstance("SHA-256")
            sha.update(intToLE(context.size))
            sha.update(context)
            sha.update(xBytes)
            sha.update(yBytes)
            sha.update(kBytes)
            sha.update(w.toByteArray32())
            val sharedKey = sha.digest()    // 32 bytes
            log("sharedKey derived: ${sharedKey.hex()}")

            // ── Step 7: encrypt our RSA public key and send ───────────────────────
            val encrypted = aesGcmEncrypt(sharedKey, ByteArray(12), rsaPubKeyPayload)
            sendFrame(out, TYPE_CERTIFICATE, encrypted)
            log("sent encrypted pubkey (${encrypted.size} bytes)")

            // ── Step 8: receive device's encrypted payload ────────────────────────
            val (_, devEncrypted) = recvFrame(inp)
            log("received device payload (${devEncrypted.size} bytes)")
            aesGcmDecrypt(sharedKey, ByteArray(12).also { it[11] = 1 }, devEncrypted)
            log("pairing SUCCESS")

            tlsSock.close()
            ""   // success
        } catch (e: Exception) {
            log("pairing FAILED: ${e::class.simpleName}: ${e.message}")
            e.message ?: "Unknown error"
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private fun codeToScalar(code: String): BigInteger {
        // ADB uses SHA-256 of the code bytes as password, then interprets mod N
        val sha = MessageDigest.getInstance("SHA-256")
        val hash = sha.digest(code.toByteArray(Charsets.UTF_8))
        return BigInteger(1, hash).mod(P256.N)
    }

    private fun randomScalar(): BigInteger {
        var k: BigInteger
        do {
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            k = BigInteger(1, bytes).mod(P256.N)
        } while (k == BigInteger.ZERO)
        return k
    }

    // ADB pairing packet header: 1 byte version + 1 byte type + 4 bytes payload size (BE)
    private const val HEADER_VERSION: Byte = 1
    private const val TYPE_SPAKE2_MSG: Byte = 0
    private const val TYPE_CERTIFICATE: Byte = 1

    private fun sendFrame(out: OutputStream, type: Byte, data: ByteArray) {
        val buf = ByteBuffer.allocate(6 + data.size)
            .put(HEADER_VERSION)
            .put(type)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(data.size)
            .put(data)
        out.write(buf.array())
        out.flush()
    }

    private fun recvFrame(inp: InputStream): Pair<Byte, ByteArray> {
        val header = ByteArray(6)
        inp.readFully(header)
        val type = header[1]
        val len = ByteBuffer.wrap(header, 2, 4).order(ByteOrder.BIG_ENDIAN).int
        require(len in 0..65536) { "Unexpected frame length $len" }
        val payload = ByteArray(len)
        inp.readFully(payload)
        return Pair(type, payload)
    }

    private fun InputStream.readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException("EOF after $off/${buf.size} bytes")
            off += n
        }
    }

    private fun intToLE(v: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

    private fun BigInteger.toByteArray32(): ByteArray {
        val raw = this.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32  -> raw.copyOfRange(raw.size - 32, raw.size)
            else           -> ByteArray(32 - raw.size) + raw
        }
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    private fun aesGcmEncrypt(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"), spec)
        return cipher.doFinal(plain)
    }

    private fun aesGcmDecrypt(key: ByteArray, iv: ByteArray, cipher: ByteArray): ByteArray {
        val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
        c.init(javax.crypto.Cipher.DECRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"), spec)
        return c.doFinal(cipher)
    }

    private fun buildTrustAllSslContext(): SSLContext {
        val trustAll = arrayOf<X509TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, random)
        return ctx
    }
}
