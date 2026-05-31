package com.max.clipops

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Pure-Kotlin P-256 (secp256r1) EC point arithmetic using BigInteger.
 * No external deps — everything is standard JVM math.
 */
object P256 {

    val P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    val A = P - BigInteger.valueOf(3)
    val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val Gx = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
    val Gy = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
    val G = ECPoint(Gx, Gy)

    // SPAKE2 M and N points (from BoringSSL crypto/spake2/spake2.cc kM_P256 / kN_P256)
    val M = decodePoint(byteArrayOf(
        0x04,
        0x88.toByte(), 0x6e, 0x2f, 0x97.toByte(), 0xac.toByte(), 0xe4.toByte(), 0x6e, 0x55,
        0xba.toByte(), 0x9d.toByte(), 0xd7.toByte(), 0x24, 0x25, 0x79, 0xf2.toByte(), 0x99.toByte(),
        0x3b, 0x64, 0xe1.toByte(), 0x6e, 0xf3.toByte(), 0xdc.toByte(), 0xab.toByte(), 0x95.toByte(),
        0xaf.toByte(), 0xd4.toByte(), 0x97.toByte(), 0x33, 0x3d, 0x8f.toByte(), 0xa1.toByte(), 0x2f,
        0x5f, 0xf3.toByte(), 0x55, 0x16, 0x3e, 0x43, 0xce.toByte(), 0x22,
        0x4e, 0x0b, 0x0e, 0x65, 0xff.toByte(), 0x02, 0xac.toByte(), 0x8e.toByte(),
        0x5c, 0x7b, 0xe0.toByte(), 0x94.toByte(), 0x19, 0xc7.toByte(), 0x85.toByte(), 0xe0.toByte(),
        0xca.toByte(), 0x54, 0x7d, 0x55, 0xa1.toByte(), 0x2e, 0x2d, 0x20
    ))

    val Npoint = decodePoint(byteArrayOf(
        0x04,
        0xd8.toByte(), 0xbb.toByte(), 0xd6.toByte(), 0xc6.toByte(), 0x39, 0xc6.toByte(), 0x29, 0x37,
        0xb0.toByte(), 0x4d, 0x99.toByte(), 0x7f, 0x38, 0xc3.toByte(), 0x77, 0x07,
        0x19, 0xc6.toByte(), 0x29, 0xd7.toByte(), 0x01, 0x4d, 0x49, 0xa2.toByte(),
        0x4b, 0x4f, 0x98.toByte(), 0xba.toByte(), 0xa1.toByte(), 0x29, 0x2b, 0x49,
        0x07, 0xd6.toByte(), 0x0a, 0xa6.toByte(), 0xbf.toByte(), 0xad.toByte(), 0xe4.toByte(), 0x50,
        0x08, 0xa6.toByte(), 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6.toByte(),
        0x4d, 0x9b.toByte(), 0xd3.toByte(), 0x60, 0x34, 0x80.toByte(), 0x8c.toByte(), 0xd5.toByte(),
        0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb.toByte(), 0xe7.toByte()
    ))

    data class ECPoint(val x: BigInteger, val y: BigInteger) {
        val isInfinity: Boolean get() = (x == BigInteger.ZERO && y == BigInteger.ZERO)
        companion object {
            val INFINITY = ECPoint(BigInteger.ZERO, BigInteger.ZERO)
        }
    }

    fun add(p1: ECPoint, p2: ECPoint): ECPoint {
        if (p1.isInfinity) return p2
        if (p2.isInfinity) return p1
        if (p1.x == p2.x) {
            return if (p1.y != p2.y) ECPoint.INFINITY else doublePoint(p1)
        }
        val lam = (p2.y - p1.y) * (p2.x - p1.x).modInverse(P) mod P
        val x3  = (lam * lam - p1.x - p2.x) mod P
        val y3  = (lam * (p1.x - x3) - p1.y) mod P
        return ECPoint(x3.let { if (it < BigInteger.ZERO) it + P else it },
                       y3.let { if (it < BigInteger.ZERO) it + P else it })
    }

    fun doublePoint(p: ECPoint): ECPoint {
        if (p.isInfinity) return p
        val lam = (BigInteger.valueOf(3) * p.x * p.x + A) * (BigInteger.valueOf(2) * p.y).modInverse(P) mod P
        val x3  = (lam * lam - BigInteger.valueOf(2) * p.x) mod P
        val y3  = (lam * (p.x - x3) - p.y) mod P
        return ECPoint(x3.let { if (it < BigInteger.ZERO) it + P else it },
                       y3.let { if (it < BigInteger.ZERO) it + P else it })
    }

    fun mul(k: BigInteger, point: ECPoint): ECPoint {
        var result = ECPoint.INFINITY
        var addend = point
        var scalar = k.mod(N)
        while (scalar != BigInteger.ZERO) {
            if (scalar.testBit(0)) result = add(result, addend)
            addend = doublePoint(addend)
            scalar = scalar.shiftRight(1)
        }
        return result
    }

    fun encodeUncompressed(pt: ECPoint): ByteArray {
        val xb = pt.x.toByteArray32()
        val yb = pt.y.toByteArray32()
        return byteArrayOf(0x04) + xb + yb
    }

    fun decodePoint(bytes: ByteArray): ECPoint {
        require(bytes[0] == 0x04.toByte() && bytes.size == 65)
        val x = BigInteger(1, bytes.sliceArray(1..32))
        val y = BigInteger(1, bytes.sliceArray(33..64))
        return ECPoint(x, y)
    }

    private fun BigInteger.toByteArray32(): ByteArray {
        val raw = this.toByteArray()
        return when {
            raw.size == 32 -> raw
            raw.size > 32  -> raw.copyOfRange(raw.size - 32, raw.size)
            else           -> ByteArray(32 - raw.size) + raw
        }
    }

    private infix fun BigInteger.mod(m: BigInteger): BigInteger = this.mod(m)
}
