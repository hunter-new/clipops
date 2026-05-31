package com.max.clipops

import java.math.BigInteger

/**
 * Minimal Ed25519 point arithmetic for SPAKE2.
 * Uses twisted Edwards curve: -x² + y² = 1 + d·x²·y²
 * Field: GF(2²⁵⁵ - 19)
 */
object Ed25519 {

    val P: BigInteger = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
    private val D: BigInteger = run {
        val num = (-BigInteger.valueOf(121665)).mod(P)
        val den = BigInteger.valueOf(121666).modInverse(P)
        (num * den).mod(P)
    }
    val ORDER: BigInteger = BigInteger.TWO.pow(252) +
            BigInteger("27742317777372353535851937790883648493")

    // Base point G
    val G: ExtPoint = run {
        val y = BigInteger.valueOf(4) * BigInteger.valueOf(5).modInverse(P) mod P
        val y2 = y * y mod P
        val x2 = (y2 - BigInteger.ONE) * (D * y2 + BigInteger.ONE).modInverse(P) mod P
        var x = x2.modPow((P + BigInteger.valueOf(3)) / BigInteger.valueOf(8), P)
        if (x * x mod P != x2) x = x * BigInteger.TWO.modPow((P - BigInteger.ONE) / 4, P) mod P
        if (x.testBit(0)) x = P - x
        fromAffine(x, y)
    }

    // BoringSSL SPAKE2 M point (compressed bytes, client role)
    val M: ExtPoint = decompressPoint(byteArrayOf(
        0xd0.toByte(), 0x48, 0x03, 0x2c, 0x6e, 0xa0.toByte(), 0xb6.toByte(), 0xd6.toByte(),
        0x97.toByte(), 0xdd.toByte(), 0xc2.toByte(), 0xe8.toByte(), 0x6b, 0xda.toByte(), 0x85.toByte(), 0xa3.toByte(),
        0x3a, 0xda.toByte(), 0xc9.toByte(), 0x20, 0xf1.toByte(), 0xbf.toByte(), 0x18, 0xe1.toByte(),
        0xb0.toByte(), 0xc6.toByte(), 0xd1.toByte(), 0x66, 0xa5.toByte(), 0xcb.toByte(), 0xca.toByte(), 0x1c
    ))

    // BoringSSL SPAKE2 N point (server role)
    val N: ExtPoint = decompressPoint(byteArrayOf(
        0xd3.toByte(), 0xbf.toByte(), 0xb5.toByte(), 0x18, 0xf4.toByte(), 0x4f, 0x34, 0x30,
        0xf2.toByte(), 0x9d.toByte(), 0x0c, 0x92.toByte(), 0xaf.toByte(), 0x50, 0x38, 0x65,
        0xa1.toByte(), 0xed.toByte(), 0x39, 0x28, 0xd3.toByte(), 0xe0.toByte(), 0x3a, 0xb4.toByte(),
        0x05, 0x02, 0xd9.toByte(), 0x9f.toByte(), 0x27, 0xff.toByte(), 0x7e, 0x5b
    ))

    // Extended coordinates: (X:Y:Z:T) where x=X/Z, y=Y/Z, T=X*Y/Z
    data class ExtPoint(val X: BigInteger, val Y: BigInteger, val Z: BigInteger, val T: BigInteger)

    val IDENTITY = ExtPoint(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    fun fromAffine(x: BigInteger, y: BigInteger) =
        ExtPoint(x, y, BigInteger.ONE, x * y mod P)

    // Point addition (unified formula for twisted Edwards)
    fun add(a: ExtPoint, b: ExtPoint): ExtPoint {
        val A = (a.Y - a.X) * (b.Y - b.X) mod P
        val B = (a.Y + a.X) * (b.Y + b.X) mod P
        val C = a.T * BigInteger.TWO * D * b.T mod P
        val D2 = a.Z * BigInteger.TWO * b.Z mod P
        val E = B - A
        val F = D2 - C
        val G2 = D2 + C
        val H = B + A
        return ExtPoint(
            (E * F).mod(P),
            (G2 * H).mod(P),
            (F * G2).mod(P),
            (E * H).mod(P)
        )
    }

    // Scalar multiplication via double-and-add
    fun mul(k: BigInteger, p: ExtPoint): ExtPoint {
        var result = IDENTITY
        var addend = p
        var scalar = k.mod(ORDER)
        while (scalar > BigInteger.ZERO) {
            if (scalar.testBit(0)) result = add(result, addend)
            addend = add(addend, addend)
            scalar = scalar.shiftRight(1)
        }
        return result
    }

    // Negate a point: (X, Y, Z, T) -> (-X, Y, Z, -T)
    fun neg(p: ExtPoint) = ExtPoint((P - p.X).mod(P), p.Y, p.Z, (P - p.T).mod(P))

    // Compress to 32-byte little-endian y with sign bit of x
    fun compress(p: ExtPoint): ByteArray {
        val zinv = p.Z.modInverse(P)
        val x = p.X * zinv mod P
        val y = p.Y * zinv mod P
        val yBytes = y.toByteArray().reversedArray()  // to little-endian
        val out = ByteArray(32)
        yBytes.copyInto(out, 0, 0, minOf(32, yBytes.size))
        if (x.testBit(0)) out[31] = (out[31].toInt() or 0x80).toByte()
        return out
    }

    // Decompress 32-byte little-endian point
    fun decompressPoint(bytes: ByteArray): ExtPoint {
        val b = bytes.copyOf(32)
        val signX = (b[31].toInt() and 0x80) != 0
        b[31] = (b[31].toInt() and 0x7F).toByte()
        val y = BigInteger(b.reversedArray())
        val y2 = y * y mod P
        val x2 = (y2 - BigInteger.ONE) * (D * y2 + BigInteger.ONE).modInverse(P) mod P
        if (x2 == BigInteger.ZERO) return fromAffine(BigInteger.ZERO, y)
        var x = x2.modPow((P + BigInteger.valueOf(3)) / BigInteger.valueOf(8), P)
        if (x * x mod P != x2) {
            x = x * BigInteger.TWO.modPow((P - BigInteger.ONE) / 4, P) mod P
        }
        if (x.testBit(0) != signX) x = P - x
        return fromAffine(x, y)
    }
}

private operator fun BigInteger.minus(other: BigInteger): BigInteger = this.subtract(other)
private operator fun BigInteger.plus(other: BigInteger): BigInteger = this.add(other)
private operator fun BigInteger.times(other: BigInteger): BigInteger = this.multiply(other)
private operator fun BigInteger.div(other: BigInteger): BigInteger = this.divide(other)
private infix fun BigInteger.mod(m: BigInteger): BigInteger = this.mod(m)
