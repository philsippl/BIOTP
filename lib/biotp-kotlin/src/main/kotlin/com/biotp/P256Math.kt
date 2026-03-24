package com.biotp

import java.math.BigInteger
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** P-256 elliptic curve point. */
sealed class ECPoint {
    data class Affine(val x: BigInteger, val y: BigInteger) : ECPoint()
    data object Infinity : ECPoint()
}

/**
 * P-256 elliptic curve arithmetic using [BigInteger].
 *
 * Provides child public key derivation for the BIOTP protocol:
 * `child_public = master_public + HMAC-SHA256(master_public, counter_BE) * G`
 */
object P256Math {
    val p: BigInteger = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    val n: BigInteger = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val a: BigInteger = p - BigInteger.valueOf(3)

    val G: ECPoint.Affine = ECPoint.Affine(
        BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
        BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
    )

    fun pointAdd(p1: ECPoint, p2: ECPoint): ECPoint {
        if (p1 is ECPoint.Infinity) return p2
        if (p2 is ECPoint.Infinity) return p1
        val a1 = p1 as ECPoint.Affine
        val a2 = p2 as ECPoint.Affine

        if (a1.x == a2.x) {
            return if (a1.y == a2.y) pointDouble(a1) else ECPoint.Infinity
        }

        val dy = (a2.y - a1.y).mod(p)
        val dx = (a2.x - a1.x).mod(p)
        val lambda = dy.multiply(dx.modInverse(p)).mod(p)

        val rx = (lambda.multiply(lambda) - a1.x - a2.x).mod(p)
        val ry = (lambda.multiply(a1.x - rx) - a1.y).mod(p)
        return ECPoint.Affine(rx, ry)
    }

    fun pointDouble(pt: ECPoint): ECPoint {
        if (pt is ECPoint.Infinity) return pt
        val af = pt as ECPoint.Affine
        if (af.y == BigInteger.ZERO) return ECPoint.Infinity

        val num = (af.x.multiply(af.x).mod(p).multiply(BigInteger.valueOf(3)) + a).mod(p)
        val den = af.y.multiply(BigInteger.TWO).mod(p)
        val lambda = num.multiply(den.modInverse(p)).mod(p)

        val rx = (lambda.multiply(lambda) - af.x.multiply(BigInteger.TWO)).mod(p)
        val ry = (lambda.multiply(af.x - rx) - af.y).mod(p)
        return ECPoint.Affine(rx, ry)
    }

    fun scalarMul(k: BigInteger, point: ECPoint): ECPoint {
        if (k == BigInteger.ZERO || point is ECPoint.Infinity) return ECPoint.Infinity
        var result: ECPoint = ECPoint.Infinity
        var addend = point
        var scalar = k.mod(n)
        while (scalar > BigInteger.ZERO) {
            if (scalar.testBit(0)) result = pointAdd(result, addend)
            scalar = scalar.shiftRight(1)
            if (scalar > BigInteger.ZERO) addend = pointDouble(addend)
        }
        return result
    }

    /**
     * Derive child public key: `master_public + tweak * G`
     *
     * @param masterPublicKey raw X||Y (64 bytes)
     * @param counter time step counter
     * @return child public key as raw X||Y (64 bytes)
     */
    fun deriveChildPublicKey(masterPublicKey: ByteArray, counter: Long): ByteArray {
        require(masterPublicKey.size == 64) { "master public key must be 64 bytes (raw X||Y)" }

        // tweak = HMAC-SHA256(master_public, counter_BE)
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(masterPublicKey, "HmacSHA256"))
        val tweakBytes = mac.doFinal(counterBytes)

        var tweak = BigInteger(1, tweakBytes).mod(n)
        if (tweak == BigInteger.ZERO) tweak = BigInteger.ONE

        // tweak * G
        val tweakPoint = scalarMul(tweak, G)

        // Parse master public key
        val mx = BigInteger(1, masterPublicKey.copyOfRange(0, 32))
        val my = BigInteger(1, masterPublicKey.copyOfRange(32, 64))
        val masterPoint = ECPoint.Affine(mx, my)

        // child = master + tweak*G
        val child = pointAdd(masterPoint, tweakPoint)
        require(child is ECPoint.Affine) { "child key derivation produced point at infinity" }

        return encodePoint(child)
    }

    /** Encode an affine point as raw X||Y (64 bytes). */
    fun encodePoint(pt: ECPoint.Affine): ByteArray {
        val xBytes = pt.x.toByteArray().let { padOrTrim(it, 32) }
        val yBytes = pt.y.toByteArray().let { padOrTrim(it, 32) }
        return xBytes + yBytes
    }

    /** Parse raw X||Y (64 bytes) into an affine point. */
    fun decodePoint(raw: ByteArray): ECPoint.Affine {
        require(raw.size == 64) { "raw point must be 64 bytes" }
        return ECPoint.Affine(
            BigInteger(1, raw.copyOfRange(0, 32)),
            BigInteger(1, raw.copyOfRange(32, 64)),
        )
    }

    private fun padOrTrim(bytes: ByteArray, length: Int): ByteArray {
        return when {
            bytes.size == length -> bytes
            bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
            else -> ByteArray(length - bytes.size) + bytes
        }
    }
}
