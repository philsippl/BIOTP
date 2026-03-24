package com.biotp

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

/** HOTP/TOTP generation and X9.63 KDF for the BIOTP protocol. */
object OTPGenerator {
    const val PERIOD: Long = 30
    const val DIGITS: Int = 6

    fun generate(sharedSecret: ByteArray, counter: Long): String {
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sharedSecret, "HmacSHA256"))
        val hs = mac.doFinal(counterBytes)

        // RFC 4226 dynamic truncation
        val offset = (hs[hs.size - 1].toInt() and 0x0F)
        val binary = ((hs[offset].toInt() and 0x7F) shl 24) or
            ((hs[offset + 1].toInt() and 0xFF) shl 16) or
            ((hs[offset + 2].toInt() and 0xFF) shl 8) or
            (hs[offset + 3].toInt() and 0xFF)

        val modulus = 10.0.pow(DIGITS).toInt()
        val otp = binary % modulus
        return otp.toString().padStart(DIGITS, '0')
    }

    fun counter(timeSeconds: Long = System.currentTimeMillis() / 1000): Long {
        return timeSeconds / PERIOD
    }

    fun secondsRemaining(timeSeconds: Long = System.currentTimeMillis() / 1000): Int {
        return (PERIOD - (timeSeconds % PERIOD)).toInt()
    }

    /**
     * X9.63 KDF with SHA-256, empty SharedInfo, 32-byte output.
     *
     * `derived = SHA-256(Z || 00000001)`
     */
    fun x963kdf(sharedSecret: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(sharedSecret)
        md.update(byteArrayOf(0, 0, 0, 1))
        return md.digest()
    }
}
