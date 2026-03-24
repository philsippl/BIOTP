package com.humancheck.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.biotp.OTPGenerator
import android.util.Base64
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

data class KeyGenResult(
    val publicKey: ByteArray,
    /** DER-encoded X.509 certificate chain (leaf first), base64. Empty if unavailable. */
    val attestationChain: List<String>,
)

class KeyStoreManager {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun biometricAvailable(activity: FragmentActivity): Boolean {
        val bm = BiometricManager.from(activity)
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    fun generateKeyPair(alias: String, activity: FragmentActivity, challenge: ByteArray? = null): KeyGenResult {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

        val useBiometric = biometricAvailable(activity)

        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))

        if (challenge != null) {
            builder.setAttestationChallenge(challenge)
        }

        // WARNING: Skipping biometric auth is ONLY acceptable for emulator/simulator
        // testing. A production app MUST always set userAuthenticationRequired(true)
        // with BIOMETRIC_STRONG. Without this, the KeyStore key is not gated on
        // user presence and any process on the device can perform ECDH silently.
        if (useBiometric) {
            builder.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(10, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        kpg.initialize(builder.build())
        val keyPair = kpg.generateKeyPair()
        val pubKey = encodePublicKey(keyPair.public as ECPublicKey)

        // Extract attestation certificate chain
        val chain = try {
            keyStore.getCertificateChain(alias)?.map { cert ->
                Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
            } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }

        return KeyGenResult(publicKey = pubKey, attestationChain = chain)
    }

    suspend fun performECDH(
        alias: String,
        serverPublicKeyData: ByteArray,
        activity: FragmentActivity,
    ): ByteArray {
        // WARNING: Same as above — skipping the biometric prompt is ONLY for
        // emulator testing. A production app MUST require biometric auth before
        // every ECDH operation. See BIOTP RFC Section 6.2 (BIO1).
        if (biometricAvailable(activity)) {
            showBiometricPrompt(activity)
        }

        val privateKey = keyStore.getKey(alias, null) as PrivateKey
        val serverPubKey = decodeToJCAPublicKey(serverPublicKeyData)

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(serverPubKey, true)
        val rawSecret = ka.generateSecret()

        return OTPGenerator.x963kdf(rawSecret)
    }

    fun getPublicKey(alias: String): ByteArray? {
        val cert = keyStore.getCertificate(alias) ?: return null
        return encodePublicKey(cert.publicKey as ECPublicKey)
    }

    fun listAliases(): List<String> {
        return keyStore.aliases().toList().sorted()
    }

    fun delete(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    private suspend fun showBiometricPrompt(activity: FragmentActivity) =
        suspendCoroutine { cont ->
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(activity, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        cont.resume(Unit)
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        cont.resumeWithException(SecurityException("Biometric auth failed: $errString"))
                    }
                    override fun onAuthenticationFailed() { /* retry automatically */ }
                })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate")
                .setSubtitle("Unlock to generate OTP")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info)
        }

    private fun encodePublicKey(pub: ECPublicKey): ByteArray {
        val w = pub.w
        val x = padOrTrim(w.affineX.toByteArray(), 32)
        val y = padOrTrim(w.affineY.toByteArray(), 32)
        return x + y
    }

    private fun decodeToJCAPublicKey(raw: ByteArray): PublicKey {
        val data = if (raw.size == 65 && raw[0] == 0x04.toByte()) raw.copyOfRange(1, 65) else raw
        require(data.size == 64) { "public key must be 64 bytes (raw X||Y)" }

        val x = BigInteger(1, data.copyOfRange(0, 32))
        val y = BigInteger(1, data.copyOfRange(32, 64))
        val ecPoint = ECPoint(x, y)

        val kf = KeyFactory.getInstance("EC")
        // Get EC params from a generated key
        val paramGen = AlgorithmParameters.getInstance("EC")
        paramGen.init(ECGenParameterSpec("secp256r1"))
        val ecParams = paramGen.getParameterSpec(java.security.spec.ECParameterSpec::class.java)

        return kf.generatePublic(ECPublicKeySpec(ecPoint, ecParams))
    }

    private fun padOrTrim(bytes: ByteArray, length: Int): ByteArray = when {
        bytes.size == length -> bytes
        bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
        else -> ByteArray(length - bytes.size) + bytes
    }

    private fun BigInteger(i: Int, bytes: ByteArray): java.math.BigInteger =
        java.math.BigInteger(i, bytes)
}
