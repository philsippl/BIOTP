package com.humancheck.app

import com.biotp.hexToBytes
import com.biotp.toHex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object RegistrationClient {

    data class QRPayload(
        val callbackURL: String,
        val rpName: String,
        val sessionId: String,
        val masterPublicKey: ByteArray,
        val attestChallenge: String,
    )

    fun parseQR(raw: String): QRPayload? {
        return try {
            val json = JSONObject(raw)
            val masterHex = json.getString("master_public")
            val masterBytes = masterHex.hexToBytes()
            require(masterBytes.size == 64 || (masterBytes.size == 65 && masterBytes[0] == 0x04.toByte()))
            QRPayload(
                callbackURL = json.getString("callback_url"),
                rpName = json.getString("rp_name"),
                sessionId = json.getString("session_id"),
                masterPublicKey = if (masterBytes.size == 65) masterBytes.copyOfRange(1, 65) else masterBytes,
                attestChallenge = json.getString("attest_challenge"),
            )
        } catch (_: Exception) { null }
    }

    suspend fun completeRegistration(
        callbackURL: String,
        sessionId: String,
        userId: String,
        publicKeyHex: String,
        attestChallenge: String,
        attestationChain: List<String> = emptyList(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val url = URL(callbackURL)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true

            val body = JSONObject().apply {
                put("session_id", sessionId)
                put("user_id", userId)
                put("public_key", publicKeyHex)
                put("attest_challenge", attestChallenge)
                put("platform", "android")
                put("android_attestation_chain", JSONArray(attestationChain))
            }

            conn.outputStream.use { it.write(body.toString().toByteArray()) }

            if (conn.responseCode == 200) {
                Result.success(Unit)
            } else {
                val error = conn.errorStream?.bufferedReader()?.readText() ?: "HTTP ${conn.responseCode}"
                Result.failure(RuntimeException(error))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
