package com.humancheck.app

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.biotp.hexToBytes
import com.biotp.toHex
import org.json.JSONObject

data class RPConfig(
    val callbackURL: String,
    val masterPublicKey: ByteArray, // raw X||Y (64 bytes)
    val relyingParty: String,
    val registrationId: String,
    val userPublicKey: ByteArray,
)

class RPConfigStore(context: Context) {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "biotp_rp_config",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun store(config: RPConfig) {
        val json = JSONObject().apply {
            put("server_url", config.callbackURL)
            put("master_public_key", config.masterPublicKey.toHex())
            put("relying_party", config.relyingParty)
            put("registration_id", config.registrationId)
            put("user_public_key", config.userPublicKey.toHex())
        }
        prefs.edit().putString(config.registrationId, json.toString()).apply()
    }

    fun load(registrationId: String): RPConfig? {
        val raw = prefs.getString(registrationId, null) ?: return null
        return try {
            val json = JSONObject(raw)
            RPConfig(
                callbackURL = json.getString("server_url"),
                masterPublicKey = json.getString("master_public_key").hexToBytes(),
                relyingParty = json.getString("relying_party"),
                registrationId = json.getString("registration_id"),
                userPublicKey = json.getString("user_public_key").hexToBytes(),
            )
        } catch (_: Exception) { null }
    }

    fun allIds(): List<String> = prefs.all.keys.toList().sorted()

    fun delete(registrationId: String) {
        prefs.edit().remove(registrationId).apply()
    }
}
