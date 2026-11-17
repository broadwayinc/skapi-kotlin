package com.skapi.android

import android.content.Context
import android.content.SharedPreferences
import com.skapi.DeviceKey
import com.skapi.DeviceKeyStore
import org.json.JSONObject

/**
 * "Remember this device" for record encryption, the Android counterpart of skapi-js keeping the
 * master key in IndexedDB: the user's encryption master key is sealed with an AES key that never
 * leaves the Android Keystore and kept in the app's private preferences. A session restored from
 * storage then opens the user's encrypted data without asking for the password again.
 *
 *     val skapi = Skapi(
 *         "<Project ID>",
 *         storage = SharedPreferencesStorage(context),
 *         encryption = EncryptionOptions(deviceKeyStore = AndroidKeystoreDeviceKeyStore(context)),
 *     )
 *
 * logout() removes the user's entry; lockEncryption(forgetDevice = true) does too.
 */
public class AndroidKeystoreDeviceKeyStore @JvmOverloads constructor(
    context: Context,
    name: String = "skapi-enc",
) : DeviceKeyStore {
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE)
    private val cipher = KeystoreCipher("skapi-device-key")

    override fun save(entry: String, masterKey: ByteArray, keyringRecordId: String) {
        val value = JSONObject()
            .put("mk", cipher.seal(masterKey))
            .put("keyringRecordId", keyringRecordId)
            .put("saved", System.currentTimeMillis())
        prefs.edit().putString(entry, value.toString()).commit()
    }

    override fun load(entry: String): DeviceKey? {
        val stored = prefs.getString(entry, null) ?: return null
        return try {
            val value = JSONObject(stored)
            val mk = cipher.open(value.getString("mk")) ?: return null
            DeviceKey(mk, value.optString("keyringRecordId", ""))
        } catch (e: Exception) {
            null
        }
    }

    override fun delete(entry: String) {
        prefs.edit().remove(entry).commit()
    }
}
