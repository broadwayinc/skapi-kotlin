package com.skapi.android

import android.content.Context
import android.content.SharedPreferences
import com.skapi.SkapiStorage

/**
 * Keeps the signed-in session in the app's private SharedPreferences, so the user stays signed in
 * when the app starts again:
 *
 *     val skapi = Skapi("<Project ID>", storage = SharedPreferencesStorage(context))
 *
 * encrypt (default true): each value is sealed with an AES key kept in the Android Keystore, so the
 * tokens are not readable from a copy of the app's files. A value that can no longer be opened
 * (for example after the app's data was restored to another device) reads as missing, which signs
 * the user out instead of failing.
 */
public class SharedPreferencesStorage @JvmOverloads constructor(
    context: Context,
    name: String = "skapi-session",
    private val encrypt: Boolean = true,
) : SkapiStorage {
    private val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(name, Context.MODE_PRIVATE)
    private val cipher = KeystoreCipher("skapi-session-key")

    override fun getItem(key: String): String? {
        val stored = prefs.getString(key, null) ?: return null
        if (!encrypt) return stored
        return cipher.open(stored)?.toString(Charsets.UTF_8)
    }

    override fun setItem(key: String, value: String) {
        val stored = if (encrypt) cipher.seal(value.toByteArray(Charsets.UTF_8)) else value
        prefs.edit().putString(key, stored).commit()
    }

    override fun removeItem(key: String) {
        prefs.edit().remove(key).commit()
    }
}
