package com.skapi

import java.io.File
import java.io.IOException

/**
 * Where the signed-in session is kept between runs. Keys and values are strings, the same keys
 * skapi-js keeps in localStorage (CognitoIdentityServiceProvider.<client id>.LastAuthUser and
 * .<username>.idToken / accessToken / refreshToken / clockDrift).
 *
 * MemoryStorage (default) keeps it for the life of the Skapi object, FileStorage in a JSON file,
 * and skapi-android's SharedPreferencesStorage in the app's private preferences. Write your own to
 * keep sessions anywhere else.
 */
public interface SkapiStorage {
    public fun getItem(key: String): String?
    public fun setItem(key: String, value: String)
    public fun removeItem(key: String)
}

/** Kept for the life of the Skapi object only. */
public class MemoryStorage : SkapiStorage {
    private val data = java.util.concurrent.ConcurrentHashMap<String, String>()
    override fun getItem(key: String): String? = data[key]
    override fun setItem(key: String, value: String) { data[key] = value }
    override fun removeItem(key: String) { data.remove(key) }
}

/**
 * One JSON file, so a program that runs again stays signed in. The file holds tokens: keep it out
 * of version control. On systems with POSIX permissions it is created readable by its owner only.
 */
public class FileStorage(path: String) : SkapiStorage {
    private val file: File = File(if (path.startsWith("~/")) System.getProperty("user.home") + path.substring(1) else path).absoluteFile
    private val lock = Any()

    @Suppress("UNCHECKED_CAST")
    private fun read(): MutableMap<String, Any?> {
        return try {
            if (!file.exists()) return LinkedHashMap()
            (parseJson(file.readText(Charsets.UTF_8)) as? MutableMap<String, Any?>) ?: LinkedHashMap()
        } catch (e: Exception) {
            LinkedHashMap()
        }
    }

    private fun write(data: Map<String, Any?>) {
        val dir = file.parentFile ?: File(".")
        if (!dir.exists() && !dir.mkdirs() && !dir.exists()) throw IOException("Cannot create ${dir.path}")
        val tmp = File.createTempFile(".skapi-", ".tmp", dir)
        try {
            ownerOnly(tmp)
            tmp.writeText(jsJson(data), Charsets.UTF_8)
            if (!tmp.renameTo(file)) {
                file.delete()
                if (!tmp.renameTo(file)) throw IOException("Cannot write ${file.path}")
            }
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private fun ownerOnly(f: File) {
        f.setReadable(false, false); f.setReadable(true, true)
        f.setWritable(false, false); f.setWritable(true, true)
        f.setExecutable(false, false)
    }

    override fun getItem(key: String): String? = synchronized(lock) { read()[key] as? String }

    override fun setItem(key: String, value: String) {
        synchronized(lock) {
            val data = read()
            data[key] = value
            write(data)
        }
    }

    override fun removeItem(key: String) {
        synchronized(lock) {
            val data = read()
            if (data.containsKey(key)) {
                data.remove(key)
                write(data)
            }
        }
    }
}

/**
 * A device store for the encryption master key: "remember this device", so a session restored
 * from storage opens the user's encrypted data without asking for the password again (as skapi-js
 * keeps it in IndexedDB). Entries are named "<service>/<owner>#<user_id>".
 *
 * The core library has none on purpose: a plain file would put the key on disk in the clear.
 * skapi-android provides AndroidKeystoreDeviceKeyStore, which seals it with a key that never
 * leaves the Android Keystore.
 */
public interface DeviceKeyStore {
    public fun save(entry: String, masterKey: ByteArray, keyringRecordId: String)
    public fun load(entry: String): DeviceKey?
    public fun delete(entry: String)
}

/** What a DeviceKeyStore keeps for one user. */
public class DeviceKey(public val masterKey: ByteArray, public val keyringRecordId: String)
