package com.skapi

import java.security.PrivateKey
import java.util.concurrent.ConcurrentHashMap
import java.util.logging.Logger

/*
 * Client-side record encryption, ported from skapi-py (_encryption.py), itself a port of skapi-js
 * (src/methods/encryption.ts), so records and files sealed by any of the SDKs open in the others.
 *
 * Only record.data of PRIVATE records is sealed, with a per-record key (DEK). The DEK is wrapped
 * for the owner under a master key (MK) that only the user's password (or encryption recovery
 * code) opens, and for each user the record is shared with through ECDH P-256. The MK lives in a
 * keyring record in the reserved table "__skapi__keyring".
 *
 * Added beyond skapi-py, as skapi-js does with IndexedDB: an optional DeviceKeyStore keeps the MK
 * so a session restored from storage opens encrypted data without asking for the password again.
 */

private val log: Logger = Logger.getLogger("skapi")

/**
 * Encryption options for Skapi(encryption = EncryptionOptions()).
 *
 * iterations: PBKDF2 rounds for the password wrap (at least 100000).
 * trustPolicy: "tofu" pins a peer's key the first time it is seen; "strict" needs pinPeerKey first.
 * withheld: what record data becomes when this session cannot decrypt it: "null" (default) or
 *   "sentinel" (a {"__skapi_no_access__": true, "reason": ...} placeholder).
 * recovery: "code" (default) issues an encryption recovery code at setup; "none" does not.
 * table: the keyring table.
 * persistDevice: keep the master key in deviceKeyStore (when one is given) so a restored session
 *   stays unlocked.
 * deviceKeyStore: where to keep it; skapi-android has AndroidKeystoreDeviceKeyStore.
 */
public class EncryptionOptions(
    public val iterations: Int = PBKDF2_ITERATIONS,
    public val trustPolicy: String = "tofu",
    public val withheld: String = "null",
    public val recovery: String = "code",
    public val table: String = "__skapi__keyring",
    public val persistDevice: Boolean = true,
    public val deviceKeyStore: DeviceKeyStore? = null,
)

internal class EncConfig(
    val iterations: Int,
    val trustPolicy: String,
    val withheld: String,
    val recovery: String,
    val table: String,
    val persistDevice: Boolean,
    val deviceKeyStore: DeviceKeyStore?,
)

internal fun parseEncryptionOptions(o: EncryptionOptions): EncConfig {
    if (o.iterations < 100000) throw perr("\"encryption.iterations\" must be at least 100000.")
    return EncConfig(
        iterations = o.iterations,
        trustPolicy = if (o.trustPolicy == "strict") "strict" else "tofu",
        withheld = if (o.withheld == "sentinel") "sentinel" else "null",
        recovery = if (o.recovery == "none") "none" else "code",
        table = o.table.ifEmpty { "__skapi__keyring" },
        persistDevice = o.persistDevice,
        deviceKeyStore = o.deviceKeyStore,
    )
}

internal class DekEntry(
    var bytes: ByteArray,
    var recipients: JMap,
    var anch: String,
    var uid: String,
    var own: String,
    var accessGroup: Any? = "private",
    var rid: String = "",
    var ctUrl: String? = null,
    var ctStale: MutableList<String> = mutableListOf(),
) {
    fun copy(rid: String = this.rid): DekEntry =
        DekEntry(bytes, recipients.copyMap(), anch, uid, own, accessGroup, rid, ctUrl, ctStale.toMutableList())
}

internal class EncResult(
    val send: Any? = null,
    val omit: Boolean = false,
    val encrypted: Boolean = false,
    val plain: Any? = null,
    val dek: DekEntry? = null,
    val spill: ByteArray? = null,
    val retire: List<String>? = null,
    val files: String? = null,
    val recipients: List<String>? = null,
    /** "plain" in skapi-py's answer: true only when this write sealed the data (plain holds what was sealed). */
    val hasPlain: Boolean = false,
)

internal class EncState(val cfg: EncConfig) {
    @Volatile var status = "locked"
    @Volatile var reason = "NO_SESSION_KEY"
    @Volatile var mk: ByteArray? = null
    @Volatile var ikPriv: PrivateKey? = null
    @Volatile var pubRaw: ByteArray? = null
    @Volatile var fpr = ""
    @Volatile var keyringRecordId = ""
    @Volatile var userId = ""
    var pins: MutableMap<String, String> = ConcurrentHashMap()
    val peerPub: MutableMap<String, Pair<ByteArray, String>> = ConcurrentHashMap()
    val deks: MutableMap<String, DekEntry> = ConcurrentHashMap()
    val passthrough: MutableMap<String, JMap> = ConcurrentHashMap()
    val roll: MutableSet<String> = ConcurrentHashMap.newKeySet()
    /** the key a revoke minted ahead of its roll (see encDropAndRoll) */
    val rollKey: MutableMap<String, ByteArray> = ConcurrentHashMap()
    @Volatile var pendingRecoveryCode: String? = null
    @Volatile var pendingRecoveryUser = ""
    /** a restored session waits to be unlocked from the device store */
    @Volatile var devicePending = false
    @Volatile var deviceRunning = false
    val deviceLock = Any()

    /**
     * Drops every key. keepRecovery is lockEncryption()'s: an encryption recovery code the app has
     * not collected yet can never be shown again, so a lock keeps it; a logout drops it.
     */
    fun clear(keepRecovery: Boolean = false) {
        status = "locked"
        reason = "NO_SESSION_KEY"
        mk = null
        ikPriv = null
        pubRaw = null
        fpr = ""
        keyringRecordId = ""
        userId = ""
        pins = ConcurrentHashMap()
        peerPub.clear()
        deks.clear()
        passthrough.clear()
        roll.clear()
        rollKey.clear()
        devicePending = false
        if (!keepRecovery) {
            pendingRecoveryCode = null
            pendingRecoveryUser = ""
        }
    }
}

// ---- strings -----------------------------------------------------------------------------------------

private fun Core.eS(kind: String, user: String): String = "$ENC_V|$kind|$service|$owner|$user"

private fun Core.payloadAad(own: String, anch: String, anchor: String): ByteArray =
    utf8(jsJson(jlist(ENC_V, service, owner, own, anch, anchor)))

private fun recipientAad(payloadAad: ByteArray, recipient: String, bind: String): ByteArray =
    payloadAad + byteArrayOf(0) + utf8(recipient) + byteArrayOf(0) + utf8(bind)

private fun Core.wrapInfo(anchor: String, own: String, recipient: String, fpr: String): String =
    "$ENC_V|dekwrap|$service|$owner|$anchor|$own|$recipient|$fpr"

private fun anchorOf(env: JMap): String = when (env["anch"]) {
    "uid" -> env.s("uid") ?: ""
    "rid" -> env.s("rid") ?: ""
    else -> ""
}

private fun anchorOf(e: DekEntry): String = when (e.anch) {
    "uid" -> e.uid
    "rid" -> e.rid
    else -> ""
}

/** A number as it is written into an AAD string ("600000"). */
private fun fmt(v: Any?): String = if (v is Number) jsJson(v) else (v?.toString() ?: "None")

private fun num(v: Any?): Double = (v as? Number)?.toDouble() ?: 0.0

private fun originOf(url: String): String {
    val i = url.indexOf("://")
    if (i < 0) return url
    val j = url.indexOf('/', i + 3)
    return if (j < 0) url else url.substring(0, j)
}

/** Percent-decoding as Python's unquote: %XX as UTF-8, "+" left alone. */
private fun pctDecode(s: String): String {
    if ('%' !in s) return s
    val out = java.io.ByteArrayOutputStream()
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '%' && i + 2 < s.length && Character.digit(s[i + 1], 16) >= 0 && Character.digit(s[i + 2], 16) >= 0) {
            out.write(Character.digit(s[i + 1], 16) * 16 + Character.digit(s[i + 2], 16))
            i += 3
        } else {
            out.write(utf8(c.toString()))
            i++
        }
    }
    return String(out.toByteArray(), Charsets.UTF_8)
}

private fun bins(rec: JMap?): List<Pair<String, JMap>> {
    val out = mutableListOf<Pair<String, JMap>>()
    val bin = rec.m("bin") ?: return out
    for ((formKey, entries) in bin) for (f in entries.asList() ?: continue) f.asMap()?.let { out.add(Pair(formKey, it)) }
    return out
}

private fun encFlag(rec: JMap?): JMap? = rec?.get("encrypted").asMap()

// ---- device store ("remember this device") ---------------------------------------------------------

private fun Core.deviceEntry(s: EncState): String = "$service/$owner#${me().ifEmpty { s.userId }}"

private fun Core.saveDevice(s: EncState) {
    val store = s.cfg.deviceKeyStore ?: return
    val mk = s.mk ?: return
    if (!s.cfg.persistDevice || s.userId.isEmpty()) return
    try {
        store.save(deviceEntry(s), mk.copyOf(), s.keyringRecordId)
    } catch (e: Throwable) {
        log.warning("skapi encryption: the device key could not be saved: $e")
    }
}

private fun Core.deleteDevice(s: EncState) {
    val store = s.cfg.deviceKeyStore ?: return
    if (me().isEmpty() && s.userId.isEmpty()) return
    try {
        store.delete(deviceEntry(s))
    } catch (e: Throwable) {
        log.warning("skapi encryption: the device key could not be removed: $e")
    }
}

/** Core.restore() calls this after adopting a restored session: the device store is tried before the first encrypted read or write. */
internal fun Core.encStartDeviceUnlock() {
    val s = enc ?: return
    if (s.cfg.persistDevice && s.cfg.deviceKeyStore != null) s.devicePending = true
}

/** Runs a pending device unlock once; other threads wait for it. Never throws. */
private fun Core.encAwaitDevice() {
    val s = enc ?: return
    if (!s.devicePending && !s.deviceRunning) return
    synchronized(s.deviceLock) {
        if (!s.devicePending) return
        s.devicePending = false
        s.deviceRunning = true
        try {
            unlockFromDevice(s)
        } catch (e: Throwable) {
            // a stale device entry (password changed elsewhere, keyring rotated) degrades to "locked"
            if (s.status != "unlocked") {
                s.status = "locked"
                s.reason = "NO_SESSION_KEY"
            }
        } finally {
            s.deviceRunning = false
        }
    }
}

private fun Core.unlockFromDevice(s: EncState): Boolean {
    val store = s.cfg.deviceKeyStore ?: return false
    val uid = me()
    if (uid.isEmpty() || !s.cfg.persistDevice || s.status == "unlocked") return false
    if (user?.get("is_openid") == true) return false
    val stored = store.load(deviceEntry(s)) ?: return false
    val keyring = findKeyring(uid)
    if (keyring == null) {
        try { store.delete(deviceEntry(s)) } catch (e: Throwable) { }
        return false
    }
    adoptKeyring(keyring, stored.masterKey, uid)
    return true
}

// ---- keyring -----------------------------------------------------------------------------------------

private fun Core.findKeyring(uid: String): JMap? {
    val s = enc!!
    val res = getRecords(jmap(
        "table" to jmap("name" to s.cfg.table, "access_group" to "private"),
        "index" to jmap("name" to "\$user_id", "value" to uid, "condition" to "="),
    ), jmap("limit" to 2L))
    val rows = (res.l("list") ?: jlist()).mapNotNull { it.asMap() }.filter { it["user_id"] == uid }.sortedBy { num(it["uploaded"]) }
    return rows.firstOrNull()
}

private fun Core.passwordWrap(mk: ByteArray, password: String, uid: String): JMap {
    val it = enc!!.cfg.iterations
    val salt = randomBytes(16)
    val s = b64u(salt)
    val kek = passwordKek(password, salt, it, eS("kek", uid))
    val sealed = seal(kek, mk, utf8("${eS("mk", uid)}|PBKDF2-SHA256|$it|$s"))
    val out = jmap("id" to b64u(randomBytes(6)), "p" to "password", "kdf" to jmap("a" to "PBKDF2-SHA256", "it" to it.toLong(), "s" to s))
    out.putAll(sealed)
    out["created"] = System.currentTimeMillis()
    return out
}

private fun Core.recoveryWrap(mk: ByteArray, uid: String): Pair<JMap, String> {
    val raw = randomBytes(16)
    val salt = randomBytes(16)
    val s = b64u(salt)
    val rk = hkdf(raw, salt, eS("recovery", uid))
    val sealed = seal(rk, mk, utf8("${eS("rk", uid)}|HKDF-SHA256|$s"))
    val out = jmap("id" to b64u(randomBytes(6)), "p" to "recovery", "kdf" to jmap("a" to "HKDF-SHA256", "s" to s))
    out.putAll(sealed)
    out["created"] = System.currentTimeMillis()
    return Pair(out, encodeRecoveryCode(raw))
}

private fun wrapsOf(data: JMap?, p: String): List<JMap> =
    (data.l("wraps") ?: jlist()).mapNotNull { it.asMap() }.filter { it["p"] == p }.sortedByDescending { num(it["created"]) }

private fun Core.openWithPassword(data: JMap?, password: String, uid: String): ByteArray? {
    val wraps = wrapsOf(data, "password")
    if (wraps.isEmpty()) throw perr("The keyring has no password wrap.", "ENCRYPTION_KEYRING_CORRUPT")
    for (w in wraps) {
        try {
            val kdf = w.m("kdf") ?: continue
            val it = toLongOrNull(kdf["it"])?.toInt() ?: continue
            val kek = passwordKek(password, b64uDec(kdf["s"]), it, eS("kek", uid))
            return openGcm(kek, b64uDec(w["iv"]), b64uDec(w["ct"]), utf8("${eS("mk", uid)}|PBKDF2-SHA256|${fmt(kdf["it"])}|${kdf["s"]}"))
        } catch (e: SkapiException) {
            throw e
        } catch (e: Exception) {
            continue
        }
    }
    return null
}

private fun Core.adoptKeyring(keyring: JMap, mk: ByteArray, uid: String) {
    val s = enc!!
    val data = keyring.m("data") ?: throw perr("The encryption keyring is malformed.", "ENCRYPTION_KEYRING_CORRUPT")
    val ik = data.m("ik") ?: throw perr("The encryption keyring is malformed.", "ENCRYPTION_KEYRING_CORRUPT")
    val pkcs8 = openGcm(mk, b64uDec(ik["iv"]), b64uDec(ik["ct"]), utf8(eS("ik", uid)))
    val pins: MutableMap<String, String> = ConcurrentHashMap()
    val p = data.m("pins")
    if (p != null && truthy(p["ct"])) {
        try {
            val opened = parseJson(utf8Dec(openGcm(mk, b64uDec(p["iv"]), b64uDec(p["ct"]), utf8("$ENC_V|pins|$service/$owner|$uid")))).asMap()
            if (opened != null) for ((k, v) in opened) if (v is String) pins[k] = v
        } catch (e: Exception) {
            pins.clear()
        }
    }
    s.mk = mk
    s.ikPriv = loadPkcs8(pkcs8)
    s.pubRaw = b64uDec(data["pub"])
    s.fpr = data.s("fpr") ?: ""
    s.keyringRecordId = keyring.s("record_id") ?: ""
    s.userId = uid
    s.pins = pins
    s.status = "unlocked"
    s.reason = ""
    try {
        repairPublicKey(uid)
    } catch (e: Exception) { // best effort: it never fails the unlock
        log.warning("skapi encryption: the public key directory could not be checked: $e")
    }
}

/**
 * Puts this keyring's public key back on top of the public key directory when a stray row is
 * there instead. Two devices logging in for the first time at once could leave the losing
 * keyring's public row behind, and it is the NEWEST row, the one peers read, so they wrapped data
 * keys to a key nobody holds. When the newest row does not carry this keyring's key, and this
 * session proves it holds the private half, the key is published again and the rows that do not
 * match it are removed. As skapi-js repairPublicKey.
 */
private fun Core.repairPublicKey(uid: String) {
    val s = enc!!
    val pubRaw = s.pubRaw
    val ikPriv = s.ikPriv
    if (uid.isEmpty() || pubRaw == null || ikPriv == null) return
    val res = getRecords(jmap(
        "table" to jmap("name" to s.cfg.table, "access_group" to "authorized"),
        "index" to jmap("name" to "\$user_id", "value" to uid, "condition" to "="),
    ), jmap("limit" to 10L))
    val rows = (res.l("list") ?: jlist()).mapNotNull { it.asMap() }
        .filter { it["user_id"] == uid && it.m("data") != null && truthy(it.m("data")!!["pub"]) }
        .sortedByDescending { num(it["uploaded"]) }
    if (rows.isEmpty()) return
    val mine = fingerprint(pubRaw)
    fun fprOf(r: JMap): String = try { fingerprint(b64uDec(r.m("data")!!["pub"])) } catch (e: Exception) { "" }
    if (fprOf(rows[0]) == mine) return
    // the key about to be published must open what is sealed to it with this session's private key
    val probe = randomBytes(32)
    val label = "$ENC_V|pubcheck|$uid"
    val holds = try {
        ecdhUnwrap(ikPriv, ecdhWrap(probe, pubRaw, label, utf8(label)), label, utf8(label)).contentEquals(probe)
    } catch (e: Exception) {
        false
    }
    if (!holds) return
    val stray = rows.filter { fprOf(it) != mine && truthy(it["record_id"]) }.map { it["record_id"] as String }
    if (s.userId != uid || me() != uid) return // a lock, logout or another user's login since the unlock: leave it
    postRecord(
        jmap("v" to 1L, "alg" to "ECDH-P-256", "user_id" to uid, "pub" to b64u(pubRaw), "fpr" to mine, "created" to System.currentTimeMillis()),
        jmap("table" to jmap("name" to s.cfg.table, "access_group" to "authorized"), "index" to jmap("name" to "pubkey", "value" to uid)),
    )
    if (stray.isNotEmpty() && s.userId == uid && me() == uid) {
        deleteRecords(jmap("record_id" to stray.toMutableList<Any?>()))
    }
}

private fun Core.unlockKeyring(keyring: JMap, password: String, uid: String) {
    val data = keyring.m("data") ?: LinkedHashMap()
    if (keyring["user_id"] != uid || (truthy(data["user_id"]) && data["user_id"] != uid)) {
        throw perr("The encryption keyring does not belong to this user.", "ENCRYPTION_KEYRING_CORRUPT")
    }
    val mk = openWithPassword(data, password, uid)
        ?: throw perr("Incorrect password: the encryption keyring could not be opened.", "ENCRYPTION_BAD_PASSWORD")
    adoptKeyring(keyring, mk, uid)
}

private fun Core.provisionKeyring(password: String, uid: String) {
    val s = enc!!
    val mk = randomBytes(32)
    val (_, pub, pkcs8) = newIdentity()
    val fpr = fingerprint(pub)
    val wraps = jlist(passwordWrap(mk, password, uid))
    var code: String? = null
    if (s.cfg.recovery == "code") {
        val (w, c) = recoveryWrap(mk, uid)
        wraps.add(w)
        code = c
    }
    val now = System.currentTimeMillis()
    val data = jmap(
        "v" to 1L, "alg" to "ECDH-P-256", "user_id" to uid, "wraps" to wraps, "ik" to seal(mk, pkcs8, utf8(eS("ik", uid))),
        "self" to seal(mk, mk, utf8(eS("self", uid))), "pub" to b64u(pub), "fpr" to fpr, "pins" to null, "created" to now, "updated" to now,
    )
    val table = s.cfg.table
    val pubRec = postRecord(
        jmap("v" to 1L, "alg" to "ECDH-P-256", "user_id" to uid, "pub" to b64u(pub), "fpr" to fpr, "created" to now),
        jmap("table" to jmap("name" to table, "access_group" to "authorized"), "index" to jmap("name" to "pubkey", "value" to uid)),
    )
    val rec = postRecord(data, jmap("table" to jmap("name" to table, "access_group" to "private")))
    val oldest = findKeyring(uid)
    if (oldest != null && oldest["record_id"] != rec["record_id"]) {
        // another device enrolled first: its keyring wins. This device's public key and keyring go
        // (best effort), or peers would read this newer public key and wrap for a key nobody holds.
        try {
            val ids = listOf(pubRec["record_id"], rec["record_id"]).filter { truthy(it) }.toMutableList()
            deleteRecords(jmap("record_id" to ids))
        } catch (e: Exception) {
            log.warning("skapi encryption: this device's unused public key and keyring could not be removed: $e")
        }
        unlockKeyring(oldest, password, uid) // adopt the keyring of the device that enrolled first
        return
    }
    val adopted = rec.copyMap()
    adopted["data"] = data
    adoptKeyring(adopted, mk, uid)
    s.pendingRecoveryCode = code
    s.pendingRecoveryUser = uid
    s.pins = ConcurrentHashMap()
}

/**
 * Open the keyring with the password, or create it when there is none. Creating is for login
 * only (the default), where the password was just proven. unlockEncryption() passes
 * create = false: a session restored from tokens proved no password, so creating a keyring there
 * would seal the data under whatever was typed. As in skapi-js.
 */
private fun Core.ensureKeyring(password: String, create: Boolean = true) {
    val s = enc ?: return
    val u = user ?: return
    if (u["is_openid"] == true) {
        s.status = "locked"
        s.reason = "OPENID_UNSUPPORTED"
        return
    }
    val uid = me()
    val keyring = findKeyring(uid)
    if (keyring != null) {
        unlockKeyring(keyring, password, uid)
    } else if (!create) {
        throw perr("Encryption has not been set up for this account yet. It is set up at the first login with the password: " +
            "log in with the password to start using it.", "NOT_EXISTS")
    } else {
        provisionKeyring(password, uid)
    }
    if (s.status == "unlocked") saveDevice(s)
}

/** Called after every password sign-in. Never fails the login. */
internal fun Core.encAfterLogin(password: String?) {
    val s = enc ?: return
    if (password.isNullOrEmpty()) return
    s.clear() // a previous user's keys never carry over
    try {
        ensureKeyring(password)
    } catch (e: Exception) {
        log.warning("skapi encryption could not be unlocked at login: $e")
    }
}

/**
 * Drops every key (logout). The device entry goes too, so the next person on the device cannot
 * reach this user's keys by restoring their session; keepDevice is lockEncryption()'s.
 */
internal fun Core.encClear(keepDevice: Boolean = false) {
    val s = enc ?: return
    if (!keepDevice) deleteDevice(s)
    s.clear(keepRecovery = keepDevice)
}

internal fun Core.encRewrapPassword(current: String, new: String): JMap? {
    val s = enc ?: return null
    encAwaitDevice()
    if (s.status != "unlocked" || s.mk == null) {
        throw perr("Encryption must be unlocked before changing the password, or the encryption keyring would be left " +
            "wrapped under a password that no longer exists. Call unlockEncryption(password) first.", "ENCRYPTION_LOCKED")
    }
    val res = getRecords(jmap("record_id" to s.keyringRecordId), jmap("limit" to 1L))
    val keyring = res.l("list")?.firstOrNull().asMap()
        ?: throw perr("The encryption keyring could not be read, so the password change was stopped before it could strand it.", "ENCRYPTION_KEYRING_CORRUPT")
    val uid = me()
    val mk = openWithPassword(keyring.m("data"), current, uid)
        ?: throw perr("Incorrect current password: the encryption keyring was not re-wrapped.", "ENCRYPTION_BAD_PASSWORD")
    val data = keyring.m("data").copyMap()
    val wraps = data.l("wraps").copyList()
    wraps.add(passwordWrap(mk, new, uid))
    data["wraps"] = wraps
    data["updated"] = System.currentTimeMillis()
    postRecord(data, jmap("record_id" to s.keyringRecordId))
    return data
}

internal fun Core.encPruneWraps() {
    val s = enc ?: return
    if (s.status != "unlocked") return
    try {
        val keyring = getRecords(jmap("record_id" to s.keyringRecordId), jmap("limit" to 1L)).l("list")!![0].asMap()!!
        val data = keyring.m("data").copyMap()
        val pw = wrapsOf(data, "password")
        if (pw.size > 1) {
            val wraps = jlist(pw[0])
            for (w in data.l("wraps") ?: jlist()) if (w.asMap()?.get("p") != "password") wraps.add(w)
            data["wraps"] = wraps
            data["updated"] = System.currentTimeMillis()
            postRecord(data, jmap("record_id" to s.keyringRecordId))
        }
    } catch (e: Exception) {
        log.warning("skapi encryption: old password wrap not pruned: $e")
    }
}

// ---- peers ------------------------------------------------------------------------------------------

private fun Core.peerKeys(ids: List<String>): Map<String, Pair<ByteArray, String>?> {
    val s = enc!!
    val out = LinkedHashMap<String, Pair<ByteArray, String>?>()
    var pinnedNew = false
    for (uid in ids) {
        val known = s.peerPub[uid]
        if (known != null) {
            out[uid] = known
            continue
        }
        val res = getRecords(jmap(
            "table" to jmap("name" to s.cfg.table, "access_group" to "authorized"),
            "index" to jmap("name" to "\$user_id", "value" to uid, "condition" to "="),
        ), jmap("limit" to 10L))
        val rows = (res.l("list") ?: jlist()).mapNotNull { it.asMap() }
            .filter { it["user_id"] == uid && it.m("data") != null && truthy(it.m("data")!!["pub"]) }
            .sortedByDescending { num(it["uploaded"]) }
        if (rows.isEmpty()) {
            out[uid] = null
            continue
        }
        val pub = b64uDec(rows[0].m("data")!!["pub"])
        val fpr = fingerprint(pub)
        val pinned = s.pins[uid]
        if (pinned != null && pinned != fpr) {
            throw perr("The public key for user \"$uid\" has changed since it was first seen. " +
                "This is expected if they reset their account, and is what a key substitution attack also looks like. " +
                "Verify the new fingerprint out of band, then call pinPeerKey(userId, fingerprint).", "ENCRYPTION_PEER_KEY_CHANGED")
        }
        if (pinned == null) {
            if (s.cfg.trustPolicy == "strict") {
                throw perr("No pinned key for user \"$uid\" and trustPolicy is \"strict\". Pin it first with pinPeerKey().", "ENCRYPTION_PEER_NOT_PINNED")
            }
            s.pins[uid] = fpr
            pinnedNew = true
        }
        s.peerPub[uid] = Pair(pub, fpr)
        out[uid] = Pair(pub, fpr)
    }
    if (pinnedNew) {
        try { persistPins() } catch (e: Exception) { }
    }
    return out
}

private fun Core.persistPins() {
    val s = enc!!
    val mk = s.mk ?: return
    if (s.keyringRecordId.isEmpty()) return
    val keyring = getRecords(jmap("record_id" to s.keyringRecordId), jmap("limit" to 1L)).l("list")!![0].asMap()!!
    val data = keyring.m("data").copyMap()
    data["pins"] = seal(mk, utf8(jsJson(LinkedHashMap<String, Any?>(s.pins))), utf8("$ENC_V|pins|$service/$owner|${s.userId}"))
    data["updated"] = System.currentTimeMillis()
    postRecord(data, jmap("record_id" to s.keyringRecordId))
}

// ---- write ---------------------------------------------------------------------------------------------

private class WriteGroup(val group: Any?, val tableName: Any?, val record: JMap?)

private fun normGroup(g: Any?): Any? = when (g) {
    "private", "*", "**" -> "private"
    "public" -> 0L
    "authorized" -> 1L
    "admin" -> 99L
    is Number -> g
    else -> 0L
}

/** (access group the write lands on, table name, the record if it had to be read). */
private fun Core.writeGroup(view: JMap, hasData: Boolean): WriteGroup {
    val table = view["table"]
    val name: Any? = if (table is String) table else table.asMap()?.get("name")
    if (table is String) return WriteGroup(0L, name, null)
    val tm = table.asMap()
    if (tm != null && tm.containsKey("access_group")) return WriteGroup(normGroup(tm["access_group"]), name, null)
    val rid = view["record_id"] as? String
    if (rid.isNullOrEmpty()) return WriteGroup(0L, name, null)
    // The cached data key says only what the group was when this session last saw the record;
    // another device may have made it non-private since, and sealing a payload into a
    // non-private record strands it. So the cache is trusted only for a write with no data,
    // where both answers write nothing (as skapi-js resolveWriteGroup).
    val cached = enc!!.deks[rid]
    if (cached != null && !hasData) return WriteGroup(cached.accessGroup ?: "private", name, null)
    val current = readOwnRecord(rid) ?: throw perr("Record \"$rid\" not found.", "NOT_EXISTS")
    val t = current.m("table")
    return WriteGroup(t?.get("access_group"), t?.get("name"), current)
}

private val ALNUM = Regex("^[a-zA-Z0-9]+$")

private fun Core.readOwnRecord(rid: String): JMap? {
    val q = if (ALNUM.matches(rid)) jmap("record_id" to rid) else jmap("unique_id" to rid)
    val res = getRecords(q, jmap("limit" to 1L))
    return res.l("list")?.firstOrNull().asMap()
}

private fun Core.ownerCheck(current: JMap?, rid: String, what: String) {
    if (current != null && truthy(current["encrypted"]) && current["user_id"] != me()) {
        throw perr("Record \"$rid\" belongs to another user (${current["user_id"]}), so $what would either seal it " +
            "under the wrong key or strand its contents. Encryption only operates on records you own, " +
            "no matter what access level you hold.", "ENCRYPTION_NOT_RECORD_OWNER")
    }
}

/** JSON length as Python's json.dumps(ensure_ascii=True) counts it: non-ASCII as \uXXXX. */
private fun asciiJsonLength(v: Any?): Int {
    var n = 0
    for (c in jsJson(v)) n += if (c.code > 127) 6 else 1
    return n
}

internal fun Core.maybeEncrypt(value: Any?, view: JMap, hasData: Boolean): EncResult {
    val s = enc ?: return EncResult(send = value, omit = !hasData)
    val rawId = (view["record_id"] as? String) ?: ""
    if (rawId.isNotEmpty()) {
        val pass = s.passthrough.remove(rawId)
        if (pass != null) return EncResult(send = pass, encrypted = true)
    }
    var v = value
    var has = hasData
    val wg = writeGroup(view, has)
    if (wg.group != "private") {
        var files: String? = null
        var current = wg.record
        if (rawId.isNotEmpty() && current == null) {
            current = try { readOwnRecord(rawId) } catch (e: SkapiException) { null }
        }
        if (current != null && truthy(current["encrypted"])) {
            ownerCheck(current, rawId, "making it non-private")
            if (!has) {
                val flag = encFlag(current)
                if (flag?.get("status") == "failed") {
                    throw perr("Cannot make record \"$rawId\" non-private: its current contents could not be decrypted " +
                        "(${flag["reason"]}), so they cannot be written back in the clear. " +
                        "Unlock encryption, or supply the record's data with the access group change.", "ENCRYPTION_LOCKED")
                }
                v = current["data"]
                has = true
            }
        }
        if (current != null && bins(current).any { truthy(it.second["encrypted"]) }) {
            files = "decrypt"
        } else if (current != null) {
            (current["record_id"] as? String)?.let { s.deks.remove(it) }
        }
        return EncResult(send = v, omit = !has, files = files)
    }
    if (wg.tableName == s.cfg.table) return EncResult(send = v, omit = !has) // the keyring itself is never sealed
    // a write issued while a restored session is still opening its device key waits for that
    encAwaitDevice()
    if (!has) return EncResult(omit = true)
    if (isWithheld(v)) {
        throw perr("This record's data could not be decrypted by this session, so it cannot be written back. " +
            "Writing it would replace the record with the placeholder.", "ENCRYPTION_CANNOT_REWRITE_WITHHELD")
    }
    val mk = s.mk
    if (s.status != "unlocked" || mk == null) {
        throw perr("Encryption is enabled but locked, so this private record cannot be written. " +
            "Call unlockEncryption(password) first, or the user must log in with their password.", "ENCRYPTION_LOCKED")
    }
    if (v.asMap()?.containsKey(ENV_MARKER) == true) throw perr("\"__skapi_enc__\" is a reserved key in record data.")
    if ((truthy(view["service"]) && view["service"] != service) || (truthy(view["owner"]) && view["owner"] != owner)) {
        throw perr("Encrypted records cannot be written to another project. The encryption key is derived per project, " +
            "so a record written under one service and read under another could never be decrypted. " +
            "Construct a separate Skapi instance for that project.", "INVALID_REQUEST")
    }
    val me = me()
    if (me.isEmpty()) throw perr("User login is required to write an encrypted record.", "INVALID_REQUEST")
    var rolling = false
    var rollKey: ByteArray? = null
    val priorCt = mutableListOf<String>()
    if (rawId.isNotEmpty() && s.roll.contains(rawId)) {
        s.roll.remove(rawId)
        rollKey = s.rollKey.remove(rawId)
        val stale = s.deks.remove(rawId)
        if (stale != null) {
            stale.ctUrl?.takeIf { it.isNotEmpty() }?.let { priorCt.add(it) }
            priorCt.addAll(stale.ctStale.filter { it.isNotEmpty() })
        }
        rolling = true
    }
    var files: String? = null
    var entry: DekEntry? = if (rawId.isNotEmpty()) dekIfCurrent(rawId) else null
    var resolvedId = ""
    var uid = (view["unique_id"] as? String) ?: ""
    var current: JMap? = null
    if (rawId.isNotEmpty() && entry == null) {
        current = try { readOwnRecord(rawId) } catch (e: SkapiException) { null }
        ownerCheck(current, rawId, "updating it")
    }
    if (current != null) {
        if (!truthy(current["encrypted"]) && bins(current).any { !truthy(it.second["encrypted"]) }) files = "encrypt"
        resolvedId = (current["record_id"] as? String) ?: ""
        if (uid.isEmpty()) uid = (current["unique_id"] as? String) ?: ""
        val flag = encFlag(current)
        if (flag?.get("status") == "failed") {
            throw perr("Cannot update encrypted record \"$rawId\": its current contents could not be decrypted (${flag["reason"]}), " +
                "so its existing key wraps cannot be preserved. Updating anyway would revoke everyone it is shared with.", "ENCRYPTION_LOCKED")
        }
        if (!rolling) entry = s.deks[resolvedId]
    }
    if (entry != null) {
        if (entry.rid.isNotEmpty()) resolvedId = entry.rid
        if (entry.anch == "uid") uid = entry.uid.ifEmpty { uid }
        if (entry.own != me) {
            throw perr("Record \"$rawId\" belongs to another user (${entry.own}). Encryption only operates on records you own.", "ENCRYPTION_NOT_RECORD_OWNER")
        }
    } else if (rawId.isNotEmpty() && resolvedId.isEmpty() && !rolling) {
        resolvedId = rawId
    }
    val dek = entry?.bytes ?: (rollKey ?: randomBytes(32))
    var recipients: JMap = entry?.recipients?.copyMap() ?: LinkedHashMap()
    val anch = if (uid.isNotEmpty()) "uid" else if (resolvedId.isNotEmpty()) "rid" else "new"
    val anchor = when (anch) { "uid" -> uid; "rid" -> resolvedId; else -> "" }
    val aad = payloadAad(me, anch, anchor)
    val mkWrap = jmap("t" to "mk")
    mkWrap.putAll(seal(mk, dek, recipientAad(aad, me, "mk")))
    recipients[me] = mkWrap
    if (entry != null && (entry.anch != anch || anchorOf(entry) != anchor)) {
        recipients = rewrapAll(dek, recipients, me, anchor, aad)
    }
    val (iv, ct) = sealRaw(dek, utf8(jsJson(v)), aad)
    val env = jmap(
        ENV_MARKER to 1L, "enc" to "A256GCM", "kw" to "ECDH-ES+A256GCM", "anch" to anch, "uid" to uid, "rid" to resolvedId, "own" to me,
        "iv" to b64u(iv), "ct" to b64u(ct), "k" to recipients,
    )
    var spill: ByteArray? = null
    var retire: List<String>? = null
    if (resolvedId.isNotEmpty() && (env["ct"] as String).length > SPILL_LIMIT) {
        spill = ct
        env["ct"] = ""
        env["ct_ref"] = CT_FILE_SUFFIX
    }
    if (resolvedId.isNotEmpty()) {
        // the stored payload files' real urls (never the bare ct_ref suffix, which the server refuses),
        // retired whether the new data spills again or now fits inline
        val old = LinkedHashSet<String>()
        entry?.ctUrl?.takeIf { it.isNotEmpty() }?.let { old.add(it) }
        entry?.ctStale?.filter { it.isNotEmpty() }?.let { old.addAll(it) }
        old.addAll(priorCt)
        retire = if (old.isEmpty()) null else old.toList()
    }
    val envSize = asciiJsonLength(env)
    if (envSize > ENVELOPE_CAP) {
        throw perr("Encrypted record data is too large: once encrypted and base64 encoded it becomes $envSize bytes, " +
            "over the $ENVELOPE_CAP byte limit. Encryption costs about 33% plus roughly 230 bytes per additional recipient.", "ENCRYPTED_DATA_TOO_LARGE")
    }
    if (resolvedId.isNotEmpty()) cacheDek(resolvedId, dek, recipients, anch, uid, me)
    val dekEntry = DekEntry(dek, recipients.copyMap(), anch, uid, me, "private")
    return EncResult(send = env, plain = v, encrypted = true, dek = dekEntry, spill = spill, retire = retire, files = files,
        recipients = recipients.keys.toList(), hasPlain = true)
}

/**
 * A record's cached data key, only while the stored envelope still carries the key wraps it was
 * cached with. Another session of the owner may have rolled the key or changed who it is wrapped
 * for since; then the cached key is forgotten (null) and the caller reads the record again.
 */
private fun Core.dekIfCurrent(key: String): DekEntry? {
    val s = enc!!
    val entry = s.deks[key] ?: return null
    val rid = entry.rid.ifEmpty { key }
    val stored = readStoredEnvelope(rid)
    if (stored != null && jsonEq(stored["k"], entry.recipients)) return entry
    s.deks.remove(key)
    s.deks.remove(rid)
    return null
}

/** A just-created record's key, under the record_id the server minted. */
internal fun Core.bindRecordDek(recordId: String, dek: DekEntry?) {
    val s = enc ?: return
    if (dek == null || recordId.isEmpty() || s.deks.containsKey(recordId)) return
    s.deks[recordId] = dek.copy(rid = recordId)
}

/** Re-uploads a record's attachments sealed ("encrypt") or in the clear ("decrypt"); returns the urls to retire. */
internal fun Core.convertRecordFiles(recordId: String, direction: String): List<String> {
    val s = enc ?: return emptyList()
    val rec = readOwnRecord(recordId) ?: return emptyList()
    val wantSealed = direction == "decrypt"
    val targets = bins(rec).filter { truthy(it.second["encrypted"]) == wantSealed }
    if (targets.isEmpty()) return emptyList()
    val uploads = mutableListOf<PreparedFile>()
    val retire = mutableListOf<String>()
    for ((formKey, f) in targets) {
        val url = f.s("url") ?: ""
        var content = getFile(url, jmap("dataType" to "bytes", "_raw" to true)) as ByteArray
        var contentType: String? = null
        if (wantSealed) {
            val (plain, meta) = decryptFileFor(url, content)
            content = plain
            contentType = (meta["t"] as? String)?.takeIf { it.isNotEmpty() } ?: "application/octet-stream"
        }
        val filename = f.s("filename") ?: ""
        uploads.add(PreparedFile(formKey, filename, content, contentType ?: guessContentType(filename) ?: "application/octet-stream"))
        retire.add("${originOf(url)}/${f["path"]}")
    }
    // The key leaves the cache for the upload (or the upload would seal the files again), but comes
    // back if anything fails: all or nothing, as in skapi-js. A failed conversion removes the copies
    // that did upload and refuses the write, so the record and its files stay as they were.
    val held = if (wantSealed) s.deks.remove(recordId) else null
    val result = try {
        uploadPrepared(uploads, recordId)
    } catch (e: Exception) {
        if (held != null) s.deks[recordId] = held
        throw e
    }
    if (result.failed.isNotEmpty()) {
        if (held != null) s.deks[recordId] = held
        val landed = result.landed.filter { it.isNotEmpty() }
        if (landed.isNotEmpty()) {
            try {
                removeLandedCopies(recordId, landed)
            } catch (e: Exception) {
                log.warning("skapi: could not remove the partly converted copies: $e")
            }
        }
        val first = result.errors[0].error
        throw perr("The record's attached files could not all be converted, so the record was not changed: $first", first.code)
    }
    return retire
}

/**
 * A record file joins the record's file list a moment after its upload, and removing an address the
 * list does not hold yet does nothing, so wait for them to appear, then remove them in one write.
 */
private fun Core.removeLandedCopies(recordId: String, urls: List<String>) {
    fun bare(u: String) = pctDecode(u.substringBefore('?'))
    val want = urls.map { bare(it) }.toSet()
    for (attempt in 0 until 8) {
        val rec = readOwnRecord(recordId)
        val have = bins(rec).map { bare(it.second.s("url") ?: "") }.toSet()
        if (have.containsAll(want)) break
        Thread.sleep((500L * (attempt + 1)))
    }
    postRecord(NoData, jmap("record_id" to recordId, "remove_bin" to urls.toMutableList<Any?>()))
}

private fun Core.rewrapAll(dek: ByteArray, recipients: JMap, me: String, anchor: String, aad: ByteArray): JMap {
    val out = jmap(me to recipients[me])
    val others = recipients.keys.filter { it != me }
    val keys = if (others.isNotEmpty()) peerKeys(others) else emptyMap()
    for (u in others) {
        val k = keys[u] ?: continue // as in skapi-js: a grantee whose key cannot be found is dropped
        val w = jmap("t" to "ecdh")
        w.putAll(ecdhWrap(dek, k.first, wrapInfo(anchor, me, u, k.second), recipientAad(aad, u, k.second)))
        w["fpr"] = k.second
        out[u] = w
    }
    return out
}

private fun Core.cacheDek(rid: String, dek: ByteArray, recipients: JMap, anch: String, uid: String, own: String,
                          ctUrl: String = "", ctStale: List<String>? = null) {
    val s = enc!!
    val entry = s.deks.getOrPut(rid) { DekEntry(dek, recipients.copyMap(), anch, uid, own, "private", rid) }
    entry.bytes = dek
    entry.recipients = recipients.copyMap()
    entry.anch = anch
    entry.uid = uid
    entry.rid = rid
    entry.own = own
    entry.accessGroup = "private"
    if (ctUrl.isNotEmpty()) {
        entry.ctUrl = ctUrl
        entry.ctStale = (ctStale ?: emptyList()).toMutableList()
    }
}

// ---- read ---------------------------------------------------------------------------------------------

/** (value, flag). Never throws. */
internal fun Core.maybeDecrypt(raw: Any?, ctx: JMap): Pair<Any?, JMap?> {
    if (!isEnvelope(raw) || ctx["access_group"] != "private") return Pair(raw, null)
    val s = enc ?: return Pair(null, jmap("status" to "failed", "reason" to "ENCRYPTION_DISABLED"))
    if (ctx["table_name"] == s.cfg.table) return Pair(raw, null)
    val env = raw.asMap()!!

    fun fail(reason: String, recipients: List<String>? = null): Pair<Any?, JMap?> {
        val flag = jmap("status" to "failed", "reason" to reason)
        if (recipients != null) flag["recipients"] = recipients.toMutableList<Any?>()
        if (s.cfg.withheld == "sentinel") {
            val v = jmap(WITHHELD to true, "reason" to reason)
            if (reason == "NOT_A_RECIPIENT") v["recipients"] = recipients?.toMutableList<Any?>()
            return Pair(v, flag)
        }
        return Pair(null, flag)
    }

    return try {
        encAwaitDevice()
        if (!numEq(env[ENV_MARKER], 1L)) return fail("UNSUPPORTED_VERSION")
        if (env["own"] != ctx["user_id"] ||
            (truthy(env["uid"]) && truthy(ctx["unique_id"]) && env["uid"] != ctx["unique_id"]) ||
            (truthy(env["rid"]) && truthy(ctx["record_id"]) && env["rid"] != ctx["record_id"])) {
            return fail("BINDING_MISMATCH")
        }
        val me = me()
        val k = env.m("k")!!
        val wrap = k[me].asMap()
        if (wrap == null || wrap.isEmpty()) return fail("NOT_A_RECIPIENT", k.keys.toList())
        val mk = s.mk
        if (s.status != "unlocked" || mk == null) return fail("NO_SESSION_KEY")
        val own = env["own"] as String
        val anch = env["anch"] as String
        val anchor = anchorOf(env)
        val aad = payloadAad(own, anch, anchor)
        val dek = try {
            when (wrap["t"]) {
                "mk" -> openGcm(mk, b64uDec(wrap["iv"]), b64uDec(wrap["ct"]), recipientAad(aad, me, "mk"))
                "ecdh" -> {
                    val ik = s.ikPriv ?: return fail("NO_SESSION_KEY")
                    val fpr = (wrap["fpr"] as? String) ?: ""
                    ecdhUnwrap(ik, wrap, wrapInfo(anchor, own, me, fpr), recipientAad(aad, me, fpr))
                }
                else -> return fail("UNSUPPORTED_VERSION")
            }
        } catch (e: Exception) {
            return fail("BAD_KEY")
        }
        var ctUsed = ""
        var ctStale = listOf<String>()
        val value: Any?
        if (truthy(env["ct_ref"])) {
            // newest payload file first (see Database.kt); older SDKs could leave several, so the first one
            // that passes the GCM tag check is the current one, and the rest are retired on the next update
            val list = ctx.l("ct_urls")?.mapNotNull { it as? String }
            val candidates = if (!list.isNullOrEmpty()) list else listOfNotNull((ctx["ct_url"] as? String)?.takeIf { it.isNotEmpty() })
            var fetched = false
            var opened: Any? = null
            for (url in candidates) {
                val ct = try {
                    getFile(url, jmap("dataType" to "bytes")) as ByteArray
                } catch (e: Exception) {
                    continue
                }
                fetched = true
                try {
                    opened = parseJson(utf8Dec(openGcm(dek, b64uDec(env["iv"]), ct, aad)))
                    ctUsed = url
                    break
                } catch (e: Exception) {
                    continue
                }
            }
            if (ctUsed.isEmpty()) return fail(if (fetched) "CORRUPT" else "DATA_UNAVAILABLE")
            ctStale = candidates.filter { it != ctUsed }
            value = opened
        } else {
            val ct = try { b64uDec(env["ct"]) } catch (e: Exception) { return fail("DATA_UNAVAILABLE") }
            value = try {
                parseJson(utf8Dec(openGcm(dek, b64uDec(env["iv"]), ct, aad)))
            } catch (e: Exception) {
                return fail("CORRUPT")
            }
        }
        val rid = ctx["record_id"] as? String
        if (!rid.isNullOrEmpty()) cacheDek(rid, dek, k, anch, (env["uid"] as? String) ?: "", own, ctUsed, ctStale)
        Pair(value, jmap("status" to "encrypted", "recipients" to k.keys.toMutableList<Any?>()))
    } catch (e: Exception) {
        fail("CORRUPT")
    }
}

// ---- files ------------------------------------------------------------------------------------------------

internal fun Core.maybeEncryptFile(recordId: String, entry: PreparedFile): PreparedFile {
    val s = enc
    if (s == null || entry.name == CT_KEY) return entry.copy(presealed = false)
    // already sealed by a revoke, under the key its roll is about to install
    if (entry.presealed) return entry.copy(presealed = false)
    if (FILE_MARKER in entry.name) throw perr("\"__skenc__\" is reserved in an upload form key.")
    encAwaitDevice()
    // as in skapi-js: without the record's key cached, the file goes up as is
    val dekEntry = s.deks[recordId] ?: return entry
    val container = encryptFile(dekEntry.bytes, mapOf("service" to service, "owner" to owner, "recordOwner" to dekEntry.own, "recordId" to recordId),
        entry.content, entry.filename, entry.contentType, 0)
    return entry.copy(name = "${entry.name}$FILE_MARKER${b62(entry.content.size.toLong())}", content = container, contentType = "application/octet-stream")
}

/**
 * Before uploadFiles seals files with a record's cached data key: the key must still be the
 * record's. Another session of the owner may have rolled it (a revoke) since, and files sealed
 * under the old key could never be opened. A stale key is replaced by reading the record again;
 * when the record is encrypted and this session cannot read its new key, the upload is refused
 * rather than sending the files up in the clear or under a dead key.
 */
internal fun Core.confirmFileDek(recordId: String?) {
    val s = enc ?: return
    if (recordId.isNullOrEmpty() || !s.deks.containsKey(recordId)) return
    if (dekIfCurrent(recordId) != null) return
    val rec = readOwnRecord(recordId)
    if (rec == null || !truthy(rec["encrypted"])) return
    val readId = rec["record_id"] as? String
    if (readId != null && readId != recordId) s.deks[readId]?.let { s.deks[recordId] = it }
    if (!s.deks.containsKey(recordId)) {
        throw perr("Cannot attach files to encrypted record \"$recordId\": its data key changed on another device and could not " +
            "be read here (${encFlag(rec)?.get("reason")}).", "ENCRYPTION_LOCKED")
    }
}

private fun sealedFileSegments(url: String): List<String>? {
    val all = url.substringBefore('?').split("/")
    if (all.size < 3) return null
    val segs = all.drop(3)
    if (segs.size < 12 || segs[4] != "records" || segs[7] != "bin" || parseFileMarker(segs[10]) == null) return null
    return segs
}

internal fun Core.maybeDecryptFile(requestedUrl: String, blob: ByteArray): ByteArray {
    if (enc == null || sealedFileSegments(requestedUrl) == null) return blob
    return decryptFileFor(requestedUrl, blob).first
}

private fun Core.decryptFileFor(requestedUrl: String, blob: ByteArray): Pair<ByteArray, JMap> {
    val segs = sealedFileSegments(requestedUrl) ?: throw perr("Not an encrypted record file url.")
    encAwaitDevice()
    val dekEntry = enc!!.deks[segs[5]]
        ?: throw perr("Cannot open this file: the data key for record \"${segs[5]}\" is not available. Read the record first, and make sure encryption is unlocked.", "ENCRYPTION_LOCKED")
    if (!isEncryptedFile(blob)) throw perr("This file is marked as encrypted but its contents are not an encrypted container.", "ENCRYPTION_FILE_CORRUPT")
    return decryptFile(dekEntry.bytes, mapOf("service" to service, "owner" to owner, "recordOwner" to segs[3], "recordId" to segs[5]), blob)
}

// ---- sharing ------------------------------------------------------------------------------------------------

private fun Core.loadForRewrap(recordId: String): DekEntry? {
    val s = enc!!
    dekIfCurrent(recordId)?.let { return it }
    val rec = readOwnRecord(recordId) ?: throw perr("Record \"$recordId\" not found.", "NOT_EXISTS")
    val flag = encFlag(rec)
    if (flag != null && flag["status"] == "failed" && flag["reason"] == "DATA_UNAVAILABLE") {
        throw perr("Cannot change sharing on record \"$recordId\": its data could not be read, " +
            "so whether it is encrypted is unknown. Retry once the record reads normally.", "ENCRYPTION_DATA_UNAVAILABLE")
    }
    if (flag == null || flag.isEmpty()) return null
    if (rec["user_id"] != me()) {
        throw perr("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
    }
    return s.deks[rec["record_id"] as? String ?: ""]
        ?: throw perr("Cannot change sharing on record \"$recordId\": its data could not be decrypted (${flag["reason"]}).", "ENCRYPTION_LOCKED")
}

/**
 * The record's stored envelope, as the server holds it (null when it is not one). Its own read,
 * never decrypted, as skapi-js readStoredEnvelope.
 */
private fun Core.readStoredEnvelope(recordId: String): JMap? {
    val (q, _) = buildQuery(if (ALNUM.matches(recordId)) jmap("record_id" to recordId) else jmap("unique_id" to recordId), false)
    val signedIn = signedIn()
    val res = call("get-records", q, auth = signedIn, method = if (signedIn) "POST" else "GET", fetchOptions = jmap("limit" to 1L))
    val raw = res.asMap().l("list")?.firstOrNull().asMap() ?: return null
    val rec = normalizeRecord(raw, skipBinResolve = true, skipDecrypt = true).asMap() ?: return null
    return if (isEnvelope(rec["data"])) rec["data"].asMap() else null
}

private fun Core.writeRecipients(recordId: String, recipients: JMap) {
    val stored = readStoredEnvelope(recordId)
        ?: throw perr("Cannot change sharing on record \"$recordId\": its stored envelope could not be read.", "ENCRYPTION_DATA_UNAVAILABLE")
    val s = enc!!
    s.deks[recordId]?.recipients = recipients.copyMap()
    val pass = stored.copyMap()
    pass["k"] = recipients
    s.passthrough[recordId] = pass
    postRecord(NoData, jmap("record_id" to recordId))
}

internal fun Core.encAddRecipients(recordId: String, ids: List<String>) {
    if (enc == null || ids.isEmpty()) return
    encAwaitDevice()
    val entry = loadForRewrap(recordId) ?: return
    val me = me()
    if (entry.own != me) {
        throw perr("Only the record owner can share an encrypted record, because adding a key wrap means writing the record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
    }
    val targets = ids.filter { it != me }
    val keys = peerKeys(targets)
    val missing = targets.filter { keys[it] == null }
    if (missing.isNotEmpty()) {
        throw perr("These users have no encryption key yet, so they cannot be given access: ${missing.joinToString(", ")}. " +
            "A user's key is created the first time they log in with encryption enabled.", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
    }
    val recipients = entry.recipients.copyMap()
    val anchor = anchorOf(entry)
    val aad = payloadAad(entry.own, entry.anch, anchor)
    for (u in targets) {
        val (pub, fpr) = keys[u]!!
        val w = jmap("t" to "ecdh")
        w.putAll(ecdhWrap(entry.bytes, pub, wrapInfo(anchor, entry.own, u, fpr), recipientAad(aad, u, fpr)))
        w["fpr"] = fpr
        recipients[u] = w
    }
    writeRecipients(recordId, recipients)
}

internal fun Core.encDropAndRoll(recordId: String, ids: List<String>?) {
    val s = enc ?: return
    encAwaitDevice()
    val entry = loadForRewrap(recordId) ?: return
    val me = me()
    if (entry.own != me) throw perr("Only the record owner can revoke access to an encrypted record.", "ENCRYPTION_GRANT_REQUIRES_OWNER")
    // the plaintext FIRST, while the current key is still usable
    val rec = readOwnRecord(recordId)
    if (rec == null || encFlag(rec)?.get("status") == "failed") {
        throw perr("Cannot change sharing on record \"$recordId\": its current data could not be read " +
            "(${encFlag(rec)?.get("reason")}), so re-writing the record would destroy it.", "ENCRYPTION_DATA_UNAVAILABLE")
    }
    val rid = (rec["record_id"] as? String)?.takeIf { it.isNotEmpty() } ?: recordId
    // who keeps access, from the record just read rather than an older cached map
    val current = s.deks[rid] ?: entry
    val keep = if (ids == null) emptyList() else current.recipients.keys.filter { it != me && it !in ids }
    val keys = if (keep.isNotEmpty()) peerKeys(keep) else emptyMap()
    val missing = keep.filter { keys[it] == null }
    if (missing.isNotEmpty()) {
        throw perr("Cannot revoke on record \"$recordId\": these users keep access but their encryption keys could not be read, " +
            "so re-sharing after the key roll would fail and lock them out: ${missing.joinToString(", ")}.", "ENCRYPTION_RECIPIENT_HAS_NO_KEY")
    }
    // The new data key, minted now so the record's sealed attachments are sealed again under it
    // BEFORE the roll: each one is opened with the current key, sealed with the new one and
    // uploaded, and the roll write retires the old copies. Interrupted before the roll, the record
    // still reads exactly as before. Until the roll lands the new copies are sealed under a key the
    // record does not hold, so a failure on the way removes the ones already stored.
    val nextKey = randomBytes(32)
    val ctx = mapOf("service" to service, "owner" to owner, "recordOwner" to me, "recordId" to rid)
    val reseal = mutableListOf<PreparedFile>()
    val retire = mutableListOf<String>()
    for ((formKey, f) in bins(rec)) {
        if (!truthy(f["encrypted"])) continue
        val url = f.s("url") ?: ""
        val filename = f.s("filename") ?: ""
        val (content, meta) = try {
            decryptFileFor(url, getFile(url, jmap("dataType" to "bytes", "_raw" to true)) as ByteArray)
        } catch (e: SkapiException) {
            if (e.code == "ENCRYPTION_FILE_STALE_KEY") continue // sealed under a key an earlier roll retired: nobody can open it
            throw SkapiException("Cannot revoke on record \"$recordId\": its encrypted file \"$filename\" could not be read, " +
                "so rolling the key would lock it: $e", "ENCRYPTION_DATA_UNAVAILABLE", e)
        } catch (e: Exception) {
            throw SkapiException("Cannot revoke on record \"$recordId\": its encrypted file \"$filename\" could not be read, " +
                "so rolling the key would lock it: $e", "ENCRYPTION_DATA_UNAVAILABLE", e)
        }
        val contentType = (meta["t"] as? String)?.takeIf { it.isNotEmpty() } ?: guessContentType(filename) ?: "application/octet-stream"
        reseal.add(PreparedFile("$formKey$FILE_MARKER${b62(content.size.toLong())}", filename,
            encryptFile(nextKey, ctx, content, filename, contentType, toLongOrNull(meta["lm"]) ?: 0L),
            "application/octet-stream", presealed = true))
        retire.add("${originOf(url)}/${f["path"]}")
    }
    var copies: List<String> = emptyList()
    if (reseal.isNotEmpty()) {
        val result = uploadPrepared(reseal, rid)
        copies = result.landed.filter { it.isNotEmpty() }
        if (result.failed.isNotEmpty()) {
            if (copies.isNotEmpty()) {
                try {
                    removeLandedCopies(rid, copies)
                } catch (e: Exception) {
                    log.warning("skapi encryption: the re-sealed copies could not be removed: $e")
                }
            }
            throw result.errors[0].error
        }
    }
    s.roll.add(rid)
    s.rollKey[rid] = nextKey
    val config = jmap("record_id" to rid, "table" to jmap("name" to rec.m("table")?.get("name"), "access_group" to "private"))
    if (retire.isNotEmpty()) config["remove_bin"] = retire.toMutableList<Any?>()
    try {
        postRecord(rec["data"], config)
    } catch (e: Exception) {
        if (copies.isNotEmpty()) {
            try {
                dropUnrolledCopies(rid, nextKey, copies)
            } catch (e2: Exception) {
                log.warning("skapi encryption: the re-sealed copies could not be removed: $e2")
            }
        }
        throw e
    } finally {
        // never left for a later write: a pending roll writes a key wrapped for the owner only
        s.roll.remove(rid)
        s.rollKey.remove(rid)
    }
    if (keep.isNotEmpty()) encAddRecipients(rid, keep)
}

/**
 * After a failed roll write: removes the re-sealed attachment copies, unless the write landed after
 * all (only its answer was lost), in which case they are the record's files now. Which one it was is
 * read off the stored envelope: the owner's wrap opens to the new key or the old one. When that
 * cannot be told, the copies are left alone. As skapi-js dropUnrolledCopies.
 */
private fun Core.dropUnrolledCopies(recordId: String, nextKey: ByteArray, copies: List<String>) {
    val s = enc!!
    val raw = readStoredEnvelope(recordId)
    val me = me()
    val w = if (raw != null && me.isNotEmpty()) raw.m("k")?.get(me).asMap() else null
    val mk = s.mk
    if (raw == null || w == null || w["t"] != "mk" || mk == null || raw["own"] != me) return
    val stored = try {
        openGcm(mk, b64uDec(w["iv"]), b64uDec(w["ct"]),
            recipientAad(payloadAad(raw["own"] as String, raw["anch"] as String, anchorOf(raw)), me, "mk"))
    } catch (e: Exception) {
        return
    }
    if (!stored.contentEquals(nextKey)) removeLandedCopies(recordId, copies)
}

// ---- public methods -----------------------------------------------------------------------------------------

internal fun Core.getEncryptionStatus(): JMap {
    val s = enc ?: return jmap("status" to "disabled")
    encAwaitDevice()
    val out = jmap("status" to s.status)
    if (s.status != "unlocked") out["reason"] = s.reason
    if (s.userId.isNotEmpty()) out["user_id"] = s.userId
    if (s.fpr.isNotEmpty()) out["fingerprint"] = s.fpr
    return out
}

internal fun isWithheld(value: Any?): Boolean = value.asMap()?.get(WITHHELD) == true

internal fun Core.unlockEncryption(password: String): JMap {
    val s = enc ?: throw perr("Encryption is not enabled for this instance.", "INVALID_REQUEST")
    if (!signedIn()) throw perr("User login is required.", "INVALID_REQUEST")
    if (password.isEmpty()) throw perr("\"password\" is required.")
    encAwaitDevice()
    ensureKeyring(password, create = false) // opens an existing keyring only
    if (s.status != "unlocked") throw perr("Encryption could not be unlocked: ${s.reason}", "ENCRYPTION_LOCKED")
    return jmap("status" to "unlocked")
}

/**
 * Forgets the keys in memory. An encryption recovery code the app has not collected yet is kept: it
 * can never be shown again. forgetDevice also removes the device store entry, so the next restored
 * session stays locked until unlockEncryption().
 */
internal fun Core.lockEncryption(forgetDevice: Boolean = false): JMap {
    val s = enc ?: return jmap("status" to "disabled")
    if (forgetDevice) deleteDevice(s)
    encClear(keepDevice = true)
    return jmap("status" to "locked")
}

/**
 * The "encryption_recovery" entry of getConnectionInfo(), or null when encryption is off or nobody
 * is signed in. The code is created once, when encryption is first set up for a user, and never
 * stored readable, so the FIRST call after that returns it and forgets it; every later call returns
 * code null and a message. As in skapi-js.
 */
internal fun Core.encryptionRecoveryInfo(): JMap? {
    val s = enc ?: return null
    if (!signedIn()) return null
    if (s.cfg.recovery != "code") {
        return jmap("code" to null, "message" to "Encryption recovery codes are turned off (\"encryption.recovery\" is \"none\").")
    }
    val pending = s.pendingRecoveryCode
    if (!pending.isNullOrEmpty() && s.pendingRecoveryUser == me()) {
        s.pendingRecoveryCode = ""
        s.pendingRecoveryUser = ""
        return jmap("code" to pending, "message" to "This is your encryption recovery code. Save it now: it is shown only this once. " +
            "If you forget your password, it is the only way to read your encrypted private data again.")
    }
    if (s.status != "unlocked") {
        return jmap("code" to null, "message" to "Encryption is locked. Unlock it with unlockEncryption() or unlockEncryptionWithRecoveryCode(), " +
            "then call regenerateEncryptionRecoveryCode() to get a new encryption recovery code.")
    }
    return jmap("code" to null, "message" to "Your encryption recovery code was shown once and cannot be shown again. " +
        "Call regenerateEncryptionRecoveryCode() to get a new one.")
}

internal fun Core.unlockEncryptionWithRecoveryCode(code: String, password: String?): JMap {
    val s = enc ?: throw perr("Encryption is not enabled for this instance.", "INVALID_REQUEST")
    if (!signedIn()) throw perr("User login is required. Reset the password and log in first, then use the encryption recovery code.", "INVALID_REQUEST")
    if (code.isEmpty()) throw perr("\"code\" is required.")
    val uid = me()
    val keyring = findKeyring(uid) ?: throw perr("This account has no encryption keyring, so there is nothing to recover.", "NOT_EXISTS")
    val raw = decodeRecoveryCode(code)
    val data = keyring.m("data").copyMap()
    var mk: ByteArray? = null
    for (w in wrapsOf(data, "recovery")) {
        try {
            val salt = w.m("kdf")?.get("s")
            val rk = hkdf(raw, b64uDec(salt), eS("recovery", uid))
            mk = openGcm(rk, b64uDec(w["iv"]), b64uDec(w["ct"]), utf8("${eS("rk", uid)}|HKDF-SHA256|$salt"))
            break
        } catch (e: Exception) {
            continue
        }
    }
    if (mk == null) {
        throw perr("That encryption recovery code did not open the keyring. Check it against the copy you saved when encryption was set up.", "ENCRYPTION_BAD_RECOVERY_CODE")
    }
    adoptKeyring(keyring, mk, uid)
    var wraps = data.l("wraps").copyList()
    var repaired = false
    var newCode: String? = null
    if (!password.isNullOrEmpty()) {
        wraps = wraps.filter { it.asMap()?.get("p") != "password" }.toMutableList()
        wraps.add(passwordWrap(mk, password, uid))
        repaired = true
    }
    if (s.cfg.recovery == "code") {
        val (w, c) = recoveryWrap(mk, uid)
        wraps = wraps.filter { it.asMap()?.get("p") != "recovery" }.toMutableList()
        wraps.add(w)
        newCode = c
    }
    data["wraps"] = wraps
    data["updated"] = System.currentTimeMillis()
    postRecord(data, jmap("record_id" to keyring["record_id"]))
    saveDevice(s)
    return jmap("status" to "unlocked", "repaired" to repaired, "encryptionRecoveryCode" to newCode)
}

internal fun Core.regenerateEncryptionRecoveryCode(): JMap {
    val s = enc ?: throw perr("Encryption is not enabled for this instance.", "INVALID_REQUEST")
    encAwaitDevice()
    val mkNow = s.mk
    if (s.status != "unlocked" || mkNow == null) {
        throw perr("Encryption must be unlocked to issue an encryption recovery code. Only someone who can already decrypt can create one.", "ENCRYPTION_LOCKED")
    }
    if (s.cfg.recovery == "none") {
        throw perr("Encryption recovery codes are turned off for this instance (\"encryption.recovery\" is \"none\").", "INVALID_REQUEST")
    }
    val res = getRecords(jmap("record_id" to s.keyringRecordId), jmap("limit" to 1L))
    val keyring = res.l("list")?.firstOrNull().asMap() ?: throw perr("The encryption keyring could not be read.", "ENCRYPTION_KEYRING_CORRUPT")
    val data = keyring.m("data").copyMap()
    val self = data.m("self")
    if (self == null || !truthy(self["ct"])) {
        throw perr("This keyring predates encryption recovery code rotation and cannot issue a new code. " +
            "Use unlockEncryptionWithRecoveryCode() with the existing code, which issues a replacement.", "ENCRYPTION_KEYRING_CORRUPT")
    }
    val mk = openGcm(mkNow, b64uDec(self["iv"]), b64uDec(self["ct"]), utf8(eS("self", s.userId)))
    val (w, code) = recoveryWrap(mk, s.userId)
    val wraps = data.l("wraps").copyList().filter { it.asMap()?.get("p") != "recovery" }.toMutableList()
    wraps.add(w)
    data["wraps"] = wraps
    data["updated"] = System.currentTimeMillis()
    postRecord(data, jmap("record_id" to s.keyringRecordId))
    return jmap("encryptionRecoveryCode" to code)
}

internal fun Core.pinPeerKey(userId: String, fingerprint: String) {
    val s = enc
    if (s == null || s.status != "unlocked") throw perr("Encryption is locked.", "ENCRYPTION_LOCKED")
    s.pins[userId] = fingerprint
    s.peerPub.remove(userId)
    persistPins()
}
