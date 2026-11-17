package com.skapi

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/*
 * Client-side record encryption primitives, ported byte for byte from skapi-py (_encryption.py),
 * itself a port of skapi-js (src/utils/crypto.ts), so records and files sealed by any of the SDKs
 * open in the others. Everything here runs on Android 7 (API 24): no java.util.Base64, no
 * java.time, and PBKDF2 written out where the platform lacks PBKDF2WithHmacSHA256.
 */

internal const val ENC_V = "skapi.enc.v1"
internal const val PBKDF2_ITERATIONS = 600000
internal const val ENV_MARKER = "__skapi_enc__"
internal const val WITHHELD = "__skapi_no_access__"
internal const val SPILL_LIMIT = 256 * 1024
internal const val CT_KEY = "__skenc_ct__"
internal const val CT_FILE = "payload.bin"
internal const val CT_FILE_SUFFIX = "/$CT_KEY/$CT_FILE"
internal const val FILE_MARKER = "__skenc__"
internal const val FILE_CHUNK = 4 * 1024 * 1024
internal const val ENVELOPE_CAP = 2 * 1024 * 1024
private const val B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
private const val B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ---- helpers that need no crypto (used with encryption off too) -----------------------------------

internal fun isEnvelope(v: Any?): Boolean {
    val m = v.asMap() ?: return false
    return m[ENV_MARKER] is Number && listOf("ct", "iv", "own", "anch").all { m[it] is String } && m["k"] is Map<*, *>
}

internal fun b62(n: Long): String {
    if (n == 0L) return "0"
    var x = n
    val sb = StringBuilder()
    while (x > 0) {
        sb.append(B62[(x % 62).toInt()])
        x /= 62
    }
    return sb.reverse().toString()
}

internal fun fromB62Strict(s: String): Long? {
    if (s.isEmpty()) return null
    var n = 0L
    for (ch in s) {
        val i = B62.indexOf(ch)
        if (i < 0) return null
        n = n * 62 + i
    }
    return n
}

/** "<form key>__skenc__<b62 plain size>" to (form key, plain size), else null. */
internal fun parseFileMarker(pathKey: String): Pair<String, Long>? {
    val i = pathKey.lastIndexOf(FILE_MARKER)
    if (i < 0) return null
    val size = fromB62Strict(pathKey.substring(i + FILE_MARKER.length)) ?: return null
    return Pair(pathKey.substring(0, i), size)
}

/** skapi-js's recovery code check: FNV-1a as JavaScript computes it (signed XOR, double multiply). */
internal fun checkBits(raw: ByteArray): Int {
    val two32 = 4294967296L
    var h = 0x811c9dc5L
    for (b in raw) {
        var x = h xor (b.toLong() and 0xFF)
        if (x >= 2147483648L) x -= two32
        val product = x.toDouble() * 16777619.0 // integral: exact below 2^53, a whole double above
        h = Math.floorMod(product.toLong(), two32)
    }
    return (h and 0x3ff).toInt()
}

internal fun encodeRecoveryCode(raw: ByteArray): String {
    val out = StringBuilder()
    var acc = 0L
    var bits = 0
    for (b in raw) {
        acc = ((acc shl 8) or (b.toLong() and 0xFF)) and 0xFFFFF
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out.append(B32[((acc shr bits) and 31).toInt()])
        }
    }
    if (bits > 0) out.append(B32[((acc shl (5 - bits)) and 31).toInt()])
    val chk = checkBits(raw)
    out.append(B32[(chk shr 5) and 31]).append(B32[chk and 31])
    return out.chunked(4).joinToString("-")
}

internal fun decodeRecoveryCode(code: String): ByteArray {
    val s = code.uppercase().filter { it !in " \t\r\n-_" }.replace("O", "0").replace("I", "1").replace("L", "1")
    if (s.length != 28) {
        throw perr("That does not look like an encryption recovery code: expected 28 characters, got ${s.length}.", "ENCRYPTION_BAD_RECOVERY_CODE")
    }
    for (ch in s) {
        if (B32.indexOf(ch) < 0) throw perr("That does not look like an encryption recovery code: \"$ch\" is not a valid character.", "ENCRYPTION_BAD_RECOVERY_CODE")
    }
    var acc = 0L
    var bits = 0
    val out = java.io.ByteArrayOutputStream()
    for (ch in s.substring(0, 26)) {
        acc = ((acc shl 5) or B32.indexOf(ch).toLong()) and 0xFFFFF
        bits += 5
        if (bits >= 8) {
            bits -= 8
            out.write(((acc shr bits) and 0xFF).toInt())
        }
    }
    val raw = out.toByteArray().copyOf(16)
    val chk = checkBits(raw)
    if (s.substring(26) != "${B32[(chk shr 5) and 31]}${B32[chk and 31]}") {
        throw perr("That encryption recovery code has a typo in it: the check characters do not match.", "ENCRYPTION_BAD_RECOVERY_CODE")
    }
    return raw
}

// ---- primitives ------------------------------------------------------------------------------------

private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
    for (p in parts) mac.update(p)
    return mac.doFinal()
}

/** HKDF-SHA256 (RFC 5869). An empty salt is the same as 32 zero bytes. */
internal fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, length: Int = 32): ByteArray {
    val prk = hmac(salt, ikm)
    val infoBytes = utf8(info)
    val out = java.io.ByteArrayOutputStream(length)
    var t = ByteArray(0)
    var counter = 1
    while (out.size() < length) {
        t = hmac(prk, t, infoBytes, byteArrayOf(counter.toByte()))
        out.write(t)
        counter++
    }
    return out.toByteArray().copyOf(length)
}

/** AES-256-GCM with a fresh 12 byte IV: {"iv", "ct"} in base64url. */
internal fun seal(key: ByteArray, pt: ByteArray, aad: ByteArray): JMap {
    val (iv, ct) = sealRaw(key, pt, aad)
    return jmap("iv" to b64u(iv), "ct" to b64u(ct))
}

internal fun sealRaw(key: ByteArray, pt: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
    val iv = randomBytes(12)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    c.updateAAD(aad)
    return Pair(iv, c.doFinal(pt))
}

/** Opens AES-256-GCM ciphertext (tag appended). Throws a GeneralSecurityException when it does not open. */
internal fun openGcm(key: ByteArray, iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray {
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
    c.updateAAD(aad)
    return c.doFinal(ct)
}

/** PBKDF2-HMAC-SHA256, 32 bytes. */
internal fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(if (password.isEmpty()) ByteArray(32) else password, "HmacSHA256"))
    mac.update(salt)
    mac.update(byteArrayOf(0, 0, 0, 1))
    var u = mac.doFinal()
    val out = u.copyOf()
    for (i in 1 until iterations) {
        u = mac.doFinal(u)
        for (j in out.indices) out[j] = (out[j].toInt() xor u[j].toInt()).toByte()
    }
    return out
}

/**
 * The key a password wrap is sealed with: PBKDF2-SHA256 of the NFC password, then HKDF with the
 * same salt. The platform's PBKDF2WithHmacSHA256 is used for a plain ASCII password (every
 * implementation encodes those the same); otherwise, or where the platform has none (Android
 * before 8), the loop above.
 */
internal fun passwordKek(password: String, salt: ByteArray, iterations: Int, info: String): ByteArray {
    val normalized = Normalizer.normalize(password, Normalizer.Form.NFC)
    val bytes = utf8(normalized)
    var prk: ByteArray? = null
    if (normalized.isNotEmpty() && normalized.all { it.code in 0x20..0x7E }) {
        try {
            val spec = PBEKeySpec(normalized.toCharArray(), salt, iterations, 256)
            prk = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            spec.clearPassword()
        } catch (e: Exception) {
            prk = null
        }
    }
    return hkdf(prk ?: pbkdf2(bytes, salt, iterations), salt, info)
}

private val ecParams: ECParameterSpec by lazy {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ECGenParameterSpec("secp256r1"))
    (g.generateKeyPair().public as ECPublicKey).params
}

private fun fixed32(n: BigInteger): ByteArray {
    val b = n.toByteArray()
    return when {
        b.size == 32 -> b
        b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
        else -> ByteArray(32 - b.size) + b
    }
}

private fun rawPublic(pub: ECPublicKey): ByteArray = byteArrayOf(4) + fixed32(pub.w.affineX) + fixed32(pub.w.affineY)

private val PKCS8_PREFIX = Srp.hexToBytes("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420")
private val PKCS8_MIDDLE = Srp.hexToBytes("a144034200")

/** A P-256 identity: (private key, 65 byte public point, PKCS8 DER in the layout WebCrypto exports). */
internal fun newIdentity(): Triple<PrivateKey, ByteArray, ByteArray> {
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ECGenParameterSpec("secp256r1"))
    val kp = g.generateKeyPair()
    val pub = rawPublic(kp.public as ECPublicKey)
    val d = fixed32((kp.private as ECPrivateKey).s)
    val pkcs8 = PKCS8_PREFIX + d + PKCS8_MIDDLE + pub
    return Triple(loadPkcs8(pkcs8), pub, pkcs8)
}

internal fun loadPkcs8(der: ByteArray): PrivateKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))

internal fun loadPub(raw: ByteArray): ECPublicKey {
    if (raw.size != 65 || raw[0].toInt() != 4) throw perr("Malformed public key: expected a 65 byte uncompressed P-256 point.")
    val x = BigInteger(1, raw.copyOfRange(1, 33))
    val y = BigInteger(1, raw.copyOfRange(33, 65))
    val curve = ecParams.curve
    val p = (curve.field as ECFieldFp).p
    val onCurve = x < p && y < p && y.multiply(y).mod(p) == x.pow(3).add(curve.a.multiply(x)).add(curve.b).mod(p)
    if (!onCurve) throw perr("Malformed public key: not a point on P-256.")
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), ecParams)) as ECPublicKey
}

internal fun fingerprint(pubRaw: ByteArray): String = b64u(sha256(pubRaw))

private fun ecdh(priv: PrivateKey, pub: ECPublicKey): ByteArray {
    val ka = KeyAgreement.getInstance("ECDH")
    ka.init(priv)
    ka.doPhase(pub, true)
    return ka.generateSecret()
}

/** Wraps a data key for a peer: {"epk", "iv", "ct"}. */
internal fun ecdhWrap(dek: ByteArray, peerPubRaw: ByteArray, info: String, aad: ByteArray): JMap {
    val peer = loadPub(peerPubRaw)
    val g = KeyPairGenerator.getInstance("EC")
    g.initialize(ECGenParameterSpec("secp256r1"))
    val eph = g.generateKeyPair()
    val z = ecdh(eph.private, peer)
    val kw = hkdf(z, ByteArray(32), info)
    val sealed = seal(kw, dek, aad)
    val out = jmap("epk" to b64u(rawPublic(eph.public as ECPublicKey)))
    out.putAll(sealed)
    return out
}

internal fun ecdhUnwrap(priv: PrivateKey, wrap: JMap, info: String, aad: ByteArray): ByteArray {
    val z = ecdh(priv, loadPub(b64uDec(wrap["epk"])))
    return openGcm(hkdf(z, ByteArray(32), info), b64uDec(wrap["iv"]), b64uDec(wrap["ct"]), aad)
}

// ---- encrypted file container "SKENCF" v2 ---------------------------------------------------------

internal fun dekId(dek: ByteArray): ByteArray = sha256(utf8("$ENC_V|dekid") + dek).copyOf(8)

private fun fileKey(dek: ByteArray, fileId: ByteArray, ctx: Map<String, String>): ByteArray =
    hkdf(dek, fileId, "$ENC_V|binfile|${ctx["service"]}|${ctx["owner"]}|${ctx["recordOwner"]}|${ctx["recordId"]}")

private fun u32(n: Long): ByteArray = byteArrayOf((n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())

private fun u64(n: Long): ByteArray = u32(n ushr 32) + u32(n and 0xFFFFFFFFL)

private fun readU32(b: ByteArray, at: Int): Long =
    ((b[at].toLong() and 0xFF) shl 24) or ((b[at + 1].toLong() and 0xFF) shl 16) or ((b[at + 2].toLong() and 0xFF) shl 8) or (b[at + 3].toLong() and 0xFF)

private fun chunkAad(headerHash: String, i: Int, count: Int): ByteArray =
    utf8(jsJson(jlist("$ENC_V|binchunk", headerHash, i.toLong(), count.toLong())))

internal fun encryptFile(dek: ByteArray, ctx: Map<String, String>, content: ByteArray, name: String, contentType: String?, lastModified: Long = 0): ByteArray {
    val meta = utf8(jsJson(jmap("n" to name, "t" to (contentType ?: ""), "lm" to lastModified)))
    if (meta.size > 4096) throw perr("Encrypted file metadata is too large.")
    val count = Math.max(1, (content.size + FILE_CHUNK - 1) / FILE_CHUNK)
    val fileId = randomBytes(16)
    val header = "SKENCF".toByteArray(Charsets.US_ASCII) + byteArrayOf(2, if (meta.isNotEmpty()) 1 else 0) + u32(FILE_CHUNK.toLong()) +
        u32(count.toLong()) + fileId + u64(content.size.toLong()) + dekId(dek) + u32(meta.size.toLong()) + ByteArray(4) + meta
    val headerHash = b64u(sha256(header))
    val key = fileKey(dek, fileId, ctx)
    val out = java.io.ByteArrayOutputStream(header.size + content.size + count * 32)
    out.write(header)
    for (i in 0 until count) {
        val chunk = content.copyOfRange(Math.min(content.size, i * FILE_CHUNK), Math.min(content.size, (i + 1) * FILE_CHUNK))
        val (iv, ct) = sealRaw(key, chunk, chunkAad(headerHash, i, count))
        out.write(u32((12 + ct.size).toLong()))
        out.write(iv)
        out.write(ct)
    }
    return out.toByteArray()
}

internal fun isEncryptedFile(b: ByteArray): Boolean =
    b.size >= 56 && String(b, 0, 6, Charsets.ISO_8859_1) == "SKENCF"

internal fun decryptFile(dek: ByteArray, ctx: Map<String, String>, blob: ByteArray): Pair<ByteArray, JMap> {
    if (blob.size < 56) throw skErr("Encrypted file header is truncated.", "INVALID_REQUEST")
    val version = blob[6].toInt() and 0xFF
    val chunkSize = readU32(blob, 8)
    val count = readU32(blob, 12)
    val fileId = blob.copyOfRange(16, 32)
    val plainLen = (readU32(blob, 32) shl 32) or readU32(blob, 36)
    val did = blob.copyOfRange(40, 48)
    val metaLen = readU32(blob, 48)
    if (blob.size < 56 + metaLen) throw skErr("Encrypted file header is truncated.", "INVALID_REQUEST")
    val ml = metaLen.toInt()
    val header = blob.copyOfRange(0, 56 + ml)
    val meta: JMap = if (ml > 0) (parseJson(utf8Dec(blob.copyOfRange(56, 56 + ml))).asMap() ?: LinkedHashMap()) else LinkedHashMap()
    if (version != 2) throw perr("This file was encrypted by a different version of the SDK (container v$version).", "NOT_SUPPORTED")
    if (count == 0L || chunkSize == 0L) throw perr("Encrypted file header is malformed.")
    if (!did.contentEquals(dekId(dek))) {
        throw perr("This file was encrypted under a previous data key for this record, so it can no longer be opened. " +
            "It was most likely left behind by an interrupted access change.", "ENCRYPTION_FILE_STALE_KEY")
    }
    val headerHash = b64u(sha256(header))
    val key = fileKey(dek, fileId, ctx)
    var pos = 56 + ml
    val out = java.io.ByteArrayOutputStream()
    val n = count.toInt()
    for (i in 0 until n) {
        if (pos + 4 > blob.size) throw skErr("Encrypted file is truncated.", "INVALID_REQUEST")
        val len = readU32(blob, pos)
        if (pos + 4 + len > blob.size) throw skErr("Encrypted file is truncated.", "INVALID_REQUEST")
        val l = len.toInt()
        val iv = blob.copyOfRange(pos + 4, pos + 16)
        val ct = blob.copyOfRange(pos + 16, pos + 4 + l)
        out.write(openGcm(key, iv, ct, chunkAad(headerHash, i, n)))
        pos += 4 + l
    }
    val plain = out.toByteArray()
    return Pair(if (plain.size > plainLen) plain.copyOf(plainLen.toInt()) else plain, meta)
}
