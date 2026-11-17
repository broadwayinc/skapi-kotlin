package com.skapi

import java.security.MessageDigest
import java.security.SecureRandom

/*
 * Base64, hex and digests. java.util.Base64 needs Android 8 (API 26), so this is written out:
 * the SDK runs on Android 7 (API 24) as well.
 */

private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
private const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

internal val secureRandom: SecureRandom by lazy { SecureRandom() }

internal fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

private fun encode(data: ByteArray, alphabet: String, pad: Boolean): String {
    val sb = StringBuilder((data.size + 2) / 3 * 4)
    var i = 0
    while (i + 3 <= data.size) {
        val n = ((data[i].toInt() and 0xFF) shl 16) or ((data[i + 1].toInt() and 0xFF) shl 8) or (data[i + 2].toInt() and 0xFF)
        sb.append(alphabet[(n shr 18) and 63]).append(alphabet[(n shr 12) and 63]).append(alphabet[(n shr 6) and 63]).append(alphabet[n and 63])
        i += 3
    }
    val rest = data.size - i
    if (rest == 1) {
        val n = (data[i].toInt() and 0xFF) shl 16
        sb.append(alphabet[(n shr 18) and 63]).append(alphabet[(n shr 12) and 63])
        if (pad) sb.append("==")
    } else if (rest == 2) {
        val n = ((data[i].toInt() and 0xFF) shl 16) or ((data[i + 1].toInt() and 0xFF) shl 8)
        sb.append(alphabet[(n shr 18) and 63]).append(alphabet[(n shr 12) and 63]).append(alphabet[(n shr 6) and 63])
        if (pad) sb.append('=')
    }
    return sb.toString()
}

/** Standard base64 with padding. */
internal fun b64(data: ByteArray): String = encode(data, B64, true)

/** base64url without padding, as skapi-js writes keys, IVs and ciphertexts. */
internal fun b64u(data: ByteArray): String = encode(data, B64URL, false)

/**
 * Base64 in the standard or URL-safe alphabet, padding optional, characters outside the alphabet
 * skipped: what Node's Buffer.from(text, 'base64') and Python's lenient decoder accept.
 */
internal fun b64Any(text: String): ByteArray {
    val out = java.io.ByteArrayOutputStream(text.length * 3 / 4)
    var acc = 0
    var bits = 0
    for (ch in text) {
        if (ch == '=') break
        val v = when (ch) {
            in 'A'..'Z' -> ch - 'A'
            in 'a'..'z' -> ch - 'a' + 26
            in '0'..'9' -> ch - '0' + 52
            '+', '-' -> 62
            '/', '_' -> 63
            else -> -1
        }
        if (v < 0) continue
        acc = (acc shl 6) or v
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((acc shr bits) and 0xFF)
        }
    }
    return out.toByteArray()
}

/** base64url (padding optional), as skapi-py b64u_dec: a length that cannot be base64 is refused. */
internal fun b64uDec(s: Any?): ByteArray {
    if (s !is String) throw perr("Expected a base64url string.")
    val stripped = s.trimEnd('=')
    if (stripped.length % 4 == 1) throw perr("Malformed base64url string.")
    return b64Any(stripped)
}

internal fun hex(data: ByteArray): String {
    val sb = StringBuilder(data.size * 2)
    for (b in data) {
        val n = b.toInt() and 0xFF
        sb.append("0123456789abcdef"[n shr 4]).append("0123456789abcdef"[n and 15])
    }
    return sb.toString()
}

internal fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

internal fun md5Hex(text: String): String = hex(MessageDigest.getInstance("MD5").digest(text.toByteArray(Charsets.UTF_8)))

/**
 * UTF-8 as TextEncoder writes it: a lone surrogate becomes U+FFFD. (Kotlin's encoder writes "?",
 * which would change the bytes an AAD or a key derivation sees.)
 */
internal fun utf8(s: String): ByteArray {
    var clean = true
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c)) {
            if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) { i += 2; continue }
            clean = false; break
        }
        if (Character.isLowSurrogate(c)) { clean = false; break }
        i++
    }
    if (clean) return s.toByteArray(Charsets.UTF_8)
    val sb = StringBuilder(s.length)
    i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
            sb.append(c).append(s[i + 1]); i += 2; continue
        }
        sb.append(if (Character.isSurrogate(c)) '�' else c)
        i++
    }
    return sb.toString().toByteArray(Charsets.UTF_8)
}

/** UTF-8 to text, invalid bytes replaced, a leading byte order mark dropped (as TextDecoder). */
internal fun utf8Dec(b: ByteArray): String {
    val s = String(b, Charsets.UTF_8)
    return if (s.startsWith("﻿")) s.substring(1) else s
}

/** String length as JavaScript counts it: UTF-16 code units, which is what a Kotlin String's length is. */
internal fun jsLength(text: String): Int = text.length

internal fun encodeURIComponent(text: String): String {
    val safe = "-_.!~*'()"
    val sb = StringBuilder()
    for (b in utf8(text)) {
        val n = b.toInt() and 0xFF
        val c = n.toChar()
        if ((c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || safe.indexOf(c) >= 0) sb.append(c)
        else sb.append('%').append("0123456789ABCDEF"[n shr 4]).append("0123456789ABCDEF"[n and 15])
    }
    return sb.toString()
}
