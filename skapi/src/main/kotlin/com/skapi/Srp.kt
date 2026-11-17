package com.skapi

import java.math.BigInteger
import java.util.Calendar
import java.util.Locale
import java.util.TimeZone
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/*
 * Cognito's SRP-6a password sign-in, ported from skapi-py (_srp.py), itself a port of skapi-js
 * (src/cognito/srp.ts) and amazon-cognito-identity-js. Every step, padHex in particular, must give
 * the same bytes: a wrong padding only fails a sign-in when a value starts with a high bit, about
 * 1 in 256 attempts, so it is easy to miss.
 *
 * The password never leaves the device: only A (g^a mod N) and a signature made with the derived
 * key are sent.
 */

internal object Srp {
    private const val N_HEX =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

    val N: BigInteger = BigInteger(N_HEX, 16)
    val G: BigInteger = BigInteger.valueOf(2)
    private val INFO_BITS = "Caldera Derived Key".toByteArray(Charsets.UTF_8) + byteArrayOf(1)

    /** Hex string to integer, as `new BigInteger(hex, 16)` read it (an empty string is 0). */
    fun hexToInt(hex: String): BigInteger = if (hex.isEmpty()) BigInteger.ZERO else BigInteger(hex, 16)

    /** Two characters at a time, stopping at the first pair that is not hex, like Buffer.from(hex, 'hex'). */
    fun hexToBytes(hex: String): ByteArray {
        val out = java.io.ByteArrayOutputStream(hex.length / 2)
        var i = 0
        while (i + 1 < hex.length) {
            val hi = Character.digit(hex[i], 16)
            val lo = Character.digit(hex[i + 1], 16)
            if (hi < 0 || lo < 0) break
            out.write((hi shl 4) or lo)
            i += 2
        }
        return out.toByteArray()
    }

    /**
     * Signed big-endian hex exactly as the library writes it: even length, a leading "00" when the
     * top bit is set (so the value stays positive), and two's complement for a negative value.
     */
    fun padHex(value: BigInteger): String {
        val negative = value.signum() < 0
        var h = (if (negative) value.negate() else value).toString(16)
        if (h.length % 2 == 1) h = "0$h"
        if (h[0] in "89abcdefABCDEF") h = "00$h"
        if (negative) {
            val inverted = StringBuilder()
            for (c in h) inverted.append("0123456789ABCDEF"[Character.digit(c, 16).inv() and 0xF])
            h = BigInteger(inverted.toString(), 16).add(BigInteger.ONE).toString(16)
            if (h.uppercase().startsWith("FF8")) h = h.substring(2)
        }
        return h
    }

    private fun hashHex(data: ByteArray): String = hex(sha256(data))

    private fun hexHash(h: String): String = hashHex(hexToBytes(h))

    val K: BigInteger = hexToInt(hexHash(padHex(N) + padHex(G)))

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** HKDF-SHA256 with Cognito's info string, first 16 bytes. */
    fun computeHkdf(ikm: ByteArray, salt: ByteArray): ByteArray {
        val prk = hmacSha256(salt, ikm)
        return hmacSha256(prk, INFO_BITS).copyOf(16)
    }

    private val WEEK = arrayOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
    private val MONTH = arrayOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    /** "Sun Nov 15 16:52:00 UTC 2026": the day is not zero padded, the time is. */
    fun cognitoTimestamp(epochMillis: Long = System.currentTimeMillis()): String {
        val c = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US)
        c.timeInMillis = epochMillis
        return String.format(
            Locale.US, "%s %s %d %02d:%02d:%02d UTC %d",
            WEEK[c.get(Calendar.DAY_OF_WEEK) - 1], MONTH[c.get(Calendar.MONTH)], c.get(Calendar.DAY_OF_MONTH),
            c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), c.get(Calendar.SECOND), c.get(Calendar.YEAR),
        )
    }
}

/**
 * poolName: the part of the user pool id after the underscore.
 * smallA: for the equivalence checks only, a fixed secret instead of 128 random bytes.
 */
internal class SrpHelper(val poolName: String, smallA: BigInteger? = null) {
    // 128 random bytes read as a positive integer; no reduction needed, N is 3072 bits.
    val smallA: BigInteger = smallA ?: BigInteger(1, randomBytes(128))
    val largeA: BigInteger = Srp.G.modPow(this.smallA, Srp.N)

    init {
        if (largeA.mod(Srp.N).signum() == 0) throw IllegalStateException("Illegal paramater. A mod N cannot be 0.")
    }

    /** u, as computed from A and B. */
    fun u(serverB: BigInteger): BigInteger = Srp.hexToInt(hexHashOf(Srp.padHex(largeA) + Srp.padHex(serverB)))

    /** x, from the salt and the hash of "<pool><username>:<password>". */
    fun x(username: String, password: String, salt: BigInteger): BigInteger {
        val usernamePasswordHash = hex(sha256("$poolName$username:$password".toByteArray(Charsets.UTF_8)))
        return Srp.hexToInt(hexHashOf(Srp.padHex(salt) + usernamePasswordHash))
    }

    /** S = (B - k * g^x) ^ (a + u * x) mod N, the base reduced to [0, N) first. */
    fun s(serverB: BigInteger, x: BigInteger, u: BigInteger): BigInteger {
        val base = serverB.subtract(Srp.K.multiply(Srp.G.modPow(x, Srp.N))).mod(Srp.N)
        return base.modPow(smallA.add(u.multiply(x)), Srp.N)
    }

    /** The 16 byte key both sides derive; Cognito checks a signature made with it. */
    fun passwordAuthenticationKey(username: String, password: String, serverB: BigInteger, salt: BigInteger): ByteArray {
        if (serverB.mod(Srp.N).signum() == 0) throw IllegalStateException("B cannot be zero.")
        val u = u(serverB)
        if (u.signum() == 0) throw IllegalStateException("U cannot be zero.")
        val x = x(username, password, salt)
        val s = s(serverB, x, u)
        return Srp.computeHkdf(Srp.hexToBytes(Srp.padHex(s)), Srp.hexToBytes(Srp.padHex(u)))
    }

    private fun hexHashOf(h: String): String = hex(sha256(Srp.hexToBytes(h)))
}
