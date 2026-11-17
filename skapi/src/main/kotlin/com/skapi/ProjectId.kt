package com.skapi

import java.math.BigInteger

/** Project IDs: the compact form shown on skapi.com, and the service id and owner id inside it. */
internal object ProjectId {
    const val BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    private const val REGION_ALPHABET = "0123456789abcdefghijkl" // 22 characters, not base62 order past the digits
    private val REGION_KEYS = listOf(
        "us31", "us72", "ap51", "ap22", "ap41", "eu71", "ap21", "us32", "us71",
        "af51", "ap31", "ap43", "ap23", "ap42", "ca01", "eu01", "eu72", "eu51",
        "eu73", "eu11", "me51", "sa31",
    )
    private val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
    private val B62 = BigInteger.valueOf(62)

    private fun b62ToInt(text: String): BigInteger {
        var n = BigInteger.ZERO
        for (ch in text) {
            val i = BASE62.indexOf(ch)
            if (i < 0) throw IllegalArgumentException()
            n = n.multiply(B62).add(BigInteger.valueOf(i.toLong()))
        }
        return n
    }

    private fun intToB62(value: BigInteger): String {
        if (value.signum() == 0) return "0"
        var n = value
        val sb = StringBuilder()
        while (n.signum() > 0) {
            val qr = n.divideAndRemainder(B62)
            sb.append(BASE62[qr[1].toInt()])
            n = qr[0]
        }
        return sb.reverse().toString()
    }

    private fun decompress(token: String): String {
        val parts = token.split("-")
        if (parts.size != 2) return token
        val (part1, part2) = parts
        val length = BASE62.indexOf(part1[0])
        if (length < 0) throw IllegalArgumentException()
        val c = part1.substring(1)
        val cut = c.length - (length + 2)
        if (cut < 0) throw IllegalArgumentException()
        val movedMiddle = c.substring(cut)
        val movedFirst = c.substring(0, cut)
        val second = movedMiddle.substring(0, length)
        val first = movedMiddle.substring(length) + movedFirst
        var h = b62ToInt(part2).toString(16)
        if (h.length > 32) throw IllegalArgumentException()
        h = "0".repeat(32 - h.length) + h
        val uuid = "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20, 32)}"
        return "$first-$second-$uuid"
    }

    /** (service, owner) from a Project ID, compact ("5g8N...-7Zd6...") or long (7 parts). */
    fun decode(projectId: String): Pair<String, String> {
        try {
            val longId = decompress(projectId.trim())
            val p = longId.split("-")
            if (p.size != 7) throw IllegalArgumentException()
            val ri = REGION_ALPHABET.indexOf(p[1][0])
            if (ri < 0) throw IllegalArgumentException()
            val region = REGION_KEYS[ri]
            val service = region + p[0] + p[1].substring(1)
            val owner = p.subList(2, 7).joinToString("-")
            if (!UUID.matches(owner)) throw IllegalArgumentException()
            return Pair(service, owner)
        } catch (e: RuntimeException) {
            throw perr("Project ID is invalid.")
        }
    }

    /** The compact Project ID of a service id and owner id: the inverse of decode. */
    fun format(service: String, owner: String): String {
        val first = service.substring(4, service.length - 4)
        val ri = REGION_KEYS.indexOf(service.substring(0, 4))
        if (ri < 0) throw IllegalArgumentException()
        val second = REGION_ALPHABET[ri] + service.substring(service.length - 4)
        val part1 = BASE62[second.length] + first.substring(2) + second + first.substring(0, 2)
        val part2 = intToB62(BigInteger(owner.replace("-", ""), 16))
        return "$part1-$part2"
    }

    fun isProjectId(text: String): Boolean = text.split("-").size in setOf(2, 7)

    fun isUserId(text: String): Boolean = UUID.matches(text)
}
