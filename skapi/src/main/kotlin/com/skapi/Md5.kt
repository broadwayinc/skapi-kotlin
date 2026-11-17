package com.skapi

/*
 * The MD5 skapi-js uses to name accounts ("<service>-<md5(e-mail or username)>"), ported from
 * skapi-py (_md5.py).
 *
 * It works on UTF-16 code units, not UTF-8 bytes: for ASCII it equals a standard MD5, for
 * U+0080..U+00FF it equals MD5 of the latin-1 bytes, and above U+00FF it gives digests no
 * standard MD5 produces. A username must hash exactly as skapi-js hashes it, or that account
 * cannot sign in from Kotlin. Int arithmetic wraps at 32 bits, as the JavaScript original's does.
 */
internal object Md5Js {
    private fun cm(q: Int, a: Int, b: Int, x: Int, s: Int, t: Int): Int = Integer.rotateLeft(a + q + (x + t), s) + b
    private fun ff(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int) = cm((b and c) or (b.inv() and d), a, b, x, s, t)
    private fun gg(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int) = cm((b and d) or (c and d.inv()), a, b, x, s, t)
    private fun hh(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int) = cm(b xor c xor d, a, b, x, s, t)
    private fun ii(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int, t: Int) = cm(c xor (b or d.inv()), a, b, x, s, t)

    private val ROUNDS: Array<IntArray> = arrayOf(
        intArrayOf(0, 7, -680876936, 1, 12, -389564586, 2, 17, 606105819, 3, 22, -1044525330, 4, 7, -176418897, 5, 12, 1200080426,
            6, 17, -1473231341, 7, 22, -45705983, 8, 7, 1770035416, 9, 12, -1958414417, 10, 17, -42063, 11, 22, -1990404162,
            12, 7, 1804603682, 13, 12, -40341101, 14, 17, -1502002290, 15, 22, 1236535329),
        intArrayOf(1, 5, -165796510, 6, 9, -1069501632, 11, 14, 643717713, 0, 20, -373897302, 5, 5, -701558691, 10, 9, 38016083,
            15, 14, -660478335, 4, 20, -405537848, 9, 5, 568446438, 14, 9, -1019803690, 3, 14, -187363961, 8, 20, 1163531501,
            13, 5, -1444681467, 2, 9, -51403784, 7, 14, 1735328473, 12, 20, -1926607734),
        intArrayOf(5, 4, -378558, 8, 11, -2022574463, 11, 16, 1839030562, 14, 23, -35309556, 1, 4, -1530992060, 4, 11, 1272893353,
            7, 16, -155497632, 10, 23, -1094730640, 13, 4, 681279174, 0, 11, -358537222, 3, 16, -722521979, 6, 23, 76029189,
            9, 4, -640364487, 12, 11, -421815835, 15, 16, 530742520, 2, 23, -995338651),
        intArrayOf(0, 6, -198630844, 7, 10, 1126891415, 14, 15, -1416354905, 5, 21, -57434055, 12, 6, 1700485571, 3, 10, -1894986606,
            10, 15, -1051523, 1, 21, -2054922799, 8, 6, 1873313359, 15, 10, -30611744, 6, 15, -1560198380, 13, 21, 1309151649,
            4, 6, -145523070, 11, 10, -1120210379, 2, 15, 718787259, 9, 21, -343485551),
    )

    fun md5(text: String): String {
        val length = text.length
        val numBlocks = ((length + 8) shr 6) + 1
        val x = IntArray(numBlocks * 16)
        for (i in 0 until length) {
            x[i shr 2] = x[i shr 2] or (text[i].code shl ((i % 4) * 8))
        }
        x[length shr 2] = x[length shr 2] or (0x80 shl ((length % 4) * 8))
        x[numBlocks * 16 - 2] = length * 8

        var a = 1732584193
        var b = -271733879
        var c = -1732584194
        var d = 271733878
        var i = 0
        while (i < x.size) {
            val la = a; val lb = b; val lc = c; val ld = d
            for ((r, steps) in ROUNDS.withIndex()) {
                for (n in 0 until 16) {
                    val k = steps[n * 3]; val s = steps[n * 3 + 1]; val t = steps[n * 3 + 2]
                    val xi = x[i + k]
                    val f: (Int, Int, Int, Int, Int, Int, Int) -> Int = when (r) { 0 -> ::ff; 1 -> ::gg; 2 -> ::hh; else -> ::ii }
                    when (n % 4) {
                        0 -> a = f(a, b, c, d, xi, s, t)
                        1 -> d = f(d, a, b, c, xi, s, t)
                        2 -> c = f(c, d, a, b, xi, s, t)
                        else -> b = f(b, c, d, a, xi, s, t)
                    }
                }
            }
            a += la; b += lb; c += lc; d += ld
            i += 16
        }
        val alphabet = "0123456789abcdef"
        fun rh(n: Int): String {
            val sb = StringBuilder()
            for (j in 0 until 4) sb.append(alphabet[(n ushr (j * 8 + 4)) and 0x0F]).append(alphabet[(n ushr (j * 8)) and 0x0F])
            return sb.toString()
        }
        return rh(a) + rh(b) + rh(c) + rh(d)
    }
}
