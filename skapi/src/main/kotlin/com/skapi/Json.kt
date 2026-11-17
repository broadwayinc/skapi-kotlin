package com.skapi

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.math.BigDecimal
import java.math.BigInteger

/*
 * JSON as skapi-kotlin uses it.
 *
 * Public methods take and return kotlinx.serialization JsonElement values (JsonObject for
 * objects). Inside the SDK the same values are plain Kotlin values, so the port reads like
 * skapi-py: LinkedHashMap<String, Any?> for objects (insertion order kept), MutableList<Any?>
 * for arrays, String, Long or Double for numbers, Boolean and null.
 */

internal typealias JMap = MutableMap<String, Any?>
internal typealias JList = MutableList<Any?>

internal fun jmap(vararg pairs: Pair<String, Any?>): JMap {
    val m = LinkedHashMap<String, Any?>()
    for ((k, v) in pairs) m[k] = v
    return m
}

internal fun jlist(vararg items: Any?): JList = items.toMutableList()

@Suppress("UNCHECKED_CAST")
internal fun Any?.asMap(): JMap? = this as? MutableMap<String, Any?>

@Suppress("UNCHECKED_CAST")
internal fun Any?.asList(): JList? = this as? MutableList<Any?>

/** A shallow copy, as Python's dict(x). Anything that is not a map gives an empty map. */
internal fun Any?.copyMap(): JMap {
    val m = LinkedHashMap<String, Any?>()
    val src = this as? Map<*, *> ?: return m
    for ((k, v) in src) m[k.toString()] = v
    return m
}

internal fun Any?.copyList(): JList = (this as? List<*>)?.toMutableList() ?: mutableListOf()

/** A deep copy of a JSON value. */
internal fun deepCopy(v: Any?): Any? = when (v) {
    is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for ((k, x) in v) m[k.toString()] = deepCopy(x) }
    is List<*> -> v.map { deepCopy(it) }.toMutableList()
    else -> v
}

/** Python truthiness: null, false, 0, "", empty list or map are false. */
internal fun truthy(v: Any?): Boolean = when (v) {
    null -> false
    is Boolean -> v
    is Number -> v.toDouble() != 0.0
    is String -> v.isNotEmpty()
    is Map<*, *> -> v.isNotEmpty()
    is Collection<*> -> v.isNotEmpty()
    is ByteArray -> v.isNotEmpty()
    else -> true
}

/** A number that is not a boolean (Kotlin booleans are never Numbers). */
internal fun isNum(v: Any?): Boolean = v is Number

internal fun numEq(a: Any?, b: Any?): Boolean {
    if (a is Number && b is Number) return a.toDouble() == b.toDouble()
    return a == b
}

/** Equality of JSON values with numbers compared by value (1 == 1.0), as Python compares them. */
internal fun jsonEq(a: Any?, b: Any?): Boolean {
    if (a is Number && b is Number) return a.toDouble() == b.toDouble()
    if (a is Map<*, *> && b is Map<*, *>) {
        if (a.size != b.size) return false
        for ((k, v) in a) {
            if (!b.containsKey(k) || !jsonEq(v, b[k])) return false
        }
        return true
    }
    if (a is List<*> && b is List<*>) {
        if (a.size != b.size) return false
        for (i in a.indices) if (!jsonEq(a[i], b[i])) return false
        return true
    }
    return a == b
}

internal fun Any?.str(): String? = this as? String

/** The value of a map key, as a string when it is one. */
internal fun JMap?.s(key: String): String? = this?.get(key) as? String

internal fun JMap?.m(key: String): JMap? = this?.get(key).asMap()

internal fun JMap?.l(key: String): JList? = this?.get(key).asList()

internal fun JMap?.has(key: String): Boolean = this != null && this.containsKey(key)

internal fun toLongOrNull(v: Any?): Long? = when (v) {
    is Long -> v
    is Int -> v.toLong()
    is Number -> { val d = v.toDouble(); if (d == Math.floor(d) && !d.isInfinite()) d.toLong() else null }
    else -> null
}

// ---- JSON.stringify ----------------------------------------------------------------------------

/** JSON.stringify: compact, insertion order kept, non-ASCII left as is, an integral number written as an integer. */
internal fun jsJson(v: Any?): String {
    val sb = StringBuilder()
    writeJs(sb, v)
    return sb.toString()
}

private fun writeJs(sb: StringBuilder, v: Any?) {
    when (v) {
        null -> sb.append("null")
        is String -> quoteJs(sb, v)
        is Boolean -> sb.append(if (v) "true" else "false")
        is Double -> sb.append(jsNumber(v))
        is Float -> sb.append(jsNumber(v.toDouble()))
        is BigDecimal -> sb.append(jsNumber(v.toDouble()))
        is Number -> sb.append(v.toString())
        is Map<*, *> -> {
            sb.append('{')
            var first = true
            for ((k, x) in v) {
                if (!first) sb.append(',')
                first = false
                quoteJs(sb, k.toString())
                sb.append(':')
                writeJs(sb, x)
            }
            sb.append('}')
        }
        is Collection<*> -> {
            sb.append('[')
            var first = true
            for (x in v) {
                if (!first) sb.append(',')
                first = false
                writeJs(sb, x)
            }
            sb.append(']')
        }
        is Array<*> -> writeJs(sb, v.toList())
        is JsonElement -> writeJs(sb, v.toAny())
        else -> quoteJs(sb, v.toString())
    }
}

private const val HEX = "0123456789abcdef"

private fun quoteJs(sb: StringBuilder, s: String) {
    sb.append('"')
    var i = 0
    while (i < s.length) {
        val c = s[i]
        when {
            c == '"' -> sb.append("\\\"")
            c == '\\' -> sb.append("\\\\")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c == '\b' -> sb.append("\\b")
            c == '\u000C' -> sb.append("\\f")
            c.code < 0x20 -> appendU(sb, c)
            Character.isHighSurrogate(c) -> {
                if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                    sb.append(c).append(s[i + 1])
                    i++
                } else appendU(sb, c)
            }
            Character.isLowSurrogate(c) -> appendU(sb, c)
            else -> sb.append(c)
        }
        i++
    }
    sb.append('"')
}

private fun appendU(sb: StringBuilder, c: Char) {
    val n = c.code
    sb.append("\\u").append(HEX[(n shr 12) and 15]).append(HEX[(n shr 8) and 15]).append(HEX[(n shr 4) and 15]).append(HEX[n and 15])
}

/** Number.prototype.toString for a double. */
internal fun jsNumber(d: Double): String {
    if (d.isNaN() || d.isInfinite()) return "null"
    if (d == 0.0) return "0"
    val neg = d < 0
    val bd = BigDecimal(java.lang.Double.toString(Math.abs(d))).stripTrailingZeros()
    val digits = bd.unscaledValue().toString()
    val k = digits.length
    val n = k - bd.scale()
    val body = when {
        n in k..21 -> digits + "0".repeat(n - k)
        n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
        n in -5..0 -> "0." + "0".repeat(-n) + digits
        else -> {
            val e = n - 1
            val exp = (if (e >= 0) "+" else "-") + Math.abs(e)
            if (k == 1) digits + "e" + exp else digits[0] + "." + digits.substring(1) + "e" + exp
        }
    }
    return if (neg) "-$body" else body
}

// ---- parsing -----------------------------------------------------------------------------------

/** JSON text to plain values. Throws IllegalArgumentException (kotlinx SerializationException) when it is not JSON. */
internal fun parseJson(text: String): Any? = kotlinx.serialization.json.Json.parseToJsonElement(text).toAny()

/** JSON text to plain values, or null when it does not parse. */
internal fun parseJsonOrNull(text: String): Result<Any?> = try {
    Result.success(parseJson(text))
} catch (e: Exception) {
    Result.failure(e)
}

private val INTEGER = Regex("^-?\\d+$")

internal fun JsonElement?.toAny(): Any? = when (this) {
    null, is JsonNull -> null
    is JsonObject -> LinkedHashMap<String, Any?>().also { m -> for ((k, v) in this) m[k] = v.toAny() }
    is JsonArray -> this.map { it.toAny() }.toMutableList()
    is JsonPrimitive -> when {
        isString -> content
        booleanOrNull != null -> booleanOrNull
        INTEGER.matches(content) -> content.toLongOrNull() ?: BigDecimal(content).toDouble()
        else -> content.toDoubleOrNull() ?: content
    }
}

internal fun Any?.toJson(): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Double -> if (this.isNaN() || this.isInfinite()) JsonNull else if (this == Math.floor(this) && Math.abs(this) < 9.007199254740992E15) JsonPrimitive(this.toLong()) else JsonPrimitive(this)
    is Float -> this.toDouble().toJson()
    is BigInteger -> JsonPrimitive(this)
    is BigDecimal -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this.toLong())
    is Map<*, *> -> JsonObject(LinkedHashMap<String, JsonElement>().also { m -> for ((k, v) in this) m[k.toString()] = v.toJson() })
    is Collection<*> -> JsonArray(this.map { it.toJson() })
    is Array<*> -> JsonArray(this.map { it.toJson() })
    is IntArray -> JsonArray(this.map { JsonPrimitive(it) })
    is LongArray -> JsonArray(this.map { JsonPrimitive(it) })
    else -> JsonPrimitive(this.toString())
}

internal fun Any?.toJsonObject(): JsonObject = this.toJson() as? JsonObject ?: JsonObject(emptyMap())

// ---- public helpers ----------------------------------------------------------------------------

/**
 * Kotlin values as JSON: Map, List, Array, String, Number, Boolean, null and JsonElement.
 * `mapOf("title" to "Hello", "tags" to listOf("a", "b")).toJsonElement()`
 */
public fun Any?.toJsonElement(): JsonElement = this.toJson()

/** A JsonObject from pairs: `jsonOf("table" to jsonOf("name" to "posts", "access_group" to "public"))`. */
public fun jsonOf(vararg pairs: Pair<String, Any?>): JsonObject {
    val m = LinkedHashMap<String, JsonElement>()
    for ((k, v) in pairs) m[k] = v.toJson()
    return JsonObject(m)
}

/** A JsonArray from values: `jsonArrayOf("a", 1, true)`. */
public fun jsonArrayOf(vararg items: Any?): JsonArray = JsonArray(items.map { it.toJson() })

/** JSON.stringify of a JsonElement: compact, with integral numbers written as integers. */
public fun JsonElement.toJsString(): String = jsJson(this.toAny())
