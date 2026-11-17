package com.skapi.java

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.math.BigDecimal
import java.math.BigInteger

/**
 * JSON as plain Java values, for SkapiJava and for your own code.
 *
 * Java to JSON (fromJava): Map (keys turned into strings), List or any Iterable, arrays, String,
 * Character, Integer, Long, Short, Byte, Double, Float, BigInteger, BigDecimal, Boolean, Enum (its name),
 * null, and kotlinx JsonElement values as they are. NaN and infinite numbers become null. Anything
 * else is refused with IllegalArgumentException (inside a SkapiJava call, the future fails with
 * SkapiException code "INVALID_PARAMETER" instead).
 *
 * JSON to Java (toJava): objects become LinkedHashMap&lt;String, Object&gt; (key order kept), arrays
 * ArrayList&lt;Object&gt;, strings String, whole numbers Long (Double when too big for a Long),
 * other numbers Double, true and false Boolean, and null null. Every map and list it returns is a new
 * one you may change.
 */
public object SkapiJson {

    /** A JSON value (JsonElement) as plain Java values. */
    @JvmStatic
    public fun toJava(value: JsonElement?): Any? = when (value) {
        null, is JsonNull -> null
        is JsonObject -> LinkedHashMap<String, Any?>(value.size * 2).also { m -> for ((k, v) in value) m[k] = toJava(v) }
        is JsonArray -> ArrayList<Any?>(value.size).also { l -> for (v in value) l.add(toJava(v)) }
        is JsonPrimitive -> primitive(value)
    }

    /** A JSON object as a Java map; null stays null. */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    public fun toJavaMap(value: JsonObject?): MutableMap<String, Any?>? = toJava(value) as MutableMap<String, Any?>?

    /** A JSON array as a Java list; null stays null. */
    @JvmStatic
    @Suppress("UNCHECKED_CAST")
    public fun toJavaList(value: JsonArray?): MutableList<Any?>? = toJava(value) as MutableList<Any?>?

    /** Plain Java values as a JsonElement (see the class notes for the accepted types). */
    @JvmStatic
    public fun fromJava(value: Any?): JsonElement = convert(value, "value")

    /** A Java map as a JsonObject. */
    @JvmStatic
    public fun fromJavaMap(value: Map<String, *>): JsonObject = convert(value, "value") as JsonObject

    /**
     * A map from keys and values in turn: obj("table", "posts", "limit", 10). Keys must be strings.
     * The map keeps the order given and can be changed afterwards.
     */
    @JvmStatic
    public fun obj(vararg keysAndValues: Any?): MutableMap<String, Any?> {
        if (keysAndValues.size % 2 != 0) throw IllegalArgumentException("obj() needs a value for every key.")
        val m = LinkedHashMap<String, Any?>()
        var i = 0
        while (i < keysAndValues.size) {
            val k = keysAndValues[i] as? String
                ?: throw IllegalArgumentException("obj() keys must be strings; argument ${i + 1} is ${typeName(keysAndValues[i])}.")
            m[k] = keysAndValues[i + 1]
            i += 2
        }
        return m
    }

    /** A list of the values given: list("a", 1, true). It can be changed afterwards. */
    @JvmStatic
    public fun list(vararg items: Any?): MutableList<Any?> = ArrayList<Any?>(items.size).also { it.addAll(items) }

    /** Parses JSON text into plain Java values. Throws IllegalArgumentException when it is not JSON. */
    @JvmStatic
    public fun parse(text: String): Any? = try {
        toJava(Json.parseToJsonElement(text))
    } catch (e: IllegalArgumentException) {
        throw IllegalArgumentException("The text is not JSON: ${e.message}", e)
    }

    /** Plain Java values as compact JSON text. */
    @JvmStatic
    public fun stringify(value: Any?): String = fromJava(value).toString()

    // ---------------------------------------------------------------------------------------------

    private val INTEGER = Regex("^-?\\d+$")

    private fun primitive(p: JsonPrimitive): Any? {
        if (p.isString) return p.content
        p.booleanOrNull?.let { return it }
        val text = p.content
        if (INTEGER.matches(text)) return text.toLongOrNull() ?: BigDecimal(text).toDouble()
        return text.toDoubleOrNull() ?: text
    }

    private fun number(d: Double): JsonElement = if (d.isNaN() || d.isInfinite()) JsonNull else JsonPrimitive(d)

    private fun convert(v: Any?, path: String): JsonElement = when (v) {
        null -> JsonNull
        is JsonElement -> v
        is String -> JsonPrimitive(v)
        is Boolean -> JsonPrimitive(v)
        is Char -> JsonPrimitive(v.toString())
        is Int -> JsonPrimitive(v.toLong())
        is Long -> JsonPrimitive(v)
        is Short -> JsonPrimitive(v.toLong())
        is Byte -> JsonPrimitive(v.toLong())
        is Double -> number(v)
        is Float -> number(v.toDouble())
        is BigInteger -> JsonPrimitive(v)
        is BigDecimal -> JsonPrimitive(v)
        is Number -> number(v.toDouble())
        is Enum<*> -> JsonPrimitive(v.name)
        is Map<*, *> -> {
            val m = LinkedHashMap<String, JsonElement>(v.size * 2)
            for ((k, x) in v) {
                if (k == null) throw IllegalArgumentException("$path has a null key; JSON keys must be strings.")
                val key = k.toString()
                m[key] = convert(x, "$path[\"$key\"]")
            }
            JsonObject(m)
        }
        is Iterable<*> -> JsonArray(v.mapIndexed { i, x -> convert(x, "$path[$i]") })
        is Array<*> -> JsonArray(v.mapIndexed { i, x -> convert(x, "$path[$i]") })
        is IntArray -> JsonArray(v.map { JsonPrimitive(it.toLong()) })
        is LongArray -> JsonArray(v.map { JsonPrimitive(it) })
        is ShortArray -> JsonArray(v.map { JsonPrimitive(it.toLong()) })
        is DoubleArray -> JsonArray(v.map { number(it) })
        is FloatArray -> JsonArray(v.map { number(it.toDouble()) })
        is BooleanArray -> JsonArray(v.map { JsonPrimitive(it) })
        is CharArray -> JsonArray(v.map { JsonPrimitive(it.toString()) })
        else -> throw IllegalArgumentException("$path is a ${typeName(v)}, which is not a JSON value. Use a Map, List, String, number, Boolean or null.")
    }

    private fun typeName(v: Any?): String = if (v == null) "null" else v.javaClass.name
}
