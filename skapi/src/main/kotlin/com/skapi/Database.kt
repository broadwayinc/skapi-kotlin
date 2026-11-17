package com.skapi

import java.io.File
import java.net.URI
import java.util.logging.Logger

/*
 * Database methods, ported from skapi-py (_database.py), itself a port of skapi-js
 * (src/methods/database.ts): same validation, same request bodies, same decoding of the records
 * the server returns.
 */

internal const val NUMBER_SHIFT = 4503599627370496L // 2^52: number index values are stored shifted by this
private val CONDITIONS = listOf("gt", "gte", "lt", "lte", ">", ">=", "<", "<=", "=", "eq")
private val CONDITIONS_NE = CONDITIONS + listOf("!=", "ne")
private val SPECIAL_INDEX = setOf("\$updated", "\$uploaded", "\$referenced_count", "\$user_id")
private val ORDER_BY = listOf("average_number", "total_number", "number_count", "average_bool", "total_bool",
    "bool_count", "string_count", "index_name", "number_of_records")
private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
/** Seconds before a private access key expires at which it is no longer sent. */
private const val PRIVATE_KEY_REFRESH_MARGIN = 60
private val EXPIRING_KEY = Regex("^([0-9]+)\\.")
private val log: Logger = Logger.getLogger("skapi")
@Volatile private var tableStringWarned = false

internal fun fromBase62(text: String): Long {
    var n = 0L
    var p = 1L
    for (ch in text.reversed()) {
        val idx = ProjectId.BASE62.indexOf(ch)
        n += idx * p
        p *= 62
    }
    return n
}

internal fun toBase62(value: Long): String {
    if (value == 0L) return "0"
    var n = value
    val sb = StringBuilder()
    while (n > 0) {
        sb.append(ProjectId.BASE62[(n % 62).toInt()])
        n /= 62
    }
    return sb.reverse().toString()
}

internal fun encodeDelimiters(value: String): String =
    value.replace("%", "%25").replace("/", "%2F").replace("!", "%21").replace("*", "%2A").replace("#", "%23")

internal fun decodeDelimiters(value: Any?): Any? {
    if (value !is String) return value
    val v = Regex("%(2F|21|2A|23)", RegexOption.IGNORE_CASE).replace(value) { m ->
        when (m.groupValues[1].uppercase()) { "2F" -> "/"; "21" -> "!"; "2A" -> "*"; else -> "#" }
    }
    return Regex("%25", RegexOption.IGNORE_CASE).replace(v, "%")
}

private fun hasControl(value: String): Boolean {
    var i = 0
    while (i < value.length) {
        val c = value[i]
        if (c.code <= 0x1F || c.code == 0x7F) return true
        // U+10FFFF, the sentinel character
        if (c == '\uDBFF' && i + 1 < value.length && value[i + 1] == '\uDFFF') return true
        i++
    }
    return false
}

internal fun validateString(
    value: Any?, field: String, allowEmpty: Boolean = false, maxLength: Int = 256,
    escape: Boolean = false, noDollar: Boolean = false, alphanumeric: Boolean = false,
): String {
    if (value !is String) throw perr("\"$field\" should be type: <string>.")
    var v: String = value
    if (alphanumeric && Regex("[^a-zA-Z0-9]").containsMatchIn(v)) throw perr("\"$field\" should only contain alphanumeric characters.")
    if (!allowEmpty && v.isEmpty()) throw perr("\"$field\" is required.")
    if (maxLength > 0 && jsLength(v) > maxLength) throw perr("\"$field\" should be <= $maxLength characters.")
    if (hasControl(v)) throw perr("\"$field\" cannot include control characters or unsupported sentinel characters.")
    if (escape) {
        v = encodeDelimiters(v)
        if (maxLength > 0 && jsLength(v) > maxLength) {
            throw perr("\"$field\" should be <= $maxLength characters. \"/\", \"!\", \"*\", \"#\" and \"%\" count as 3 characters each.")
        }
    }
    if (noDollar && v.startsWith("$")) throw perr("\"$field\" cannot start with \"$\".")
    return v
}

internal fun tableName(v: Any?, field: String = "table.name", allowEmpty: Boolean = false) = validateString(v, field, allowEmpty = allowEmpty, escape = true)
internal fun tagName(v: Any?, field: String = "tag", allowEmpty: Boolean = false) = validateString(v, field, allowEmpty = allowEmpty, escape = true)
internal fun indexName(v: Any?, field: String = "index.name", allowEmpty: Boolean = false) =
    validateString(v, field, allowEmpty = allowEmpty, escape = true, noDollar = true)

internal fun validateUserId(v: Any?, field: String = "User ID"): String {
    if (!truthy(v)) throw perr("$field is empty.")
    if (v !is String) throw perr("$field should be type: string.")
    if (!UUID_RE.matches(v)) throw perr("$field is invalid.")
    return v
}

internal fun accessGroupIn(v: Any?, signedIn: Boolean): Any {
    val result: Any = when (v) {
        is Boolean -> throw perr("\"table.access_group\" should be type: <number | string>.")
        is Number -> {
            if (v.toDouble() > 99 || v.toDouble() < 0) throw perr("\"table.access_group\" value should be within a range of 0 ~ 99.")
            v
        }
        is String -> when (v) {
            "*", "private" -> "private"
            "public" -> 0L
            "authorized" -> 1L
            "admin" -> 99L
            else -> throw perr("\"table.access_group\" is invalid.")
        }
        else -> throw perr("\"table.access_group\" should be type: <number | string>.")
    }
    if (!signedIn && truthy(result)) throw perr("Unsigned users have no access to records with access group.")
    return result
}

internal fun accessGroupOut(v: Any?): Any? {
    if (v == "**") return "private"
    val n = (if (v is String) v.trim() else v?.toString())?.toLongOrNull() ?: return v
    return when (n) { 0L -> "public"; 1L -> "authorized"; 99L -> "admin"; else -> n }
}

internal fun indexValue(v: Any?, field: String = "index.value"): Any? {
    if (v is Boolean) return v
    if (v is Number) {
        if (Math.abs(v.toDouble()) > NUMBER_SHIFT) throw perr("Number value should be within range -4503599627370496 ~ +4503599627370496")
        return v
    }
    if (v is String) return validateString(v, field, allowEmpty = true)
    throw perr("\"$field\" should be type: <number | boolean | string>.")
}

private fun typeOf(v: Any?): String = when (v) {
    is Boolean -> "boolean"
    is Number -> "number"
    is String -> "string"
    else -> "object"
}

private fun condition(v: Any?, allowed: List<String> = CONDITIONS, field: String = "condition"): Any? {
    if (v !in allowed) throw perr("${jd(v)} is invalid in \"$field\". allowed types or values are: " + allowed.joinToString(", ") { jd(it) } + ".")
    return v
}

/** ID mode: only service, owner and record_id (or else unique_id) survive. */
private fun recordOrUniqueId(query: JMap, isDelete: Boolean): JMap? {
    if (isDelete) {
        for (key in listOf("record_id", "unique_id")) {
            val v = query[key]
            if (v != null && (v == "" || (v is List<*> && v.isEmpty()))) throw perr("\"$key\" is empty.")
        }
    }
    if (!truthy(query["record_id"]) && !truthy(query["unique_id"])) return null
    val out = LinkedHashMap<String, Any?>()
    for (key in listOf("service", "owner")) if (truthy(query[key])) out[key] = query[key]
    val key = if (truthy(query["record_id"])) "record_id" else "unique_id"
    val value = query[key]

    fun one(v: Any?, field: String): String {
        if (key == "record_id") return validateString(v, field, alphanumeric = true, maxLength = 0)
        if (v !is String) throw perr("\"$field\" should be type: <string>.")
        if (v.isEmpty()) throw perr("\"$field\" is required.")
        return v
    }

    if (value is List<*>) {
        if (!isDelete) throw perr("\"$key\" should be type: <string>.")
        if (value.isEmpty()) throw perr("\"$key\" should not be an empty list.")
        if (value.size > 1000) throw perr("\"$key\" can hold at most 1000 ids.")
        out[key] = value.mapIndexed { i, v -> one(v, "$key[$i]") }.toMutableList<Any?>()
    } else {
        out[key] = one(value, key)
    }
    return out
}

/** Index values as the server stores them ("!S%text", "!N%<number + 2^52>", "!B%1"). */
private fun typedString(v: String): Any? {
    val prefix = v.take(3)
    val body = v.drop(3)
    when (prefix) {
        "!S%" -> return body
        "!B%" -> return body == "1"
        "!L%", "!D%" -> return parseJsonOrNull(body).getOrElse { throw skErr("Value parse error.", "PARSE_ERROR") }
        "!N%" -> {
            val dot = body.indexOf('.')
            val whole = if (dot >= 0) body.substring(0, dot) else body
            val frac = if (dot >= 0) body.substring(dot + 1) else ""
            val n = java.math.BigInteger(whole).subtract(java.math.BigInteger.valueOf(NUMBER_SHIFT)).toLong()
            if (frac.isEmpty()) return n
            if (n >= 0 || !Regex("[1-9]").containsMatchIn(frac)) return "$n.$frac".toDouble()
            val digits = frac.trimEnd('0')
            val complement = digits.dropLast(1).map { (9 - (it - '0')).toString() }.joinToString("") + (10 - (digits.last() - '0')).toString()
            return "-${-n - 1}.$complement".toDouble()
        }
    }
    return v
}

/** The stored record payload ("!J%<json>" and the legacy forms) as the value that was posted. */
internal fun parseStoredData(r: Any?): Any? {
    if (r is String) {
        if (r.startsWith("!J%")) return parseJsonOrNull(r.substring(3)).getOrElse { r }
        if (r == "!D%{}") return LinkedHashMap<String, Any?>()
        if (r == "!L%[]") return mutableListOf<Any?>()
        return r
    }
    val m = r.asMap()
    if (m != null && m.size == 1 && m["__json__"] is String) {
        return parseJsonOrNull(m["__json__"] as String).getOrElse { r }
    }
    return r
}

internal fun isOffloadMarker(r: Any?): Boolean {
    val m = r.asMap() ?: return false
    return m.size == 1 && (m["__data__"] as? String)?.endsWith("/__data__/__json__.json") == true
}

private fun randomKey(n: Int = 6): String {
    val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return (1..n).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
}

/*
 * The ASCII bytes a URL path encoder percent-encodes (as the WHATWG URL parser skapi-js uses):
 * C0 controls except tab/LF/CR, space " < > ` { } DEL, and ^. getFile itself only encodes the
 * space, which is in this set, so urls from any SDK are undone the same way.
 */
private val URL_PATH_ENCODED_ASCII = setOf(
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x22, 0x3C, 0x3E, 0x5E, 0x60, 0x7B, 0x7D, 0x7F,
)

/**
 * Undoes only what a url path encoder produces: uppercase %XX of the bytes above and of valid
 * UTF-8 sequences. Any other "%" is part of the file's own name ("50%25 off.pdf", "a%2Fb.pdf")
 * and is kept. Same as skapi-js database.ts undoUrlPathEncoding.
 */
internal fun undoUrlPathEncoding(url: String): String {
    return Regex("(?:%[0-9A-F]{2})+").replace(url) { m ->
        val tokens = Regex("%[0-9A-F]{2}").findAll(m.value).map { it.value }.toList()
        val out = StringBuilder()
        var i = 0
        while (i < tokens.size) {
            val b = tokens[i].substring(1).toInt(16)
            if (b < 0x80) {
                if (b in URL_PATH_ENCODED_ASCII) out.append(b.toChar()) else out.append(tokens[i])
                i++
                continue
            }
            val n = if (b >= 0xF0) 4 else if (b >= 0xE0) 3 else if (b >= 0xC0) 2 else 1
            val seq = tokens.subList(i, Math.min(tokens.size, i + n))
            var decoded: String? = null
            if (seq.size == n && n != 1) {
                val bytes = ByteArray(n) { seq[it].substring(1).toInt(16).toByte() }
                decoded = try {
                    java.nio.charset.StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                        .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
                } catch (e: java.nio.charset.CharacterCodingException) {
                    null
                }
            }
            if (decoded != null) {
                out.append(decoded)
                i += n
            } else {
                out.append(tokens[i])
                i++
            }
        }
        Regex.escapeReplacement(out.toString())
    }
}

/** scheme://host of a url, as urlsplit gives them. */
private fun origin(url: String): String {
    val u = URI(url.substringBefore('?').replace(" ", "%20"))
    return "${u.scheme}://${u.rawAuthority}"
}

private fun jsonBytes(v: Any?): ByteArray = try {
    utf8(jsJson(v))
} catch (e: Exception) {
    throw skErr("Invalid data type.", "INVALID_REQUEST")
}

// ---- state helpers --------------------------------------------------------------------------------

internal fun Core.scope(service: Any? = null, owner: Any? = null): String =
    "${(service as? String)?.takeIf { it.isNotEmpty() } ?: this.service}/${(owner as? String)?.takeIf { it.isNotEmpty() } ?: this.owner}"

/** Drops every remembered unique_id that points at one of these records (renamed or deleted). */
private fun Core.forgetUniqueIdsOf(scope: String, recordIds: Collection<String>) {
    val known = myUniqueIds[scope] ?: return
    for (uid in known.entries.filter { it.value in recordIds }.map { it.key }) known.remove(uid)
}

/** After a write: the record's current unique_id, and none of its earlier ones. */
private fun Core.rememberUniqueId(scope: String, record: JMap) {
    val rid = record.s("record_id")
    if (rid.isNullOrEmpty()) return
    forgetUniqueIdsOf(scope, listOf(rid))
    val uid = record.s("unique_id")
    if (!uid.isNullOrEmpty()) myUniqueIds.getOrPut(scope) { java.util.concurrent.ConcurrentHashMap() }[uid] = rid
}

/**
 * A record file url getFile gave out (as "endpoint" or "info") may come back to deleteFiles or
 * remove_bin. The server removes the stored file url by exact string, so the url given out is
 * mapped back to the exact url it was made from. Kept only when the two differ, or when the url
 * looks encoded ("a%20b.pdf" is its own stored form), so the map stays small.
 */
private fun Core.rememberHandedOutUrl(handedOut: String, requested: String) {
    val base = handedOut.substringBefore('?')
    val raw = requested.substringBefore('?')
    if (base.startsWith("https://") && (base != raw || undoUrlPathEncoding(base) != base)) handedOutFileUrls[base] = raw
}

/**
 * The form the server stores a record file url in. A non-public file's url from getFile ends in
 * "?t=<token>" and has its spaces percent-encoded; sent back like that it matched no stored file,
 * and the server answers success when nothing matched, so the file stayed.
 */
private fun Core.storedRecordFileUrl(url: String): String {
    val base = url.substringBefore('?')
    handedOutFileUrls[base]?.let { return it }
    return if ('?' in url) undoUrlPathEncoding(base) else base
}

internal fun Core.isAdmin(): Boolean {
    restore()
    val u = user
    return u != null && u["service"] == service && u["owner"] == "skapi"
}

private fun Core.requireLoginGate(method: String) {
    val conn = ensureConnection()
    if (!signedIn() && conn.m("opt")?.get("require_login") == true) {
        throw skErr("This project requires users to sign in before reading its database, so \"$method\" is not available to a signed-out visitor.", "REQUIRE_LOGIN")
    }
}

// ---- query builder ----------------------------------------------------------------------------------

internal fun Core.buildQuery(queryIn: JMap?, isDelete: Boolean): Pair<JMap, Any?> {
    var query = queryIn.copyMap()
    val scope = scope(query["service"], query["owner"])
    var isReferenceFetch: Any? = null
    val signedIn = signedIn()

    val idQuery = recordOrUniqueId(query, isDelete)
    if (idQuery != null) {
        query = idQuery
        val single = query["record_id"]?.takeIf { truthy(it) } ?: query["unique_id"]
        if (single is List<*>) {
            if (query.containsKey("unique_id")) {
                for (uid in single) myUniqueIds[scope]?.remove(uid as String)
            } else if (isDelete) {
                forgetUniqueIdsOf(scope, single.map { it as String }.toSet())
            }
            return Pair(query, "")
        }
        single as String
        isReferenceFetch = single
        cachedPrivateKey(single)?.let { query["private_key"] = it }
        val cached = myUniqueIds[scope]?.get(single)
        if (isDelete) {
            myUniqueIds[scope]?.remove(single)
            if (query.containsKey("record_id")) forgetUniqueIdsOf(scope, listOf(single))
        } else if (cached != null) {
            query["record_id"] = cached
        }
        return Pair(query, isReferenceFetch)
    }

    val isAdmin = isAdmin()
    var refUserIsMe = false
    val ref = query["reference"].asMap()
    if (ref != null) {
        val rid = ref["record_id"]?.takeIf { truthy(it) } ?: ref["unique_id"]
        if (truthy(rid)) {
            isReferenceFetch = rid
            cachedPrivateKey(rid)?.let { query["private_key"] = it }
            query["reference"] = rid
        } else if (truthy(ref["user_id"])) {
            refUserIsMe = user != null && ref["user_id"] == user.s("user_id")
            query["reference"] = ref["user_id"]
        }
    }

    var table = query["table"]
    if (table is String) {
        if (!tableStringWarned) {
            tableStringWarned = true
            log.warning("skapi: table: \"$table\" in getRecords() and deleteRecords() is deprecated. Write the access group with the name: " +
                "table: {\"name\": \"$table\", \"access_group\": \"public\"}. See https://docs.skapi.com/deprecated/deprecated.html")
        }
        table = jmap("name" to table, "access_group" to 0L)
        query["table"] = table
    }
    val tm = table.asMap()
    if (!isAdmin && tm != null && tm["access_group"] == null) {
        throw perr("\"table.access_group\" is required: a table is always { name, access_group }. " +
            "To read what references a record in every table, send \"reference\" without \"table\".")
    }
    val idx = query["index"].asMap()
    if (idx != null && idx.containsKey("range") && idx.containsKey("condition")) {
        val copy = idx.copyMap()
        copy.remove("range")
        query["index"] = copy
    }

    val readsByReference = !isDelete && signedIn && (truthy(isReferenceFetch) || (query["reference"] is String && truthy(query["reference"])))
    val requiredTable = !(refUserIsMe || isAdmin || readsByReference)

    val out = LinkedHashMap<String, Any?>()
    if (query.containsKey("table")) {
        val t = query["table"]
        val tmap = t.asMap() ?: throw perr("${jd(t)} is invalid in \"table\". allowed type or value is: Type<object>.")
        val nt = tmap.copyMap()
        if (tmap.containsKey("name")) nt["name"] = tableName(tmap["name"])
        if (tmap.containsKey("access_group")) nt["access_group"] = accessGroupIn(tmap["access_group"], signedIn)
        if (tmap.containsKey("subscription")) nt["subscription"] = validateUserId(tmap["subscription"], "User ID in \"subscription\"")
        out["table"] = nt
    } else if (requiredTable) {
        throw perr("Key \"table\" is required.")
    }
    if (query.containsKey("reference")) {
        val r = query["reference"]
        if (r !is String) throw perr("${jd(r)} is invalid in \"reference\". allowed type or value is: Type<string>.")
        out["reference"] = r
    }
    if (query.containsKey("index")) {
        val i = query["index"]
        val imap = i.asMap() ?: throw perr("${jd(i)} is invalid in \"index\". allowed type or value is: Type<object>.")
        val ni = imap.copyMap()
        val rawName = imap["name"]
        if (imap.containsKey("name")) ni["name"] = if (rawName in SPECIAL_INDEX) rawName else indexName(rawName)
        if (imap.containsKey("value")) {
            var v = imap["value"]
            v = when {
                rawName == "\$updated" || rawName == "\$uploaded" || rawName == "\$referenced_count" -> {
                    if (v !is Number) throw perr("\"index.value\" should be type: number.")
                    v
                }
                rawName == "\$user_id" -> validateUserId(v)
                v == "" -> ""
                v is String && rawName is String && rawName.endsWith(".") -> validateString(v, "index.value", allowEmpty = true, escape = true)
                else -> indexValue(v)
            }
            ni["value"] = v
        }
        if (imap.containsKey("condition")) ni["condition"] = condition(imap["condition"], CONDITIONS, "condition")
        if (imap.containsKey("range")) {
            if (!imap.containsKey("value")) throw perr("\"index.value\" is required.")
            if (rawName == "\$record_id") throw perr("Cannot do \"index.range\" on \$record_id")
            var r = imap["range"]
            if (typeOf(imap["value"]) != typeOf(r)) throw perr("\"index.range\" type should match the type of \"index.value\".")
            if (r is String) r = validateString(r, "index.range", allowEmpty = true, escape = rawName is String && rawName.endsWith("."))
            ni["range"] = r
        }
        out["index"] = ni
    }
    if (query["tag"] != null) {
        val tag = query["tag"] as? String ?: throw perr("\"tag\" should be type: string.")
        out["tag"] = tagName(tag)
    }
    for (key in listOf("private_key", "service", "owner")) {
        if (query.containsKey(key)) {
            val v = query[key]
            if (v !is String) throw perr("${jd(v)} is invalid in \"$key\". allowed type or value is: Type<string>.")
            out[key] = v
        }
    }
    return Pair(out, isReferenceFetch)
}

// ---- reads ------------------------------------------------------------------------------------------

/** Records by id, unique id, table, index, tag or reference. */
internal fun Core.getRecords(query: JMap?, fetchOptions: JMap? = null): JMap {
    requireLoginGate("getRecords")
    val (q, refId) = buildQuery(query, false)
    val signedIn = signedIn()
    val result = call("get-records", q, auth = signedIn, method = if (signedIn) "POST" else "GET", fetchOptions = fetchOptions)
    val rm = result.asMap() ?: return jmap("list" to jlist(), "result" to result)
    if (refId is String && refId.isNotEmpty() && rm["reference_private_key"] is String) {
        privateAccessKey[refId] = rm["reference_private_key"] as String
    }
    val list = rm["list"].asList()
    if (list != null) rm["list"] = list.map { normalizeRecord(it) }.toMutableList()
    return rm
}

/** Deletes your records (or any, as an admin) by id, unique id, or query. */
internal fun Core.deleteRecords(query: JMap, fetchOptions: JMap? = null): Any? {
    ensureConnection()
    val (q, refId) = buildQuery(query, true)
    val result = call("del-records", q, auth = true, fetchOptions = fetchOptions)
    val rm = result.asMap()
    if (rm != null) {
        if (refId is String && refId.isNotEmpty() && rm["reference_private_key"] is String) {
            privateAccessKey[refId] = rm["reference_private_key"] as String
        }
        val list = rm["list"].asList()
        if (list != null) {
            val out = list.map { r ->
                try {
                    if (r is Map<*, *>) normalizeRecord(r, skipDataFetch = true, skipBinResolve = true) else r
                } catch (e: Exception) {
                    r
                }
            }.toMutableList()
            rm["list"] = out
            // A delete by query names no ids up front: the unique_ids remembered for the records it
            // deleted are dropped here, from the records it returns (as skapi-js deleteRecords).
            val deleted = out.mapNotNull { r ->
                val m = r.asMap() ?: return@mapNotNull null
                (m["record_id"]?.takeIf { truthy(it) } ?: m["rec"]) as? String
            }.filter { it.isNotEmpty() }.toSet()
            if (deleted.isNotEmpty()) forgetUniqueIdsOf(scope(query["service"], query["owner"]), deleted)
        }
        if (truthy(rm["message"])) return rm["message"]
    }
    return result
}

internal fun Core.getTables(query: JMap?, fetchOptions: JMap? = null): Any? {
    val qm = query ?: LinkedHashMap()
    val p = LinkedHashMap<String, Any?>()
    if (qm.containsKey("table")) p["table"] = tableName(qm["table"], "table", allowEmpty = true)
    if (qm.containsKey("condition")) p["condition"] = condition(qm["condition"], CONDITIONS_NE)
    for (k in listOf("service", "owner")) if (qm.containsKey(k)) p[k] = qm[k]
    val res = call("get-table", p, auth = signedIn(), fetchOptions = fetchOptions)
    val names = mapOf("pv" to "private", "00" to "public", "01" to "authorized", "99" to "admin")
    for (item in res.asMap().l("list") ?: emptyList<Any?>()) {
        val im = item.asMap() ?: continue
        for (k in im.keys.toList()) {
            if (k.startsWith("grp_")) {
                val x = k.substring(4)
                im["number_of_records_in_access_group_${names[x] ?: x}"] = im.remove(k)
            }
        }
        for ((old, new) in listOf("cnt_rec" to "number_of_records", "tbl" to "table", "srvc" to "service")) {
            if (im.containsKey(old)) im[new] = im.remove(old)
        }
        if (im.containsKey("table")) im["table"] = decodeDelimiters(im["table"])
    }
    return res
}

internal fun Core.getTags(query: JMap?, fetchOptions: JMap? = null): Any? {
    val qm = query ?: LinkedHashMap()
    val p = LinkedHashMap<String, Any?>()
    if (qm.containsKey("table")) p["table"] = tableName(qm["table"], "table", allowEmpty = true)
    if (qm.containsKey("tag")) p["tag"] = tagName(qm["tag"], "tag", allowEmpty = true)
    if (qm.containsKey("condition")) p["condition"] = condition(qm["condition"], CONDITIONS_NE)
    for (k in listOf("service", "owner")) if (qm.containsKey(k)) p[k] = qm[k]
    val res = call("get-tag", p, auth = signedIn(), fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { item ->
            val im = item.asMap()
            val parts = (im.s("tag") ?: "").split("/")
            jmap("table" to decodeDelimiters(if (parts.size > 1) parts[1] else ""), "tag" to decodeDelimiters(parts[0]),
                "number_of_records" to im?.get("cnt_rec"))
        }.toMutableList<Any?>()
    }
    return res
}

internal fun Core.getIndexes(query: JMap?, fetchOptions: JMap? = null): Any? {
    val qm = query ?: LinkedHashMap()
    if (!truthy(qm["table"])) throw perr("\"table\" is required.")
    val p = jmap("table" to tableName(qm["table"], "table", allowEmpty = true))
    if (qm.containsKey("index")) p["index"] = indexName(qm["index"], "index.name")
    if (qm.containsKey("order")) {
        val o = qm["order"]
        val om = o.asMap() ?: throw perr("${jd(o)} is invalid in \"order\". allowed type or value is: Type<object>.")
        val no = om.copyMap()
        if (om.containsKey("by")) no["by"] = condition(om["by"], ORDER_BY, "by")
        if (om.containsKey("value")) {
            var v = om["value"]
            if (om["by"] == "index_name" && v is String) v = validateString(v, "order.value", allowEmpty = true, escape = true)
            else if (!(v is String || v is Number || v is Boolean)) throw perr("\"order.value\" should be type: <string | number | boolean>.")
            no["value"] = v
        }
        if (om.containsKey("condition")) no["condition"] = condition(om["condition"], CONDITIONS_NE)
        if (!no.containsKey("by")) throw perr("\"order.by\" is required.")
        if (no.containsKey("condition") && !no.containsKey("value")) throw perr("\"value\" is required for \"condition\".")
        if (p.containsKey("index") && !(p["index"] as String).endsWith(".")) {
            throw perr("\"index\" should be a parent index name of the compound index when using \"order.by\"")
        }
        p["order"] = no
    }
    for (k in listOf("service", "owner")) if (qm.containsKey(k)) p[k] = qm[k]
    val res = call("get-index", p, auth = signedIn(), fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        val rename = linkedMapOf("cnt_bool" to "boolean_count", "cnt_numb" to "number_count", "totl_numb" to "total_number", "totl_bool" to "total_bool",
            "avrg_numb" to "average_number", "avrg_bool" to "average_bool", "cnt_str" to "string_count")
        rm["list"] = list.map { i ->
            val im = i.asMap() ?: LinkedHashMap()
            val parts = (im.s("idx") ?: "").split("/")
            val item = jmap("table" to decodeDelimiters(if (parts.size > 1) parts[1] else ""), "index" to decodeDelimiters(if (parts.size > 2) parts[2] else ""),
                "number_of_records" to im["cnt_rec"])
            for ((k, v) in rename) if (im.containsKey(k)) item[v] = im[k]
            item
        }.toMutableList<Any?>()
    }
    return res
}

internal fun Core.getUniqueId(query: JMap?, fetchOptions: JMap? = null): Any? {
    val qm = query ?: LinkedHashMap()
    val p = LinkedHashMap<String, Any?>()
    if (qm.containsKey("unique_id")) {
        val u = qm["unique_id"]
        if (u !is String) throw perr("${jd(u)} is invalid in \"unique_id\". allowed type or value is: Type<string>.")
        p["unique_id"] = u
    }
    if (qm.containsKey("condition")) p["condition"] = condition(qm["condition"], CONDITIONS_NE)
    for (k in listOf("service", "owner")) if (qm.containsKey(k)) p[k] = qm[k]
    val res = call("get-uniqueid", p, auth = signedIn(), fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { i -> val im = i.asMap(); jmap("unique_id" to im?.get("unq"), "record_id" to im?.get("rec")) }.toMutableList<Any?>()
    }
    return res
}

// ---- writes -----------------------------------------------------------------------------------------

/** Validated config (what goes on the wire) and the reference id to remember a private key under. */
internal fun Core.setupPostConfig(config: JMap?): Pair<JMap, String?> {
    if (config == null) throw perr("\"config\" argument is required.")
    val signedIn = signedIn()
    val c = config.copyMap()
    if (!truthy(c["record_id"]) && !truthy(c["table"])) throw perr("\"table.name\" is required.")
    if (c["table"] is String) {
        c["table"] = if (truthy(c["record_id"])) jmap("name" to c["table"]) else jmap("name" to c["table"], "access_group" to 0L)
    }
    val scope = scope(c["service"], c["owner"])
    val out = LinkedHashMap<String, Any?>()
    var isReferencePost: String? = null

    if (c["record_id"] != null) {
        val rid = c["record_id"]
        val cached = if (rid is String) myUniqueIds[scope]?.get(rid) else null
        out["record_id"] = cached ?: validateString(rid, "record_id", maxLength = 0)
    }
    if (c.containsKey("unique_id")) {
        val u = c["unique_id"]
        if (u != null && u !is String) throw perr("${jd(u)} is invalid in \"unique_id\". allowed types or values are: Type<string>, null.")
        out["unique_id"] = u
    }
    if (c.containsKey("readonly")) {
        val r = c["readonly"]
        if (r !is Boolean) throw perr("${jd(r)} is invalid in \"readonly\". allowed type or value is: Type<boolean>.")
        out["readonly"] = r
    }
    if (c["table"] != null) {
        val t = c["table"]
        val tm = t.asMap() ?: throw perr("${jd(t)} is invalid in \"table\". allowed types or values are: Type<string>, Type<object>.")
        val nt = tm.copyMap()
        if (tm.containsKey("name")) nt["name"] = tableName(tm["name"])
        if (tm.containsKey("access_group")) nt["access_group"] = accessGroupIn(tm["access_group"], signedIn)
        if (tm["subscription"] != null) {
            val sub = tm["subscription"].asMap() ?: throw perr("\"table.subscription\" should be type: <object | null>.")
            for ((k, v) in sub) {
                if (k in setOf("is_subscription_record", "upload_to_feed", "notify_subscribers", "feed_referencing_records", "notify_referencing_records") && v !is Boolean) {
                    throw perr("\"table.subscription.$k\" should be type: <boolean>.")
                }
            }
        }
        out["table"] = nt
    }
    if (c["notification"] != null) {
        val n = c["notification"].asMap() ?: throw perr("\"notification\" should be an object with \"title\" and \"body\".")
        for (k in listOf("title", "body")) {
            val v = n[k]
            if (v !is String || v.isBlank()) throw perr("\"notification.$k\" is required.")
        }
        out["notification"] = jmap("title" to n["title"], "body" to n["body"])
    }
    if (c["source"] != null) {
        val s = c["source"].copyMap()
        if (s["referencing_limit"] != null) {
            val v = s["referencing_limit"]
            if (v !is Number) throw perr("\"reference_limit\" should be type: <number | null>")
            if (v.toDouble() < 0) throw perr("\"reference_limit\" should be >= 0")
            if (v.toDouble() > 4503599627370546.0) throw perr("\"reference_limit\" should be <= 4503599627370546")
        }
        for (k in listOf("prevent_multiple_referencing", "can_remove_referencing_records", "only_granted_can_reference", "allow_granted_to_grant_others")) {
            if (s.containsKey(k) && s[k] !is Boolean) throw perr("\"source.$k\" should be type: <boolean>.")
        }
        if (s.containsKey("referencing_index_restrictions")) {
            val r = s["referencing_index_restrictions"]
            if (!truthy(r)) {
                s["referencing_index_restrictions"] = null
            } else {
                val items = if (r is List<*>) r else listOf(r)
                val fixed = mutableListOf<Any?>()
                for (item in items) {
                    val im = item.asMap() ?: throw perr("Key \"name\" is required.")
                    if (!im.containsKey("name")) throw perr("Key \"name\" is required.")
                    if (im.containsKey("range")) throw perr("Index restriction \"range\" type should match the type of \"value\".")
                    val ni = im.copyMap()
                    ni["name"] = indexName(im["name"], "\"name\" in \"index_restrictions\"")
                    if (im.containsKey("value")) ni["value"] = indexValue(im["value"])
                    ni["condition"] = if (im["condition"] in CONDITIONS_NE) im["condition"] else null
                    fixed.add(ni)
                }
                s["referencing_index_restrictions"] = fixed
            }
        }
        out["source"] = s
    }
    if (c.containsKey("reference")) {
        val ref = c["reference"]
        when {
            ref == null -> out["reference"] = jmap("record_id" to null)
            !truthy(ref) -> {}
            ref is String -> {
                val r = myUniqueIds[scope]?.get(ref) ?: ref
                out["reference"] = r
                isReferencePost = r
            }
            ref is Map<*, *> -> {
                val rm = ref.copyMap()
                if (rm["record_id"] != null) rm["record_id"] = validateString(rm["record_id"], "reference.record_id", alphanumeric = true, maxLength = 0)
                if (rm.containsKey("unique_id") && rm["unique_id"] !is String) throw perr("\"reference.unique_id\" should be type: <string>.")
                out["reference"] = rm
            }
            else -> throw perr("\"reference\" should be type: <string | object>.")
        }
    }
    if (c.containsKey("index")) {
        val i = c["index"]
        if (i == null) {
            out["index"] = null
        } else {
            val im = i.asMap() ?: throw perr("\"index\" should be type: <object | null>.")
            val ni = im.copyMap()
            if (im.containsKey("name")) ni["name"] = indexName(im["name"])
            if (im.containsKey("value")) ni["value"] = indexValue(im["value"])
            out["index"] = ni
        }
    }
    if (c.containsKey("tags") && c["tags"] == null) {
        out["tags"] = null // removes every tag, as in skapi-js
    } else if (c.containsKey("tags")) {
        var tags = c["tags"]
        if (tags is String) tags = tags.split(",").map { it.trim() }
        if (tags !is List<*>) throw perr("\"tag\" should be type: <string | string[]>.")
        out["tags"] = tags.map { tagName(it) }.toMutableList<Any?>()
    }
    if (c.containsKey("remove_bin")) {
        val rb = c["remove_bin"]
        // JavaScript falsiness: null, false, 0 and "" mean null; an empty list removes nothing
        if (rb == null || rb == false || (rb is Number && rb.toDouble() == 0.0) || rb == "") {
            out["remove_bin"] = null
        } else {
            if (rb !is List<*>) throw perr("\"remove_bin\" should be type: <string[] | BinaryFile[] | null>")
            val fixed = mutableListOf<Any?>()
            for (item in rb) {
                val im = item.asMap()
                if (item is String) {
                    // the stored file url, as deleteFiles sends it: no "?t=<token>", and getFile's
                    // encoding undone without touching a "%" of the name itself
                    fixed.add(storedRecordFileUrl(item))
                } else if (im != null && truthy(im["url"]) && truthy(im["size"]) && truthy(im["filename"])) {
                    fixed.add("${origin(im["url"] as String)}/${im["path"]}")
                } else {
                    throw perr("\"remove_bin\" should be type: <string[] | BinaryFile[] | null>")
                }
            }
            out["remove_bin"] = fixed
        }
    }
    for (key in listOf("service", "owner")) if (c.containsKey(key)) out[key] = c[key]

    if (!signedIn) {
        val t = out["table"].asMap() ?: LinkedHashMap()
        if (truthy(out["record_id"])) throw skErr("Public users cannot update existing records.", "INVALID_REQUEST")
        if (!(t["access_group"] == "public" || numEq(t["access_group"], 0L))) throw skErr("Public users can only post records to public tables.", "INVALID_REQUEST")
        if ((t["subscription"].asMap() ?: LinkedHashMap()).values.any { truthy(it) }) throw skErr("Public users cannot post subscription records.", "INVALID_REQUEST")
        if (truthy(out["remove_bin"])) throw skErr("Public users cannot remove files from records.", "INVALID_REQUEST")
        if (truthy(out["unique_id"])) throw skErr("Public users cannot set unique_id for records.", "INVALID_REQUEST")
    }
    return Pair(out, isReferencePost)
}

/**
 * Creates a record, or updates one when config has record_id.
 * data: any JSON value. NoData on an update keeps the stored data; null stores null.
 */
internal fun Core.postRecord(dataIn: Any? = NoData, config: JMap?, files: List<FileUpload>? = null): JMap {
    ensureConnection()
    if (config == null) throw perr("\"config\" argument is required.")
    val (conf, isReferencePost) = setupPostConfig(config)
    val uploadFiles = prepareFiles(files) // read and checked before the record is created
    var data = dataIn
    if (config.containsKey("data")) data = config["data"]
    val sentData = data !== NoData
    val view = config.copyMap()
    if (conf.containsKey("table")) view["table"] = conf["table"]
    val enc = maybeEncrypt(if (sentData) data else null, view, sentData)
    conf.remove("data")
    if (!enc.omit) {
        if (!enc.encrypted && jsonBytes(enc.send).size > 2 * 1024 * 1024) throw skErr("Data should not exceed 2MB", "INVALID_REQUEST")
        conf["data"] = enc.send
    }
    val ridIn = conf["record_id"] as? String
    if (enc.files == "decrypt" && !ridIn.isNullOrEmpty()) {
        // private -> not private: attachments back to plaintext while the key is still here
        conf["remove_bin"] = ((conf["remove_bin"] as? List<*>)?.toMutableList() ?: mutableListOf()).also { it.addAll(convertRecordFiles(ridIn, "decrypt")) }
    }
    if (enc.spill != null && !ridIn.isNullOrEmpty()) {
        // ciphertext over 256 KB travels as a file, uploaded before the record points at it
        val up = uploadPrepared(listOf(PreparedFile("__skenc_ct__", "payload.bin", enc.spill, "application/octet-stream")), ridIn)
        if (up.failed.isNotEmpty()) throw up.errors[0].error
        val entry = this.enc?.deks?.get(ridIn)
        if (entry != null && up.binEndpoints[0].isNotEmpty()) {
            entry.ctUrl = up.binEndpoints[0]
            entry.ctStale = mutableListOf()
        }
    }
    if (!enc.retire.isNullOrEmpty() && !ridIn.isNullOrEmpty()) {
        // old payload files: retired whether this write spilled again or now fits inline
        conf["remove_bin"] = ((conf["remove_bin"] as? List<*>)?.toMutableList() ?: mutableListOf()).also { it.addAll(enc.retire) }
    }
    val rec = call("post-record", conf, auth = signedIn(), method = "POST").asMap() ?: LinkedHashMap()
    val recId = rec["rec"] as? String
    if (enc.encrypted && !recId.isNullOrEmpty()) bindRecordDek(recId, enc.dek)
    if (enc.files == "encrypt" && !recId.isNullOrEmpty()) {
        // now private with its key cached: seal the existing attachments, then retire the plain ones
        try {
            val retire = convertRecordFiles(recId, "encrypt")
            if (retire.isNotEmpty()) postRecord(NoData, jmap("record_id" to recId, "remove_bin" to retire.toMutableList<Any?>()))
        } catch (e: Exception) {
            log.warning("Failed to encrypt existing attachments after making the record private: $e")
        }
    }

    if (uploadFiles.isNotEmpty()) {
        // this write did not seal the record, so its cached key was not confirmed by it
        if (!enc.encrypted) confirmFileDek(recId)
        val result = uploadPrepared(uploadFiles, recId ?: "", service = conf["service"] as? String)
        val bins = (rec["bin"] as? List<*>)?.toMutableList() ?: mutableListOf()
        bins.addAll(result.binEndpoints)
        rec["bin"] = bins
    }
    if (isReferencePost != null && rec["reference_private_key"] is String) privateAccessKey[isReferencePost] = rec["reference_private_key"] as String
    val record = normalizeRecord(rec, skipDataFetch = sentData, skipDecrypt = enc.encrypted).asMap() ?: LinkedHashMap()
    if (sentData && isOffloadMarker(rec["data"])) record["data"] = data
    if (enc.encrypted && enc.hasPlain) {
        record["data"] = enc.plain
        record["encrypted"] = jmap("status" to "encrypted", "recipients" to (enc.recipients ?: emptyList()).toMutableList<Any?>())
    }
    rememberUniqueId(scope(conf["service"], conf["owner"]), record)
    return record
}

/** Many records in few requests: items = [{"data": ..., "config": {...}}]. Returns {list, failed}. */
internal fun Core.postRecords(items: List<JMap>): JMap {
    ensureConnection()
    if (items.isEmpty()) throw perr("\"items\" should be a non-empty array.")
    val queue = mutableListOf<Pair<Int, JMap>>()
    val failed = mutableListOf<JMap>()
    val out = mutableListOf<Any?>()
    for ((i, item) in items.withIndex()) {
        try {
            val cfg = item["config"].asMap() ?: throw perr("\"items[$i].config\" is required.")
            val (conf, _) = setupPostConfig(cfg)
            val payload: Any? = if (cfg.containsKey("data")) cfg["data"] else if (item.containsKey("data")) item["data"] else NoData
            val has = payload !== NoData
            val view = cfg.copyMap()
            if (conf.containsKey("table")) view["table"] = conf["table"]
            val enc = maybeEncrypt(if (has) payload else null, view, has)
            conf.remove("data")
            if (enc.encrypted) {
                if (enc.spill != null) {
                    // skapi-js stores an empty ciphertext here (no payload file is uploaded in bulk); refuse instead
                    throw skErr("This encrypted update is over 256 KB once sealed; save it with postRecord().", "INVALID_REQUEST")
                }
                conf["data"] = enc.send
                conf["_skapi_plain"] = enc
            } else if (has) {
                if (jsonBytes(payload).size > 2 * 1024 * 1024) throw skErr("Data should not exceed 2MB", "INVALID_REQUEST")
                conf["data"] = payload
            }
            queue.add(Pair(i, conf))
        } catch (err: SkapiException) {
            failed.add(jmap("index" to i.toLong(), "code" to err.code.ifEmpty { "INVALID_PARAMETER" }, "message" to err.message))
        }
    }
    var position = 0
    while (position < queue.size) {
        val chunk = queue.subList(position, Math.min(queue.size, position + 100))
        val answered = bulkPost(chunk.map { it.second })
        if (answered.isEmpty()) {
            for ((idx, _) in chunk) failed.add(jmap("index" to idx.toLong(), "code" to "ERROR", "message" to "The server answered nothing for this record."))
            position += chunk.size
            continue
        }
        val taken = Math.min(answered.size, chunk.size)
        for (k in 0 until taken) {
            val rec = answered[k]
            if (truthy(rec["record_id"])) {
                out.add(rec)
            } else {
                val e = rec["error"].asMap() ?: LinkedHashMap()
                failed.add(jmap("index" to chunk[k].first.toLong(), "code" to (e["code"]?.takeIf { truthy(it) } ?: "ERROR"),
                    "message" to (e["message"]?.takeIf { truthy(it) } ?: "The record was not saved.")))
            }
        }
        position += taken
    }
    failed.sortBy { (it["index"] as Long) }
    return jmap("list" to out, "failed" to failed.toMutableList<Any?>())
}

private fun Core.bulkPost(configs: List<JMap>): List<JMap> {
    val services = configs.filter { it.containsKey("service") }.map { it["service"] }.toSet()
    val owners = configs.filter { it.containsKey("owner") }.map { it["owner"] }.toSet()
    if (services.size > 1) throw perr("All bulk params should share the same \"service\" value.")
    if (owners.size > 1) throw perr("All bulk params should share the same \"owner\" value.")
    val commonService = (services.firstOrNull() as? String) ?: ""
    val commonOwner = (owners.firstOrNull() as? String) ?: ""
    val sent = configs.map { c -> LinkedHashMap<String, Any?>().also { m -> for ((k, v) in c) if (k != "service" && k != "owner" && k != "_skapi_plain") m[k] = v } }
    val res = call("post-record", jmap("_is_bulk_" to sent.toMutableList<Any?>(), "service" to commonService, "owner" to commonOwner), auth = signedIn(), method = "POST")
    val list = res as? List<*> ?: return emptyList()
    val records = mutableListOf<JMap>()
    for ((conf, raw) in configs.zip(list)) {
        val sealed = conf["_skapi_plain"] as? EncResult
        val rm = raw.asMap()
        val rec = if (rm != null) (normalizeRecord(rm, skipDataFetch = conf.containsKey("data"), skipDecrypt = sealed != null).asMap() ?: LinkedHashMap()) else LinkedHashMap()
        if (conf.containsKey("data") && rm != null && isOffloadMarker(rm["data"]) && !truthy(rm["error"])) rec["data"] = conf["data"]
        val rid = rec["record_id"] as? String
        if (sealed != null && !rid.isNullOrEmpty()) {
            bindRecordDek(rid, sealed.dek)
            rec["data"] = sealed.plain
            rec["encrypted"] = jmap("status" to "encrypted")
        }
        if (rm != null && truthy(rm["error"]) && !truthy(rec["record_id"])) rec["error"] = rm["error"]
        rememberUniqueId(scope(commonService.ifEmpty { null }, commonOwner.ifEmpty { null }), rec)
        records.add(rec)
    }
    return records
}

// ---- files ------------------------------------------------------------------------------------------

/** Attaches files to a record you can write. */
internal fun Core.uploadFiles(files: List<FileUpload>, recordId: String, service: String? = null): UploadResult {
    if (recordId.isEmpty()) throw perr("\"record_id\" is required.")
    val entries = prepareFiles(files)
    confirmFileDek(recordId) // an encrypted record's files are sealed only with its current key
    return uploadPrepared(entries, recordId, service)
}

internal fun Core.uploadPrepared(entriesIn: List<PreparedFile>, recordId: String, service: String? = null): UploadResult {
    val entries = entriesIn.map { maybeEncryptFile(recordId, it) } // sealed when the record's key is cached
    val reservedKey = randomKey(6)
    val svc = service?.takeIf { it.isNotEmpty() } ?: this.service
    val base = jmap("reserved_key" to reservedKey, "service" to svc, "request" to "post", "id" to recordId)
    val params = entries.map { e -> jmap("key" to "${e.name}/${e.filename}", "sizeKey" to toBase62(e.content.size.toLong()), "contentType" to e.contentType) }
    val permits = arrayOfNulls<Any>(entries.size)
    if (entries.size >= 5 && !bulkPermitsUnavailable) {
        try {
            var start = 0
            while (start < entries.size) {
                val chunk = params.subList(start, Math.min(params.size, start + 100))
                val res = call("get-signed-urls", jmap("files" to chunk.toMutableList<Any?>(), "reserved_key" to reservedKey, "service" to svc,
                    "request" to "post", "id" to recordId), auth = signedIn()).asMap() ?: LinkedHashMap()
                val answered = res.l("list") ?: mutableListOf()
                val errors = HashMap<Long, JMap>()
                for (f in res.l("failed") ?: mutableListOf()) {
                    val fm = f.asMap() ?: continue
                    toLongOrNull(fm["index"])?.let { errors[it] = fm }
                }
                for (k in chunk.indices) {
                    val e = errors[k.toLong()]
                    permits[start + k] = when {
                        e != null -> skErr((e["message"] as? String)?.takeIf { it.isNotEmpty() } ?: "Upload permit refused.", (e["code"] as? String)?.takeIf { it.isNotEmpty() } ?: "ERROR")
                        k < answered.size && truthy(answered[k]) -> answered[k]
                        else -> skErr("No upload permit was answered for this file.", "ERROR")
                    }
                }
                start += 100
            }
        } catch (err: SkapiException) {
            if (err.code == "404" || err.code == "501" || Regex("missing authentication token|not implemented", RegexOption.IGNORE_CASE).containsMatchIn(err.message) ||
                (err.code == "403" && Regex("not found", RegexOption.IGNORE_CASE).containsMatchIn(err.message))) {
                bulkPermitsUnavailable = true
                permits.fill(null)
            } else throw err
        }
    }
    val result = UploadResult()
    for ((i, e) in entries.withIndex()) {
        var permit: Any? = permits[i]
        if (permit == null) {
            permit = try {
                val body = params[i].copyMap()
                body.putAll(base)
                call("get-signed-url", body, auth = signedIn())
            } catch (err: SkapiException) {
                err
            }
        }
        if (permit is SkapiException) {
            result.binEndpoints.add("")
            result.failed.add(e.filename)
            result.errors.add(UploadError(e.filename, e.name, permit))
            continue
        }
        val pm = permit.asMap() ?: LinkedHashMap()
        val cdn = pm["cdn"] as? String ?: ""
        result.binEndpoints.add(cdn)
        try {
            requester.upload(pm["url"] as? String ?: throw skErr("No upload permit was answered for this file.", "ERROR"),
                pm["fields"].asMap() ?: LinkedHashMap(), e.filename, e.content, e.contentType)
            result.completed.add(e.filename)
            result.landed.add(cdn)
        } catch (err: SkapiException) {
            result.failed.add(e.filename)
            result.errors.add(UploadError(e.filename, e.name, err))
        }
    }
    return result
}

internal fun Core.deleteFiles(endpointsIn: List<String>): Any? {
    // A non-public file's url ends in "?t=<token>" and is percent-encoded (getFile "endpoint").
    // The server removes the stored, decoded url by exact string and answers success when
    // nothing matched, so the stored form is sent.
    val endpoints = endpointsIn.map { storedRecordFileUrl(it) }.toMutableList<Any?>()
    val res = call("del-files", jmap("endpoints" to endpoints, "storage" to "records"), auth = true, method = "POST")
    return if (res is List<*>) res.map { normalizeRecord(it) }.toMutableList() else res
}

/**
 * A file of a record. config["dataType"]: "bytes" (default, a ByteArray), "text", "endpoint" (a
 * url you can open), "info" (what the url says, no download). config["expires"]: seconds, for a
 * signed url that works without signing in. config["save_to"]: a path (or File) to write the file
 * to (returns the File).
 */
internal fun Core.getFile(urlIn: String, configIn: JMap? = null): Any? {
    val config = configIn.copyMap()
    val requestedUrl = urlIn
    val q = urlIn.indexOf('?')
    var base = if (q >= 0) urlIn.substring(0, q) else urlIn
    val query = if (q >= 0) urlIn.substring(q + 1) else ""
    try {
        val u = URI(base.replace(" ", "%20"))
        if ((u.scheme != "http" && u.scheme != "https") || u.rawAuthority.isNullOrEmpty()) throw IllegalArgumentException()
        base = base.replace(" ", "%20")
    } catch (e: Exception) {
        throw perr("\"$urlIn\" is an invalid url.")
    }
    var url = base + (if (q >= 0) "?$query" else "")
    var dataType = (config["dataType"] ?: config["data_type"] ?: "bytes") as? String ?: "bytes"
    if (dataType == "blob") dataType = "bytes"
    if (dataType !in setOf("bytes", "text", "endpoint", "info")) dataType = "bytes"
    val expires = (config["expires"] as? Number)?.toDouble() ?: 0.0

    val host = URI(base).rawAuthority.split(".")
    val subdomain = if (host.size == 3 && host[1] == "skapi") host[0] else null
    var targetKey: List<String> = base.split("/").drop(3)
    var needAuth = false
    var isSkapiFile = subdomain != null
    val presigned = Regex("(^|&)(Signature|X-Amz-Signature)=").containsMatchIn(query)
    if (presigned) {
        // a link from getFile(..., expires): already signed, opened as it is
        if (dataType == "endpoint") return url
        targetKey = emptyList()
    }
    if (subdomain == null && targetKey.isNotEmpty() && (targetKey[0] == "auth" || targetKey[0] == "publ")) {
        if (targetKey.size < 4 || !UUID_RE.matches(targetKey[2]) || !UUID_RE.matches(targetKey[3])) throw perr("Invalid file url.")
        needAuth = targetKey[0] == "auth"
        isSkapiFile = true
    }
    val service = if (subdomain != null) null else targetKey.getOrNull(1)

    if (dataType == "info") {
        rememberHandedOutUrl(url, requestedUrl)
        val g = targetKey.getOrNull(6)
        return jmap(
            "url" to url,
            "filename" to (targetKey.lastOrNull() ?: ""),
            "fileKey" to (if (targetKey.size > 1) targetKey[targetKey.size - 2] else ""),
            "access_group" to when {
                g == "**" -> "private"
                g == "01" -> "authorized"
                g == "00" -> "public"
                g != null && g.isNotEmpty() && g.all { it in '0'..'9' } -> g.toLong()
                else -> g
            },
            "uploader" to targetKey.getOrNull(3),
            "record_id" to (if (targetKey.size > 5 && targetKey[4] == "records") targetKey[5] else "N/A"),
            "filesize" to targetKey.getOrNull(9)?.let { fromBase62(it) },
            "uploaded" to targetKey.getOrNull(8)?.let { fromBase62(it) },
        )
    }

    if (expires != 0.0) {
        if (!isSkapiFile) throw perr("Expires option can only be used on skapi cdn endpoints.")
        if (expires < 0) throw perr("\"config.expires\" should be > 0. (seconds)")
        val params = jmap("request" to (if (subdomain != null) "get-host" else "get"), "id" to (subdomain ?: targetKey.getOrNull(5)),
            "key" to requestedUrl.substringBefore('?'), "expires" to config["expires"])
        if (service != null) params["service"] = service
        url = call("get-signed-url", params, auth = true).asMap()?.get("url") as? String ?: throw skErr("No signed url was answered.", "ERROR")
    } else if (needAuth) {
        val token = freshIdToken()
        url += (if ('?' in url) "&" else "?") + "t=" + encodeURIComponent(token)
        val group = targetKey[6]
        val u = userCopy() ?: LinkedHashMap()
        val userGroup = (u["access_group"] as? Number)?.toLong() ?: 0L
        if (u["user_id"] != targetKey[3] && (group == "**" || (group.isNotEmpty() && group.all { it in '0'..'9' } && userGroup < group.toLong()))) {
            val rid = targetKey[5]
            var key = cachedPrivateKey(rid)
            if (key == null && owner != "skapi") {
                key = try {
                    requestPrivateRecordAccessKey(jmap("record_id" to rid, "reference_id" to config["_ref"]))
                } catch (e: SkapiException) {
                    null
                }
            }
            if (key != null) url += "&p=" + encodeURIComponent(key)
        }
    }

    if (dataType == "endpoint") {
        // a url handed out here may be fed back to deleteFiles or remove_bin
        rememberHandedOutUrl(url, requestedUrl)
        return url
    }
    var content: ByteArray = if (presigned || expires != 0.0) {
        requester.fetchPlain(url)
    } else {
        requester.request(url, null, method = "GET", contentType = "application/x-www-form-urlencoded", ignoreService = true, raw = true) as ByteArray
    }
    if (config["_raw"] != true) content = maybeDecryptFile(requestedUrl, content)
    val saveTo = config["save_to"]
    if (saveTo != null) {
        val f = when (saveTo) {
            is File -> saveTo
            else -> File(saveTo.toString().let { if (it.startsWith("~/")) System.getProperty("user.home") + it.substring(1) else it })
        }.absoluteFile
        f.writeBytes(content)
        return f
    }
    if (dataType == "text") return String(content, Charsets.UTF_8)
    return content
}

// ---- private record access ----------------------------------------------------------------------------

private fun recordAccessIds(recordId: Any?, uid: Any?): List<String> {
    if (recordId !is String) throw perr("${jd(recordId)} is invalid in \"record_id\". allowed type or value is: Type<string>.")
    if (!truthy(uid)) throw perr("User ID is required.")
    val ids = if (uid is String) listOf(uid) else (uid as? List<*>) ?: throw perr("User ID is required.")
    if (ids.size > 100) throw perr("Cannot process more than 100 users at once.")
    return ids.map { validateUserId(it, "User ID in \"user_id\"") }
}

private fun Core.recordAccess(recordId: Any?, uid: Any?, execute: String): Any? {
    val ids = recordAccessIds(recordId, uid)
    return call("grant-private-access", jmap("record_id" to recordId, "user_id" to ids.toMutableList<Any?>(), "execute" to execute), auth = true, ignoreService = true)
}

internal fun Core.grantPrivateRecordAccess(params: JMap): Any? {
    val uid = params["user_id"]
    val rid = params["record_id"]
    if (enc != null && truthy(uid) && rid is String) {
        // an encrypted record gets a key wrap for each new user first
        encAddRecipients(rid, if (uid is String) listOf(uid) else (uid as List<*>).map { it.toString() })
    }
    return recordAccess(rid, uid, "add")
}

internal fun Core.removePrivateRecordAccess(params: JMap): Any? {
    val uid = params["user_id"]?.takeIf { truthy(it) }
    if (enc != null) {
        // The data key is rolled BEFORE the access change: a fresh key, wrapped only for the users
        // who keep access. The roll is the step that can fail (attachments are sealed again and
        // uploaded), and failing first leaves access exactly as it was. As skapi-js.
        val ids = recordAccessIds(params["record_id"], uid)
        encDropAndRoll(params["record_id"] as String, ids)
    }
    return recordAccess(params["record_id"], uid, "remove")
}

internal fun Core.listPrivateRecordAccess(params: JMap, fetchOptions: JMap? = null): Any? {
    val rid = params["record_id"]?.takeIf { truthy(it) }
    val uid = params["user_id"]?.takeIf { truthy(it) }
    if (rid == null && uid == null) throw perr("Either record_id or user_id must be provided.")
    val p = LinkedHashMap<String, Any?>()
    if (rid != null) p["record_id"] = rid
    if (uid != null) {
        p["user_id"] = when (uid) {
            is String -> jlist(validateUserId(uid))
            is List<*> -> uid.map { validateUserId(it) }.toMutableList<Any?>()
            else -> throw perr("user_id should be type: <string | string[]>")
        }
    }
    p["execute"] = "list"
    val res = call("grant-private-access", p, auth = true, fetchOptions = fetchOptions, ignoreService = true)
    for (item in res.asMap().l("list") ?: emptyList<Any?>()) {
        val im = item.asMap() ?: continue
        val ru = im["rec_usr"] as? String
        val ur = im["usr_rec"] as? String
        if (!ru.isNullOrEmpty()) {
            val parts = ru.split("/")
            im["record_id"] = parts[0]; im["user_id"] = parts.getOrNull(1)
        } else if (!ur.isNullOrEmpty()) {
            val parts = ur.split("/")
            im["user_id"] = parts[0]; im["record_id"] = parts.getOrNull(1)
        }
    }
    return res
}

/**
 * The cached private access key for `recordId`, or null when there is none worth sending.
 * The server mints "<exp>.<hash>", exp the unix second the key stops working (an hour after it was
 * minted). A key that has expired or expires within a minute is dropped, so the caller fetches a
 * fresh one the usual way. A legacy key (64 hex characters, no expiry) is dropped too.
 */
internal fun Core.cachedPrivateKey(recordId: Any?): String? {
    if (recordId !is String) return null
    val key = privateAccessKey[recordId]
    if (key.isNullOrEmpty()) return null
    val m = EXPIRING_KEY.find(key)
    if (m != null && (m.groupValues[1].toLongOrNull() ?: 0L) - PRIVATE_KEY_REFRESH_MARGIN > System.currentTimeMillis() / 1000) return key
    privateAccessKey.remove(recordId)
    return null
}

internal fun Core.requestPrivateRecordAccessKey(params: JMap): String {
    val rid = params["record_id"]
    val ref = params["reference_id"]
    if (!truthy(rid)) throw perr("Record ID is required.")
    if (rid !is String) throw perr("Record ID should be type: <string | string[]>")
    if (truthy(ref) && ref !is String) throw perr("Reference ID should be type: <string>")
    cachedPrivateKey(rid)?.let { return it }
    val body = jmap("record_id" to rid)
    if (truthy(ref)) body["reference_id"] = ref
    val res = call("request-private-access-key", body, auth = true)
    val key = res as? String ?: res.asMap()?.get("private_key") as? String ?: throw skErr("Invalid private access key response.", "ERROR")
    privateAccessKey[rid] = key
    return key
}

// ---- decoding -------------------------------------------------------------------------------------------

private fun binUploaded(u: String): Long {
    val sp = u.split("/").drop(3)
    return try {
        if (sp.getOrNull(7) == "bin") fromBase62(sp[8]) else 0L
    } catch (e: Exception) {
        0L
    }
}

internal fun Core.normalizeRecord(record: Any?, skipDataFetch: Boolean = false, skipBinResolve: Boolean = false, skipDecrypt: Boolean = false): Any? {
    val r = record.asMap() ?: return record
    if (truthy(r["record_id"])) return r
    val subscription = jmap("is_subscription_record" to false, "upload_to_feed" to false, "notify_subscribers" to false,
        "feed_referencing_records" to false, "notify_referencing_records" to false)
    val table = jmap("name" to "", "access_group" to 0L, "subscription" to subscription)
    val source = jmap("referencing_limit" to null, "prevent_multiple_referencing" to false, "can_remove_referencing_records" to false,
        "only_granted_can_reference" to false)
    val bin = LinkedHashMap<String, Any?>()
    val out = jmap("user_id" to "", "record_id" to "", "updated" to 0L, "uploaded" to 0L, "readonly" to false, "table" to table,
        "referenced_count" to 0L, "source" to source, "ip" to "", "bin" to bin)
    var anonymous = false
    val bins = r["bin"] as? List<*> ?: emptyList<Any?>()
    var dataUrl: String? = null
    val ctUrls = mutableListOf<String>()
    for (u in bins) {
        if (u is String) {
            val sp = u.split("/").drop(3)
            if (sp.size >= 12 && sp[10] == "__data__" && sp.last() == "__json__.json") dataUrl = u
            if (sp.size >= 12 && sp[10] == "__skenc_ct__" && sp.last() == "payload.bin") ctUrls.add(u) // an encrypted record's large ciphertext
        }
    }
    // Newest upload first: every record file url carries its upload time right after "bin"
    // (".../bin/<base62 ms>/<size>/<field>/<name>"), and the record's file list is a set with no
    // order. Older SDKs could leave several payload files; the newest is the current one.
    ctUrls.sortByDescending { binUploaded(it) }
    val ctUrl = ctUrls.firstOrNull()

    if (r.containsKey("ip")) {
        val parts = (r["ip"]?.let { if (it is String) it else jsJson(it) } ?: "None").split("#")
        var ip = parts[0]
        if (parts.size > 1) out["unique_id"] = parts.drop(1).joinToString("#")
        if (ip.endsWith("R")) {
            out["readonly"] = true
            ip = ip.dropLast(1)
        }
        if (Regex("^\\d{1,3}-\\d{1,3}-\\d{1,3}-\\d{1,3}$").matches(ip)) {
            ip = ip.replace("-", ".")
            anonymous = true
        }
        out["ip"] = ip
    }
    val rec = r["rec"] as? String
    if (!rec.isNullOrEmpty()) {
        out["record_id"] = rec
        out["uploaded"] = fromBase62(rec.dropLast(9))
    }
    if (r.containsKey("usr")) out["user_id"] = r["usr"]
    if (r.containsKey("tbl") && (table["name"] as String).isEmpty()) {
        val p = r["tbl"].toString().split("/")
        table["name"] = decodeDelimiters(p[0])
        table["access_group"] = if (p.size > 2) accessGroupOut(p[2]) else 0L
        subscription["is_subscription_record"] = p.size > 3 && p[3].isNotEmpty()
    }
    if (r.containsKey("usr_tbl")) {
        val p = r["usr_tbl"].toString().split("/")
        if (!truthy(out["user_id"])) out["user_id"] = p[0]
        if (!truthy(table["name"])) {
            table["name"] = decodeDelimiters(p.getOrElse(1) { "" })
            table["access_group"] = if (p.size > 3) accessGroupOut(p[3]) else 0L
            subscription["is_subscription_record"] = p.size > 4 && p[4].isNotEmpty()
        }
    }
    val idx = r["idx"]
    if (idx is String) {
        val parts = idx.split("!")
        out["index"] = jmap("name" to decodeDelimiters(parts[0]), "value" to typedString("!" + parts.drop(1).joinToString("!")))
    }
    if (truthy(r["ref"])) out["reference"] = r["ref"].toString().split("/")[0]
    if (r.containsKey("tags")) {
        val tags = r["tags"]
        out["tags"] = if (tags is List<*>) tags.map { decodeDelimiters(it) }.toMutableList() else tags
    }
    if (r.containsKey("upd")) out["updated"] = r["upd"]
    if (r.containsKey("acpt_mrf")) source["prevent_multiple_referencing"] = !truthy(r["acpt_mrf"])
    if (r.containsKey("ref_limt")) source["referencing_limit"] = r["ref_limt"]
    if (r.containsKey("rfd")) out["referenced_count"] = r["rfd"]
    for (u in bins) {
        if (u !is String || u.isEmpty()) continue
        val path = u.split("/").drop(3).joinToString("/")
        val sp = path.split("/")
        if (sp.size < 12 || sp[10] == "__data__" || sp[10] == "__skenc_ct__") continue
        var pathKey = sp[10]
        val group = accessGroupOut(sp[6])
        var endpoint: String = u
        if (group != "public" && !skipBinResolve) {
            endpoint = try {
                getFile(u, jmap("dataType" to "endpoint", "_ref" to out["reference"])) as? String ?: u
            } catch (e: SkapiException) {
                u
            }
        }
        val entry = jmap("access_group" to group, "filename" to sp.last(), "url" to endpoint, "path" to path,
            "size" to fromBase62(sp[9]), "uploaded" to fromBase62(sp[8]))
        val sealed = parseFileMarker(pathKey)
        if (sealed != null) {
            // an encrypted attachment: listed under its own field name, with the plaintext size
            pathKey = sealed.first
            entry["size"] = sealed.second
            entry["encrypted"] = true
            entry["stored_size"] = fromBase62(sp[9])
        }
        (bin.getOrPut(pathKey) { mutableListOf<Any?>() } as MutableList<Any?>).add(entry)
    }
    val prv = r["prv_acs"].asMap()
    if (prv != null) {
        for ((k, v) in prv) {
            when {
                k in setOf("notify_subscribers", "upload_to_feed", "feed_referencing_records", "notify_referencing_records") -> subscription[k] = v
                k == "referencing_index_restrictions" && v is List<*> -> source[k] = v.map { i ->
                    val im = i.asMap()
                    if (im != null && im["name"] is String) im.copyMap().also { it["name"] = decodeDelimiters(im["name"]) } else i
                }.toMutableList()
                else -> source[k] = v
            }
        }
    }
    if (r.containsKey("data")) {
        val raw = r["data"]
        val decoded = parseStoredData(raw)
        if (decoded !== raw || raw is String) {
            out["data"] = decoded
        } else if (isOffloadMarker(raw)) {
            if (dataUrl != null && skipDataFetch) {
                out["data"] = raw
            } else if (dataUrl != null || !skipDataFetch) {
                val url = dataUrl ?: derivedDataUrl(r, raw.asMap()!!["__data__"] as String, bins)
                out["data"] = raw
                if (url != null) {
                    try {
                        out["data"] = parseJson(getFile(url, jmap("dataType" to "text", "_ref" to out["reference"])) as String)
                    } catch (e: Exception) {
                        out["data"] = if (dataUrl != null) null else raw
                        if (enc != null) out["encrypted"] = jmap("status" to "failed", "reason" to "DATA_UNAVAILABLE")
                    }
                }
            } else {
                out["data"] = raw
            }
        } else {
            out["data"] = raw
        }
        if (!skipDecrypt && out.containsKey("data")) {
            val (value, flag) = maybeDecrypt(out["data"], jmap(
                "access_group" to table["access_group"], "table_name" to table["name"], "user_id" to out["user_id"],
                "record_id" to out["record_id"], "unique_id" to out["unique_id"], "ct_url" to ctUrl, "ct_urls" to ctUrls.toMutableList<Any?>()))
            if (flag != null) {
                out["data"] = value
                out["encrypted"] = flag
            }
        }
    }
    if (anonymous) out["user_id"] = "anonymous:" + out["user_id"]
    return out
}

/** The offloaded data file's URL when the record's file list does not carry it. */
private fun Core.derivedDataUrl(record: JMap, markerPath: String, bins: List<*>): String? {
    if (!Regex("^[0-9A-Za-z]+/[0-9A-Za-z]+/__data__/__json__\\.json$").matches(markerPath)) return null
    var service: String? = null
    var owner: String? = null
    var uploader: String? = null
    var group: String? = null
    val srvc = record["srvc"]
    if (srvc is String) {
        val head = srvc.split("!")[0]
        val slash = head.indexOf('/')
        service = if (slash >= 0) head.substring(0, slash) else head
        owner = if (slash >= 0) head.substring(slash + 1) else ""
    }
    val usrTbl = record["usr_tbl"]
    val tbl = record["tbl"]
    if (usrTbl is String) {
        val p = usrTbl.split("/")
        uploader = p[0]
        service = service?.takeIf { it.isNotEmpty() } ?: p.getOrNull(2)
        group = p.getOrNull(3)
    } else if (tbl is String) {
        val p = tbl.split("/")
        service = service?.takeIf { it.isNotEmpty() } ?: p.getOrNull(1)
        group = p.getOrNull(2)
    }
    uploader = (record["usr"] as? String)?.takeIf { it.isNotEmpty() } ?: uploader
    if (owner.isNullOrEmpty() && service == this.service) owner = this.owner
    var origin: String? = null
    for (u in bins) {
        if (u is String && !service.isNullOrEmpty() && "/$service/" in u) {
            origin = try { origin(u) } catch (e: Exception) { null }
            break
        }
    }
    origin = origin ?: service?.let { cdnOrigins[it] }
    val rec = record["rec"]
    val idOk = Regex("^[0-9A-Za-z_-]+$")
    val idsOk = listOf(service, owner, uploader, rec).all { it is String && idOk.matches(it) }
    if (!(origin != null && idsOk && group != null && Regex("^(\\d{2}|\\*\\*)$").matches(group))) return null
    return "$origin/${if (group == "00") "publ" else "auth"}/$service/$owner/$uploader/records/$rec/$group/bin/$markerPath"
}
