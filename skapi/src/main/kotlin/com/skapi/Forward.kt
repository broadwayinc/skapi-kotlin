package com.skapi

import java.util.UUID
import java.util.logging.Logger

/*
 * Request forwarding (call another API through Skapi, with your stored client secrets) and
 * inquiries, ported from skapi-py (_forward.py), itself a port of skapi-js (src/methods/request.ts).
 *
 * Answers arrive by polling, exactly as skapi-js does without its realtime connection: a queued or
 * streamed request is dispatched, then polled until it settles. Streamed text is handed to an
 * onStream(text, seq) callback as it arrives.
 */

private val METHODS = setOf("get", "post", "delete", "put", "patch", "head")
private val UPPER_METHODS = listOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
private const val STREAM_DEGRADED_RETRIES = 3
private const val MULTIPART_LIMIT = 2 * 1024 * 1024 - 64 * 1024
private val ABSOLUTE_URL = Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]+")
private const val ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

private fun absoluteUrl(v: Any?): String {
    if (v == "*") return "*"
    if (v !is String || !ABSOLUTE_URL.containsMatchIn(v)) throw perr("\"${if (v is String) v else jsJson(v)}\" is an invalid url.")
    return v
}

/** The full id skapi-js and the server know a forwarded request by. */
internal fun requestKey(method: String, url: String, service: String, requestId: String): String =
    "[${method.uppercase()}]${url.lowercase()}#$service:$requestId"

private fun hasSecret(v: Any?): Boolean = when (v) {
    is String -> "\$CLIENT_SECRET" in v
    is Map<*, *> -> v.values.any { hasSecret(it) }
    is List<*> -> v.any { hasSecret(it) }
    else -> false
}

private fun isStatusEnvelope(v: Any?): Boolean {
    val m = v.asMap() ?: return false
    return m["status"] is String && m["id"] is String && m.containsKey("in_queue")
}

private fun intSeq(v: Any?): Long? = when (v) {
    is Long -> v
    is Int -> v.toLong()
    else -> null
}

private fun deliverChunks(result: Any?, cursorIn: Long, onStream: (String, Int) -> Unit): Pair<Long, Boolean> {
    var cursor = cursorIn
    var moved = false
    val rm = result.asMap()
    val chunks = rm?.get("chunks").asList()
    if (chunks != null) {
        val sorted = chunks.mapNotNull { c -> c.asMap()?.takeIf { intSeq(it["seq"]) != null } }.sortedBy { intSeq(it["seq"])!! }
        for (c in sorted) {
            val seq = intSeq(c["seq"])!!
            if (seq > cursor) {
                cursor = seq
                moved = true
                val txt = c["txt"]
                if (txt is String && txt.isNotEmpty()) {
                    try {
                        onStream(txt, seq.toInt())
                    } catch (e: Exception) {
                        // the request goes on; the callback's error is reported, not thrown
                        Logger.getLogger("skapi").warning("onStream threw $e for chunk $seq")
                    }
                }
            }
        }
    }
    val last = intSeq(rm?.get("last_seq"))
    if (last != null && last > cursor) {
        cursor = last
        moved = true
    }
    return Pair(cursor, moved)
}

/** A multipart/form-data body from a map: files as file parts, the rest as text. */
private fun multipart(form: JMap): Pair<ByteArray, String> {
    val boundary = "----skapi" + UUID.randomUUID().toString().replace("-", "")
    val out = java.io.ByteArrayOutputStream()

    fun textPart(name: String, value: String) {
        out.write(utf8("--$boundary\r\nContent-Disposition: form-data; name=\"$name\"\r\n\r\n"))
        out.write(utf8(value))
        out.write(utf8("\r\n"))
    }

    fun filePart(name: String, filename: String, content: ByteArray, contentType: String?) {
        val safe = filename.replace("\"", "%22").replace("\r", "").replace("\n", "")
        out.write(utf8("--$boundary\r\nContent-Disposition: form-data; name=\"$name\"; filename=\"$safe\"\r\n" +
            "Content-Type: ${contentType ?: "application/octet-stream"}\r\n\r\n"))
        out.write(content)
        out.write(utf8("\r\n"))
    }

    for ((name, value) in form) {
        val values: List<Any?> = if (value is List<*>) value else listOf(value)
        for (v in values) {
            when (v) {
                is FileUpload -> {
                    val content = try {
                        v.readBytes()
                    } catch (e: java.io.IOException) {
                        throw SkapiException("\"$name\" cannot be read: ${e.message ?: e}.", "INVALID_PARAMETER", e)
                    }
                    if (v.filename.isEmpty()) throw perr("\"$name\" needs a filename.")
                    filePart(name, v.filename, content, v.contentType ?: guessContentType(v.filename))
                }
                is ByteArray -> filePart(name, name, v, null)
                null -> textPart(name, "")
                is Boolean -> textPart(name, if (v) "true" else "false")
                is Map<*, *>, is List<*> -> textPart(name, jsJson(v))
                is Double, is Float -> textPart(name, jsJson(v))
                else -> textPart(name, v.toString())
            }
        }
    }
    out.write(utf8("--$boundary--\r\n"))
    return Pair(out.toByteArray(), "multipart/form-data; boundary=$boundary")
}

// ---- forwardRequest -----------------------------------------------------------------------------

/**
 * Calls another API through Skapi. options: url (required), method, headers, data, params,
 * secretName (a client secret stored on skapi.com; put "$CLIENT_SECRET" where it goes),
 * skapiHeaders, queue, expires, stream, poll (milliseconds between checks), multipart.
 *
 * Without queue/poll/stream: returns the API's answer. With poll or stream: waits for the answer
 * and returns it, handing streamed text to onStream(text, seq) as it arrives. With a queue and no
 * poll: returns {id, status, queue_name, in_queue, request_id} at once; check it later with
 * forwardRequestPoll(request_id).
 */
internal fun Core.forwardRequest(options: JMap, form: JMap?, onStream: ((String, Int) -> Unit)?): Any? {
    if (options["apiKeyHeader"] != null || options["apiKeyScheme"] != null) {
        throw perr("\"apiKeyHeader\" and \"apiKeyScheme\" are no longer supported. Store the key as a client secret, name it with \"secretName\", and put \"\$CLIENT_SECRET\" where the key goes.")
    }
    val multipart = options["multipart"]
    if (multipart != null && multipart !is Boolean) throw perr("\"multipart\" should be type: <boolean>.")
    val responseType = options["responseType"]
    if (responseType != null) {
        if (responseType == "response") {
            throw perr("\"responseType\": \"response\" is not available here. The request is relayed from the server and what comes back is the stored answer, not a live Response; the destination's status code is the \"status_code\" of the row forwardRequestHistory lists.")
        }
        if (responseType != "json" && responseType != "text") throw perr("\"responseType\" should be either \"json\" or \"text\".")
    }
    val method = options["method"].takeIf { truthy(it) } ?: "POST"
    val mergeInto = if (method is String && method.lowercase() in setOf("get", "delete", "head")) "params" else "data"

    val params = jmap("url" to options["url"], "method" to method)
    for (k in listOf("secretName", "headers", "data", "params", "skapiHeaders", "service", "owner", "queue", "expires", "stream", "realtime", "poll")) {
        if (options[k] != null) params[k] = options[k]
    }

    if (multipart == true) {
        if (options["data"] != null) throw perr("\"data\" cannot be sent with \"multipart\": true. The form itself is the body.")
        if (form == null) throw perr("\"multipart\": true needs a form body in the first argument.")
        val (body, contentType) = multipart(form)
        val encoded = b64(body)
        if (encoded.length > MULTIPART_LIMIT) {
            throw perr("Multipart body is too large: ${encoded.length} bytes once base64 encoded, and the limit is $MULTIPART_LIMIT. Upload the file first and send its url instead.")
        }
        params["body_b64"] = encoded
        params["body_content_type"] = contentType
    } else if (form != null && form.isNotEmpty()) {
        val existing = params[mergeInto]
        if (existing != null && existing !is Map<*, *>) throw perr("\"$mergeInto\" should be type: <object>.")
        if (utf8(jsJson(form)).size > 2 * 1024 * 1024) throw skErr("Data should not exceed 2MB", "INVALID_REQUEST")
        val merged = form.copyMap()
        merged.putAll(existing.copyMap())
        params[mergeInto] = merged
    }

    return dispatchForward(params, onStream, responseType as String?)
}

private fun Core.dispatchForward(params: JMap, onStream: ((String, Int) -> Unit)?, responseType: String?): Any? {
    val secretNamed = truthy(params["secretName"])
    val poll = params.remove("poll")
    if (poll is Number && poll.toDouble() < 0) throw perr("\"poll\" should be a non-negative number.")
    val latency: Double = if (poll is Number) poll.toDouble() else if (truthy(poll)) 1000.0 else 0.0
    ensureConnection()
    val signedIn = signedIn()
    if ((latency != 0.0 || truthy(params["stream"])) && !truthy(params["queue"])) {
        val rnd = (1..6).map { ALNUM[secureRandom.nextInt(ALNUM.length)] }.joinToString("")
        params["queue"] = "${(user?.get("user_id") as? String)?.takeIf { it.isNotEmpty() } ?: "anonymous"}-$rnd"
    }

    val body = LinkedHashMap<String, Any?>()
    val url = params["url"]
    if (url !is String || url.isEmpty()) throw perr("\"url\" should be type: <string>.")
    absoluteUrl(url)
    body["url"] = url
    var secret = "\$CLIENT_SECRET" in url
    if (params.containsKey("secretName")) {
        if (params["secretName"] !is String) {
            throw perr("${jd(params["secretName"])} is invalid in \"secretName\". allowed type or value is: Type<string>.")
        }
        body["secretName"] = params["secretName"]
    }
    val m = params["method"]
    if (truthy(m) && (m !is String || m.lowercase() !in METHODS)) {
        throw perr("\"method\" should be one of \"GET\", \"POST\", \"PUT\", \"PATCH\", \"DELETE\" or \"HEAD\".")
    }
    val lowerMethod = (m as? String ?: "POST").lowercase()
    body["method"] = lowerMethod
    for (k in listOf("stream", "realtime")) {
        if (params.containsKey(k)) {
            if (params[k] !is Boolean) throw perr("\"$k\" should be type: <boolean>.")
            body[k] = params[k]
        }
    }
    if (params.containsKey("headers")) {
        val h = params["headers"]
        if (truthy(h) && h !is Map<*, *>) throw perr("\"headers\" should be type: <object>.")
        for (k in (h as? Map<*, *>)?.keys ?: emptySet<Any?>()) {
            if (k.toString().lowercase().startsWith("x-skapi-")) {
                throw perr("\"headers\" cannot set \"$k\": the \"x-skapi-\" prefix is reserved. Use \"skapiHeaders\" to tell the destination who the caller is.")
            }
        }
        secret = secret || hasSecret(h)
        body["headers"] = h
    }
    if (params.containsKey("skapiHeaders")) {
        val sh = params["skapiHeaders"]
        body["skapiHeaders"] = when (sh) {
            is Boolean -> sh
            is Map<*, *> -> jmap("user" to truthy(sh["user"]), "service" to truthy(sh["service"]))
            else -> throw perr("\"skapiHeaders\" should be type: <boolean> or { user?: boolean; service?: boolean }.")
        }
    }
    for (k in listOf("data", "params")) {
        if (params.containsKey(k)) {
            val v = params[k]
            if (truthy(v) && v !is Map<*, *>) throw perr("\"$k\" should be type: <object>.")
            secret = secret || hasSecret(v)
            body[k] = v
        }
    }
    for (k in listOf("body_b64", "body_content_type")) {
        if (params.containsKey(k)) body[k] = params[k]
    }
    if (params.containsKey("expires")) {
        if (params["expires"] !is Number) throw perr("${jd(params["expires"])} is invalid in \"expires\". allowed type or value is: Type<number>.")
        body["expires"] = params["expires"]
    }
    if (params.containsKey("queue")) {
        if (params["queue"] !is String) throw perr("${jd(params["queue"])} is invalid in \"queue\". allowed type or value is: Type<string>.")
        body["queue"] = params["queue"]
    }
    for (k in listOf("service", "owner")) {
        if (params.containsKey(k)) body[k] = params[k]
    }
    if (truthy(body["realtime"]) && !truthy(body["stream"])) throw perr("\"realtime\" requires \"stream\": true.")
    if (truthy(body["body_b64"]) && truthy(body["data"])) throw perr("\"data\" cannot be sent with \"multipart\": true.")
    if (secretNamed && !secret) body.remove("secretName")

    val token = if (signedIn) freshIdToken() else null
    val extra = if (signedIn) session?.accessToken?.jwtToken?.let { mapOf("X-Access-Token" to it) } else null
    var res = requester.request("csr", body, auth = signedIn, token = token, extraHeaders = extra)

    val service = (params["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service
    val rm = res.asMap()
    if (isStatusEnvelope(res) && (rm!!["status"] == "running" || rm["status"] == "pending")) {
        val fullId = requestKey(lowerMethod, url, service, rm["id"] as String)
        rm["request_id"] = fullId
        if (latency > 0 || truthy(body["stream"])) {
            res = forwardRequestPoll(fullId, poll = if (latency != 0.0) latency else 1000.0, onStream = onStream,
                service = params["service"] as? String, owner = params["owner"] as? String)
        }
    }
    return responseTypeOf(res, responseType)
}

private fun responseTypeOf(res: Any?, responseType: String?): Any? {
    if (responseType.isNullOrEmpty() || isStatusEnvelope(res) || res.asMap()?.get("status") == "stopped") return res
    if (responseType == "text") return if (res is String) res else jsJson(res)
    if (res is String) return parseJsonOrNull(res).getOrElse { res }
    return res
}

private fun Core.fullRequestId(requestId: Any?, url: Any?, method: Any?, service: Any?): String {
    if (requestId !is String || requestId.isEmpty()) throw perr("\"requestId\" should be type: <string>.")
    if ('#' in requestId) return requestId
    if (url !is String || method !is String || url.isEmpty() || method.isEmpty()) {
        throw perr("\"url\" and \"method\" are required to address a request by its short id.")
    }
    absoluteUrl(url)
    return requestKey(method, url, (service as? String)?.takeIf { it.isNotEmpty() } ?: this.service, requestId)
}

/** Waits for a queued request (its request_id, or its short id with url and method) and returns the answer. */
internal fun Core.forwardRequestPoll(
    requestId: String,
    poll: Double = 1000.0,
    url: String? = null,
    method: String? = null,
    onStream: ((String, Int) -> Unit)? = null,
    service: String? = null,
    owner: String? = null,
): Any? {
    if (poll.isNaN()) throw perr("\"poll\" should be a number.")
    if (poll < 0) throw perr("\"poll\" should be a non-negative number.")
    val wait = if (poll == 0.0) 1000.0 else poll
    val fullId = fullRequestId(requestId, url, method, service)
    ensureConnection()
    var cursor = 0L
    var stalled = 0
    while (true) {
        Thread.sleep(wait.toLong())
        while (true) {
            val body = jmap("id" to fullId, "service" to (service ?: this.service), "owner" to (owner ?: this.owner))
            if (onStream != null) body["since"] = cursor
            val result = call("csr-poll", body, auth = signedIn())
            // Chunks, "more" and a running status belong to skapi's status envelope. A resolved
            // read is the destination's own body, returned as it is: a "chunks", "more" or
            // "status": "pending" key in THAT is the destination's data, not text to stream or
            // a cue to read again.
            val envelope = isStatusEnvelope(result)
            var moved = false
            if (onStream != null && envelope) {
                val r = deliverChunks(result, cursor, onStream)
                cursor = r.first
                moved = r.second
            }
            val rm = result.asMap()
            val running = envelope && (rm!!["status"] == "running" || rm["status"] == "pending")
            val more = envelope && truthy(rm!!["more"])
            if (more && moved) {
                stalled = 0
                continue
            }
            if (running) {
                stalled = 0
                break
            }
            stalled = if (more) stalled + 1 else 0
            if (more && stalled < STREAM_DEGRADED_RETRIES) break
            return result
        }
    }
}

/** Reads a streamed request's text from `since` (or the start) until it settles; returns the final answer. */
internal fun Core.forwardRequestStream(requestId: String, options: JMap?, onStream: ((String, Int) -> Unit)?): Any? {
    val o = options.copyMap()
    val poll = o["poll"]
    val latency = if (poll is Number) poll.toDouble() else 1000.0
    if (latency < 0) throw perr("\"poll\" should be a non-negative number.")
    if (o.containsKey("since") && o["since"] !is Number) throw perr("\"since\" should be a number.")
    val fullId = fullRequestId(requestId, o["url"], o["method"], o["service"])
    ensureConnection()
    val since = (o["since"] as? Number)?.toDouble() ?: 0.0
    var cursor = if (since > 0) since.toLong() else 0L
    var stalled = 0
    while (true) {
        val result = call("csr-poll", jmap(
            "id" to fullId,
            "service" to ((o["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service),
            "owner" to ((o["owner"] as? String)?.takeIf { it.isNotEmpty() } ?: this.owner),
            "since" to cursor,
        ), auth = signedIn())
        if (!isStatusEnvelope(result)) return result
        val rm = result.asMap()!!
        var moved = false
        if (onStream != null) {
            val r = deliverChunks(result, cursor, onStream)
            cursor = r.first
            moved = r.second
        } else {
            val last = intSeq(rm["last_seq"])
            if (last != null && last > cursor) {
                cursor = last
                moved = true
            }
        }
        val running = rm["status"] == "running" || rm["status"] == "pending"
        val more = truthy(rm["more"])
        if (more && moved) continue
        stalled = if (more) stalled + 1 else 0
        if (!running && (!more || stalled >= STREAM_DEGRADED_RETRIES)) return result
        Thread.sleep(latency.toLong())
    }
}

/** Stores `data` as a streamed request's final answer, so later polls return it. */
internal fun Core.forwardRequestFinalize(requestId: String, data: Any?, options: JMap?): Any? {
    val o = options.copyMap()
    val fullId = fullRequestId(requestId, o["url"], o["method"], o["service"])
    ensureConnection()
    val body = jmap("id" to fullId)
    if (data != null) body["data"] = data
    body["service"] = (o["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service
    body["owner"] = (o["owner"] as? String)?.takeIf { it.isNotEmpty() } ?: this.owner
    return call("csr-finalize", body, auth = signedIn())
}

/** The forwarded requests you made to one url and method, newest last, with their answers. */
internal fun Core.forwardRequestHistory(params: JMap, fetchOptions: JMap?): Any? {
    ensureConnection()
    val p = params.copyMap()
    val service = (p["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service
    val owner = (p["owner"] as? String)?.takeIf { it.isNotEmpty() } ?: this.owner
    for (key in listOf("url", "method")) {
        if (!p.containsKey(key)) throw perr("Key \"$key\" is required.")
    }
    if (p["url"] !is String) throw perr("${jd(p["url"])} is invalid in \"url\". allowed type or value is: Type<string>.")
    if (p["method"] !in UPPER_METHODS) {
        throw perr("${jd(p["method"])} is invalid in \"method\". allowed types or values are: " + UPPER_METHODS.joinToString(", ") { jd(it) } + ".")
    }
    if (p.containsKey("status") && p["status"] !in listOf("pending", "running", "resolved", "failed")) {
        throw perr("${jd(p["status"])} is invalid in \"status\". allowed types or values are: \"pending\", \"running\", \"resolved\", \"failed\".")
    }
    for (k in listOf("queue", "queue_exclude")) {
        if (p.containsKey(k) && p[k] != null && p[k] !is String) {
            throw perr("${jd(p[k])} is invalid in \"$k\". allowed type or value is: Type<string>.")
        }
    }
    for (k in listOf("compact", "queue_exact")) {
        if (p.containsKey(k) && p[k] !is Boolean) throw perr("${jd(p[k])} is invalid in \"$k\". allowed type or value is: Type<boolean>.")
    }
    val prefix = requestKey(p["method"] as String, p["url"] as String, service, "")
    var req = jmap("id" to prefix, "queue" to p["queue"], "status" to p["status"], "service" to service, "owner" to owner)
    if (truthy(p["compact"])) req["compact"] = true
    if (truthy(p["queue_exact"])) req["queue_exact"] = true
    if (truthy(p["queue_exclude"])) req["queue_exclude"] = p["queue_exclude"]
    req = LinkedHashMap(req.filterValues { truthy(it) })
    if (truthy(req["queue"])) req["id_prefix"] = req.remove("id")
    val res = call("csr-poll", req, auth = signedIn(), fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        val out = jlist()
        for (rAny in list) {
            val r = rAny.asMap() ?: LinkedHashMap()
            val rslvAny = if (truthy(r["rslv"])) r["rslv"] else LinkedHashMap<String, Any?>()
            val rslv = rslvAny.asMap()
            val item = jmap(
                "id" to r["id"],
                "status_code" to rslv?.get("status_code"),
                "response_body" to rslv?.let { if (truthy(it["body"])) it["body"] else it["truncated"] },
            )
            for ((key, src) in listOf("error" to "err", "created" to "stmp", "updated" to "utmp")) {
                if (r.containsKey(src)) item[key] = r[src]
            }
            val att = r["att"]
            if (att is Number) item["executed"] = if (att is Long) att * 1000 else att.toDouble() * 1000
            if (r["rtmp"] is Number) item["responded"] = r["rtmp"]
            for ((key, src) in listOf("request_body" to "reqbdy", "expires" to "expt", "status" to "stts", "queue_name" to "qid",
                "request_text" to "reqtxt", "response_text" to "rslvtxt")) {
                if (r.containsKey(src)) item[key] = r[src]
            }
            if (r["rslvmk"] != null) item["response_complete_marker"] = truthy(r["rslvmk"])
            if (truthy(r["cmpct"])) item["compact"] = true
            val id = r["id"]
            item["request_id"] = prefix + (if (id is String) id else if (id == null) "None" else jsJson(id))
            out.add(item)
        }
        rm["list"] = out
    }
    return res
}

/** Cancels a queued request that has not run yet: {url, method, id}. */
internal fun Core.cancelForwardRequest(params: JMap): Any? {
    val p = params.copyMap()
    for (key in listOf("url", "method", "id")) {
        if (!p.containsKey(key)) throw perr("Key \"$key\" is required.")
    }
    if (p["method"] !in UPPER_METHODS) {
        throw perr("${jd(p["method"])} is invalid in \"method\". allowed types or values are: " + UPPER_METHODS.joinToString(", ") { jd(it) } + ".")
    }
    for (key in listOf("url", "id", "queue")) {
        if (p.containsKey(key) && p[key] !is String) throw perr("${jd(p[key])} is invalid in \"$key\". allowed type or value is: Type<string>.")
    }
    ensureConnection()
    val service = (p["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service
    val fullId = requestKey(p["method"] as String, p["url"] as String, service, p["id"] as String)
    return call("csr-cancel", jmap("id" to fullId, "service" to service,
        "owner" to ((p["owner"] as? String)?.takeIf { it.isNotEmpty() } ?: this.owner)), auth = signedIn())
}

/** How many requests are waiting in one of your queues. Signed-in users only. */
internal fun Core.forwardRequestQueueCount(params: JMap): Any? {
    val p = params.copyMap()
    if (!truthy(p["queue"])) throw perr("\"queue\" is required.")
    val res = call("csr-poll", jmap(
        "service" to ((p["service"] as? String)?.takeIf { it.isNotEmpty() } ?: this.service),
        "owner" to ((p["owner"] as? String)?.takeIf { it.isNotEmpty() } ?: this.owner),
        "queue" to "${p["queue"]}:",
    ), auth = true)
    val rm = res.asMap()
    val qn = rm?.get("queue_name")
    if (qn is String) rm["queue_name"] = qn.trimEnd(':')
    return res
}

// ---- inquiry ----------------------------------------------------------------------------------

/** Sends a message to the project's owner: {name, email, subject, message}. */
internal fun Core.sendInquiry(data: JMap): String {
    ensureConnection()
    val d = data.copyMap()
    for (key in listOf("name", "email", "subject", "message")) {
        if (!d.containsKey(key)) throw perr("Key \"$key\" is required.")
    }
    for (key in listOf("name", "subject", "message")) {
        if (d[key] !is String) throw perr("${jd(d[key])} is invalid in \"$key\". allowed type or value is: Type<string>.")
    }
    validateEmail(d["email"])
    call("send-inquiry", jmap("name" to d["name"], "email" to d["email"], "subject" to d["subject"], "message" to d["message"]))
    return "SUCCESS: Inquiry has been sent."
}
