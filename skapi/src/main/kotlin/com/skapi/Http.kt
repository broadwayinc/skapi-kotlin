package com.skapi

import okhttp3.Headers
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.SocketTimeoutException
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/*
 * The request layer: endpoint discovery, headers, body encoding, errors, rate-limit retries and
 * paging, matching skapi-js (src/utils/network.ts) and skapi-py (_http.py) so the server sees
 * the same requests.
 */

internal const val DEFAULT_TARGET_CDN = "d3e9syvbtso631"
internal const val ENDPOINT_VERSION = "v2"
internal val KNOWN_ERROR_CODES = setOf("INVALID_CORS", "INVALID_REQUEST", "SERVICE_DISABLED", "INVALID_PARAMETER", "ERROR", "EXISTS", "NOT_EXISTS")
internal const val RATE_LIMIT_MAX_RETRIES = 6
// Uploads (2.4.4): once the whole body is written, MB can still drain from the OS buffers with
// nothing to show, so the answer may take this many times `timeoutSeconds` before the upload
// counts as stalled. Writing already has an idle limit: OkHttp's writeTimeout applies to each
// write, never to the file's total time, so a slow upload that keeps moving is not cut off.
internal const val UPLOAD_SENT_WAIT_FACTOR = 5L

internal val ADMIN_ROUND_ROBIN = setOf(
    "get-newsletters", "get-public-newsletters", "subscribe-newsletter", "subscribe-public-newsletter",
    "signupkey", "admin-newsletter-request", "admin-signup", "confirm-signup", "openid-logger",
    "block-account", "admin-edit-profile", "remove-account", "recover-account", "mock",
    "grant-access", "last-verified-email", "ticket", "register-ticket", "get-newsletter-subscription",
    "send-inquiry", "register-newsletter-group", "delete-newsletter-group", "newsletter-group-endpoint",
    "invitation-list", "csr", "csr-poll", "csr-cancel", "csr-finalize",
)
internal val RECORD_ROUND_ROBIN = setOf(
    "store-subscription", "get-vapid-public-key", "push-notification", "delete-subscription",
    "subscription", "get-subscription", "get-table", "get-tag", "get-uniqueid", "get-index",
    "get-signed-url", "get-signed-urls", "extract-file-text", "grid-query", "anonymous-login",
    "anonymous-session", "grant-private-access", "request-private-access-key", "get-ws-group",
    "check-schema", "get-feed", "castspell", "dopamine", "getspell",
)

/** One counter for admin and record picks, as in skapi-js. */
private val requestCounter = AtomicInteger(0)

internal fun sortedKeys(v: Any?): Any? = when (v) {
    is Map<*, *> -> LinkedHashMap<String, Any?>().also { m -> for (k in v.keys.map { it.toString() }.sorted()) m[k] = sortedKeys(v[k]) }
    is List<*> -> v.map { sortedKeys(it) }
    else -> v
}

private fun retryDelayMs(value: String?): Double? {
    if (value.isNullOrEmpty()) return null
    value.trim().toDoubleOrNull()?.let { return Math.max(0.0, it * 1000) }
    return try {
        val fmt = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US)
        Math.max(0.0, (fmt.parse(value)!!.time - System.currentTimeMillis()).toDouble())
    } catch (e: Exception) {
        null
    }
}

private fun rateLimitWaitMs(delay: Double, attempt: Int): Double {
    var base = if (delay > 0) delay else Math.min(60000.0, 500.0 * Math.pow(2.0, attempt.toDouble()))
    base = Math.min(60000.0, base)
    return base + Math.floor(Math.random() * Math.min(1000.0, Math.max(50.0, base * 0.25)))
}

/**
 * A non-2xx answer as a SkapiException, read the way skapi-js reads it.
 *
 * serverFault (2.7.0, on by default): a 5xx other than 501 is a server fault, not a refusal, so it
 * is SERVER_ERROR whatever the body says (the body is kept as the cause), and a caller can tell
 * "try again" from "no". 501 says the route does not exist here, which is an answer. Uploads pass
 * false: they read errors as skapi-js uploads do (toFileUploadError).
 */
internal fun parseError(status: Int, text: String, serverFault: Boolean = true): SkapiException {
    val fault = serverFault && status >= 500 && status != 501
    val body: Any? = parseJsonOrNull(text).getOrElse { text }
    if (body is String) {
        val parts = body.split(":")
        val code = parts[0].trim()
        val message = parts.drop(1).joinToString(":").trim()
        if (fault) return skErr(message.ifEmpty { body }.ifEmpty { "Server error $status." }, "SERVER_ERROR", body.ifEmpty { null })
        return skErr(message.ifEmpty { body }, if (code in KNOWN_ERROR_CODES) code else "ERROR")
    }
    val m = body.asMap()
    if (m != null && (m.containsKey("message") || m.containsKey("stage") || m.containsKey("code"))) {
        val code = m["code"]?.takeIf { truthy(it) }?.let { if (it is String) it else jsJson(it) } ?: status.toString()
        val message = (m["message"] as? String ?: "").trim().ifEmpty { code }
        val cause = if (m.containsKey("cause")) m["cause"] else if (m.containsKey("stage")) m else null
        if (fault) return skErr(message, "SERVER_ERROR", cause ?: m)
        return skErr(message, code, cause)
    }
    if (fault) return skErr("Server error $status.", "SERVER_ERROR", body)
    return skErr(if (body is String) body else jsJson(body), "ERROR")
}

/**
 * A caller's hold on one request (2.7.0): a deadline (milliseconds in all, from the call) and an
 * abort signal. Past the deadline the request fails with TIMEOUT, an abort fails it with ABORTED,
 * and either one cancels the call on the network.
 */
internal class RequestControl(deadlineMs: Double?, val signal: SkapiAbortSignal?) {
    val deadlineMs: Long? = deadlineMs?.toLong()
    private val startedAt = System.nanoTime()

    /** Milliseconds left, or null for no deadline. */
    fun remainingMs(): Long? = deadlineMs?.let { it - (System.nanoTime() - startedAt) / 1_000_000 }

    fun timeoutError(): SkapiException = skErr("No answer within $deadlineMs ms.", "TIMEOUT")

    /** Throws when the caller gave up (aborted or past the deadline). */
    fun check() {
        if (signal?.aborted == true) throw skErr("Aborted", "ABORTED")
        val left = remainingMs()
        if (left != null && left <= 0) throw timeoutError()
    }

    /** True once the caller gave up (aborted or past the deadline). */
    fun gaveUp(): Boolean = signal?.aborted == true || (remainingMs()?.let { it <= 0 } ?: false)

    /** Waits `ms` (a back-off), cut short by an abort (ABORTED) or the deadline (TIMEOUT). */
    fun pause(ms: Long) {
        awaitWithin(CompletableFuture<Unit>(), ms, this)
    }

    /**
     * Runs `block` (the wait for the connection, a sign-in restored from storage) on its own thread
     * and waits for it within the deadline; an abort ends the wait at once. When the caller gives
     * up, the block still runs to its end for the calls that come after.
     */
    fun <T> bounded(block: () -> T): T {
        val done = CompletableFuture<T>()
        Thread({
            try { done.complete(block()) } catch (e: Throwable) { done.completeExceptionally(e) }
        }, "skapi-request").also { it.isDaemon = true }.start()
        awaitWithin(done, null, this)
        try {
            return done.get()
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    }
}

/**
 * Waits for `future` at most `limitMs` (null: no limit of its own) and at most the caller's
 * deadline; the caller's abort ends the wait at once. Returns true once the future is done, false
 * when limitMs ran out; throws ABORTED, or TIMEOUT when the deadline came first. The future is
 * left running either way.
 */
internal fun awaitWithin(future: CompletableFuture<*>, limitMs: Long?, control: RequestControl?): Boolean {
    val left = control?.remainingMs()
    val byDeadline = left != null && (limitMs == null || left < limitMs)
    val wait = if (byDeadline) Math.max(0L, left!!) else limitMs
    val wake = CompletableFuture<Unit>()
    future.whenComplete { _, _ -> wake.complete(Unit) }
    val unhook = control?.signal?.onAbort { wake.complete(Unit) } ?: {}
    try {
        if (wait == null) wake.get() else wake.get(wait, TimeUnit.MILLISECONDS)
    } catch (e: TimeoutException) {
        // the time is up: said below
    } finally {
        unhook()
    }
    if (future.isDone) return true
    control?.check()
    if (byDeadline) throw control!!.timeoutError()
    return false
}

internal class Requester(
    val service: String,
    val owner: String,
    val version: String,
    targetCdn: String?,
    val timeoutSeconds: Long,
) {
    val targetCdn: String = targetCdn ?: DEFAULT_TARGET_CDN
    var publicIdentifier: String = ""
    internal var admin: JMap? = null
    internal var record: JMap? = null
    private val lock = Any()

    /** paging: the startKeys a query has seen, newest last ("end" when the list is done) */
    val startKeyHistory: MutableMap<String, MutableMap<String, MutableList<String>>> = ConcurrentHashMap()

    val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .build()

    /** `client` with the longer wait for the answer after an upload body is sent. */
    private val uploadClient: OkHttpClient by lazy {
        client.newBuilder().readTimeout(timeoutSeconds * UPLOAD_SENT_WAIT_FACTOR, TimeUnit.SECONDS).build()
    }

    // ---- endpoints ------------------------------------------------------------------------------

    private fun fetchEndpointFile(name: String): JMap {
        val url = "https://$targetCdn.cloudfront.net/${service.take(4)}/$name-$ENDPOINT_VERSION.json"
        // Only the CDN's "no such file" (403 or 404) means the project does not exist. Anything else is
        // a failure on the way, reported with a code a caller (and a poll) retries: before, a passing
        // CDN error or a cut-off answer said "The project ID does not exist", and the next call, which
        // fetches the list again, worked.
        try {
            client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
                val text = resp.body?.string() ?: ""
                when {
                    resp.code == 403 || resp.code == 404 ->
                        throw skErr("The project ID does not exist. Create your project from skapi.com", "NOT_EXISTS")
                    resp.code == 429 -> throw skErr("Too many requests", "RATE_LIMITED")
                    !resp.isSuccessful -> throw skErr("Server error ${resp.code}.", "SERVER_ERROR")
                }
                return parseJsonOrNull(text).getOrNull().asMap()
                    ?: throw skErr("Network error: the project's endpoint list \"$name\" arrived incomplete.", "NETWORK_ERROR")
            }
        } catch (e: IOException) {
            throw transportFailure(e, null)
        }
    }

    fun endpoints(): Pair<JMap, JMap> = synchronized(lock) {
        if (admin == null) admin = fetchEndpointFile("admin")
        if (record == null) record = fetchEndpointFile("record")
        Pair(admin!!, record!!)
    }

    private fun selectGateway(kind: String, auth: Boolean, stable: Boolean = false): String {
        val (admin, record) = endpoints()
        val n = requestCounter.incrementAndGet()
        val items: List<String>
        if (kind == "admin") {
            val suffix = if (auth) "_private" else "_public"
            items = admin.entries.filter { (k, v) -> suffix in k && k != "get_users_private" && k != "service_public" && v is String }.map { it.value as String }
            if (items.isEmpty()) throw skErr("No available admin gateways.", "INVALID_REQUEST")
        } else {
            val prefix = if (auth) "record_private" else "record_public"
            items = record.entries.filter { (k, v) -> prefix in k && v is String }.map { it.value as String }
            if (items.isEmpty()) throw skErr("No available record gateways.", "INVALID_REQUEST")
            if (stable) return items[0]
        }
        return items[n % items.size]
    }

    fun endpointUrl(dest: String, auth: Boolean, stable: Boolean = false): String {
        val (admin, record) = endpoints()
        val q = dest.indexOf('?')
        val path = if (q >= 0) dest.substring(0, q) else dest
        val query = if (q >= 0 && q < dest.length - 1) "?" + dest.substring(q + 1) else ""
        val base: String = when {
            path == "get-users" -> admin["get_users_private"] as String
            path == "service" -> admin["service_public"] as String
            path in ADMIN_ROUND_ROBIN -> selectGateway("admin", auth)
            path == "post-record" -> (if (auth) record["post_private"] else record["post_public"]) as String
            path == "get-records" -> (if (auth) record["get_private"] else record["get_public"]) as String
            path == "del-files" || path == "del-records" -> record["del_private"] as String
            path in RECORD_ROUND_ROBIN -> selectGateway("record", auth, stable)
            else -> {
                if (!path.startsWith("https://") && !path.startsWith("http://")) throw perr("\"$dest\" is not a valid url.")
                return dest
            }
        }
        return base + path + query
    }

    // ---- request --------------------------------------------------------------------------------

    /**
     * token: the idToken, already fresh, when auth is on (sent raw as Authorization).
     * fetchOptions: limit, startKey, ascending (sent) and fetchMore (paging, not sent).
     * raw: return the response bytes as they are (a ByteArray).
     */
    fun request(
        dest: String,
        data: Any? = null,
        auth: Boolean = false,
        method: String = "POST",
        token: String? = null,
        fetchOptions: JMap? = null,
        ignoreService: Boolean = false,
        stableGateway: Boolean = false,
        contentType: String? = "application/json",
        raw: Boolean = false,
        extraHeaders: Map<String, String>? = null,
        control: RequestControl? = null,
    ): Any? {
        control?.check()
        val m = method.uppercase()
        var url = endpointUrl(dest, auth, stableGateway)
        val dataMap = data.asMap()
        val service = (dataMap?.get("service") as? String)?.takeIf { it.isNotEmpty() } ?: this.service
        val owner = (dataMap?.get("owner") as? String)?.takeIf { it.isNotEmpty() } ?: this.owner

        val fo = fetchOptions.copyMap()
        var fetchMore = truthy(fo.remove("fetchMore") ?: fo.remove("fetch_more"))
        fo.remove("fetch_more")
        if (fo.containsKey("start_key") && !fo.containsKey("startKey")) fo["startKey"] = fo.remove("start_key")
        val sent = LinkedHashMap<String, Any?>()
        if (fo["limit"] != null) {
            val limit = fo["limit"]
            if (limit !is Number) throw skErr("Fetch limit should be a number.", "INVALID_REQUEST")
            if (limit.toDouble() > 1000) throw skErr("Fetch limit should be below 1000.", "INVALID_REQUEST")
            sent["limit"] = limit
        }
        if (fo["startKey"] != null) sent["startKey"] = fo["startKey"]
        if (fo["ascending"] != null) {
            if (fo["ascending"] !is Boolean) throw perr("\"ascending\" should be a boolean.")
            sent["ascending"] = fo["ascending"]
        }

        var body: Any? = if (ignoreService) LinkedHashMap<String, Any?>() else jmap("service" to service, "owner" to owner)
        (body as JMap).putAll(sent)
        if (dataMap != null) {
            for ((k, v) in dataMap) body[k] = v
        } else if (truthy(data)) {
            body = data
        }

        // paging: a query asked again with fetchMore continues from the last startKey it got
        var historyKey: String? = null
        val bm = body.asMap()
        if (bm != null) {
            val startKey = bm["startKey"]
            if (truthy(startKey)) {
                if (startKey == "start") {
                    bm.remove("startKey")
                    fetchMore = false
                } else if (!(startKey == "end" || (startKey is Map<*, *> && startKey.isNotEmpty()))) {
                    throw perr("\"${if (startKey is String) startKey else jsJson(startKey)}\" is invalid startKey key.")
                }
            }
            val fingerprint = "$m:${if (auth) "auth" else "public"}:$dest"
            // the private key of a shared record is attached once this client has it (after page 1),
            // so it stays out of the paging key: the next page of the same query continues the same list
            val paramsForKey = LinkedHashMap<String, Any?>()
            for ((k, v) in bm) if (k != "startKey" && k != "private_key") paramsForKey[k] = v
            historyKey = md5Hex(fingerprint + "/" + jsJson(sortedKeys(paramsForKey)))
            val history = startKeyHistory.getOrPut(dest) { ConcurrentHashMap() }
            if (!fetchMore) {
                history.remove(historyKey)
            } else {
                val seen = history[historyKey]
                if (!seen.isNullOrEmpty()) {
                    val last = seen.last()
                    if (last == "end") {
                        return jmap("list" to jlist(), "startKey" to "end", "endOfList" to true, "startKeyHistory" to seen.toMutableList<Any?>())
                    }
                    bm["startKey"] = parseJson(last)
                }
            }
        }

        val headers = LinkedHashMap<String, String>()
        headers["Accept"] = "*/*"
        if (contentType != null) headers["Content-Type"] = contentType
        if (token != null) headers["Authorization"] = token
        if (extraHeaders != null) headers.putAll(extraHeaders)
        headers["Content-Meta"] = jsJson(jmap(
            "public_identifier" to publicIdentifier,
            "service" to service,
            "owner" to owner,
            "resolves_offloaded_data" to true,
            "skapi_version" to version,
            "expiring_private_keys" to true, // renews private access keys before they expire, so 1-hour keys are safe
        ))

        var payload: ByteArray? = null
        if (m == "GET") {
            val gm = body.asMap()
            if (gm != null && gm.isNotEmpty()) {
                val pairs = gm.entries.joinToString("&") { (k, v) ->
                    encodeURIComponent(k) + "=" + encodeURIComponent(if (v is String) v else jsJson(v))
                }
                url += (if ('?' !in url) "?" else if (url.endsWith("?") || url.endsWith("&")) "" else "&") + pairs
            }
        } else if (body is ByteArray) {
            payload = body
        } else if (body is String) {
            payload = utf8(body)
        } else if (truthy(body)) {
            payload = utf8(jsJson(body))
        }

        var result = send(url, m, headers, payload, raw, control = control)

        val rm = result.asMap()
        if (historyKey != null && rm != null && truthy(rm["startKey"])) {
            val seen = startKeyHistory.getOrPut(dest) { ConcurrentHashMap() }.getOrPut(historyKey) { java.util.Collections.synchronizedList(mutableListOf()) }
            val entry = if (rm["startKey"] == "end") "end" else jsJson(rm["startKey"])
            if (entry !in seen) seen.add(entry)
            val out = jmap("startKeyHistory" to seen.toMutableList<Any?>())
            out.putAll(rm)
            result = out
        }
        return result
    }

    fun send(url: String, method: String, headers: Map<String, String>, payload: ByteArray?, raw: Boolean = false,
             uploadName: String? = null, control: RequestControl? = null): Any? {
        var attempt = 0
        while (true) {
            control?.check()
            val hb = Headers.Builder()
            for ((k, v) in headers) hb.addUnsafeNonAscii(k, v)
            val body = if (method == "GET" || method == "HEAD") null else (payload ?: ByteArray(0)).toRequestBody(null)
            val req = try {
                Request.Builder().url(url).headers(hb.build()).method(method, body).build()
            } catch (e: IllegalArgumentException) {
                throw perr("\"$url\" is not a valid url.")
            }
            val call = (if (uploadName != null) uploadClient else client).newCall(req)
            var unhook: () -> Unit = {}
            if (control != null) {
                // The caller's deadline bounds this attempt; an abort cancels it on the network.
                control.remainingMs()?.let { call.timeout().timeout(Math.max(1L, it), TimeUnit.MILLISECONDS) }
                control.signal?.let { sig -> unhook = sig.onAbort { call.cancel() } }
            }
            try {
                call.execute().use { resp ->
                    val content = resp.body?.bytes() ?: ByteArray(0)
                    if (resp.isSuccessful) {
                        if (raw) return content
                        val text = String(content, Charsets.UTF_8)
                        return parseJsonOrNull(text).getOrElse { text }
                    }
                    val text = String(content, Charsets.UTF_8)
                    if (resp.code == 429) {
                        val delay = retryDelayMs(resp.header("Retry-After"))
                        if (delay == null) {
                            // a 429 that carries its own error (a ticket whose slots are all taken) keeps it
                            if (text.isNotBlank()) {
                                val carried = parseError(resp.code, text)
                                if (carried.code != "ERROR" && carried.code != "429") throw carried
                            }
                            // 2.7.0: a typed transport failure. Uploads say TOO_MANY_REQUESTS, as skapi-js uploads do.
                            throw skErr("Too many requests", if (uploadName != null) "TOO_MANY_REQUESTS" else "RATE_LIMITED")
                        }
                        if (attempt >= RATE_LIMIT_MAX_RETRIES) {
                            throw skErr("Too many requests: \"${url.substringBefore('?')}\" still answered 429 after $RATE_LIMIT_MAX_RETRIES retries.", "TOO_MANY_REQUESTS")
                        }
                        val pause = rateLimitWaitMs(delay, attempt).toLong()
                        // the caller's deadline and abort cut the wait short
                        if (control != null) control.pause(pause) else Thread.sleep(pause)
                        attempt++
                        return@use
                    }
                    throw parseError(resp.code, text, serverFault = uploadName == null)
                }
            } catch (e: IOException) {
                // The caller gave up: that, not the cancelled call, is the error.
                if (control != null) {
                    if (control.signal?.aborted == true) throw skErr("Aborted", "ABORTED", e)
                    val left = control.remainingMs()
                    if (left != null && left <= 0) throw control.timeoutError()
                }
                throw transportFailure(e, uploadName)
            } finally {
                unhook()
            }
        }
    }

    private fun transportFailure(e: IOException, uploadName: String?): SkapiException {
        if (e is SocketTimeoutException) {
            if (uploadName != null) {
                return skErr("Upload timeout: \"$uploadName\" stalled (nothing sent for $timeoutSeconds seconds, " +
                    "or no answer ${timeoutSeconds * UPLOAD_SENT_WAIT_FACTOR} seconds after it was sent).", "TIMEOUT", e)
            }
            // Nothing moved for timeoutSeconds (OkHttp's read/write timeouts are idle limits): TIMEOUT,
            // as skapi-js 2.4.4 does ("No response for 60 seconds.").
            return skErr("No response for $timeoutSeconds seconds.", "TIMEOUT", e)
        }
        return skErr("Network error", "NETWORK_ERROR", e)
    }

    /** A plain GET with no extra headers: for pre-signed links, whose signature covers the headers. */
    fun fetchPlain(url: String): ByteArray {
        try {
            client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
                val content = resp.body?.bytes() ?: ByteArray(0)
                if (resp.isSuccessful) return content
                val text = String(content, Charsets.UTF_8)
                val code = Regex("<Code>(.*?)</Code>").find(text)
                val message = Regex("<Message>(.*?)</Message>").find(text)
                if (code != null || message != null) {
                    throw skErr(message?.groupValues?.get(1) ?: text.take(300), code?.groupValues?.get(1) ?: "ERROR")
                }
                throw parseError(resp.code, text)
            }
        } catch (e: SocketTimeoutException) {
            throw skErr("No response for $timeoutSeconds seconds.", "TIMEOUT", e)
        } catch (e: IOException) {
            throw skErr("Network error", "NETWORK_ERROR", e)
        } catch (e: IllegalArgumentException) {
            throw perr("\"$url\" is not a valid url.")
        }
    }

    /** multipart/form-data POST to a signed upload URL: every field in order, then the file. */
    fun upload(url: String, fields: Map<String, Any?>, filename: String, content: ByteArray, contentType: String?): Any? {
        val boundary = "----skapi" + md5Hex(Math.random().toString())
        val out = java.io.ByteArrayOutputStream(content.size + 1024)
        for ((k, v) in fields) {
            out.write(utf8("--$boundary\r\nContent-Disposition: form-data; name=\"$k\"\r\n\r\n${if (v is String) v else jsJson(v)}\r\n"))
        }
        val safeName = filename.replace("\"", "%22").replace("\r", "").replace("\n", "")
        out.write(utf8("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"$safeName\"\r\n" +
            "Content-Type: ${contentType ?: "application/octet-stream"}\r\n\r\n"))
        out.write(content)
        out.write(utf8("\r\n--$boundary--\r\n"))
        return send(url, "POST", mapOf("Content-Type" to "multipart/form-data; boundary=$boundary"), out.toByteArray(),
            uploadName = filename)
    }
}
