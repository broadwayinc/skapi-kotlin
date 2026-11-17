package com.skapi

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.TreeMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import java.util.logging.Logger

/*
 * Realtime messaging over a WebSocket, ported from skapi-py (_realtime.py), itself a port of
 * skapi-js (src/methods/realtime.ts) without WebRTC: one connection per Skapi object, one group at
 * a time, private messages to users, presence notices, keep-alive, planned renewal before the
 * server's 2 hour cut, and reconnects.
 *
 * The callback runs on a background thread with maps shaped as in skapi-js:
 * {"type", "message", "sender", "sender_cid", "sender_rid", "code"} for messages and notices, and
 * {"type", "message"} for connection events (success, close, error, reconnect).
 */

private const val PING_INTERVAL = 60.0
private const val PONG_TIMEOUT = 10.0
private const val PONGLESS_PINGS_DEAD = 3
private const val CONNECTION_LIFETIME = 7200.0
private const val RENEW_BEFORE = 300.0
private const val RENEW_JITTER = 120.0
private const val JOIN_WAIT = 3.0
private const val SEND_WINDOW_MS = 100L
private const val SEQ_WAIT_MS = 1500L
private const val OPEN_TIMEOUT_SECONDS = 30L
private const val MAX_FRAME_BYTES = 32768
private const val BATCH_CHARS = MAX_FRAME_BYTES - 2048
private const val MAX_NOTIFICATION_BYTES = 3072
private val RT_UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
private val PRESENCE: Map<String, List<Pair<String, String>>> = mapOf(
    "j" to listOf("has joined the message group." to "USER_JOINED"),
    "l" to listOf("has left the message group." to "USER_LEFT"),
    "d" to listOf("has been disconnected." to "USER_DISCONNECTED", "has left the message group." to "USER_LEFT"),
)

private fun now(): Double = System.currentTimeMillis() / 1000.0

/** One WebSocket and what is known about it. */
internal class RtSocket {
    lateinit var ws: WebSocket
    @Volatile var opened = false
    @Volatile var closed = false
    /** set once the end of this socket (or its drop) has been handled, so it is handled once */
    @Volatile var endHandled = false
    @Volatile var generation = -1
    /** counted down once the socket is set up: frames read before that wait for it */
    val readyLatch = CountDownLatch(1)
    val openLatch = CountDownLatch(1)
    @Volatile var nextPing = 0.0
    @Volatile var pinger: ScheduledFuture<*>? = null

    fun send(text: String): Boolean = !closed && ws.send(text)
}

internal class JoinWait(val group: String, val until: Double) {
    val event = CountDownLatch(1)
}

private class OrderState(var next: Long) {
    val waiting = TreeMap<Long, JMap>()
    var timer: ScheduledFuture<*>? = null
}

private class SendWindow(val group: String, val items: MutableList<Any?>, val base: JMap) {
    var timer: ScheduledFuture<*>? = null
}

/** The live state of one Skapi object's realtime connection. */
internal class Realtime(val core: Core, @Volatile var callback: (JMap) -> Unit) {
    @Volatile var ws: RtSocket? = null
    val lock = Any()
    private val openLock = ReentrantLock()
    @Volatile var closing = false
    @Volatile var room: String? = null
    @Volatile var reconnectAttempts = 0
    private var seq = 0L
    private val order = HashMap<String, OrderState>()
    @Volatile var joinWait: JoinWait? = null
    @Volatile var pongSeen = false
    @Volatile var ponglessPings = 0
    @Volatile var pongDeadline: Double? = null
    @Volatile var pingSentAt = 0.0
    @Volatile var renewAt = 0.0
    @Volatile var generation = 0
    private val lastSend = HashMap<String, Double>()
    private var window: SendWindow? = null
    private val sendLock = Any()

    private val wsClient: OkHttpClient = core.requester.client.newBuilder().readTimeout(0, TimeUnit.SECONDS).build()

    // ---- events to the user's callback -----------------------------------------------------------

    fun emit(msg: JMap) {
        try {
            callback(msg)
        } catch (e: Exception) {
            Logger.getLogger("skapi").warning("realtime callback threw $e")
        }
    }

    // ---- connection -------------------------------------------------------------------------------

    /**
     * Opens a socket (fresh token first) and starts reading it and its keep-alive.
     * expected: a reconnect's generation; when another open got in first, this one stands down.
     */
    fun open(renew: Boolean = false, expected: Int? = null) {
        openLock.lock()
        try {
            if (expected != null && (expected != generation || closing)) return
            val token = core.accessToken()
            val (_, record) = core.requester.endpoints()
            val base = record["websocket_private"] as? String ?: throw skErr("WebSocket closed before it opened.", "INVALID_REQUEST")
            val sock = RtSocket()
            try {
                sock.ws = wsClient.newWebSocket(Request.Builder().url("$base?token=$token").build(), listener(sock))
            } catch (e: IllegalArgumentException) {
                throw skErr("WebSocket closed before it opened.", "INVALID_REQUEST", e)
            }
            val ok = sock.openLatch.await(OPEN_TIMEOUT_SECONDS, TimeUnit.SECONDS) && sock.opened && !sock.closed
            if (!ok) {
                sock.endHandled = true
                sock.closed = true
                sock.ws.cancel()
                sock.readyLatch.countDown()
                throw skErr("WebSocket closed before it opened.", "INVALID_REQUEST")
            }
            val old: RtSocket?
            synchronized(lock) {
                if (closing || (expected != null && expected != generation)) {
                    sock.endHandled = true
                    sock.closed = true
                    sock.ws.close(1000, null)
                    sock.readyLatch.countDown()
                    return
                }
                old = ws
                ws = sock
                generation += 1
                sock.generation = generation
                pongSeen = false
                ponglessPings = 0
                pongDeadline = null
                reconnectAttempts = 0
                renewAt = now() + CONNECTION_LIFETIME - RENEW_BEFORE - Math.random() * RENEW_JITTER
            }
            if (!renew) emit(jmap("type" to "success", "message" to "Connected to WebSocket server."))
            forgetOrder()
            val r = room
            if (r != null) {
                try {
                    sendRaw(jmap("action" to "joinRoom", "rid" to r, "token" to (core.session?.accessToken?.jwtToken ?: token), "ver" to 2L))
                } catch (e: SkapiException) {
                    // the read below sees the socket close and reconnects
                }
            }
            sock.readyLatch.countDown()
            startPinging(sock, sock.generation)
            if (renew && old != null) {
                old.endHandled = true
                old.closed = true
                try { old.ws.close(1000, null) } catch (e: Exception) { }
            }
        } finally {
            openLock.unlock()
        }
    }

    private fun listener(sock: RtSocket) = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            sock.opened = true
            sock.openLatch.countDown()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            try { sock.readyLatch.await(OPEN_TIMEOUT_SECONDS, TimeUnit.SECONDS) } catch (e: InterruptedException) { return }
            if (sock.generation < 0) return
            pongDeadline = null
            val data = parseJsonOrNull(text).getOrNull().asMap() ?: return
            try {
                readFrame(data)
            } catch (e: Exception) {
                Logger.getLogger("skapi").warning("realtime frame not read: $e")
            }
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            sock.closed = true
            try { webSocket.close(code, null) } catch (e: Exception) { }
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            sock.closed = true
            sock.openLatch.countDown()
            socketEnded(sock)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            sock.closed = true
            sock.openLatch.countDown()
            socketEnded(sock)
        }
    }

    /** The socket closed (or failed): an unexpected close reconnects, a close by intention says so once. */
    private fun socketEnded(sock: RtSocket) {
        try { sock.readyLatch.await(OPEN_TIMEOUT_SECONDS, TimeUnit.SECONDS) } catch (e: InterruptedException) { }
        sock.pinger?.cancel(false)
        synchronized(sock) {
            if (sock.endHandled) return
            sock.endHandled = true
        }
        val gen = sock.generation
        if (gen < 0) return
        if (current(gen)) {
            emit(jmap("type" to "error", "message" to "Skapi: WebSocket unexpected close."))
            scheduleReconnect(gen)
        } else if (closing && gen == generation) {
            emit(jmap("type" to "close", "message" to "WebSocket connection closed."))
        }
    }

    fun sendRaw(frame: JMap) {
        val sock = ws
        if (sock == null || sock.closed) {
            throw skErr("Realtime connection is not open. Try reconnecting with connectRealtime().", "INVALID_REQUEST")
        }
        if (!sock.send(jsJson(frame))) {
            throw skErr("Realtime connection is not open. Try reconnecting with connectRealtime().", "INVALID_REQUEST")
        }
    }

    fun current(gen: Int): Boolean = gen == generation && !closing

    private fun startPinging(sock: RtSocket, gen: Int) {
        sock.nextPing = now()
        sock.pinger = core.scheduler.scheduleWithFixedDelay(Runnable {
            try {
                if (!pingTick(sock, gen)) sock.pinger?.cancel(false)
            } catch (e: Exception) {
                Logger.getLogger("skapi").warning("realtime keep-alive: $e")
            }
        }, 0, 500, TimeUnit.MILLISECONDS)
    }

    /** One step of the keep-alive. False when this socket's keep-alive is over. */
    private fun pingTick(sock: RtSocket, gen: Int): Boolean {
        if (!current(gen) || sock.closed) return false
        val t = now()
        val deadline = pongDeadline
        if (deadline != null && t >= deadline) {
            if (t - pingSentAt > 30) {
                pongDeadline = null // this timer ran late: ping again instead
                sock.nextPing = t
            } else {
                drop(sock, gen)
                return false
            }
        }
        if (t >= renewAt) {
            renewAt = Double.POSITIVE_INFINITY
            Thread({ renew(gen) }, "skapi-realtime-renew").also { it.isDaemon = true }.start()
        }
        if (t >= sock.nextPing) {
            if (pongSeen) {
                ponglessPings += 1
                if (ponglessPings >= PONGLESS_PINGS_DEAD) {
                    drop(sock, gen)
                    return false
                }
                if (pongDeadline == null) {
                    pingSentAt = t
                    pongDeadline = t + PONG_TIMEOUT
                }
            }
            if (!sock.send("{\"action\":\"keepAlive\"}")) return false
            sock.nextPing = t + PING_INTERVAL
        }
        return true
    }

    private fun renew(gen: Int) {
        if (!current(gen)) return
        try {
            open(renew = true, expected = gen)
        } catch (e: SkapiException) {
            // the old socket stays
        } catch (e: Exception) {
        }
    }

    private fun drop(sock: RtSocket, gen: Int) {
        if (!current(gen)) return
        synchronized(sock) {
            if (sock.endHandled) return
            sock.endHandled = true
        }
        sock.closed = true
        try { sock.ws.cancel() } catch (e: Exception) { }
        emit(jmap("type" to "error", "message" to "Skapi: WebSocket unexpected close."))
        scheduleReconnect(gen)
    }

    fun scheduleReconnect(gen: Int) {
        val run = Runnable {
            while (current(gen)) {
                if (!core.signedIn()) {
                    emit(jmap("type" to "error", "message" to "Skapi: Realtime connection closed. User login is required."))
                    return@Runnable
                }
                reconnectAttempts += 1
                val attempts = reconnectAttempts
                val base = Math.min(30.0, 3.0 * Math.pow(2.0, (attempts - 1).toDouble()))
                emit(jmap("type" to "reconnect", "message" to "Reconnecting to WebSocket server...$attempts"))
                try {
                    Thread.sleep((base * (1 + Math.random() * 0.5) * 1000).toLong())
                } catch (e: InterruptedException) {
                    return@Runnable
                }
                if (!current(gen)) return@Runnable
                try {
                    if (core.user?.get("anonymous") == true) {
                        if (core.verifyAnonymousSession() == null) continue
                    }
                    open(expected = gen)
                    return@Runnable
                } catch (e: SkapiException) {
                    continue
                } catch (e: Exception) {
                    continue
                }
            }
        }
        Thread(run, "skapi-realtime-reconnect").also { it.isDaemon = true }.start()
    }

    /**
     * The app came back to the foreground, or the network came back (as skapi-js does on
     * visibilitychange and online): a socket that looks open may have died meanwhile, so it is
     * pinged now; a closed one is reopened now rather than at the end of the reconnect wait. A
     * failure keeps the reconnect schedule as it was.
     */
    fun wake() {
        if (closing) return
        val sock = ws
        if (sock != null && !sock.closed) {
            sock.nextPing = 0.0
            return
        }
        val gen = generation
        Thread({
            if (!current(gen) || !openLock.tryLock()) return@Thread
            try {
                if (!current(gen)) return@Thread
                val s = ws
                if (s != null && !s.closed) return@Thread
                if (!core.signedIn()) return@Thread
                if (core.user?.get("anonymous") == true && core.verifyAnonymousSession() == null) return@Thread
                open(expected = gen)
            } catch (e: Exception) {
                // the reconnect schedule goes on
            } finally {
                if (openLock.isHeldByCurrentThread) openLock.unlock()
            }
        }, "skapi-realtime-wake").also { it.isDaemon = true }.start()
    }

    // ---- incoming frames -------------------------------------------------------------------------

    fun readFrame(data: JMap) {
        if (data.containsKey("#pong")) {
            pongSeen = true
            ponglessPings = 0
            return
        }
        val presence = data["#presence"].asList()
        if (presence != null) {
            val rid = data["#srid"]
            for (eventAny in presence) {
                val event = eventAny.asList() ?: continue
                if (event.isEmpty() || event[0] !is String || event[0] !in PRESENCE) continue
                val uid = if (event.size > 1) event[1] else null
                val cid = if (event.size > 2) event[2] else null
                for ((text, code) in PRESENCE.getValue(event[0] as String)) {
                    notice(jmap(
                        "type" to "notice",
                        "message" to "User \"${if (uid is String) uid else jsJson(uid)}\" $text",
                        "sender" to uid.takeIf { truthy(it) },
                        "sender_cid" to (if (truthy(cid)) "cid:${if (cid is String) cid else jsJson(cid)}" else null),
                        "sender_rid" to rid.takeIf { truthy(it) },
                        "code" to code,
                    ))
                }
            }
            return
        }
        val batch = data["#batch"].asList()
        if (batch != null) {
            for (entry in batch) entry.asMap()?.let { readFrame(it) }
            return
        }
        var kind: String? = null
        var payload: Any? = null
        for ((key, name) in listOf("#message" to "message", "#private" to "private", "#notice" to "notice", "#rtc" to "rtc", "#error" to "error", "#ice" to "ice")) {
            if (data.containsKey(key)) {
                kind = name
                payload = data[key]
                break
            }
        }
        if (kind == null || kind == "rtc" || kind == "ice") return
        val scid = data["#scid"]
        val msg = jmap(
            "type" to kind,
            "message" to payload,
            "sender" to data["#user_id"].takeIf { truthy(it) },
            "sender_cid" to (if (truthy(scid)) "cid:${if (scid is String) scid else jsJson(scid)}" else null),
            "sender_rid" to data["#srid"].takeIf { truthy(it) },
            "code" to data["#code"].takeIf { truthy(it) },
        )
        val seqValue = data["#seq"]
        if (kind == "notice") {
            notice(msg)
        } else if (kind == "message" && seqValue is Number && truthy(msg["sender_cid"])) {
            inOrder(msg, seqValue.toLong())
        } else {
            deliver(msg)
        }
    }

    fun deliver(msg: JMap) {
        val body = msg["message"].asMap()
        val items = body?.get("__skapi_batch").asList()
        if (body != null && items != null) {
            for (item in items) {
                val m = LinkedHashMap(msg)
                m["message"] = item
                emit(m)
            }
        } else {
            emit(msg)
        }
    }

    private fun notice(msg: JMap) {
        val cid = msg["sender_cid"] as? String
        if ((msg["code"] == "USER_LEFT" || msg["code"] == "USER_DISCONNECTED") && cid != null) forgetOrder(cid)
        val wait = joinWait
        if (wait != null && msg["code"] == "USER_JOINED" && msg["sender_rid"] == wait.group && msg["sender"] == core.user?.get("user_id")) {
            wait.event.countDown()
        }
        emit(msg)
    }

    // in-order delivery of a sender's numbered group messages (the fan-out can reorder them)
    private fun inOrder(msg: JMap, s: Long) {
        val ready: List<JMap>
        synchronized(lock) {
            val cid = msg["sender_cid"] as String
            val state = order.getOrPut(cid) { OrderState(s) }
            if (s < state.next) {
                ready = listOf(msg)
            } else {
                state.waiting[s] = msg
                ready = drain(state)
                if (state.waiting.isNotEmpty() && state.timer == null) {
                    state.timer = core.scheduler.schedule(Runnable { skipGap(cid) }, SEQ_WAIT_MS, TimeUnit.MILLISECONDS)
                }
            }
        }
        for (m in ready) deliver(m)
    }

    private fun drain(state: OrderState): List<JMap> {
        val out = mutableListOf<JMap>()
        while (state.waiting.containsKey(state.next)) {
            out.add(state.waiting.remove(state.next)!!)
            state.next += 1
        }
        return out
    }

    private fun skipGap(cid: String) {
        val ready: List<JMap>
        synchronized(lock) {
            val state = order[cid] ?: return
            state.timer = null
            if (state.waiting.isNotEmpty()) state.next = state.waiting.firstKey()
            ready = drain(state)
            if (state.waiting.isNotEmpty()) {
                state.timer = core.scheduler.schedule(Runnable { skipGap(cid) }, SEQ_WAIT_MS, TimeUnit.MILLISECONDS)
            }
        }
        for (m in ready) deliver(m)
    }

    fun forgetOrder(cid: String? = null) {
        val ready = mutableListOf<JMap>()
        synchronized(lock) {
            val cids = if (cid != null) listOf(cid) else order.keys.toList()
            for (c in cids) {
                val state = order.remove(c) ?: continue
                state.timer?.cancel(false)
                ready.addAll(state.waiting.values)
            }
        }
        for (m in ready) deliver(m)
    }

    // ---- outgoing group posts: posts within 100 ms travel as one frame, so they arrive in order

    fun queueGroupPost(group: String, content: Any?, frameBase: JMap) {
        synchronized(sendLock) {
            val w = window
            if (w != null && w.group != group) flushLocked()
            val w2 = window
            if (w2 != null) {
                w2.items.add(content)
                return
            }
            val t = now()
            val since = t - (lastSend[group] ?: 0.0)
            lastSend[group] = t
            if (since >= SEND_WINDOW_MS / 1000.0) {
                sendGroup(frameBase, content)
                return
            }
            val nw = SendWindow(group, mutableListOf(content), frameBase)
            window = nw
            nw.timer = core.scheduler.schedule(Runnable { flush() }, SEND_WINDOW_MS, TimeUnit.MILLISECONDS)
        }
    }

    fun flush() {
        synchronized(sendLock) { flushLocked() }
    }

    private fun flushLocked() {
        val w = window ?: return
        window = null
        w.timer?.cancel(false)
        lastSend[w.group] = now()
        var items: List<Any?> = w.items
        while (items.isNotEmpty()) {
            var n = items.size
            // JavaScript string length (UTF-16 code units), which a Kotlin String's length is
            while (n > 1 && jsJson(jmap("__skapi_batch" to items.subList(0, n))).length > BATCH_CHARS) {
                n = (n + 1) / 2
            }
            sendGroup(w.base, if (n == 1) items[0] else jmap("__skapi_batch" to items.subList(0, n).toMutableList()))
            items = items.subList(n, items.size)
        }
    }

    fun sendGroup(base: JMap, content: Any?) {
        val s: Long
        synchronized(lock) {
            s = seq
            seq += 1
        }
        val frame = LinkedHashMap(base)
        frame["content"] = content
        frame["seq"] = s
        try {
            sendRaw(frame)
        } catch (e: Exception) {
            // not open at send time: dropped, as in skapi-js
        }
    }

    fun close() {
        closing = true
        synchronized(sendLock) {
            window?.timer?.cancel(false)
            window = null
        }
        val sock = ws
        joinWait?.event?.countDown()
        room = null
        if (sock != null) {
            sock.pinger?.cancel(false)
            if (!sock.closed) {
                sock.closed = true
                try { sock.ws.close(1000, null) } catch (e: Exception) { }
            }
        }
        forgetOrder()
    }
}

// ---- methods ----------------------------------------------------------------------------------------

/**
 * Opens the realtime connection. callback(event) runs on a background thread for every message,
 * notice and connection event. Returns once connected; reconnects on its own.
 */
internal fun Core.connectRealtime(callback: (JMap) -> Unit) {
    ensureConnection()
    if (!signedIn()) throw skErr("No access.", "INVALID_REQUEST")
    val existing = rt
    if (existing != null && !existing.closing) {
        existing.callback = callback
        return
    }
    val r = Realtime(this, callback)
    rt = r
    try {
        r.open()
    } catch (e: SkapiException) {
        rt = null
        r.emit(jmap("type" to "error", "message" to "Skapi: WebSocket connection failed."))
        throw e
    }
}

/** Closes the realtime connection; the group hears that you disconnected and left. */
internal fun Core.closeRealtime() {
    val r = rt
    rt = null
    r?.close()
}

private fun Core.live(): Realtime {
    val r = rt
    if (r == null || r.closing) throw skErr("No realtime connection. Execute connectRealtime() before this method.", "INVALID_REQUEST")
    return r
}

/** The app is in the foreground again, or the network is back: see Realtime.wake. */
internal fun Core.realtimeWake() {
    val r = rt ?: return
    if (!r.closing) r.wake()
}

/** Joins a message group (one at a time), or leaves the current one with null. */
internal fun Core.joinRealtime(group: String?): JMap {
    val r = live()
    val g = group?.takeIf { it.isNotEmpty() }
    if (g == null && r.room == null) return jmap("type" to "success", "message" to "Left realtime message group.")
    val token = accessToken()
    r.joinWait?.event?.countDown()
    val sock = r.ws
    if (sock != null && !sock.closed) {
        r.sendRaw(jmap("action" to "joinRoom", "rid" to g, "token" to token, "ver" to 2L))
        if (g != null) r.joinWait = JoinWait(g, now() + JOIN_WAIT)
    }
    r.room = g
    return jmap("type" to "success", "message" to if (g != null) "Joined realtime message group: \"$g\"." else "Left realtime message group.")
}

/** Sends to a user (by user ID) or to the group you joined. notification: {title, body, config?: {always}}. */
internal fun Core.postRealtime(message: Any?, recipient: String, notification: JMap?): JMap {
    val r = live()
    if (recipient.isEmpty()) throw skErr("No recipient.", "INVALID_REQUEST")
    freshIdToken()
    var notificationStr = ""
    var config: Any? = LinkedHashMap<String, Any?>()
    if (notification != null) {
        for (key in listOf("title", "body")) {
            if (!notification.containsKey(key)) throw perr("Key \"$key\" is required.")
            if (notification[key] !is String) throw perr("\"$key\" should be type: <string>.")
        }
        config = if (truthy(notification["config"])) notification["config"] else LinkedHashMap<String, Any?>()
        val cm = config.asMap()
        if (cm == null || (cm.containsKey("always") && cm["always"] !is Boolean)) throw perr("\"config.always\" should be type: <boolean>.")
        notificationStr = jsJson(jmap("title" to notification["title"], "body" to notification["body"]))
        if (utf8(notificationStr).size > MAX_NOTIFICATION_BYTES) throw perr("Notification size exceeds 3kb.")
    }
    val sock = r.ws
    if (sock == null || sock.closed) {
        throw skErr("Realtime connection is not open. Try reconnecting with connectRealtime().", "INVALID_REQUEST")
    }
    val token = "IdT:$service:$owner:${session?.idToken?.jwtToken ?: ""}"

    fun checked(frame: JMap): JMap {
        val size = utf8(jsJson(frame)).size
        if (size > MAX_FRAME_BYTES) {
            throw perr("Message is $size bytes; a realtime message can be at most $MAX_FRAME_BYTES bytes including its headers.")
        }
        return frame
    }

    if (RT_UUID.matches(recipient)) {
        r.sendRaw(checked(jmap("action" to "sendMessage", "uid" to recipient, "content" to message, "notification" to notificationStr,
            "notificationConfig" to config, "token" to token)))
        return jmap("type" to "success", "message" to "Message sent.")
    }

    if (recipient != r.room) {
        throw skErr("User has not joined to the recipient group. Run joinRealtime(\"$recipient\")", "INVALID_REQUEST")
    }
    checked(jmap("action" to "broadcast", "rid" to recipient, "content" to message, "notification" to notificationStr,
        "notificationConfig" to config, "token" to token, "#seq" to 0L))
    val wait = r.joinWait
    if (wait != null && wait.group == recipient) {
        // until the server announces your own join, the group would not get the message yet
        val ms = ((wait.until - now()) * 1000).toLong()
        if (ms > 0) wait.event.await(ms, TimeUnit.MILLISECONDS)
        if (r.joinWait === wait) r.joinWait = null
    }
    val base = jmap("action" to "broadcast", "rid" to recipient, "notification" to notificationStr, "notificationConfig" to config, "token" to token)
    if (notification != null) {
        r.sendGroup(base, message) // a post with a notification is never grouped
    } else {
        r.queueGroupPost(recipient, message, base)
    }
    return jmap("type" to "success", "message" to "Message sent.")
}

/** Who is connected in a group (default: the group you joined): [{user_id, cid}]. */
internal fun Core.getRealtimeUsers(params: JMap?, fetchOptions: JMap?): Any? {
    val p = params.copyMap()
    val body = LinkedHashMap<String, Any?>()
    if (p.containsKey("group")) {
        if (p["group"] !is String) throw perr("${jd(p["group"])} is invalid in \"group\". allowed type or value is: Type<string>.")
        body["group"] = p["group"]
    } else {
        val room = rt?.room
        if (room.isNullOrEmpty()) throw perr("No group has been joined. Otherwise \"group\" is required.")
        body["group"] = room
    }
    if (p.containsKey("user_id")) body["user_id"] = validateUserId(p["user_id"], "User ID in \"user_id\"")
    val res = call("get-ws-group", body, auth = true, fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { iAny ->
            val i = iAny.asMap() ?: LinkedHashMap()
            val uid = i["uid"]
            val uidStr = if (uid == null) "" else if (uid is String) uid else jsJson(uid)
            jmap(
                "user_id" to (if ('#' in uidStr) uidStr.split("#")[1] else uid),
                "cid" to "cid:${i["cid"].let { if (it is String) it else if (it == null) "None" else jsJson(it) }}",
            )
        }.toMutableList()
    }
    return res
}

/** Groups that have members now: [{group, number_of_users}]. */
internal fun Core.getRealtimeGroups(params: JMap?, fetchOptions: JMap?): Any? {
    ensureConnection()
    val p = if (params.isNullOrEmpty()) jmap("searchFor" to "group", "value" to " ", "condition" to ">") else params.copyMap()
    val searchFor = if (p.containsKey("searchFor")) p["searchFor"] else "group"
    if (searchFor != "group" && searchFor != "number_of_users") {
        throw perr("${jd(searchFor)} is invalid in \"searchFor\". allowed types or values are: \"group\", \"number_of_users\".")
    }
    val value = if (p.containsKey("value")) p["value"] else if (searchFor == "number_of_users") 0L else " "
    val conditions = listOf(">", ">=", "=", "<", "<=", "!=", "gt", "gte", "eq", "lt", "lte", "ne")
    var condition = p["condition"]
    if (condition != null && condition !in conditions) {
        throw perr("${jd(condition)} is invalid in \"condition\". allowed types or values are: " + conditions.joinToString(", ") { jd(it) } + ".")
    }
    if (condition == null) condition = if (value == " " || !truthy(value)) ">" else "="
    val body = jmap("searchFor" to searchFor, "value" to value)
    if (p["range"] != null) {
        body["range"] = p["range"]
        condition = null
    }
    if (searchFor == "number_of_users" && value !is Number) throw perr("\"value\" must be a number.")
    if (searchFor == "group" && value !is String) throw perr("\"value\" must be a string.")
    if (body.containsKey("range")) {
        val r = body["range"]
        val same = (r is Number && value is Number && r.javaClass == value.javaClass) || (r is String && value is String)
        if (!same) throw perr("\"range\" must be a ${if (value is Number) "number" else "string"}.")
    }
    if (condition != null) body["condition"] = condition
    val res = call("get-ws-group", body, auth = true, fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { iAny ->
            val i = iAny.asMap() ?: LinkedHashMap()
            val rid = i["rid"]
            val ridStr = if (rid == null) "" else if (rid is String) rid else jsJson(rid)
            jmap("group" to (if ('#' in ridStr) ridStr.split("#")[1] else rid), "number_of_users" to i["cnt"])
        }.toMutableList()
    }
    return res
}
