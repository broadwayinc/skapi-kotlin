package com.skapi

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

/*
 * Request status push (skapi-js 2.5.0 / 2.7.0, src/methods/request_status.ts): the server tells
 * this client when one of its forwarded requests changes status, so polls can run slowly and
 * read at once when something happened.
 *
 * A request dispatched with "notify": true is stamped server side with the caller's user. From then
 * on every status change of it (pending, running, resolved, failed, cancelled) arrives on that
 * user's realtime connections as one private frame:
 *
 *     {"#private": {"v": 1, "ev": [{ id, q, s, p, t, att }, ...]}, "#code": "CSR_STATUS"}
 *
 * The frame is a HINT and never an outcome. A poll that a frame names reads the row at once, and
 * the row is what settles it. So a frame that is lost, late, duplicated or forged costs at most
 * one read or one slow interval, never a wrong answer. A frame sent by a user carries "#user_id",
 * so a frame without one can only have come from the server; such frames never reach the app's
 * own realtime callback (they arrive on every connection of the user, whether or not this client
 * asked for them).
 *
 * The connection: frames ride on this Skapi object's realtime connection. One is opened only when
 * none exists and a user is signed in, and only a connection opened here is ever closed by this
 * module, once nobody holds it, the app has not taken it over, and no group is joined on it.
 */

/** While frames are arriving, a poll of a `notify` request reads the row only this often on its own. */
internal const val STATUS_PUSH_IDLE_POLL_MS = 60_000L

/** How long a connection this module opened stays open after the last holder let go. */
private const val STATUS_PUSH_LINGER_MS = 10 * 60_000L

/** How soon to look again for a connection after the one in use went away. */
private const val STATUS_PUSH_REATTACH_MS = 3_000L

/** "stamp:entropy" from any form of a request id (a full id ends with it). */
internal fun shortRequestId(id: String): String {
    val parts = id.split(":")
    return if (parts.size >= 2) parts[parts.size - 2] + ":" + parts[parts.size - 1] else id
}

/** True for a frame that is a server status push (and so not the app's business). */
internal fun isStatusPushFrame(data: JMap): Boolean =
    data["#code"] == "CSR_STATUS" && truthy(data["#private"]) && !truthy(data["#user_id"])

/**
 * A sleep that a status frame (or anything else) can cut short. Thread interrupts still end it
 * with InterruptedException, so cancelling the caller still ends a poll.
 */
internal class Wakeup {
    private val lock = java.util.concurrent.locks.ReentrantLock()
    private val signal = lock.newCondition()
    private var woken = false

    fun wake() {
        lock.lock()
        try {
            woken = true
            signal.signalAll()
        } finally {
            lock.unlock()
        }
    }

    /** Sleeps up to `ms`. True when woken (the wake is used up). */
    fun sleep(ms: Long): Boolean {
        var left = Math.max(0L, ms) * 1_000_000
        lock.lockInterruptibly()
        try {
            while (!woken && left > 0) left = signal.awaitNanos(left)
            val w = woken
            woken = false
            return w
        } finally {
            lock.unlock()
        }
    }
}

private class StatusListener(val callback: (JMap) -> Unit)

internal class StatusPush(private val core: Core) {
    private val lock = Any()
    private var holders = 0
    /** The server accepted `notify` at least once: frames can exist for this client. */
    @Volatile private var acked = false
    /** The connection whose open socket frames ride on. */
    @Volatile private var live: Realtime? = null
    /** A frame arrived on the current socket since it opened. */
    @Volatile private var frameSeen = false
    /** The connection this module opened, and so may close. */
    private var opened: Realtime? = null
    private var attaching = false
    private var retryTimer: ScheduledFuture<*>? = null
    private var lingerTimer: ScheduledFuture<*>? = null
    private val wakers = ConcurrentHashMap<String, CopyOnWriteArrayList<() -> Unit>>()
    private val listeners = CopyOnWriteArrayList<StatusListener>()

    /** The server acknowledged `notify` on a dispatch. */
    fun ack() {
        acked = true
    }

    /**
     * True while status frames are known to be arriving: the server accepted `notify`, the
     * connection is open, and a frame came in on its current socket. Only then may a poll slow
     * down; a missing push path never costs anyone speed.
     */
    fun warm(): Boolean = acked && frameSeen && live?.socketOpen() == true

    /** Runs `wake` whenever a frame names this request. Returns the unregister. */
    fun addWaker(id: String, wake: () -> Unit): () -> Unit {
        val key = shortRequestId(id)
        val set = wakers.computeIfAbsent(key) { CopyOnWriteArrayList() }
        set.add(wake)
        return {
            wakers.computeIfPresent(key) { _, s ->
                s.remove(wake)
                if (s.isEmpty()) null else s
            }
        }
    }

    /** Keeps the listener attached. Returns the matching release (safe to call more than once). */
    fun hold(): () -> Unit {
        synchronized(lock) {
            holders += 1
            lingerTimer?.cancel(false)
            lingerTimer = null
        }
        attach()
        var done = false
        return {
            var last = false
            synchronized(lock) {
                if (!done) {
                    done = true
                    holders = Math.max(0, holders - 1)
                    if (holders == 0) {
                        last = true
                        retryTimer?.cancel(false)
                        retryTimer = null
                        lingerTimer?.cancel(false)
                    }
                }
            }
            if (last) {
                synchronized(lock) {
                    lingerTimer = schedule(STATUS_PUSH_LINGER_MS) {
                        var idle: Boolean
                        synchronized(lock) {
                            lingerTimer = null
                            idle = holders == 0
                        }
                        if (idle) release()
                    }
                }
            }
        }
    }

    /** onRequestStatus: listen to every status event. Returns the remover. */
    fun listen(callback: (JMap) -> Unit): () -> Unit {
        val entry = StatusListener(callback)
        listeners.add(entry)
        val unhold = hold()
        if (live?.socketOpen() == true) {
            // Already listening: this subscriber starts from a live connection too.
            schedule(0) { if (entry in listeners) call(entry, jmap("type" to "connected")) }
        }
        return {
            if (listeners.remove(entry)) unhold()
        }
    }

    // ---- hooks from Realtime ------------------------------------------------------------------

    /** A socket of `r` opened (the first one, a reconnect, the planned renewal). */
    fun socketUp(r: Realtime) {
        live = r
        frameSeen = false
        emit(jmap("type" to "connected"))
    }

    /** The socket of `r` went away. */
    fun socketDown(r: Realtime) {
        if (live !== r) return
        live = null
        frameSeen = false
        emit(jmap("type" to "disconnected"))
        scheduleAttach()
    }

    /** A CSR_STATUS frame read off `r`'s socket. */
    fun onFrame(r: Realtime, data: JMap) {
        var body = data["#private"]
        if (body is String) body = parseJsonOrNull(body).getOrNull()
        val list = body.asMap()?.get("ev").asList() ?: return
        if (r === live) frameSeen = true
        for (eAny in list) {
            val e = eAny.asMap() ?: continue
            val id = e["id"] as? String ?: continue
            val status = e["s"] as? String ?: continue
            val event = jmap("type" to "status", "id" to id)
            (e["q"] as? String)?.let { event["queue"] = it }
            event["status"] = status
            (e["p"] as? String)?.let { event["previous"] = it }
            (e["t"] as? Number)?.let { event["updated"] = it }
            (e["att"] as? Number)?.let { event["executed"] = it }
            wakers[id]?.forEach { wake ->
                try { wake() } catch (err: Exception) { Logger.getLogger("skapi").warning("request status waker threw $err") }
            }
            emit(event)
        }
    }

    /** The app called connectRealtime: the connection is the app's from now on. */
    fun adoptedByApp(r: Realtime) {
        synchronized(lock) {
            if (opened === r) opened = null
        }
    }

    /** Skapi.close(): timers off. */
    fun shutdown() {
        synchronized(lock) {
            retryTimer?.cancel(false)
            retryTimer = null
            lingerTimer?.cancel(false)
            lingerTimer = null
            opened = null
        }
    }

    // ---- attaching ----------------------------------------------------------------------------

    private fun attach() {
        synchronized(lock) {
            if (holders == 0 || attaching) return
            val r = core.rt
            if (r != null && !r.closing) {
                // The connection exists (and reconnects on its own): its next socket calls socketUp.
                if (r.socketOpen() && live == null) live = r
                return
            }
            // Nobody has a connection. Opening one needs a session.
            if (core.session == null || core.user == null) return
            attaching = true
        }
        Thread({
            var failed = false
            try {
                val r = core.openRealtimeForStatusPush()
                if (r != null) synchronized(lock) { opened = r }
            } catch (e: Exception) {
                // Silent: the push is an accelerator, and polls run at their own speed without it.
                failed = true
            } finally {
                synchronized(lock) { attaching = false }
            }
            if (failed) scheduleAttach()
        }, "skapi-request-status").also { it.isDaemon = true }.start()
    }

    private fun scheduleAttach() {
        synchronized(lock) {
            if (holders == 0 || retryTimer != null) return
            retryTimer = schedule(STATUS_PUSH_REATTACH_MS) {
                synchronized(lock) { retryTimer = null }
                attach()
            }
        }
    }

    private fun release() {
        val r: Realtime?
        synchronized(lock) {
            r = opened
            opened = null
        }
        // Ours, still the live connection, not taken over by the app, and no group joined on it.
        if (r != null && core.rt === r && r.ownedByStatusPush && r.room == null) {
            try { core.closeRealtime() } catch (e: Exception) { }
        }
    }

    private fun schedule(ms: Long, block: () -> Unit): ScheduledFuture<*>? = try {
        core.scheduler.schedule(Runnable {
            try { block() } catch (e: Exception) { Logger.getLogger("skapi").warning("request status: $e") }
        }, ms, TimeUnit.MILLISECONDS)
    } catch (e: java.util.concurrent.RejectedExecutionException) {
        null // the Skapi object was closed
    }

    private fun emit(event: JMap) {
        for (l in listeners) call(l, event)
    }

    private fun call(l: StatusListener, event: JMap) {
        try {
            l.callback(LinkedHashMap(event))
        } catch (e: Exception) {
            // a listener that throws must not cost the others their event
            Logger.getLogger("skapi").warning("onRequestStatus callback threw $e")
        }
    }
}

/** onRequestStatus, see Skapi.onRequestStatus. */
internal fun Core.onRequestStatus(callback: (JMap) -> Unit): () -> Unit = statusPush.listen(callback)

/** True while request status frames are arriving on this client. */
internal fun Core.isRequestStatusLive(): Boolean = statusPush.warm()
