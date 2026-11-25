package com.skapi

import java.util.concurrent.CopyOnWriteArrayList

/**
 * An abort handle for a request, as skapi-js takes an AbortSignal (2.7.0). Pass it as `signal` to
 * forwardRequestStatus, forwardRequestQueueCounters, forwardRequestRead or forwardRequestHistory;
 * abort() then fails that call with code ABORTED and takes it off the network. Usable from any
 * thread, and from Java:
 *
 * ```java
 * SkapiAbortSignal signal = new SkapiAbortSignal();
 * CompletableFuture<Map<String, Object>> read = skapi.forwardRequestRead(params, signal);
 * signal.abort();
 * ```
 *
 * One signal may be passed to several calls; abort() ends all of them. Once aborted it stays
 * aborted: a call given an aborted signal fails at once.
 */
public class SkapiAbortSignal {
    @Volatile private var abortedFlag = false
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    /** True once abort() was called. */
    public val aborted: Boolean get() = abortedFlag

    /** Aborts every call this signal was given. Calling it again does nothing. */
    public fun abort() {
        synchronized(this) {
            if (abortedFlag) return
            abortedFlag = true
        }
        val run = listeners.toList()
        listeners.clear()
        for (fn in run) {
            try { fn() } catch (e: Exception) { }
        }
    }

    /** Runs `fn` on abort (at once when already aborted). Returns the unregister. */
    internal fun onAbort(fn: () -> Unit): () -> Unit {
        synchronized(this) {
            if (!abortedFlag) {
                listeners.add(fn)
                return { listeners.remove(fn) }
            }
        }
        try { fn() } catch (e: Exception) { }
        return {}
    }
}
