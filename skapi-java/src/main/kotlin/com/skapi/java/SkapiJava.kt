package com.skapi.java

import com.skapi.EncryptionOptions
import com.skapi.FetchOptions
import com.skapi.FileUpload
import com.skapi.MemoryStorage
import com.skapi.Skapi
import com.skapi.SkapiException
import com.skapi.SkapiAbortSignal
import com.skapi.SkapiSession
import com.skapi.SkapiStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.future.future
import kotlinx.coroutines.isActive
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.function.BiConsumer
import java.util.function.Consumer

/**
 * Skapi for Java: the same methods as Skapi, each returning a CompletableFuture, with plain Java
 * values instead of kotlinx JSON.
 *
 * ```java
 * SkapiJava skapi = new SkapiJava("<Project ID>");
 * Map<String, Object> posts = skapi.getRecords(SkapiJson.obj("table", "posts")).get();
 * ```
 *
 * Parameters take Map&lt;String, Object&gt;, List&lt;Object&gt;, String, Number, Boolean or null;
 * results come back as Map&lt;String, Object&gt;, List&lt;Object&gt;, String, Long (whole numbers),
 * Double, Boolean or null (see SkapiJson).
 *
 * Every call runs on a background thread (Dispatchers.IO). Cancelling a future stops its request.
 * A failure completes the future exceptionally with the SkapiException the Kotlin call throws:
 * `future.get()` throws ExecutionException whose getCause() is that SkapiException (getCode(),
 * getMessage()). A parameter that is not a JSON value fails the future with code "INVALID_PARAMETER".
 * Callbacks given to `thenAccept` and the like run on the background thread that finished the call
 * (or at once on your thread, when the future was already done).
 *
 * close() cancels the calls still running and closes the wrapped Skapi; later calls return a
 * cancelled future.
 */
public class SkapiJava(
    /** The Skapi this object calls; use it from Kotlin code, or for anything SkapiJava does not cover. */
    public val skapi: Skapi,
) : AutoCloseable {

    /**
     * new SkapiJava("<Project ID>"): one project, its connection, and the signed-in user's session.
     * The settings are those of the Skapi constructor.
     */
    @JvmOverloads
    public constructor(
        projectId: String,
        storage: SkapiStorage = MemoryStorage(),
        timeoutSeconds: Long = 120,
        targetCdn: String? = null,
        encryption: EncryptionOptions? = null,
    ) : this(Skapi(projectId, storage, timeoutSeconds, targetCdn, encryption))

    public companion object {
        /** A SkapiJava over an existing Skapi (for example one your Kotlin code made). */
        @JvmStatic
        public fun wrap(skapi: Skapi): SkapiJava = SkapiJava(skapi)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** One call as a future on the scope; after close() the future is already cancelled. */
    private fun <T> call(block: suspend () -> T): CompletableFuture<T> {
        if (!scope.isActive) return CompletableFuture<T>().also { it.cancel(false) }
        return scope.future { block() }
    }

    /** Java values to JSON inside a call: a value that is not JSON fails the future with INVALID_PARAMETER. */
    private fun <T> converted(block: () -> T): T = try {
        block()
    } catch (e: IllegalArgumentException) {
        throw SkapiException(e.message ?: "A value is not JSON.", "INVALID_PARAMETER", e)
    }

    private fun obj(m: Map<String, *>): JsonObject = converted { SkapiJson.fromJavaMap(m) }

    private fun objOrNull(m: Map<String, *>?): JsonObject? = m?.let { obj(it) }

    private fun el(v: Any?): JsonElement = converted { SkapiJson.fromJava(v) }

    private fun java(v: JsonElement?): Any? = SkapiJson.toJava(v)

    private fun map(v: JsonObject): MutableMap<String, Any?> = SkapiJson.toJavaMap(v)!!

    private fun mapOrNull(v: JsonObject?): MutableMap<String, Any?>? = SkapiJson.toJavaMap(v)

    private fun stream(cb: BiConsumer<String, Int>?): ((String, Int) -> Unit)? = cb?.let { c -> { text: String, seq: Int -> c.accept(text, seq) } }

    // ---- properties -----------------------------------------------------------------------------

    /** The compact Project ID. */
    public val projectId: String get() = skapi.projectId

    /** The project's service id, from the Project ID. */
    public val service: String get() = skapi.service

    /** The project owner's id, from the Project ID. */
    public val owner: String get() = skapi.owner

    /** The version of skapi-kotlin. */
    public val version: String get() = skapi.version

    /** The signed-in user's profile as this object last saw it, or null. Call getProfile() once after the app starts. */
    public val user: MutableMap<String, Any?>? get() = mapOrNull(skapi.user)

    /** The signed-in session's tokens, or null. */
    public val session: SkapiSession? get() = skapi.session

    override fun toString(): String = "SkapiJava(projectId=$projectId)"

    // ---- connection -----------------------------------------------------------------------------

    /** The project's name and settings, and the caller's IP and location as the server sees them. */
    @JvmOverloads
    public fun getConnectionInfo(refresh: Boolean = false): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getConnectionInfo(refresh)) }

    /** Call when the app comes back to the foreground. Returns at once. */
    public fun onForeground(): Unit = skapi.onForeground()

    /** Call when the network comes back. Returns at once. */
    public fun onNetworkAvailable(): Unit = skapi.onNetworkAvailable()

    /**
     * Cancels the calls still running, then closes the wrapped Skapi (realtime connection, timers and
     * network threads), so a JVM program can exit. The object cannot be used after this.
     */
    override fun close() {
        scope.cancel()
        skapi.close()
    }

    // ---- authentication -------------------------------------------------------------------------

    /** Creates an account: params "email" and "password", and any profile fields. Returns a "SUCCESS: ..." String, or the profile with option "login". */
    @JvmOverloads
    public fun signup(params: Map<String, *>, option: Map<String, *>? = null): CompletableFuture<Any?> =
        call { java(skapi.signup(obj(params), objOrNull(option))) }

    public fun resendSignupConfirmation(): CompletableFuture<Any?> = call { java(skapi.resendSignupConfirmation()) }

    /** Signs in with the e-mail (or username) and password. Fails with code "MFA_REQUIRED" when the account has two-step login on. */
    @JvmOverloads
    public fun login(email: String?, password: String, username: String? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.login(email, password, username)) }

    public fun verifyMfa(code: String): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.verifyMfa(code)) }

    @JvmOverloads
    public fun logout(globalLogout: Boolean = false): CompletableFuture<String> = call { skapi.logout(globalLogout) }

    /** The signed-in user's profile, or null. The first call restores a saved sign-in from storage. */
    @JvmOverloads
    public fun getProfile(refreshToken: Boolean = false): CompletableFuture<MutableMap<String, Any?>?> =
        call { mapOrNull(skapi.getProfile(refreshToken)) }

    public fun loginWithToken(idToken: String, accessToken: String, refreshToken: String): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.loginWithToken(idToken, accessToken, refreshToken)) }

    public fun updateProfile(params: Map<String, *>): CompletableFuture<MutableMap<String, Any?>?> =
        call { mapOrNull(skapi.updateProfile(obj(params))) }

    public fun changePassword(currentPassword: String, newPassword: String): CompletableFuture<String> =
        call { skapi.changePassword(currentPassword, newPassword) }

    @JvmOverloads
    public fun forgotPassword(email: String, template: Map<String, *>? = null): CompletableFuture<String> =
        call { skapi.forgotPassword(email, objOrNull(template)) }

    public fun resetPassword(email: String, code: String, newPassword: String): CompletableFuture<String> =
        call { skapi.resetPassword(email, code, newPassword) }

    @JvmOverloads
    public fun verifyEmail(code: String? = null, template: Map<String, *>? = null): CompletableFuture<String> =
        call { skapi.verifyEmail(code, objOrNull(template)) }

    @JvmOverloads
    public fun lastVerifiedEmail(revert: Boolean? = null): CompletableFuture<Any?> = call { java(skapi.lastVerifiedEmail(revert)) }

    public fun disableAccount(): CompletableFuture<Any?> = call { java(skapi.disableAccount()) }

    @JvmOverloads
    public fun recoverAccount(redirect: String? = null): CompletableFuture<String> = call { skapi.recoverAccount(redirect) }

    /** merge: true, or a list of profile field names. */
    @JvmOverloads
    public fun openIdLogin(token: String, id: String, merge: Any? = null, template: Map<String, *>? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.openIdLogin(token, id, merge?.let { el(it) }, objOrNull(template))) }

    public fun anonymousLogin(): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.anonymousLogin()) }

    public fun verifyAnonymousSession(): CompletableFuture<MutableMap<String, Any?>?> = call { mapOrNull(skapi.verifyAnonymousSession()) }

    @JvmOverloads
    public fun setupMfa(issuer: String? = null, accountName: String? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.setupMfa(issuer, accountName)) }

    public fun enableMfa(code: String): CompletableFuture<String> = call { skapi.enableMfa(code) }

    public fun disableMfa(): CompletableFuture<String> = call { skapi.disableMfa() }

    public fun getMfaStatus(): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.getMfaStatus()) }

    // ---- database -------------------------------------------------------------------------------

    /** Creates a record, or updates one when config has "record_id". data: any JSON value (null stores null). */
    @JvmOverloads
    public fun postRecord(data: Any?, config: Map<String, *>, files: List<FileUpload>? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.postRecord(el(data), obj(config), files)) }

    /** Updates a record (config has "record_id") without changing its data. */
    @JvmOverloads
    public fun postRecord(config: Map<String, *>, files: List<FileUpload>? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.postRecord(obj(config), files)) }

    /** items: [{"data": ..., "config": {...}}]. Returns {"list", "failed"}. */
    public fun postRecords(items: List<Map<String, *>>): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.postRecords(items.map { obj(it) })) }

    @JvmOverloads
    public fun getRecords(query: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getRecords(objOrNull(query), fetchOptions)) }

    @JvmOverloads
    public fun deleteRecords(query: Map<String, *>, fetchOptions: FetchOptions? = null): CompletableFuture<Any?> =
        call { java(skapi.deleteRecords(obj(query), fetchOptions)) }

    @JvmOverloads
    public fun getTables(query: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getTables(objOrNull(query), fetchOptions)) }

    @JvmOverloads
    public fun getTags(query: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getTags(objOrNull(query), fetchOptions)) }

    @JvmOverloads
    public fun getIndexes(query: Map<String, *>, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getIndexes(obj(query), fetchOptions)) }

    @JvmOverloads
    public fun getUniqueId(query: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getUniqueId(objOrNull(query), fetchOptions)) }

    /** Returns {"completed", "failed", "errors", "bin_endpoints"}. */
    @JvmOverloads
    public fun uploadFiles(files: List<FileUpload>, recordId: String, service: String? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.uploadFiles(files, recordId, service)) }

    public fun getFile(url: String): CompletableFuture<ByteArray> = call { skapi.getFile(url) }

    public fun getFileText(url: String): CompletableFuture<String> = call { skapi.getFileText(url) }

    @JvmOverloads
    public fun getFileUrl(url: String, expiresSeconds: Long = 0): CompletableFuture<String> = call { skapi.getFileUrl(url, expiresSeconds) }

    public fun getFileInfo(url: String): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.getFileInfo(url)) }

    @JvmOverloads
    public fun downloadFile(url: String, destination: File, expiresSeconds: Long = 0): CompletableFuture<File> =
        call { skapi.downloadFile(url, destination, expiresSeconds) }

    public fun deleteFiles(endpoints: List<String>): CompletableFuture<Any?> = call { java(skapi.deleteFiles(endpoints)) }

    public fun grantPrivateRecordAccess(recordId: String, userIds: List<String>): CompletableFuture<Any?> =
        call { java(skapi.grantPrivateRecordAccess(recordId, userIds)) }

    public fun removePrivateRecordAccess(recordId: String, userIds: List<String>): CompletableFuture<Any?> =
        call { java(skapi.removePrivateRecordAccess(recordId, userIds)) }

    @JvmOverloads
    public fun listPrivateRecordAccess(recordId: String? = null, userIds: List<String>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.listPrivateRecordAccess(recordId, userIds, fetchOptions)) }

    @JvmOverloads
    public fun requestPrivateRecordAccessKey(recordId: String, referenceId: String? = null): CompletableFuture<String> =
        call { skapi.requestPrivateRecordAccessKey(recordId, referenceId) }

    // ---- encryption -----------------------------------------------------------------------------

    public fun getEncryptionStatus(): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.getEncryptionStatus()) }

    public fun unlockEncryption(password: String): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.unlockEncryption(password)) }

    @JvmOverloads
    public fun lockEncryption(forgetDevice: Boolean = false): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.lockEncryption(forgetDevice)) }

    @JvmOverloads
    public fun unlockEncryptionWithRecoveryCode(code: String, password: String? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.unlockEncryptionWithRecoveryCode(code, password)) }

    public fun regenerateEncryptionRecoveryCode(): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.regenerateEncryptionRecoveryCode()) }

    /** Completes with null. */
    public fun pinPeerKey(userId: String, fingerprint: String): CompletableFuture<Void?> =
        call { skapi.pinPeerKey(userId, fingerprint); null }

    /** True for the placeholder put in place of data this session cannot decrypt (withheld = "sentinel"). Throws IllegalArgumentException for a value that is not JSON. */
    public fun isWithheld(value: Any?): Boolean = skapi.isWithheld(if (value == null) null else SkapiJson.fromJava(value))

    // ---- users ----------------------------------------------------------------------------------

    @JvmOverloads
    public fun getUsers(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getUsers(objOrNull(params), fetchOptions)) }

    @JvmOverloads
    public fun subscribe(userId: String, getFeed: Boolean? = null, getNotified: Boolean? = null, getEmail: Boolean? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.subscribe(userId, getFeed, getNotified, getEmail)) }

    public fun unsubscribe(userId: String): CompletableFuture<Any?> = call { java(skapi.unsubscribe(userId)) }

    public fun blockSubscriber(userId: String): CompletableFuture<Any?> = call { java(skapi.blockSubscriber(userId)) }

    public fun unblockSubscriber(userId: String): CompletableFuture<Any?> = call { java(skapi.unblockSubscriber(userId)) }

    @JvmOverloads
    public fun getSubscriptions(subscriber: String? = null, subscription: String? = null, blocked: Boolean? = null,
                                fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getSubscriptions(subscriber, subscription, blocked, fetchOptions)) }

    @JvmOverloads
    public fun getFeed(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getFeed(objOrNull(params), fetchOptions)) }

    public fun subscribeNewsletter(params: Map<String, *>): CompletableFuture<Any?> = call { java(skapi.subscribeNewsletter(obj(params))) }

    /** One group ("public", "authorized", a number or a group name), or every group with null. */
    public fun unsubscribeNewsletter(group: Any?): CompletableFuture<Any?> =
        call { java(skapi.unsubscribeNewsletter(if (group == null) null else el(group))) }

    @JvmOverloads
    public fun getNewsletters(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getNewsletters(objOrNull(params), fetchOptions)) }

    @JvmOverloads
    public fun getNewsletterSubscription(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<Any?> =
        call { java(skapi.getNewsletterSubscription(objOrNull(params), fetchOptions)) }

    public fun sendInquiry(name: String, email: String, subject: String, message: String): CompletableFuture<String> =
        call { skapi.sendInquiry(name, email, subject, message) }

    // ---- realtime -------------------------------------------------------------------------------

    /**
     * Opens the realtime connection. callback gets every message, notice and connection event as a
     * Map {"type", "message", "sender", "sender_cid", "sender_rid", "code"}, on a background thread.
     * Completes with null once connected.
     */
    public fun connectRealtime(callback: Consumer<MutableMap<String, Any?>>): CompletableFuture<Void?> =
        call { skapi.connectRealtime { event -> callback.accept(map(event)) }; null }

    /** Completes with null. */
    public fun closeRealtime(): CompletableFuture<Void?> = call { skapi.closeRealtime(); null }

    /** Joins a message group, or leaves the current one with null. */
    public fun joinRealtime(group: String?): CompletableFuture<MutableMap<String, Any?>> = call { map(skapi.joinRealtime(group)) }

    @JvmOverloads
    public fun postRealtime(message: Any?, recipient: String, notification: Map<String, *>? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.postRealtime(el(message), recipient, objOrNull(notification))) }

    @JvmOverloads
    public fun getRealtimeUsers(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getRealtimeUsers(objOrNull(params), fetchOptions)) }

    @JvmOverloads
    public fun getRealtimeGroups(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getRealtimeGroups(objOrNull(params), fetchOptions)) }

    /**
     * Listens to status changes of this user's forwarded requests dispatched with "notify": true (see
     * Skapi.onRequestStatus). callback gets {"type": "status", "id", "queue", "status", "previous",
     * "updated", "executed"}, {"type": "connected"} and {"type": "disconnected"}, on a background
     * thread. Returns a Runnable that removes the listener.
     */
    public fun onRequestStatus(callback: Consumer<MutableMap<String, Any?>>): Runnable {
        val remove = skapi.onRequestStatus { event -> callback.accept(map(event)) }
        return Runnable { remove() }
    }

    /** True while request status frames are arriving on this client. */
    public fun isRequestStatusLive(): Boolean = skapi.isRequestStatusLive()

    // ---- API bridge -----------------------------------------------------------------------------

    /**
     * Calls another API through Skapi. form values: plain Java values, byte[] or FileUpload (also in a
     * List). onStream(text, seq) receives streamed text as it arrives, on a background thread.
     */
    @JvmOverloads
    public fun forwardRequest(options: Map<String, *>, form: Map<String, *>? = null, onStream: BiConsumer<String, Int>? = null): CompletableFuture<Any?> =
        call { java(skapi.forwardRequest(obj(options), form?.let { formValues(it) }, stream(onStream))) }

    @JvmOverloads
    public fun forwardRequestPoll(requestId: String, pollMillis: Long = 1000, url: String? = null, method: String? = null,
                                  onStream: BiConsumer<String, Int>? = null, service: String? = null, owner: String? = null,
                                  notify: Boolean = false): CompletableFuture<Any?> =
        call { java(skapi.forwardRequestPoll(requestId, pollMillis, url, method, stream(onStream), service, owner, notify)) }

    @JvmOverloads
    public fun forwardRequestStream(requestId: String, options: Map<String, *>? = null, onStream: BiConsumer<String, Int>? = null): CompletableFuture<Any?> =
        call { java(skapi.forwardRequestStream(requestId, objOrNull(options), stream(onStream))) }

    @JvmOverloads
    public fun forwardRequestFinalize(requestId: String, data: Any? = null, options: Map<String, *>? = null): CompletableFuture<Any?> =
        call { java(skapi.forwardRequestFinalize(requestId, if (data == null) null else el(data), objOrNull(options))) }

    @JvmOverloads
    public fun forwardRequestHistory(params: Map<String, *>, fetchOptions: FetchOptions? = null,
                                     signal: SkapiAbortSignal? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.forwardRequestHistory(obj(params), fetchOptions, signal)) }

    /**
     * Where many forwarded requests stand, in one call per 100. requests: full request ids (String)
     * or maps {"id", "url", "method"} with the short id. options: "deadline", "fresh", "service",
     * "owner". Completes with {"list"} in the order asked.
     */
    @JvmOverloads
    public fun forwardRequestStatus(requests: List<*>, options: Map<String, *>? = null,
                                    signal: SkapiAbortSignal? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.forwardRequestStatus(requests.map { el(it) }, objOrNull(options), signal)) }

    /** The counters of up to 20 queues: {"queues": {name: {"cnt", "rct", "seq", "in_queue"}}}. */
    @JvmOverloads
    public fun forwardRequestQueueCounters(queues: List<String>, options: Map<String, *>? = null,
                                           signal: SkapiAbortSignal? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.forwardRequestQueueCounters(queues, objOrNull(options), signal)) }

    /**
     * Reads one forwarded request in full, always as {"id", "status", "body"?, "error"?, "chunks"?, ...}.
     * params: "id" (with "url" and "method", or a full id), "since", "service", "owner", "deadline", "fresh".
     */
    @JvmOverloads
    public fun forwardRequestRead(params: Map<String, *>, signal: SkapiAbortSignal? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.forwardRequestRead(obj(params), signal)) }

    public fun cancelForwardRequest(params: Map<String, *>): CompletableFuture<Any?> = call { java(skapi.cancelForwardRequest(obj(params))) }

    public fun forwardRequestQueueCount(params: Map<String, *>): CompletableFuture<Any?> = call { java(skapi.forwardRequestQueueCount(obj(params))) }

    // ---- tickets --------------------------------------------------------------------------------

    @JvmOverloads
    public fun consumeTicket(ticketId: String, method: String = "POST", data: Any? = null, auth: Boolean = false): CompletableFuture<Any?> =
        call { java(skapi.consumeTicket(ticketId, method, if (data == null) null else el(data), auth)) }

    @JvmOverloads
    public fun getTickets(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getTickets(objOrNull(params), fetchOptions)) }

    @JvmOverloads
    public fun getConsumedTickets(params: Map<String, *>? = null, fetchOptions: FetchOptions? = null): CompletableFuture<MutableMap<String, Any?>> =
        call { map(skapi.getConsumedTickets(objOrNull(params), fetchOptions)) }
}

private fun formJson(v: Any?): JsonElement = try {
    SkapiJson.fromJava(v)
} catch (e: IllegalArgumentException) {
    throw SkapiException(e.message ?: "A form value is not JSON.", "INVALID_PARAMETER", e)
}

/** Form values for forwardRequest: files and bytes kept, everything else turned into JSON. */
private fun formValues(form: Map<String, *>): Map<String, Any?> {
    val out = LinkedHashMap<String, Any?>()
    for ((k, v) in form) out[k] = formValue(v)
    return out
}

private fun formValue(v: Any?): Any? = when (v) {
    is FileUpload, is ByteArray -> v
    is Iterable<*> -> if (v.any { it is FileUpload || it is ByteArray }) v.map { formValue(it) } else formJson(v)
    else -> formJson(v)
}
