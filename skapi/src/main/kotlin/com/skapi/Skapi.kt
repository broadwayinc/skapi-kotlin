package com.skapi

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.File

/**
 * Options for reading a list page by page.
 *
 * limit: how many items per page (up to 1000; the server's default is 50).
 * ascending: the sort direction.
 * startKey: where to start: the startKey of an earlier answer, "start" to start over, or "end".
 * fetchMore: true reads the next page of the same query, continuing from the last answer.
 */
public class FetchOptions(
    public val limit: Int? = null,
    public val ascending: Boolean? = null,
    public val startKey: JsonElement? = null,
    public val fetchMore: Boolean = false,
) {
    internal fun toMap(): JMap {
        val m = LinkedHashMap<String, Any?>()
        if (limit != null) m["limit"] = limit.toLong()
        if (ascending != null) m["ascending"] = ascending
        if (startKey != null && startKey !is JsonNull) m["startKey"] = startKey.toAny()
        if (fetchMore) m["fetchMore"] = true
        return m
    }
}

/** The signed-in session's tokens. */
public class SkapiSession internal constructor(
    public val idToken: String,
    public val accessToken: String,
    public val refreshToken: String,
)

/**
 * Skapi("<Project ID>"): one project, its connection, and the signed-in user's session.
 *
 * projectId: the Project ID from your project's Settings page on skapi.com.
 * storage: where the signed-in session is kept between runs. MemoryStorage (default) keeps it for
 *   this object only; FileStorage keeps it in a JSON file; on Android use skapi-android's
 *   SharedPreferencesStorage. Or any SkapiStorage of your own.
 * timeoutSeconds: how long a request may go with nothing sent or received before it fails with TIMEOUT.
 * encryption: EncryptionOptions to seal the data of private records on the device before upload.
 *
 * Every method that talks to the server is a suspend function, run on Dispatchers.IO, and throws
 * SkapiException on failure. Cancelling the calling coroutine stops the request.
 */
public class Skapi @JvmOverloads constructor(
    projectId: String,
    storage: SkapiStorage = MemoryStorage(),
    timeoutSeconds: Long = 120,
    targetCdn: String? = null,
    encryption: EncryptionOptions? = null,
) {
    internal val core: Core = Core(projectId, storage, timeoutSeconds, targetCdn, encryption)

    /** The compact Project ID. */
    public val projectId: String get() = core.projectId

    /** The project's service id, from the Project ID. */
    public val service: String get() = core.service

    /** The project owner's id, from the Project ID. */
    public val owner: String get() = core.owner

    /** The version of skapi-kotlin. */
    public val version: String get() = core.version

    /**
     * The signed-in user's profile as this object last saw it, or null. It does not read the saved
     * session: after the app starts, call getProfile() once to restore a saved sign-in.
     */
    public val user: JsonObject? get() = core.user?.let { deepCopy(it).toJsonObject() }

    /** The signed-in session's tokens, or null. */
    public val session: SkapiSession?
        get() = core.session?.let { SkapiSession(it.idToken.jwtToken, it.accessToken.jwtToken, it.refreshToken) }

    override fun toString(): String = "Skapi(projectId=$projectId)"

    private suspend fun <T> io(block: () -> T): T = runInterruptible(Dispatchers.IO) { block() }

    // ---- connection -----------------------------------------------------------------------------

    /** The project's name and settings, and the caller's IP and location as the server sees them. */
    public suspend fun getConnectionInfo(refresh: Boolean = false): JsonObject = io { core.getConnectionInfo(refresh).toJsonObject() }

    /**
     * Call when the app comes back to the foreground (as skapi-js does on visibilitychange). A
     * temporary account is checked at once, and the realtime connection is checked and reconnected
     * if it dropped while the app was in the background. Returns at once; the work runs in the
     * background. skapi-android's SkapiLifecycle calls it for you.
     */
    public fun onForeground() {
        core.scheduler.execute { try { core.wake() } catch (e: Exception) { } }
    }

    /** Call when the network comes back (as skapi-js does on "online"). Same checks as onForeground(). */
    public fun onNetworkAvailable() {
        core.scheduler.execute { try { core.wake() } catch (e: Exception) { } }
    }

    /**
     * Closes the realtime connection, stops this object's timers and releases its network threads, so a
     * JVM program can exit. The object cannot be used after this. The session stays saved in storage.
     */
    public fun close() {
        try { core.closeRealtime() } catch (e: Exception) { }
        core.stopAnonymousKeepAlive()
        core.scheduler.shutdownNow()
        // OkHttp's worker threads would keep a JVM program running for a minute after main returns
        try {
            core.requester.client.dispatcher.executorService.shutdown()
            core.requester.client.connectionPool.evictAll()
        } catch (e: Exception) { }
    }

    // ---- authentication ---------------------------------------------------------------------------

    /**
     * Creates an account. params: "email" and "password" (required), and any profile fields.
     * option: "signup_confirmation" (true or a redirect url), "email_subscription", "login"
     * (sign in right after), "template". Returns a "SUCCESS: ..." string, or the profile with login.
     */
    public suspend fun signup(params: JsonObject, option: JsonObject? = null): JsonElement =
        io { core.signup(params.toAny().asMap(), option?.toAny().asMap()).toJson() }

    /** Sends the signup confirmation e-mail again, after a login answered SIGNUP_CONFIRMATION_NEEDED. */
    public suspend fun resendSignupConfirmation(): JsonElement = io { core.resendSignupConfirmation().toJson() }

    /**
     * Signs in with the e-mail (or username) and password. Returns the user's profile.
     * Throws code "MFA_REQUIRED" when the account has two-step login on: call verifyMfa(code).
     */
    public suspend fun login(email: String? = null, password: String, username: String? = null): JsonObject =
        io { core.login(email, password, username).toJsonObject() }

    /** Finishes a login that threw MFA_REQUIRED, with the 6 digit code from the authenticator app. */
    public suspend fun verifyMfa(code: String): JsonObject = io { core.verifyMfa(code).toJsonObject() }

    /** Signs out. globalLogout = true also ends every session of the account on every device. */
    public suspend fun logout(globalLogout: Boolean = false): String = io { core.logout(globalLogout) }

    /**
     * The signed-in user's profile, or null. The first call restores a saved sign-in from storage.
     * refreshToken = true asks the server for fresh tokens first.
     */
    public suspend fun getProfile(refreshToken: Boolean = false): JsonObject? = io { core.getProfile(refreshToken)?.toJsonObject() }

    /** Adopts the tokens of a sign-in made elsewhere (for example skapi-js on a web page). */
    public suspend fun loginWithToken(idToken: String, accessToken: String, refreshToken: String): JsonObject =
        io { core.loginWithToken(idToken, accessToken, refreshToken).toJsonObject() }

    /** Changes the signed-in user's own profile fields. "" clears a field. */
    public suspend fun updateProfile(params: JsonObject): JsonObject? = io { core.updateProfile(params.toAny().asMap())?.toJsonObject() }

    public suspend fun changePassword(currentPassword: String, newPassword: String): String = io { core.changePassword(currentPassword, newPassword) }

    /** Sends a password reset code to the account's e-mail. Then call resetPassword(). template: {"forgot_password": message_id}. */
    public suspend fun forgotPassword(email: String, template: JsonObject? = null): String = io { core.forgotPassword(email, template?.toAny().asMap()) }

    public suspend fun resetPassword(email: String, code: String, newPassword: String): String = io { core.resetPassword(email, code, newPassword) }

    /** Without a code: sends a verification code to the user's e-mail. With a code: verifies it. */
    public suspend fun verifyEmail(code: String? = null, template: JsonObject? = null): String = io { core.verifyEmail(code, template?.toAny().asMap()) }

    /** The last verified e-mail; revert = true sets it back as the account's e-mail. */
    public suspend fun lastVerifiedEmail(revert: Boolean? = null): JsonElement = io { core.lastVerifiedEmail(revert).toJson() }

    /** Disables the signed-in user's own account and signs out. */
    public suspend fun disableAccount(): JsonElement = io { core.disableAccount().toJson() }

    /** Sends the recovery e-mail to a disabled account, after a login attempt answered USER_IS_DISABLED. */
    public suspend fun recoverAccount(redirect: String? = null): String = io { core.recoverAccount(redirect ?: false) }

    /**
     * Signs in with a token from your OpenID provider, through the OpenID logger set up as `id`.
     * merge: true, or a list of profile field names, to merge into an existing account.
     */
    public suspend fun openIdLogin(token: String, id: String, merge: JsonElement? = null, template: JsonObject? = null): JsonObject =
        io { core.openIdLogin(token, id, merge?.toAny(), template?.toAny().asMap()).toJsonObject() }

    /** A temporary account without e-mail or password, deleted 30 minutes after this object stops keeping it alive. */
    public suspend fun anonymousLogin(): JsonObject = io { core.anonymousLogin().toJsonObject() }

    /** For a restored temporary account: the profile, or null (signed out) when the account was already deleted. */
    public suspend fun verifyAnonymousSession(): JsonObject? = io { core.verifyAnonymousSession()?.toJsonObject() }

    /** Starts two-step login setup: {"secret", "uri"}. Show uri as a QR code, then call enableMfa(code). */
    public suspend fun setupMfa(issuer: String? = null, accountName: String? = null): JsonObject = io { core.setupMfa(issuer, accountName).toJsonObject() }

    public suspend fun enableMfa(code: String): String = io { core.enableMfa(code) }

    public suspend fun disableMfa(): String = io { core.disableMfa() }

    /** {"enabled": true | false} */
    public suspend fun getMfaStatus(): JsonObject = io { core.getMfaStatus().toJsonObject() }

    // ---- database ---------------------------------------------------------------------------------

    /**
     * Creates a record, or updates one when config has "record_id".
     * data: any JSON value (JsonNull stores null). files: attachments.
     */
    public suspend fun postRecord(data: JsonElement?, config: JsonObject, files: List<FileUpload>? = null): JsonObject =
        io { core.postRecord(data?.toAny(), config.toAny().asMap(), files).toJsonObject() }

    /** Updates a record without changing its data (the stored data is kept). */
    public suspend fun postRecord(config: JsonObject, files: List<FileUpload>? = null): JsonObject =
        io { core.postRecord(NoData, config.toAny().asMap(), files).toJsonObject() }

    /** Many records in few requests: items = [{"data": ..., "config": {...}}]. Returns {"list", "failed"}. */
    public suspend fun postRecords(items: List<JsonObject>): JsonObject =
        io { core.postRecords(items.map { it.toAny().asMap() ?: LinkedHashMap() }).toJsonObject() }

    /** Records by id, unique id, table, index, tag or reference. */
    public suspend fun getRecords(query: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getRecords(query?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Deletes your records by id, unique id, or query. */
    public suspend fun deleteRecords(query: JsonObject, fetchOptions: FetchOptions? = null): JsonElement =
        io { core.deleteRecords(query.toAny().asMap() ?: LinkedHashMap(), fetchOptions?.toMap()).toJson() }

    /** The tables of the project, with how many records each access group holds. */
    public suspend fun getTables(query: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getTables(query?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** The tags used in a table (or every table). */
    public suspend fun getTags(query: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getTags(query?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** The indexes of a table, with counts, totals and averages. */
    public suspend fun getIndexes(query: JsonObject, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getIndexes(query.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Unique IDs and the records they point at. */
    public suspend fun getUniqueId(query: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getUniqueId(query?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Attaches files to a record you can write. Returns {"completed", "failed", "errors", "bin_endpoints"}. */
    public suspend fun uploadFiles(files: List<FileUpload>, recordId: String, service: String? = null): JsonObject =
        io { core.uploadFiles(files, recordId, service).toMap().toJsonObject() }

    /** A record file's bytes. An encrypted attachment is opened when its record's key is at hand. */
    public suspend fun getFile(url: String): ByteArray = io { core.getFile(url, jmap("dataType" to "bytes")) as ByteArray }

    /** A record file as UTF-8 text. */
    public suspend fun getFileText(url: String): String = io { core.getFile(url, jmap("dataType" to "text")) as String }

    /**
     * A url to open the file with. expiresSeconds > 0 makes a signed url that works without signing
     * in, for that many seconds.
     */
    public suspend fun getFileUrl(url: String, expiresSeconds: Long = 0): String =
        io { core.getFile(url, jmap("dataType" to "endpoint", "expires" to expiresSeconds)) as String }

    /** What a file url says, without downloading: url, filename, access_group, uploader, record_id, filesize, uploaded. */
    public suspend fun getFileInfo(url: String): JsonObject = io { core.getFile(url, jmap("dataType" to "info")).toJsonObject() }

    /** Downloads a record file to `destination` (overwritten) and returns it. */
    public suspend fun downloadFile(url: String, destination: File, expiresSeconds: Long = 0): File =
        io { core.getFile(url, jmap("dataType" to "bytes", "save_to" to destination, "expires" to expiresSeconds)) as File }

    /** Removes files from records, by their urls. */
    public suspend fun deleteFiles(endpoints: List<String>): JsonElement = io { core.deleteFiles(endpoints).toJson() }

    /** Lets users read one of your private records. An encrypted record gets a key wrap for each new user first. */
    public suspend fun grantPrivateRecordAccess(recordId: String, userIds: List<String>): JsonElement =
        io { core.grantPrivateRecordAccess(jmap("record_id" to recordId, "user_id" to userIds.toMutableList<Any?>())).toJson() }

    /** Takes access to one of your private records away. An encrypted record gets a new key first. */
    public suspend fun removePrivateRecordAccess(recordId: String, userIds: List<String>): JsonElement =
        io { core.removePrivateRecordAccess(jmap("record_id" to recordId, "user_id" to userIds.toMutableList<Any?>())).toJson() }

    /** Who can read a private record (recordId), or which private records a user can read (userIds). */
    public suspend fun listPrivateRecordAccess(recordId: String? = null, userIds: List<String>? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io {
            val p = LinkedHashMap<String, Any?>()
            if (recordId != null) p["record_id"] = recordId
            if (userIds != null) p["user_id"] = userIds.toMutableList<Any?>()
            core.listPrivateRecordAccess(p, fetchOptions?.toMap()).toJsonObject()
        }

    /** A key to read a private record shared with you (kept and renewed by this object; you rarely need it yourself). */
    public suspend fun requestPrivateRecordAccessKey(recordId: String, referenceId: String? = null): String =
        io { core.requestPrivateRecordAccessKey(jmap("record_id" to recordId, "reference_id" to referenceId)) }

    // ---- encryption -------------------------------------------------------------------------------

    /** {"status": "disabled" | "locked" | "unlocked", "reason"?, "user_id"?, "fingerprint"?} */
    public suspend fun getEncryptionStatus(): JsonObject = io { core.getEncryptionStatus().toJsonObject() }

    /** Opens the user's encryption keys with their password (for a session restored from storage). */
    public suspend fun unlockEncryption(password: String): JsonObject = io { core.unlockEncryption(password).toJsonObject() }

    /** Forgets the keys in memory. forgetDevice = true also removes the key kept by the DeviceKeyStore. */
    public suspend fun lockEncryption(forgetDevice: Boolean = false): JsonObject = io { core.lockEncryption(forgetDevice).toJsonObject() }

    /** Opens the keys with the encryption recovery code; with a password, also sets the keys up for it. */
    public suspend fun unlockEncryptionWithRecoveryCode(code: String, password: String? = null): JsonObject =
        io { core.unlockEncryptionWithRecoveryCode(code, password).toJsonObject() }

    /** Retires the encryption recovery code and returns a new one: {"encryptionRecoveryCode": ...}. */
    public suspend fun regenerateEncryptionRecoveryCode(): JsonObject = io { core.regenerateEncryptionRecoveryCode().toJsonObject() }

    /** Trusts another user's key fingerprint for sharing encrypted records. */
    public suspend fun pinPeerKey(userId: String, fingerprint: String): Unit = io { core.pinPeerKey(userId, fingerprint) }

    /** True for the placeholder put in place of data this session cannot decrypt (withheld = "sentinel"). */
    public fun isWithheld(value: JsonElement?): Boolean = com.skapi.isWithheld(value?.toAny())

    // ---- users ------------------------------------------------------------------------------------

    /** Searches the project's users by one profile field. Signed-in users only. */
    public suspend fun getUsers(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getUsers(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Subscribes the signed-in user to another user. */
    public suspend fun subscribe(userId: String, getFeed: Boolean? = null, getNotified: Boolean? = null, getEmail: Boolean? = null): JsonObject =
        io {
            val p = jmap("user_id" to userId)
            if (getFeed != null) p["get_feed"] = getFeed
            if (getNotified != null) p["get_notified"] = getNotified
            if (getEmail != null) p["get_email"] = getEmail
            core.subscribe(p).toJsonObject()
        }

    public suspend fun unsubscribe(userId: String): JsonElement = io { core.unsubscribe(jmap("user_id" to userId)).toJson() }

    /** Stops a user from subscribing to the signed-in user (and from getting their feed). */
    public suspend fun blockSubscriber(userId: String): JsonElement = io { core.blockSubscriber(jmap("user_id" to userId)).toJson() }

    public suspend fun unblockSubscriber(userId: String): JsonElement = io { core.unblockSubscriber(jmap("user_id" to userId)).toJson() }

    /** Who a user subscribes to (subscriber = ...) or who subscribes to a user (subscription = ...). */
    public suspend fun getSubscriptions(subscriber: String? = null, subscription: String? = null, blocked: Boolean? = null,
                                        fetchOptions: FetchOptions? = null): JsonObject =
        io {
            val p = LinkedHashMap<String, Any?>()
            if (subscriber != null) p["subscriber"] = subscriber
            if (subscription != null) p["subscription"] = subscription
            if (blocked != null) p["blocked"] = blocked
            core.getSubscriptions(p, fetchOptions?.toMap()).toJsonObject()
        }

    /** Records the users you subscribe to posted to their feed, newest first. params: {"access_group"?}. */
    public suspend fun getFeed(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getFeed(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Subscribes to the project's newsletters of one group: {"group", "email"? (signed out), "redirect"?}. */
    public suspend fun subscribeNewsletter(params: JsonObject): JsonElement = io { core.subscribeNewsletter(params.toAny().asMap() ?: LinkedHashMap()).toJson() }

    /** Unsubscribes from one group ("public", "authorized", a number or a group name), or from every group with null. */
    public suspend fun unsubscribeNewsletter(group: JsonElement?): JsonElement = io { core.unsubscribeNewsletter(group?.toAny()).toJson() }

    /** Unsubscribes from one group by name ("public", "authorized" or a newsletter group name), or every group with null. */
    public suspend fun unsubscribeNewsletter(group: String?): JsonElement = unsubscribeNewsletter(group?.let { JsonPrimitive(it) })

    /** Newsletters sent to a group, newest first by default. */
    public suspend fun getNewsletters(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getNewsletters(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** The signed-in user's newsletter subscriptions. */
    public suspend fun getNewsletterSubscription(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonElement =
        io { core.getNewsletterSubscription(params?.toAny().asMap(), fetchOptions?.toMap()).toJson() }

    /** Sends a message to the project's owner. */
    public suspend fun sendInquiry(name: String, email: String, subject: String, message: String): String =
        io { core.sendInquiry(jmap("name" to name, "email" to email, "subject" to subject, "message" to message)) }

    // ---- realtime ---------------------------------------------------------------------------------

    /**
     * Opens the realtime connection. callback(event) runs on a background thread for every message,
     * notice and connection event: {"type", "message", "sender", "sender_cid", "sender_rid", "code"}.
     * Returns once connected; reconnects on its own.
     */
    public suspend fun connectRealtime(callback: (JsonObject) -> Unit): Unit =
        io { core.connectRealtime { event -> callback(event.toJsonObject()) } }

    /** Closes the realtime connection; the group hears that you disconnected and left. */
    public suspend fun closeRealtime(): Unit = io { core.closeRealtime() }

    /** Joins a message group (one at a time), or leaves the current one with null. */
    public suspend fun joinRealtime(group: String?): JsonObject = io { core.joinRealtime(group).toJsonObject() }

    /** Sends to a user (by user ID) or to the group you joined. notification: {"title", "body", "config"?: {"always"}}. */
    public suspend fun postRealtime(message: JsonElement, recipient: String, notification: JsonObject? = null): JsonObject =
        io { core.postRealtime(message.toAny(), recipient, notification?.toAny().asMap()).toJsonObject() }

    /** Who is connected in a group (default: the group you joined). */
    public suspend fun getRealtimeUsers(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getRealtimeUsers(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Groups that have members now. */
    public suspend fun getRealtimeGroups(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getRealtimeGroups(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    // ---- API bridge -------------------------------------------------------------------------------

    /**
     * Calls another API through Skapi. options: "url" (required), "method", "headers", "data",
     * "params", "secretName", "skapiHeaders", "queue", "expires", "stream", "poll" (milliseconds, 1000 or more; 0 does not poll), "multipart",
     * "responseType". form: form fields (JsonElement, String, numbers, ByteArray or FileUpload values),
     * merged into data or params, or sent as the multipart body. onStream(text, seq) receives
     * streamed text as it arrives.
     */
    public suspend fun forwardRequest(options: JsonObject, form: Map<String, Any?>? = null, onStream: ((String, Int) -> Unit)? = null): JsonElement =
        io { core.forwardRequest(options.toAny().asMap() ?: LinkedHashMap(), form?.let { formValues(it) }, onStream).toJson() }

    /**
     * Waits for a queued request (its request_id, or its short id with url and method) and returns the answer.
     * pollMillis: milliseconds between checks, 1000 or more (0 means the default, 1000).
     */
    public suspend fun forwardRequestPoll(requestId: String, pollMillis: Long = 1000, url: String? = null, method: String? = null,
                                          onStream: ((String, Int) -> Unit)? = null, service: String? = null, owner: String? = null): JsonElement =
        io { core.forwardRequestPoll(requestId, pollMillis.toDouble(), url, method, onStream, service, owner).toJson() }

    /** Reads a streamed request's text from "since" (or the start) until it settles; returns the final answer. */
    public suspend fun forwardRequestStream(requestId: String, options: JsonObject? = null, onStream: ((String, Int) -> Unit)? = null): JsonElement =
        io { core.forwardRequestStream(requestId, options?.toAny().asMap(), onStream).toJson() }

    /** Stores `data` as a streamed request's final answer, so later polls return it. */
    public suspend fun forwardRequestFinalize(requestId: String, data: JsonElement? = null, options: JsonObject? = null): JsonElement =
        io { core.forwardRequestFinalize(requestId, data?.toAny(), options?.toAny().asMap()).toJson() }

    /** The forwarded requests you made to one url and method, with their answers. */
    public suspend fun forwardRequestHistory(params: JsonObject, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.forwardRequestHistory(params.toAny().asMap() ?: LinkedHashMap(), fetchOptions?.toMap()).toJsonObject() }

    /** Cancels a queued request that has not run yet: {"url", "method", "id"}. */
    public suspend fun cancelForwardRequest(params: JsonObject): JsonElement =
        io { core.cancelForwardRequest(params.toAny().asMap() ?: LinkedHashMap()).toJson() }

    /** How many requests are waiting in one of your queues: {"queue"}. */
    public suspend fun forwardRequestQueueCount(params: JsonObject): JsonElement =
        io { core.forwardRequestQueueCount(params.toAny().asMap() ?: LinkedHashMap()).toJson() }

    // ---- tickets ----------------------------------------------------------------------------------

    /** Calls a ticket of the project (set up on skapi.com) with `data`. Returns its receipt or answer. */
    public suspend fun consumeTicket(ticketId: String, method: String = "POST", data: JsonElement? = null, auth: Boolean = false): JsonElement =
        io { core.consumeTicket(ticketId, method, data?.toAny(), auth).toJson() }

    /** The project's tickets (or one, with {"ticket_id": ...}) as a signed-in user sees them. */
    public suspend fun getTickets(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getTickets(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }

    /** The signed-in user's own ticket calls. */
    public suspend fun getConsumedTickets(params: JsonObject? = null, fetchOptions: FetchOptions? = null): JsonObject =
        io { core.getConsumedTickets(params?.toAny().asMap(), fetchOptions?.toMap()).toJsonObject() }
}

/** Form values as the SDK reads them: JsonElement turned into plain values; files and bytes kept. */
private fun formValues(form: Map<String, Any?>): JMap {
    val out = LinkedHashMap<String, Any?>()
    for ((k, v) in form) {
        out[k] = when (v) {
            is JsonElement -> v.toAny()
            is List<*> -> v.map { if (it is JsonElement) it.toAny() else it }.toMutableList()
            else -> v
        }
    }
    return out
}
