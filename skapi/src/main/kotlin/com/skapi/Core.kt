package com.skapi

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ThreadFactory

/** The version of skapi-kotlin, sent to the server as skapi_version. */
public const val SKAPI_VERSION: String = "2.4.1"

internal const val TOKEN_REFRESH_SKEW_SECONDS = 60 * 60 // refresh the ID token when it has less than an hour left

/** The password-free state of a sign-in waiting for an authenticator code. */
internal class PendingMfa(val username: String, val session: String?, val password: String?)

/** Passed for "data" when it was left out (keep the stored data on an update), as skapi-py's _NO_DATA. */
internal object NoData

/**
 * The state of one Skapi object: its project, its connection, and the signed-in user's session.
 * Ported from skapi-py client.py. Every method of the SDK is an extension of this class, in the
 * file of its area (User.kt, Database.kt, Encryption.kt, ...). They block: the public Skapi class
 * runs them on Dispatchers.IO.
 */
internal class Core(
    projectId: String,
    val storage: SkapiStorage,
    timeoutSeconds: Long,
    targetCdn: String?,
    encryption: EncryptionOptions?,
) {
    val service: String
    val owner: String
    val projectId: String
    val version: String = SKAPI_VERSION

    @Volatile var connection: JMap? = null
    val requester: Requester
    @Volatile var pool: UserPool? = null
    @Volatile var session: Session? = null
    @Volatile var cognitoUsername: String? = null
    @Volatile var user: JMap? = null
    @Volatile var restored = false
    val lock = Any()
    /** one token refresh at a time, shared by every thread */
    val refreshLock = Any()
    /**
     * Counts sign-outs: clearSession adds one. A token refresh that started before a sign-out
     * compares it before adopting its tokens, so a refresh still running when the user logged out
     * cannot sign them back in (as skapi-js sessionEpoch).
     */
    @Volatile var signOuts = 0
    /** makes "not signed out since" + adopting one step */
    val sessionLock = Any()
    /** the id token restore() just refreshed to */
    @Volatile var restoreRefreshedToken: String? = null

    val enc: EncState?

    // per-instance state, as in skapi-js
    val privateAccessKey: MutableMap<String, String> = ConcurrentHashMap()
    val myUniqueIds: MutableMap<String, MutableMap<String, String>> = ConcurrentHashMap()
    /** getFile url given out -> the stored file url */
    val handedOutFileUrls: MutableMap<String, String> = ConcurrentHashMap()
    @Volatile var pendingMfa: PendingMfa? = null
    @Volatile var requestSignupConfirmation: String? = null
    @Volatile var disabledAccount: String? = null
    @Volatile var anonymousTimer: ScheduledFuture<*>? = null
    /** when the server last confirmed the temporary account (ms) */
    @Volatile var lastAnonymousBeat: Long = 0
    @Volatile var rt: Realtime? = null
    @Volatile var bulkPermitsUnavailable = false
    val cdnOrigins: MutableMap<String, String> = ConcurrentHashMap()

    /** Timers: the anonymous keep-alive and realtime keep-alive, renewal and reconnects. Daemon threads. */
    val scheduler: ScheduledExecutorService by lazy {
        Executors.newScheduledThreadPool(4, ThreadFactory { r -> Thread(r, "skapi-timer").also { it.isDaemon = true } })
    }

    init {
        if (projectId.isBlank()) throw perr("Project ID is required.")
        if (!ProjectId.isProjectId(projectId.trim())) throw perr("Project ID is invalid.")
        val (s, o) = ProjectId.decode(projectId)
        service = s
        owner = o
        this.projectId = try { ProjectId.format(s, o) } catch (e: RuntimeException) { "" }
        requester = Requester(service, owner, SKAPI_VERSION, targetCdn, timeoutSeconds)
        enc = encryption?.let { EncState(parseEncryptionOptions(it)) }
    }

    // ---- connection -----------------------------------------------------------------------------

    fun ensureConnection(refresh: Boolean = false): JMap = synchronized(lock) {
        var c = connection
        if (c == null || refresh) {
            c = requester.request("service", jmap("service" to service, "owner" to owner, "refresh" to refresh), method = "GET").asMap()
                ?: throw skErr("The project ID does not exist. Create your project from skapi.com", "NOT_EXISTS")
            connection = c
        }
        c
    }

    fun getConnectionInfo(refresh: Boolean = false): JMap {
        val conn = ensureConnection(refresh)
        val info = jmap(
            "project_id" to projectId,
            "user_ip" to conn["ip"],
            "user_agent" to conn["user_agent"],
            "user_location" to conn["locale"],
            "service_name" to conn["service_name"],
            "version" to version,
            "ai_agent" to conn["ai_agent"],
            "conf" to conn["opt"],
        )
        // Only with encryption on and a signed-in user: the encryption recovery code on the first
        // call after it was created, then only a message (see encryptionRecoveryInfo).
        val recovery = encryptionRecoveryInfo()
        if (recovery != null) info["encryption_recovery"] = recovery
        return info
    }

    // ---- session --------------------------------------------------------------------------------

    fun userPool(): UserPool {
        pool?.let { return it }
        synchronized(lock) {
            pool?.let { return it }
            val (admin, _) = requester.endpoints()
            val p = UserPool(admin.s("userpool_id") ?: "", admin.s("userpool_client") ?: "", storage, requester.client)
            pool = p
            return p
        }
    }

    /** Once: sign back in from storage (refreshing the tokens when they expired). */
    fun restore() {
        if (restored) return
        synchronized(lock) {
            if (restored) return
            restored = true
            val pool = userPool()
            val username = pool.lastAuthUser()
            if (username.isNullOrEmpty()) return
            var session = pool.cachedSession(username) ?: return
            try {
                if (!session.isValid()) {
                    if (session.refreshToken.isEmpty()) return
                    try {
                        session = pool.refresh(username, session.refreshToken)
                        // getProfile(refreshToken = true) right after this has nothing left to ask for
                        restoreRefreshedToken = session.idToken.jwtToken
                    } catch (e: CognitoError) {
                        if (e.code != "NetworkError") throw e
                        // The server never answered: that says nothing about the session, which is kept
                        // with its stored tokens. The next signed-in call refreshes again (NETWORK_ERROR
                        // while there is no network), as for a session that expires while running.
                    }
                }
                adoptSession(username, session)
                if (user?.get("anonymous") == true) {
                    // a temporary account restored from storage: check it still exists, and keep it alive
                    startAnonymousKeepAlive(beatNow = true)
                } else {
                    // "remember this device": open encrypted data from the device store, when there is one
                    encStartDeviceUnlock()
                }
            } catch (e: CognitoError) {
                if (e.code != "NetworkError") clearSession(localOnly = true)
            } catch (e: SkapiException) {
                // kept signed out
            }
        }
    }

    fun adoptSession(username: String, session: Session): JMap {
        val claims = session.idToken.payload
        if (claims["custom:service"] != service) {
            clearSession(localOnly = true)
            throw skErr("Invalid session.", "INVALID_REQUEST")
        }
        val previous = cognitoUsername
        if (!previous.isNullOrEmpty() && previous != username) {
            // a new sign-in as someone else: nothing the previous user was handed carries over
            privateAccessKey.clear()
            myUniqueIds.clear()
            pool?.let { p ->
                // the previous user's tokens leave the storage
                stopAnonymousKeepAlive()
                for (key in listOf("idToken", "accessToken", "refreshToken", "clockDrift", "userData")) {
                    p.storage.removeItem("${p.keyPrefix}.$previous.$key")
                }
            }
        }
        this.session = session
        this.cognitoUsername = username
        val parsed = parseUserAttributes(claims)
        this.user = parsed
        return parsed
    }

    fun clearSession(localOnly: Boolean = true) {
        if (rt != null) closeRealtime() // a signed-in connection does not outlive the session
        stopAnonymousKeepAlive()
        encClear()
        pendingMfa = null
        val username = cognitoUsername
        if (!username.isNullOrEmpty()) pool?.clearCachedTokens(username)
        synchronized(sessionLock) {
            session = null
            cognitoUsername = null
            user = null
            signOuts += 1 // a refresh still running from before this point is not adopted
            restoreRefreshedToken = null
        }
        privateAccessKey.clear()
        myUniqueIds.clear()
        requester.startKeyHistory.clear()
    }

    fun signedIn(): Boolean {
        restore()
        return user != null && session != null
    }

    /** Forced token refresh. A network failure keeps the session; any other refusal ends it. */
    fun refreshSession() {
        synchronized(refreshLock) {
            val current = session ?: throw skErr("User login is required.", "INVALID_REQUEST")
            val epoch = signOuts
            val username = cognitoUsername ?: throw skErr("User login is required.", "INVALID_REQUEST")
            val pool = userPool()
            val fresh = try {
                pool.refresh(username, current.refreshToken)
            } catch (e: CognitoError) {
                if (signOuts != epoch) signedOutMeanwhile(pool, username)
                if (e.code == "NetworkError") throw skErr("Network error", "NETWORK_ERROR", e)
                clearSession()
                throw skErr("User login is required.", "INVALID_REQUEST", e)
            }
            synchronized(sessionLock) {
                if (signOuts != epoch) signedOutMeanwhile(pool, username)
                adoptSession(username, fresh)
            }
        }
    }

    /**
     * logout() ran while a token refresh waited on the server. The refresh is not adopted, and the
     * tokens it wrote back to storage are removed again; a sign-in made after the logout keeps its
     * own tokens. Throws, as for any call made without a session.
     */
    private fun signedOutMeanwhile(pool: UserPool, username: String): Nothing {
        pool.clearCachedTokens(username)
        val s = session
        val u = cognitoUsername
        if (s != null && !u.isNullOrEmpty()) pool.cacheTokens(u, s)
        throw skErr("User login is required.", "INVALID_REQUEST")
    }

    fun freshIdToken(): String {
        restore()
        var s = session
        if (s == null) {
            clearSession()
            throw skErr("User login is required.", "INVALID_REQUEST")
        }
        val now = System.currentTimeMillis() / 1000
        if ((s.idToken.expiration ?: 0) < now + TOKEN_REFRESH_SKEW_SECONDS) {
            synchronized(refreshLock) {
                // another thread may have refreshed (or ended the session) while this one waited
                s = session ?: throw skErr("User login is required.", "INVALID_REQUEST")
                if ((s!!.idToken.expiration ?: 0) < System.currentTimeMillis() / 1000 + TOKEN_REFRESH_SKEW_SECONDS) {
                    refreshSession()
                    s = session ?: throw skErr("User login is required.", "INVALID_REQUEST")
                }
            }
        }
        return s!!.idToken.jwtToken
    }

    fun accessToken(): String {
        freshIdToken()
        return (session ?: throw skErr("User login is required.", "INVALID_REQUEST")).accessToken.jwtToken
    }

    fun call(
        path: String,
        data: Any? = null,
        auth: Boolean = false,
        method: String = "POST",
        fetchOptions: JMap? = null,
        ignoreService: Boolean = false,
    ): Any? {
        ensureConnection()
        val token = if (auth) freshIdToken() else null
        return requester.request(path, data, auth = auth, method = method, token = token, fetchOptions = fetchOptions, ignoreService = ignoreService)
    }

    /** The signed-in user's profile (a copy), or null. */
    fun userCopy(): JMap? {
        restore()
        return user?.let { deepCopy(it).asMap() }
    }

    fun me(): String = user.s("user_id") ?: ""
}
