package com.skapi

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ThreadFactory

/** The version of skapi-kotlin, sent to the server as skapi_version. */
public const val SKAPI_VERSION: String = "2.7.0"

internal const val TOKEN_REFRESH_SKEW_SECONDS = 60 * 60 // refresh the ID token when it has less than an hour left

/**
 * How long a token refresh may take in all, retries included (skapi-js 2.7.0). Past it the call
 * that needed the token fails with code TIMEOUT, the user stays signed in, and the next call
 * starts a new refresh.
 */
internal const val TOKEN_REFRESH_TIME_LIMIT_MS = 15_000L

/** The password-free state of a sign-in waiting for an authenticator code. */
internal class PendingMfa(val username: String, val session: String?, val password: String?)

/** One token refresh: done completes when it ends, error is what it failed with. */
internal class RefreshFlight(val seq: Long) {
    val done = java.util.concurrent.CompletableFuture<Unit>()
    @Volatile var error: Throwable? = null
}

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
    /** guards refreshFlight and refreshSeq */
    val refreshLock = Any()
    /** the token refresh in flight, shared by every thread that needs one (as skapi-js tokenRefreshInFlight) */
    @Volatile var refreshFlight: RefreshFlight? = null
    /** numbers the refreshes in the order they started */
    var refreshSeq = 0L
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
    /** The request status push (RequestStatus.kt). */
    val statusPush: StatusPush by lazy { StatusPush(this) }
    /** one status-push connection opening at a time */
    val statusPushOpenLock = Any()
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
                        if (e.code != "NetworkError" && e.code != "Timeout") throw e
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
                if (e.code != "NetworkError" && e.code != "Timeout") clearSession(localOnly = true)
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

    /**
     * Forced token refresh. A network failure or no answer within TOKEN_REFRESH_TIME_LIMIT_MS
     * (TIMEOUT) keeps the session; any other refusal ends it. Threads that need a refresh at the
     * same time share one, as skapi-js shares its tokenRefreshInFlight, and each waits for it at
     * most TOKEN_REFRESH_TIME_LIMIT_MS from when it started waiting (TIMEOUT past it, still signed
     * in; the stalled refresh is no longer shared, so the next call starts a new one).
     *
     * newClaims: the caller just changed the user (updateProfile, verifyEmail, ...) and needs
     * tokens issued after this call. It joins only a refresh that started after it asked; one that
     * started earlier could carry the old claims, so it is waited out (within the time limit) and a
     * new refresh is started.
     * onlyIfStale: skip the refresh when the ID token is no longer within the refresh skew (another
     * thread refreshed it meanwhile).
     * control: the caller's deadline and abort also end its wait.
     */
    fun refreshSession(newClaims: Boolean = false, control: RequestControl? = null, onlyIfStale: Boolean = false) {
        val mark: Long
        val earlier: RefreshFlight?
        synchronized(refreshLock) {
            if (session == null) throw skErr("User login is required.", "INVALID_REQUEST")
            mark = refreshSeq // a refresh numbered above this started after this call
            earlier = if (newClaims) refreshFlight else null
        }
        if (earlier != null) {
            try {
                waitRefresh(earlier, control)
            } catch (e: SkapiException) {
                if (e.code == "TIMEOUT" || e.code == "ABORTED") throw e
                // its own failure is not this caller's answer: the new refresh below gives that
            }
        }
        val flight = synchronized(refreshLock) {
            val current = session ?: throw skErr("User login is required.", "INVALID_REQUEST")
            val username = cognitoUsername ?: throw skErr("User login is required.", "INVALID_REQUEST")
            var f = refreshFlight
            if (f == null && onlyIfStale && !stale(current)) return
            if (f == null || (newClaims && f.seq <= mark)) {
                refreshSeq += 1
                val started = RefreshFlight(refreshSeq)
                refreshFlight = started
                val epoch = signOuts
                val refreshToken = current.refreshToken
                Thread({ runRefresh(started, epoch, username, refreshToken) }, "skapi-token-refresh")
                    .also { it.isDaemon = true }.start()
                f = started
            }
            f
        }
        waitRefresh(flight, control)
    }

    private fun stale(s: Session): Boolean =
        (s.idToken.expiration ?: 0) < System.currentTimeMillis() / 1000 + TOKEN_REFRESH_SKEW_SECONDS

    /** Waits for a refresh at most TOKEN_REFRESH_TIME_LIMIT_MS; throws its error, or TIMEOUT. */
    private fun waitRefresh(flight: RefreshFlight, control: RequestControl?) {
        if (!awaitWithin(flight.done, TOKEN_REFRESH_TIME_LIMIT_MS, control)) {
            synchronized(refreshLock) {
                // stops sharing the stalled refresh, so the next call tries again
                if (refreshFlight === flight) refreshFlight = null
            }
            throw skErr("The sign-in token refresh did not answer within ${TOKEN_REFRESH_TIME_LIMIT_MS / 1000} seconds.", "TIMEOUT")
        }
        when (val err = flight.error) {
            null -> return
            // a copy for each waiting caller, so what one caller marks on it stays its own
            is SkapiException -> throw SkapiException(err.message, err.code, err.cause ?: err, err.details)
            else -> throw err
        }
    }

    /** The refresh itself, on its own thread: it runs to its end even when nobody waits any more. */
    private fun runRefresh(flight: RefreshFlight, epoch: Int, username: String, refreshToken: String) {
        try {
            val pool = userPool()
            val fresh = try {
                pool.refresh(username, refreshToken)
            } catch (e: CognitoError) {
                if (signOuts != epoch) signedOutMeanwhile(pool, username)
                if (e.code == "NetworkError") throw skErr("Network error", "NETWORK_ERROR", e)
                if (e.code == "Timeout") {
                    throw skErr("The sign-in token refresh did not answer within ${TOKEN_REFRESH_TIME_LIMIT_MS / 1000} seconds.", "TIMEOUT", e)
                }
                // the server refused the refresh: the session ends (unless another user signed in meanwhile)
                if (cognitoUsername == username) clearSession()
                throw skErr("User login is required.", "INVALID_REQUEST", e)
            }
            synchronized(sessionLock) {
                if (signOuts != epoch) signedOutMeanwhile(pool, username)
                adoptSession(username, fresh)
            }
        } catch (e: Throwable) {
            flight.error = e // handed to the waiting callers
        } finally {
            synchronized(refreshLock) {
                if (refreshFlight === flight) refreshFlight = null
            }
            flight.done.complete(Unit)
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

    /**
     * The ID token, refreshed first when it has less than TOKEN_REFRESH_SKEW_SECONDS left (joining
     * a refresh another thread already started; waiting at most the refresh time limit, or the
     * caller's deadline or abort when `control` is given).
     */
    fun freshIdToken(control: RequestControl? = null): String {
        restore()
        var s = session
        if (s == null) {
            clearSession()
            throw skErr("User login is required.", "INVALID_REQUEST")
        }
        if (stale(s)) {
            refreshSession(control = control, onlyIfStale = true)
            s = session ?: throw skErr("User login is required.", "INVALID_REQUEST")
        }
        return s.idToken.jwtToken
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
        control: RequestControl? = null,
    ): Any? {
        control?.check()
        if (control != null && (connection == null || (auth && !restored))) {
            // the deadline counts from this call: the wait for the connection is part of it
            control.bounded { ensureConnection(); if (auth) restore() }
        } else {
            ensureConnection()
        }
        val token = if (auth) {
            try {
                freshIdToken(control)
            } catch (e: SkapiException) {
                // Marked so a caller can tell "this client could not get a token" (no answer from
                // the sign-in service, or a session that is gone) from the server's answer. Not
                // when the caller itself gave up (its deadline or abort).
                if (control == null || !control.gaveUp()) e.tokenFailure = true
                throw e
            }
        } else null
        return requester.request(path, data, auth = auth, method = method, token = token, fetchOptions = fetchOptions,
            ignoreService = ignoreService, control = control)
    }

    /** The signed-in user's profile (a copy), or null. */
    fun userCopy(): JMap? {
        restore()
        return user?.let { deepCopy(it).asMap() }
    }

    fun me(): String = user.s("user_id") ?: ""
}
