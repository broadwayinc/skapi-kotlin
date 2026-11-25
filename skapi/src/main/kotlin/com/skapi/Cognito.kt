package com.skapi

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/*
 * The Cognito user pool client skapi-kotlin signs in with, ported from skapi-py (_cognito.py),
 * itself a port of skapi-js (src/cognito/index.ts).
 *
 * Same requests, error codes and messages, retry timing and storage keys
 * (CognitoIdentityServiceProvider.<clientId>.LastAuthUser and .<username>.idToken / accessToken /
 * refreshToken / clockDrift). Sign-in is SRP only: the password never leaves the device. No device
 * tracking (off on every Skapi user pool) and no text messages of any kind.
 */

internal const val COGNITO_REQUEST_TIMEOUT = 60L // seconds per call to the user pool API

/** An error answered by the user pool API, or a network failure (code "NetworkError"). */
internal class CognitoError(override val message: String?, val code: String, val status: Int? = null) : Exception(message)

/** Raised by sign-in steps that need one more answer (new password, authenticator code). */
internal class Challenge(val name: String, parameters: JMap?, val session: String?) : Exception(name) {
    val parameters: JMap = parameters ?: LinkedHashMap()
}

// ---- tokens and session -------------------------------------------------------------------------

internal class JwtToken(token: String?) {
    val jwtToken: String = token ?: ""
    val payload: JMap = try {
        parseJson(utf8Dec(b64Any(jwtToken.split(".")[1]))).asMap() ?: LinkedHashMap()
    } catch (e: Exception) {
        LinkedHashMap()
    }

    val expiration: Long? get() = toLongOrNull(payload["exp"])
    val issuedAt: Long? get() = toLongOrNull(payload["iat"])
}

internal class Session(idToken: String?, accessToken: String?, refreshToken: String?, clockDrift: Long? = null) {
    val idToken = JwtToken(idToken)
    val accessToken = JwtToken(accessToken)
    val refreshToken: String = refreshToken ?: ""
    val clockDrift: Long = clockDrift ?: calculateClockDrift()

    /** Seconds this device's clock is ahead of the token issuer's, measured when the tokens arrive. */
    private fun calculateClockDrift(): Long {
        val now = System.currentTimeMillis() / 1000
        return now - Math.min(accessToken.issuedAt ?: now, idToken.issuedAt ?: now)
    }

    fun isValid(): Boolean {
        val adjusted = System.currentTimeMillis() / 1000 - clockDrift
        return adjusted < (accessToken.expiration ?: 0) && adjusted < (idToken.expiration ?: 0)
    }
}

// ---- client ---------------------------------------------------------------------------------------

internal class CognitoClient(region: String, base: OkHttpClient) {
    private val endpoint = "https://cognito-idp.$region.amazonaws.com/"
    private val client = base.newBuilder()
        .connectTimeout(COGNITO_REQUEST_TIMEOUT, TimeUnit.SECONDS)
        .readTimeout(COGNITO_REQUEST_TIMEOUT, TimeUnit.SECONDS)
        .writeTimeout(COGNITO_REQUEST_TIMEOUT, TimeUnit.SECONDS)
        .build()

    /** One call to the user pool API. Keys whose value is null are left out, as JSON.stringify drops undefined. */
    fun request(operation: String, params: JMap, timeLimitMs: Long? = null): JMap {
        val clean = LinkedHashMap<String, Any?>()
        for ((k, v) in params) if (v != null) clean[k] = v
        val req = Request.Builder().url(endpoint)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "AWSCognitoIdentityProviderService.$operation")
            .header("Cache-Control", "no-store")
            .post(utf8(jsJson(clean)).toRequestBody(null))
            .build()
        val call = client.newCall(req)
        if (timeLimitMs != null) call.timeout().timeout(Math.max(1L, timeLimitMs), TimeUnit.MILLISECONDS)
        try {
            call.execute().use { resp ->
                val raw = resp.body?.bytes() ?: ByteArray(0)
                val data = if (raw.isEmpty()) LinkedHashMap() else (parseJsonOrNull(utf8Dec(raw)).getOrNull().asMap() ?: LinkedHashMap())
                if (resp.isSuccessful) return data
                val kind = (data["__type"] as? String)?.takeIf { it.isNotEmpty() } ?: (data["code"] as? String)?.takeIf { it.isNotEmpty() }
                if (kind != null) {
                    throw CognitoError((data["message"] as? String) ?: (data["Message"] as? String), kind.split("#").last(), resp.code)
                }
                val header = resp.header("x-amzn-errortype")
                if (!header.isNullOrEmpty()) throw CognitoError(resp.code.toString(), header.split(":")[0], resp.code)
                throw CognitoError(resp.code.toString(), "UnknownError", resp.code)
            }
        } catch (e: java.io.InterruptedIOException) {
            // the time limit of the whole call (timeLimitMs) ran out
            if (timeLimitMs != null && e.message == "timeout") throw CognitoError("Timeout", "Timeout")
            throw CognitoError("Network error", "NetworkError")
        } catch (e: IOException) {
            throw CognitoError("Network error", "NetworkError")
        }
    }

    /**
     * request() with jittered exponential retries on ANY error, as skapi-js does for a token
     * refresh: waits of about 0.2, 0.4, 0.8, 1.6 and 3.2 seconds (plus up to 0.1 s), then gives
     * up when the next wait would pass 5 seconds.
     */
    fun requestWithRetry(operation: String, params: JMap, timeLimitMs: Long? = null): JMap {
        var attempt = 1
        val startedAt = System.nanoTime()
        fun left(): Long? = timeLimitMs?.let { it - (System.nanoTime() - startedAt) / 1_000_000 }
        while (true) {
            val before = left()
            if (before != null && before <= 0) throw CognitoError("Timeout", "Timeout")
            try {
                return request(operation, params, before)
            } catch (e: CognitoError) {
                if (e.code == "Timeout") throw e
                val delay = Math.pow(2.0, attempt.toDouble()) * 100 + 100 * Math.random()
                if (delay > 5000) throw e
                // The retries stay inside the time limit too. An answer from the server (a refused
                // refresh token, a deleted user) is kept as it is: only "no answer" becomes Timeout.
                val now = left()
                if (now != null && now <= delay) throw if (e.status != null) e else CognitoError("Timeout", "Timeout")
                Thread.sleep(delay.toLong())
                attempt++
            }
        }
    }
}

// ---- the user pool, as skapi-kotlin uses it -------------------------------------------------------

internal class UserPool(val userPoolId: String, val clientId: String, val storage: SkapiStorage, base: OkHttpClient) {
    val poolName: String
    val client: CognitoClient
    val keyPrefix: String = "CognitoIdentityServiceProvider.$clientId"

    init {
        if (userPoolId.isEmpty() || clientId.isEmpty() || "_" !in userPoolId) throw IllegalArgumentException("Both UserPoolId and ClientId are required.")
        poolName = userPoolId.split("_")[1]
        client = CognitoClient(userPoolId.split("_")[0], base)
    }

    // -- storage --------------------------------------------------------------------------------

    fun lastAuthUser(): String? = storage.getItem("$keyPrefix.LastAuthUser")

    fun cacheTokens(username: String, session: Session) {
        val p = "$keyPrefix.$username"
        storage.setItem("$p.idToken", session.idToken.jwtToken)
        storage.setItem("$p.accessToken", session.accessToken.jwtToken)
        storage.setItem("$p.refreshToken", session.refreshToken)
        storage.setItem("$p.clockDrift", session.clockDrift.toString())
        storage.setItem("$keyPrefix.LastAuthUser", username)
    }

    fun clearCachedTokens(username: String) {
        val p = "$keyPrefix.$username"
        for (key in listOf("$p.idToken", "$p.accessToken", "$p.refreshToken", "$keyPrefix.LastAuthUser", "$p.clockDrift", "$p.userData")) {
            storage.removeItem(key)
        }
    }

    fun cachedSession(username: String): Session? {
        val p = "$keyPrefix.$username"
        val idToken = storage.getItem("$p.idToken")
        if (idToken.isNullOrEmpty()) return null
        val clockDrift = storage.getItem("$p.clockDrift")?.toLongOrNull() ?: 0L
        return Session(idToken, storage.getItem("$p.accessToken") ?: "", storage.getItem("$p.refreshToken") ?: "", clockDrift)
    }

    fun sessionFromResult(result: JMap?, refreshToken: String? = null): Session =
        Session(result.s("IdToken"), result.s("AccessToken"), result.s("RefreshToken")?.takeIf { it.isNotEmpty() } ?: refreshToken)

    // -- sign-up and sign-in -------------------------------------------------------------------

    fun signUp(username: String, password: String, attributes: List<JMap>, clientMetadata: JMap? = null): JMap =
        client.request("SignUp", jmap(
            "ClientId" to clientId,
            "Username" to username,
            "Password" to password,
            "UserAttributes" to attributes,
            "ValidationData" to null,
            "ClientMetadata" to clientMetadata,
        ))

    /**
     * SRP sign-in. Returns (username for SRP, Session) on success, or throws Challenge for a next
     * step (NEW_PASSWORD_REQUIRED, SOFTWARE_TOKEN_MFA, ...) and CognitoError for a refusal.
     */
    fun authenticate(username: String, password: String): Pair<String, Session> {
        val helper = SrpHelper(poolName)
        val data = client.request("InitiateAuth", jmap(
            "AuthFlow" to "USER_SRP_AUTH",
            "ClientId" to clientId,
            "AuthParameters" to jmap("USERNAME" to username, "SRP_A" to helper.largeA.toString(16)),
            "ClientMetadata" to jmap(),
        ))
        val params = data.m("ChallengeParameters") ?: throw CognitoError("Missing challenge parameters.", "UnknownError")
        val srpUsername = params.s("USER_ID_FOR_SRP") ?: username
        val hkdf = helper.passwordAuthenticationKey(srpUsername, password, Srp.hexToInt(params.s("SRP_B") ?: ""), Srp.hexToInt(params.s("SALT") ?: ""))
        val now = Srp.cognitoTimestamp()
        val secretBlock = params.s("SECRET_BLOCK") ?: ""
        val message = poolName.toByteArray(Charsets.UTF_8) + srpUsername.toByteArray(Charsets.UTF_8) + b64Any(secretBlock) + now.toByteArray(Charsets.UTF_8)
        val signature = b64(Srp.hmacSha256(hkdf, message))
        val answer = client.request("RespondToAuthChallenge", jmap(
            "ChallengeName" to "PASSWORD_VERIFIER",
            "ClientId" to clientId,
            "ChallengeResponses" to jmap(
                "USERNAME" to srpUsername,
                "PASSWORD_CLAIM_SECRET_BLOCK" to secretBlock,
                "TIMESTAMP" to now,
                "PASSWORD_CLAIM_SIGNATURE" to signature,
            ),
            "Session" to data["Session"],
            "ClientMetadata" to jmap(),
        ))
        return Pair(srpUsername, finish(srpUsername, answer))
    }

    private fun finish(username: String, answer: JMap): Session {
        val name = answer.s("ChallengeName")
        if (name == "DEVICE_SRP_AUTH") throw CognitoError("Device authentication is not supported.", "DeviceAuthenticationNotSupported")
        if (!name.isNullOrEmpty()) throw Challenge(name, answer.m("ChallengeParameters"), answer.s("Session"))
        val session = sessionFromResult(answer.m("AuthenticationResult"))
        cacheTokens(username, session)
        return session
    }

    fun completeNewPassword(username: String, newPassword: String, challengeSession: String?): Session {
        val answer = client.request("RespondToAuthChallenge", jmap(
            "ChallengeName" to "NEW_PASSWORD_REQUIRED",
            "ClientId" to clientId,
            "ChallengeResponses" to jmap("NEW_PASSWORD" to newPassword, "USERNAME" to username),
            "Session" to challengeSession,
        ))
        return finish(username, answer)
    }

    fun sendMfaCode(username: String, code: String, challengeSession: String?): Session {
        val answer = client.request("RespondToAuthChallenge", jmap(
            "ChallengeName" to "SOFTWARE_TOKEN_MFA",
            "ChallengeResponses" to jmap("USERNAME" to username, "SMS_MFA_CODE" to code, "SOFTWARE_TOKEN_MFA_CODE" to code),
            "ClientId" to clientId,
            "Session" to challengeSession,
        ))
        return finish(username, answer)
    }

    fun selectMfaType(username: String, answerName: String, challengeSession: String?): Challenge {
        val data = client.request("RespondToAuthChallenge", jmap(
            "ChallengeName" to "SELECT_MFA_TYPE",
            "ChallengeResponses" to jmap("USERNAME" to username, "ANSWER" to answerName),
            "ClientId" to clientId,
            "Session" to challengeSession,
        ))
        return Challenge(data.s("ChallengeName")?.takeIf { it.isNotEmpty() } ?: answerName, data.m("ChallengeParameters"), data.s("Session"))
    }

    // -- session --------------------------------------------------------------------------------

    /** REFRESH_TOKEN_AUTH with retries. A NotAuthorizedException ends the stored session. */
    fun refresh(username: String, refreshToken: String): Session {
        var user = username
        val auth = jmap("REFRESH_TOKEN" to refreshToken)
        val last = lastAuthUser()
        if (!last.isNullOrEmpty()) {
            user = last
            // sent as skapi-js sends it: null, since no device is ever remembered
            auth["DEVICE_KEY"] = storage.getItem("$keyPrefix.$user.deviceKey")
        }
        val params = jmap("ClientId" to clientId, "AuthFlow" to "REFRESH_TOKEN_AUTH", "AuthParameters" to auth)
        val result = try {
            // 2.7.0: a refresh gets TOKEN_REFRESH_TIME_LIMIT_MS in all, retries included. A connection
            // that stalls (after a sleep, a network change) instead of failing then ends with
            // code "Timeout" and the session is kept, rather than holding every signed-in call.
            client.requestWithRetry("InitiateAuth", params, TOKEN_REFRESH_TIME_LIMIT_MS)
        } catch (e: CognitoError) {
            if (e.code == "NotAuthorizedException") clearCachedTokens(user)
            throw e
        }
        val session = sessionFromResult(result.m("AuthenticationResult"), refreshToken)
        cacheTokens(user, session)
        return session
    }

    // -- calls made with the access token -----------------------------------------------------

    fun call(operation: String, accessToken: String, vararg params: Pair<String, Any?>): JMap {
        val m = jmap(*params)
        m["AccessToken"] = accessToken
        return client.request(operation, m)
    }

    fun callPublic(operation: String, vararg params: Pair<String, Any?>): JMap {
        val m = jmap(*params)
        m["ClientId"] = clientId
        return client.request(operation, m)
    }
}
