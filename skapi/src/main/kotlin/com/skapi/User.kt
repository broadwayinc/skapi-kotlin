package com.skapi

import java.net.URI
import java.util.concurrent.TimeUnit

/*
 * Account methods, ported from skapi-py (_user.py), itself a port of skapi-js
 * (src/methods/user.ts): sign-up, sign-in (with authenticator app MFA), sessions, profile,
 * password and e-mail verification, user search and tickets.
 */

private val SKIP_CLAIMS = setOf("aud", "cognito:username", "event_id", "exp", "iat", "iss", "jti", "origin_jti", "secret_key", "token_use")
private val RENAME_CLAIMS = mapOf("auth_time" to "log", "sub" to "user_id")
private val EMAIL = Regex("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$")
private val BIRTHDATE = Regex("([12]\\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01]))")
private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOption.IGNORE_CASE)
internal const val ANONYMOUS_KEEPALIVE_SECONDS = 600L
/** a return within a minute of the last confirmation needs no check (skapi-js ANONYMOUS_RECHECK_MS) */
internal const val ANONYMOUS_RECHECK_MS = 60_000L
private val CUSTOM = setOf("email_public", "address_public", "gender_public", "birthdate_public", "phone_number_public", "misc", "service", "owner")

/** The ID token's claims as the user profile skapi-js returns. */
internal fun parseUserAttributes(claims: JMap): JMap {
    val user = LinkedHashMap<String, Any?>()
    val username = claims["cognito:username"]
    if (username is String) {
        val parts = username.split("-")
        if (parts.size == 2 && parts[1].startsWith("anon")) user["anonymous"] = true
    }
    for ((k, v) in claims) {
        if (k in SKIP_CLAIMS) continue
        val renamed = RENAME_CLAIMS[k]
        when {
            renamed != null -> user[renamed] = v
            "custom:" in k -> user[k.replace("custom:", "")] = v
            k == "address" -> {
                val m = v.asMap()
                if (m != null) {
                    val formatted = m["formatted"]
                    if (truthy(formatted)) {
                        user["address"] = (formatted as? String)?.let { f -> parseJsonOrNull(f).getOrElse { f } } ?: formatted
                    }
                } else user["address"] = v
            }
            else -> user[k] = v
        }
    }
    for (k in listOf("address_public", "birthdate_public", "email_public", "gender_public", "phone_number_public")) {
        val base = k.removeSuffix("_public") // the attribute the flag belongs to: "phone_number" for "phone_number_public"
        if (user.containsKey(base)) {
            val v = user[k]
            user[k] = try {
                when (v) {
                    null -> false
                    is Boolean -> v
                    is Number -> v.toDouble() != 0.0
                    is String -> if (v.isEmpty()) false else v.trim().toDouble() != 0.0
                    else -> false
                }
            } catch (e: NumberFormatException) {
                false
            }
        } else user.remove(k)
    }
    user["access_group"] = try {
        when (val g = user["access_group"]) {
            null -> 0L
            is Number -> g.toDouble().toLong()
            is String -> if (g.isEmpty()) 0L else g.trim().toDouble().toLong()
            is Boolean -> if (g) 1L else 0L
            else -> 0L
        }
    } catch (e: NumberFormatException) {
        0L
    }
    for (k in listOf("email", "phone_number")) {
        if (user.containsKey(k)) user["${k}_verified"] = user["${k}_verified"] == true
        else user.remove("${k}_verified")
    }
    return user
}

internal fun validateEmail(v: Any?): String {
    if (!truthy(v)) throw perr("\"email\" is required.")
    if (v !is String) throw perr("\"email\" should be type: string.")
    if (v.length < 5) throw perr("\"email\" should be at least 5 characters.")
    val domain = v.trim().split("@").getOrNull(1) ?: ""
    if (!EMAIL.matches(v) || domain.split(".").size < 2) throw perr("\"$v\" is an invalid email.")
    return v.trim().lowercase()
}

internal fun validatePassword(v: Any?, field: String = "password"): String {
    if (!truthy(v)) throw perr("\"$field\" is required.")
    if (v !is String) throw perr("\"$field\" should be type: string.")
    if (v.length < 6) throw perr("\"$field\" should be at least 6 characters.")
    if (v.length > 60) throw perr("\"$field\" can be up to 60 characters max.")
    return v
}

private fun validatePhone(v: Any?): String {
    if (!truthy(v)) return ""
    if (v !is String || !v.startsWith("+")) throw perr("\"phone_number\" is invalid. The format should be \"+00123456789\". Type: string.")
    val rest = v.substring(1).trim().replaceFirst(".", "")
    if (rest.isEmpty() || !rest.all { it in '0'..'9' }) throw perr("\"phone_number\" is invalid. The format should be \"+00123456789\". Type: string.")
    return v
}

private fun validateBirthdate(v: Any?): String {
    if (!truthy(v)) return ""
    if (v !is String || v.length != 10 || v.split("-").size != 3 || BIRTHDATE.find(v) == null) {
        throw perr("\"birthdate\" is invalid. The format should be \"yyyy-mm-dd\". Type: string.")
    }
    return v
}

/** An absolute url ("*" allowed); a url with no path gets "/" (as skapi-py _url). */
internal fun validateUrl(v: Any?): String {
    if (!truthy(v)) return ""
    if (v == "*") return "*"
    val text = v as? String ?: throw perr("\"${jsJson(v).trim('"')}\" is an invalid url.")
    val uri = try { URI(text) } catch (e: Exception) { null }
    if (uri == null || uri.scheme.isNullOrEmpty() || uri.rawAuthority.isNullOrEmpty()) throw perr("\"$text\" is an invalid url.")
    return if (!uri.rawPath.isNullOrEmpty()) text else "$text/"
}

private fun validateAddress(v: Any?): String {
    if (!truthy(v)) return ""
    if (v is String) return v
    if (v is Map<*, *>) return jsJson(v)
    throw perr("\"address\" should be type: <string | dict>.")
}

private fun stringField(field: String): (Any?) -> Any? = { v ->
    if (v !is String) throw perr("${jd(v)} is invalid in \"$field\". allowed type or value is: Type<string>.")
    v
}

private fun booleanField(field: String): (Any?) -> Any? = { v ->
    if (v !is Boolean) throw perr("${jd(v)} is invalid in \"$field\". allowed type or value is: Type<boolean>.")
    v
}

private fun mfaCode(v: Any?): String {
    val code = (v?.toString() ?: "").replace(Regex("\\s+"), "")
    if (!Regex("^\\d{6}$").matches(code)) throw perr("\"code\" should be the 6 digit code from the authenticator app.")
    return code
}

/** "#CODE: text" messages from the pool's triggers carry their own code. */
private fun parsedCognitoError(err: CognitoError): SkapiException {
    val code = err.code.trim().ifEmpty { "ERROR" }
    val message = (err.message ?: "An error occurred.").trim().ifEmpty { "An error occurred." }
    val m = Regex("#([A-Za-z0-9_]+)\\s*:\\s*([\\s\\S]+)").find(message)
    if (m != null) return SkapiException(m.groupValues[2].trim(), m.groupValues[1].trim(), err)
    return SkapiException(message, code, err)
}

// ---- helpers ------------------------------------------------------------------------------------

internal fun Core.cognitoName(name: String): String = if ("$service-" in name) name else "$service-${Md5Js.md5(name)}"

internal fun Core.refuseAnonymous(what: String) {
    if (user?.get("anonymous") == true) throw skErr("Anonymous accounts cannot $what.", "INVALID_REQUEST")
}

internal fun Core.requireSession() {
    ensureConnection()
    if (!signedIn()) throw skErr("User login is required.", "INVALID_REQUEST")
}

// ---- sign-in ------------------------------------------------------------------------------------

private fun Core.authenticate(name: String, password: String, raw: Boolean = false, isOpenId: Boolean = false): JMap {
    requestSignupConfirmation = null
    disabledAccount = null
    pendingMfa = null
    val pool = userPool()
    val username = if (raw) name else cognitoName(name)
    try {
        val (srpUsername, session) = pool.authenticate(username, password)
        adoptSession(srpUsername, session)
        disabledAccount = null
        encAfterLogin(password)
        return userCopy() ?: LinkedHashMap()
    } catch (ch: Challenge) {
        return handleChallenge(ch, username, password)
    } catch (err: CognitoError) {
        val code = err.code
        val message = err.message ?: ""
        if (code == "NotAuthorizedException") {
            if ("User is disabled." in message) {
                disabledAccount = username
                throw SkapiException("This account is disabled.", "USER_IS_DISABLED", err)
            }
            if (isOpenId) throw SkapiException("The account already exists.", "ACCOUNT_EXISTS", err)
            throw SkapiException("Incorrect username or password.", "INCORRECT_USERNAME_OR_PASSWORD", err)
        }
        if (code == "UserNotFoundException") throw SkapiException("Incorrect username or password.", "INCORRECT_USERNAME_OR_PASSWORD", err)
        if (code == "UserNotConfirmedException") {
            requestSignupConfirmation = username
            throw SkapiException("User's signup confirmation is required.", "SIGNUP_CONFIRMATION_NEEDED", err)
        }
        if (code == "TooManyRequestsException" || code == "LimitExceededException") {
            throw SkapiException("Too many attempts. Please try again later.", "REQUEST_EXCEED", err)
        }
        if (code == "NetworkError") throw SkapiException("Network error", "NETWORK_ERROR", err)
        val parsed = parsedCognitoError(err)
        if (parsed.code == "SIGNUP_CONFIRMATION_NEEDED") requestSignupConfirmation = username
        throw parsed
    }
}

private fun Core.handleChallenge(ch: Challenge, username: String, password: String): JMap {
    val pool = userPool()
    val srpUsername = ch.parameters.s("USER_ID_FOR_SRP")?.takeIf { it.isNotEmpty() } ?: username
    when (ch.name) {
        "NEW_PASSWORD_REQUIRED" -> {
            disabledAccount = null
            requestSignupConfirmation = username
            val attrs = (ch.parameters.s("userAttributes")?.takeIf { it.isNotEmpty() } ?: "{}").let { parseJsonOrNull(it).getOrNull().asMap() } ?: LinkedHashMap()
            if (attrs["custom:signup_ticket"] in setOf("PASS", "MEMBER", "OIDPASS")) {
                // an account an admin created, an invitation, or an OpenID account: confirmed by
                // setting the same password
                val session = try {
                    pool.completeNewPassword(srpUsername, password, ch.session)
                } catch (next: Challenge) {
                    return handleChallenge(next, username, password)
                } catch (err: CognitoError) {
                    throw SkapiException(err.message ?: "Failed to authenticate user.", err.code, err)
                }
                adoptSession(srpUsername, session)
                encAfterLogin(password)
                return userCopy() ?: LinkedHashMap()
            }
            throw skErr("User's signup confirmation is required.", "SIGNUP_CONFIRMATION_NEEDED")
        }
        "SOFTWARE_TOKEN_MFA" -> {
            // the password stays in memory only until verifyMfa, to open the encryption keyring
            pendingMfa = PendingMfa(srpUsername, ch.session, password)
            throw skErr("A code from the authenticator app is required to sign in. Call verifyMfa() with the code.", "MFA_REQUIRED")
        }
        "SELECT_MFA_TYPE" -> {
            val next = pool.selectMfaType(srpUsername, "SOFTWARE_TOKEN_MFA", ch.session)
            return handleChallenge(next, username, password)
        }
        "SMS_MFA" -> throw skErr("Sign-in codes by SMS are not supported.", "INVALID_REQUEST")
        "MFA_SETUP" -> throw skErr("The account must set up an authenticator app before signing in.", "INVALID_REQUEST")
    }
    throw skErr("Unsupported sign-in step: ${ch.name}.", "INVALID_REQUEST")
}

private fun Core.authenticateWrapped(name: String, password: String, raw: Boolean = false, isOpenId: Boolean = false): JMap = try {
    authenticate(name, password, raw, isOpenId)
} catch (e: CognitoError) {
    throw parsedCognitoError(e)
} catch (e: IllegalStateException) {
    throw SkapiException(e.message ?: "Failed to authenticate user.", "ERROR", e)
}

/**
 * Signs in with the e-mail (or username) and password. Returns the user's profile.
 * Throws code "MFA_REQUIRED" when the account has two-step login on: call verifyMfa(code).
 */
internal fun Core.login(email: String?, password: String?, usernameIn: String? = null): JMap {
    if (password == null) throw perr("Key \"password\" is required.")
    userPool()
    var username = usernameIn
    var mail = email
    var normalized: String? = null
    if (!mail.isNullOrEmpty()) {
        try {
            normalized = validateEmail(mail)
        } catch (e: SkapiException) {
            username = mail
            mail = null
        }
    }
    if (username.isNullOrEmpty() && mail.isNullOrEmpty()) throw perr("At least one of \"username\" or \"email\" is required.")
    val typed = if (!username.isNullOrEmpty()) username else mail!!
    val first = normalized ?: typed
    val fallback = if (normalized != null && normalized != typed) typed else null
    try {
        return authenticateWrapped(first, password)
    } catch (err: SkapiException) {
        val retryable = err.code in setOf("INCORRECT_USERNAME_OR_PASSWORD", "UserNotFoundException", "NotAuthorizedException")
        if (retryable && fallback != null) {
            try {
                return authenticateWrapped(fallback, password)
            } catch (second: SkapiException) {
                if (second.code in setOf("INCORRECT_USERNAME_OR_PASSWORD", "NOT_EXISTS", "UserNotFoundException", "NotAuthorizedException")) throw err
                throw second
            }
        }
        throw err
    }
}

/** Finishes a login that threw MFA_REQUIRED, with the 6 digit code from the authenticator app (within 3 minutes). */
internal fun Core.verifyMfa(codeIn: String): JMap {
    val code = mfaCode(codeIn)
    val pending = pendingMfa ?: throw skErr("No sign-in is waiting for an authenticator code. Call login() first.", "INVALID_REQUEST")
    val session = try {
        userPool().sendMfaCode(pending.username, code, pending.session)
    } catch (err: CognitoError) {
        if (err.code == "CodeMismatchException") throw SkapiException("Incorrect authenticator code.", "INVALID_CODE", err)
        if (err.code == "ExpiredCodeException") throw SkapiException("This authenticator code was already used. Wait for the next code.", "INVALID_CODE", err)
        pendingMfa = null
        if (err.code in setOf("TooManyRequestsException", "LimitExceededException", "TooManyFailedAttemptsException")) {
            throw SkapiException("Too many attempts. Please try again later.", "REQUEST_EXCEED", err)
        }
        if (err.code == "NotAuthorizedException") throw SkapiException("The sign-in has expired. Call login() again.", "INVALID_REQUEST", err)
        throw parsedCognitoError(err)
    } catch (ch: Challenge) {
        throw skErr("Unsupported sign-in step: ${ch.name}.", "INVALID_REQUEST")
    }
    pendingMfa = null
    adoptSession(pending.username, session)
    disabledAccount = null
    encAfterLogin(pending.password)
    return userCopy() ?: LinkedHashMap()
}

/** Signs out. globalLogout = true also ends every session of the account on every device. */
internal fun Core.logout(globalLogout: Boolean = false): String {
    restore()
    val s = session
    if (user?.get("anonymous") == true) {
        try {
            call("anonymous-session", jmap("end" to true), auth = true)
        } catch (e: SkapiException) {
        }
        clearSession()
    } else if (globalLogout && s != null) {
        try {
            userPool().call("GlobalSignOut", accessToken())
        } catch (err: CognitoError) {
            throw parsedCognitoError(err)
        }
        clearSession()
    } else {
        clearSession()
    }
    return "SUCCESS: The user has been logged out."
}

/** The signed-in user's profile, or null. refreshToken = true asks the server for fresh tokens first. */
internal fun Core.getProfile(refreshToken: Boolean = false): JMap? {
    if (!refreshToken) return userCopy()
    return try {
        restore()
        val s = session
        if (s != null && restoreRefreshedToken == s.idToken.jwtToken) {
            // the stored tokens had expired and were just refreshed: one refresh, not two
            restoreRefreshedToken = null
        } else {
            refreshSession(newClaims = true)
        }
        userCopy()
    } catch (e: SkapiException) {
        null
    }
}

/**
 * Adopts the tokens of a sign-in made elsewhere (for example skapi-js on a web page that sent
 * skapi.session's tokens to your app). All three tokens are needed to make signed-in calls.
 */
internal fun Core.loginWithToken(idToken: String, accessToken: String, refreshToken: String): JMap {
    for ((name, value) in listOf("id_token" to idToken, "access_token" to accessToken, "refresh_token" to refreshToken)) {
        if (value.isEmpty()) throw perr("\"$name\" is required.")
    }
    val payload = JwtToken(idToken).payload
    if (payload["custom:service"] != service) throw skErr("Token does not belong to this service.", "INVALID_REQUEST")
    if ((toLongOrNull(payload["exp"]) ?: 0) < System.currentTimeMillis() / 1000) throw skErr("Token has expired.", "INVALID_REQUEST")
    restore()
    val session = Session(idToken, accessToken, refreshToken)
    val username = payload["cognito:username"] as? String ?: throw skErr("Invalid session.", "INVALID_REQUEST")
    adoptSession(username, session)
    userPool().cacheTokens(username, session)
    return userCopy() ?: LinkedHashMap()
}

// ---- sign-up ------------------------------------------------------------------------------------

/**
 * Creates an account. params: email and password (required), and any profile fields.
 * option: signup_confirmation (true or a redirect URL), email_subscription, login (sign in right after), template.
 */
internal fun Core.signup(paramsIn: JMap?, optionIn: JMap?): Any {
    userPool()
    val params = paramsIn.copyMap()
    val option = optionIn.copyMap()
    if (!params.containsKey("email")) throw perr("Key \"email\" is required.")
    if (!params.containsKey("password")) throw perr("Key \"password\" is required.")
    val p = LinkedHashMap<String, Any?>()
    val checks: List<Pair<String, (Any?) -> Any?>> = listOf(
        "username" to stringField("username"), "password" to { v -> validatePassword(v) }, "email" to { v -> validateEmail(v) },
        "name" to stringField("name"), "address" to { v -> validateAddress(v) }, "gender" to stringField("gender"),
        "birthdate" to { v -> validateBirthdate(v) }, "phone_number" to { v -> validatePhone(v) }, "misc" to stringField("misc"),
        "picture" to { v -> validateUrl(v) }, "profile" to { v -> validateUrl(v) }, "family_name" to stringField("family_name"),
        "given_name" to stringField("given_name"), "middle_name" to stringField("middle_name"), "nickname" to stringField("nickname"),
        "website" to { v -> validateUrl(v) },
    )
    for ((k, fn) in checks) if (params.containsKey(k)) p[k] = fn(params[k])
    for (k in listOf("email_public", "address_public", "gender_public", "birthdate_public", "phone_number_public")) {
        p[k] = params[k] as? Boolean ?: false
    }

    logout()

    var sc: Any? = option["signup_confirmation"] ?: false
    if (sc is String) sc = validateUrl(sc)
    else if (sc !is Boolean) throw perr("\"option.signup_confirmation\" should be type: <string | boolean>.")
    if (truthy(sc) && !truthy(p["email"])) throw perr("\"email\" is required for signup confirmation.")
    val es: Any? = if (option.containsKey("email_subscription")) option["email_subscription"] else false
    val esOk = es is Boolean || es is String || (es is Number && (es.toDouble() == 0.0 || es.toDouble() == 1.0) && es.toDouble() == Math.floor(es.toDouble()))
    if (!esOk) throw perr("\"option.email_subscription\" takes 0 (public), 1 (authorized), true, false or the name of a newsletter group.")
    if (es != false && !truthy(sc)) throw perr("\"option.signup_confirmation\" is required for email subscription.")
    val loginAfter = option["login"] ?: false
    if (loginAfter !is Boolean) throw perr("\"option.login\" should be type: boolean.")
    if (loginAfter && truthy(sc)) throw perr("\"login\" is not allowed when \"option.signup_confirmation\" is true.")
    val templateRaw = option["template"]
    val template = if (!truthy(templateRaw)) LinkedHashMap() else templateRaw.asMap() ?: throw perr("\"option.template\" should be type: <object>.")
    for (key in listOf("signup_confirmation", "welcome")) {
        if (template.containsKey(key) && (template[key] !is String || (template[key] as String).isEmpty())) {
            throw perr("\"option.template.$key\" should be a non-empty <string> (template message_id).")
        }
    }
    if (truthy(template["signup_confirmation"]) && !truthy(sc)) throw perr("\"option.signup_confirmation\" is required when \"option.template.signup_confirmation\" is set.")
    if (p["email_public"] == true && !truthy(sc)) throw perr("\"option.signup_confirmation\" should be true if \"email_public\" is set to true.")

    val nameForAccount = (p["username"] as? String)?.takeIf { it.isNotEmpty() } ?: p["email"] as String
    val cognitoUsername = cognitoName(nameForAccount)
    val keyReply = call("signupkey", jmap(
        "username" to cognitoUsername,
        "signup_confirmation" to (if (sc is Boolean) jsJson(sc) else sc),
        "email_subscription" to es,
        "template_confirmation" to (template.s("signup_confirmation") ?: ""),
        "template_welcome" to (template.s("welcome") ?: ""),
    ))
    val parts = (if (keyReply is String) keyReply else jsJson(keyReply)).split(":")
    val signupKey = parts[0]
    val signupTicket = parts.drop(1).joinToString(":")
    val attributes = mutableListOf(
        jmap("Name" to "custom:signup", "Value" to signupKey),
        jmap("Name" to "locale", "Value" to (if ("#" in signupTicket) signupTicket.split("#")[1] else "")),
        jmap("Name" to "custom:signup_ticket", "Value" to signupTicket),
    )
    val values = LinkedHashMap(p)
    values["service"] = service
    values["owner"] = owner
    for (k in listOf("email", "name", "address", "gender", "birthdate", "phone_number", "email_public", "address_public", "gender_public",
        "birthdate_public", "phone_number_public", "misc", "picture", "profile", "family_name", "given_name", "middle_name",
        "nickname", "website", "service", "owner")) {
        var v = values[k]
        if (v == "") continue
        if (k.endsWith("_public")) v = if (truthy(v)) "1" else "0"
        attributes.add(jmap("Name" to (if (k in CUSTOM) "custom:$k" else k), "Value" to (if (v == null) "" else if (v is String) v else jsJson(v))))
    }
    try {
        userPool().signUp(cognitoUsername, p["password"] as String, attributes)
    } catch (err: CognitoError) {
        val parsed = parsedCognitoError(err)
        when (err.code) {
            "UsernameExistsException" -> throw SkapiException("The account already exists.", "EXISTS", err)
            "InvalidPasswordException" -> throw SkapiException("Invalid password. Password must be at least 6 characters.", "INVALID_PARAMETER", err)
            "InvalidParameterException" -> throw SkapiException(parsed.message.ifEmpty { "Invalid parameter." }, "INVALID_PARAMETER", err)
            "TooManyRequestsException", "LimitExceededException" -> throw SkapiException("Too many attempts. Please try again later.", "REQUEST_EXCEED", err)
            "CodeDeliveryFailureException" -> throw SkapiException("Failed to deliver verification code.", "CODE_DELIVERY_FAILURE", err)
            "UserLambdaValidationException" -> throw SkapiException(parsed.message.ifEmpty { "Signup validation failed." }, if (parsed.code == "EXISTS") "EXISTS" else "INVALID_REQUEST", err)
        }
        throw parsed
    }
    if (truthy(sc)) {
        requestSignupConfirmation = cognitoUsername
        return "SUCCESS: The account has been created. User's signup confirmation is required."
    }
    if (loginAfter) return login(nameForAccount, p["password"] as String)
    return "SUCCESS: The account has been created."
}

internal fun Core.resendSignupConfirmation(): Any? {
    val username = requestSignupConfirmation ?: throw skErr("Least one login attempt is required.", "INVALID_REQUEST")
    return call("confirm-signup", jmap("username" to username))
}

/** Sends the recovery e-mail to a disabled account, after a login attempt answered USER_IS_DISABLED. */
internal fun Core.recoverAccount(redirectIn: Any? = false): String {
    var redirect = redirectIn
    if (redirect is String) redirect = validateUrl(redirect)
    else if (redirect !is Boolean) throw skErr("Argument should be type: <boolean | string>.", "INVALID_REQUEST")
    val account = disabledAccount ?: throw skErr("Least one signin attempt of disabled account is required.", "INVALID_REQUEST")
    call("recover-account", jmap("username" to account, "redirect" to redirect))
    return "SUCCESS: Recovery e-mail has been sent."
}

internal fun Core.disableAccount(): Any? {
    requireSession()
    refuseAnonymous("be disabled")
    val result = call("remove-account", jmap("disable" to user.s("user_id")), auth = true)
    logout()
    return result
}

// ---- profile and password -------------------------------------------------------------------------

/** Changes the signed-in user's own profile fields. "" clears a field. */
internal fun Core.updateProfile(paramsIn: JMap?): JMap? {
    requireSession()
    refuseAnonymous("edit their profile")
    val params = paramsIn.copyMap()
    val p = LinkedHashMap<String, Any?>()
    val checks = mutableListOf<Pair<String, (Any?) -> Any?>>(
        "email" to { v -> validateEmail(v) }, "address" to { v -> validateAddress(v) }, "name" to stringField("name"),
        "gender" to stringField("gender"), "birthdate" to { v -> validateBirthdate(v) }, "phone_number" to { v -> validatePhone(v) },
        "misc" to stringField("misc"), "picture" to { v -> validateUrl(v) }, "profile" to { v -> validateUrl(v) },
        "website" to { v -> validateUrl(v) }, "family_name" to stringField("family_name"), "given_name" to stringField("given_name"),
        "middle_name" to stringField("middle_name"), "nickname" to stringField("nickname"),
    )
    for (k in listOf("email_public", "phone_number_public", "address_public", "gender_public", "birthdate_public")) checks.add(k to booleanField(k))
    for ((k, fn) in checks) if (params.containsKey(k)) p[k] = fn(params[k])
    if (p.isEmpty()) return userCopy()
    if (p["email_public"] == true && user?.get("email_verified") != true) {
        throw skErr("User's e-mail should be verified to set \"email_public\" to true.", "INVALID_REQUEST")
    }
    val current = user ?: LinkedHashMap()
    val attributes = mutableListOf<JMap>()
    for ((k, v0) in p) {
        if (v0 !is Map<*, *> && v0 !is List<*> && current.containsKey(k) && jsonEq(current[k], v0)) continue
        val name = if (k in CUSTOM) "custom:$k" else k
        val v = if (v0 is Boolean) (if (v0) "1" else "0") else v0
        attributes.add(jmap("Name" to name, "Value" to (if (v == null) "" else if (v is String) v else jsJson(v))))
    }
    if (attributes.isNotEmpty()) {
        try {
            userPool().call("UpdateUserAttributes", accessToken(), "UserAttributes" to attributes)
        } catch (err: CognitoError) {
            throw SkapiException(err.message ?: "Failed to update user settings.", err.code, err)
        }
        refreshSession(newClaims = true)
    }
    return userCopy()
}

internal fun Core.changePassword(currentPassword: String, newPassword: String): String {
    requireSession()
    refuseAnonymous("change their password")
    if (currentPassword.isEmpty()) throw perr("\"current_password\" is required to change password.")
    if (newPassword.isEmpty()) throw perr("\"new_password\" is required to change password.")
    validatePassword(currentPassword, "current_password")
    validatePassword(newPassword, "new_password")
    // the keyring gets a wrap under the new password BEFORE the password changes (fails while locked)
    val rewrapped = encRewrapPassword(currentPassword, newPassword)
    try {
        userPool().call("ChangePassword", accessToken(), "PreviousPassword" to currentPassword, "ProposedPassword" to newPassword)
    } catch (err: CognitoError) {
        when (err.code) {
            "InvalidParameterException" -> throw SkapiException("Invalid password parameter.", "INVALID_PARAMETER", err)
            "NotAuthorizedException" -> throw SkapiException("Incorrect password.", "INVALID_REQUEST", err)
            "TooManyRequestsException", "LimitExceededException" -> throw SkapiException("Too many attempts. Please try again later.", "REQUEST_EXCEED", err)
        }
        throw parsedCognitoError(err)
    }
    if (rewrapped != null) encPruneWraps()
    return "SUCCESS: Password has been changed."
}

/** Sends a password reset code to the account's e-mail. Then call resetPassword(). */
internal fun Core.forgotPassword(emailIn: String, template: JMap? = null): String {
    ensureConnection()
    val email = validateEmail(emailIn)
    var metadata: JMap? = null
    if (template != null) {
        if (template.containsKey("verification")) {
            throw perr("\"template.verification\" is not an option of forgotPassword(). Use \"template.forgot_password\" (template message_id).")
        }
        if (template.containsKey("forgot_password")) {
            val t = template["forgot_password"]
            if (t !is String || t.isEmpty()) throw perr("\"template.forgot_password\" should be a non-empty <string> (template message_id).")
            metadata = jmap("template_forgot_password" to t)
        }
    }
    try {
        userPool().callPublic("ForgotPassword", "Username" to cognitoName(email), "ClientMetadata" to metadata)
    } catch (err: CognitoError) {
        val parsed = parsedCognitoError(err)
        val code = mapOf(
            "UserNotFoundException" to "NOT_EXISTS", "InvalidParameterException" to "INVALID_PARAMETER", "NotAuthorizedException" to "INVALID_REQUEST",
            "LimitExceededException" to "REQUEST_EXCEED", "TooManyRequestsException" to "REQUEST_EXCEED",
            "CodeDeliveryFailureException" to "CODE_DELIVERY_FAILURE",
        )[err.code] ?: parsed.code.ifEmpty { err.code.ifEmpty { "ERROR" } }
        throw SkapiException(parsed.message, code, err)
    }
    return "SUCCESS: Verification code has been sent."
}

internal fun Core.resetPassword(emailIn: String, code: Any?, newPassword: String): String {
    ensureConnection()
    val email = validateEmail(emailIn)
    if (code !is String && !(code is Number && code.toDouble() == Math.floor(code.toDouble()))) {
        throw perr("${jd(code)} is invalid in \"code\". allowed types or values are: Type<number>, Type<string>.")
    }
    validatePassword(newPassword)
    val codeText = if (code is Number) code.toLong().toString() else code as String
    try {
        userPool().callPublic("ConfirmForgotPassword", "Username" to cognitoName(email), "ConfirmationCode" to codeText, "Password" to newPassword)
    } catch (err: CognitoError) {
        throw SkapiException(err.message ?: "Failed to reset password.", err.code.ifEmpty { "ERROR" }, err)
    }
    return "SUCCESS: New password has been set."
}

/** Without a code: sends a verification code to the user's e-mail. With a code: verifies it. */
internal fun Core.verifyEmail(code: String? = null, template: JMap? = null): String {
    ensureConnection()
    if (!signedIn()) throw skErr("The user has to be logged in.", "INVALID_REQUEST")
    refuseAnonymous("verify an e-mail")
    val u = user ?: throw skErr("The user has to be logged in.", "INVALID_REQUEST")
    if (!u.containsKey("email")) throw skErr("No e-mail to verify", "INVALID_REQUEST")
    if (u["email_verified"] == true) return "SUCCESS: \"email\" is verified."
    var metadata: JMap? = null
    if (template != null && template.containsKey("verification")) {
        val t = template["verification"]
        if (t !is String || t.isEmpty()) throw perr("\"template.verification\" should be a non-empty <string> (template message_id).")
        metadata = jmap("template_verification" to t)
    }
    try {
        if (!code.isNullOrEmpty()) {
            userPool().call("VerifyUserAttribute", accessToken(), "AttributeName" to "email", "Code" to code)
            refreshSession(newClaims = true)
            user?.set("email_verified", true)
            return "SUCCESS: \"email\" is verified."
        }
        userPool().call("GetUserAttributeVerificationCode", accessToken(), "AttributeName" to "email", "ClientMetadata" to metadata)
        return "SUCCESS: Verification code has been sent."
    } catch (err: CognitoError) {
        throw SkapiException(err.message ?: "Failed to request verification code.", err.code, err)
    }
}

internal fun Core.lastVerifiedEmail(revert: Boolean? = null): Any? {
    requireSession()
    refuseAnonymous("change their e-mail")
    val body = if (revert == null) jmap() else jmap("revert" to revert)
    val reply = call("last-verified-email", body, auth = true)
    if (reply is String && "SUCCESS" in reply) {
        refreshSession(newClaims = true)
        return userCopy()
    }
    return reply
}

// ---- OpenID and anonymous -------------------------------------------------------------------------

/** Signs in with a token from your OpenID provider, through the OpenID logger set up as `id`. */
internal fun Core.openIdLogin(token: String, id: String, mergeIn: Any? = null, template: JMap? = null): JMap {
    ensureConnection()
    val body = jmap("token" to token, "id" to id)
    if (mergeIn != null) {
        var merge = mergeIn
        if (merge is String) merge = jlist(merge)
        if (merge is List<*>) {
            if (!merge.all { it is String }) throw perr("\"merge\" array items should be type: <string>.")
        } else if (merge !is Boolean) throw perr("\"merge\" should be type: <boolean | string[]>.")
        body["merge"] = merge
    }
    if (template != null && template.containsKey("welcome")) {
        val t = template["welcome"]
        if (t !is String || t.isEmpty()) throw perr("\"template.welcome\" should be a non-empty <string> (template message_id).")
        body["template_welcome"] = t
    }
    val reply = call("openid-logger", body).asMap() ?: LinkedHashMap()
    val logger = (reply["logger"]?.let { if (it is String) it else jsJson(it) } ?: "").split("#")
    val profile = authenticateWrapped("$service-${logger[0]}", if (logger.size > 1) logger[1] else "", raw = true, isOpenId = true)
    return jmap("userProfile" to profile, "openid" to reply["openid"])
}

/** A temporary account without e-mail or password, deleted 30 minutes after this object stops keeping it alive. */
internal fun Core.anonymousLogin(): JMap {
    ensureConnection()
    if (signedIn()) {
        if (user?.get("anonymous") == true) {
            startAnonymousKeepAlive()
            return userCopy() ?: LinkedHashMap()
        }
        throw skErr("A user is already logged in. Log out first.", "INVALID_REQUEST")
    }
    val creds = call("anonymous-login", jmap()).asMap() ?: throw skErr("Anonymous login failed.", "ERROR")
    val profile = authenticateWrapped(creds.s("username") ?: "", creds.s("password") ?: "", raw = true)
    lastAnonymousBeat = System.currentTimeMillis()
    startAnonymousKeepAlive()
    return profile
}

/**
 * For a temporary account restored from storage: asks the server whether it still exists.
 * Returns the profile, or null (and signs out) when the account was already deleted.
 * Any other user is returned as is, without a request.
 */
internal fun Core.verifyAnonymousSession(): JMap? {
    ensureConnection()
    restore()
    if (user?.get("anonymous") != true) return userCopy()
    try {
        call("anonymous-session", jmap(), auth = true)
        lastAnonymousBeat = System.currentTimeMillis()
    } catch (err: SkapiException) {
        if (err.code == "NOT_EXISTS") {
            clearSession()
            return null
        }
    }
    return userCopy()
}

internal fun Core.startAnonymousKeepAlive(beatNow: Boolean = false) {
    stopAnonymousKeepAlive()
    val core = this
    anonymousTimer = scheduler.schedule({
        if (core.user?.get("anonymous") == true) {
            var gone = false
            try {
                core.call("anonymous-session", jmap(), auth = true)
                core.lastAnonymousBeat = System.currentTimeMillis()
            } catch (err: SkapiException) {
                if (err.code == "NOT_EXISTS") {
                    core.clearSession()
                    gone = true
                }
            } catch (e: Exception) {
            }
            if (!gone) core.startAnonymousKeepAlive()
        }
    }, if (beatNow) 0L else ANONYMOUS_KEEPALIVE_SECONDS, TimeUnit.SECONDS)
}

internal fun Core.stopAnonymousKeepAlive() {
    anonymousTimer?.cancel(false)
    anonymousTimer = null
}

/**
 * The app came back to the foreground, or the network came back (skapi-js does this on
 * visibilitychange, online and pageshow). A phone pauses background work, so the 10 minute keep-alive
 * of a temporary account can miss its 30 minute window: the account is checked at once (unless the
 * server confirmed it within the last minute), and a swept one is signed out right away. The realtime
 * connection is checked too.
 */
internal fun Core.wake() {
    if (user?.get("anonymous") == true && System.currentTimeMillis() - lastAnonymousBeat > ANONYMOUS_RECHECK_MS) {
        try {
            verifyAnonymousSession()
        } catch (e: Exception) {
        }
    }
    realtimeWake()
}

// ---- authenticator app MFA ------------------------------------------------------------------------

private fun Core.mfaUser(what: String): String {
    requireSession()
    refuseAnonymous(what)
    return accessToken()
}

/** Starts two-step login setup: returns {"secret", "uri"}. Show uri as a QR code, then call enableMfa(code). */
internal fun Core.setupMfa(issuerIn: String? = null, accountName: String? = null): JMap {
    val token = mfaUser("set up MFA")
    val secret = try {
        userPool().call("AssociateSoftwareToken", token)["SecretCode"] as? String ?: ""
    } catch (err: CognitoError) {
        throw parsedCognitoError(err)
    }
    val conn = connection ?: LinkedHashMap()
    val issuer = ((issuerIn?.takeIf { it.isNotEmpty() } ?: conn.s("service_name")?.takeIf { it.isNotEmpty() } ?: service)).replace(":", " ").trim()
    val u = user ?: LinkedHashMap()
    val account = (accountName?.takeIf { it.isNotEmpty() } ?: u.s("email")?.takeIf { it.isNotEmpty() }
        ?: u.s("username")?.takeIf { it.isNotEmpty() } ?: u.s("user_id") ?: "").replace(":", " ").trim()
    val label = if (issuer.isNotEmpty()) "${encodeURIComponent(issuer)}:${encodeURIComponent(account)}" else encodeURIComponent(account)
    val uri = "otpauth://totp/$label?secret=$secret" + (if (issuer.isNotEmpty()) "&issuer=${encodeURIComponent(issuer)}" else "") + "&algorithm=SHA1&digits=6&period=30"
    return jmap("secret" to secret, "uri" to uri)
}

internal fun Core.enableMfa(codeIn: String): String {
    val code = mfaCode(codeIn)
    val token = mfaUser("turn on MFA")
    try {
        userPool().call("VerifySoftwareToken", token, "UserCode" to code)
    } catch (err: CognitoError) {
        if (err.code == "SoftwareTokenMFANotFoundException" ||
            (err.code == "InvalidParameterException" && Regex("software token", RegexOption.IGNORE_CASE).containsMatchIn(err.message ?: ""))) {
            throw SkapiException("Call setupMfa() first.", "INVALID_REQUEST", err)
        }
        if (err.code == "EnableSoftwareTokenMFAException" || err.code == "CodeMismatchException") throw SkapiException("Incorrect authenticator code.", "INVALID_CODE", err)
        if (err.code == "TooManyRequestsException" || err.code == "LimitExceededException") throw SkapiException("Too many attempts. Please try again later.", "REQUEST_EXCEED", err)
        throw parsedCognitoError(err)
    }
    try {
        userPool().call("SetUserMFAPreference", token, "SoftwareTokenMfaSettings" to jmap("Enabled" to true, "PreferredMfa" to true))
    } catch (err: CognitoError) {
        throw parsedCognitoError(err)
    }
    return "SUCCESS: MFA has been enabled."
}

internal fun Core.disableMfa(): String {
    val token = mfaUser("turn off MFA")
    try {
        userPool().call("SetUserMFAPreference", token, "SoftwareTokenMfaSettings" to jmap("Enabled" to false, "PreferredMfa" to false))
    } catch (err: CognitoError) {
        throw parsedCognitoError(err)
    }
    return "SUCCESS: MFA has been disabled."
}

internal fun Core.getMfaStatus(): JMap {
    val token = mfaUser("use MFA")
    val data = try {
        userPool().call("GetUser", token)
    } catch (err: CognitoError) {
        throw parsedCognitoError(err)
    }
    return jmap("enabled" to ((data["UserMFASettingList"] as? List<*>)?.contains("SOFTWARE_TOKEN_MFA") ?: false))
}

// ---- users ------------------------------------------------------------------------------------------

/** Searches the project's users by one profile field. Signed-in users only. */
internal fun Core.getUsers(paramsIn: JMap?, fetchOptionsIn: JMap?): Any? {
    val fetchOptions = fetchOptionsIn.copyMap()
    val params: JMap = if (!truthy(paramsIn)) {
        fetchOptions["ascending"] = false
        jmap("searchFor" to "timestamp", "condition" to ">", "value" to 0L)
    } else paramsIn.copyMap()
    val fields = listOf("user_id", "name", "email", "phone_number", "address", "gender", "birthdate", "locale", "subscribers", "timestamp", "access_group", "approved")
    val searchFor = params["searchFor"]
    if (!params.containsKey("searchFor")) throw perr("Key \"searchFor\" is required.")
    if (!params.containsKey("value")) throw perr("Key \"value\" is required.")
    if (searchFor == "") throw perr("\"searchFor\" should not be an empty string.")
    if (searchFor !in fields) {
        throw perr("${jd(searchFor)} is invalid in \"searchFor\". allowed types or values are: " + fields.joinToString(", ") { jd(it) } + ".")
    }
    val conditions = listOf(">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte")
    var condition = if (params.containsKey("condition")) params["condition"] else "="
    if (condition !in conditions) condition = "="

    fun check(v: Any?, what: String): Any? {
        when (searchFor) {
            "user_id" -> if (v !is String || !UUID_RE.matches(v)) throw perr("User ID is invalid.")
            "locale" -> if (v !is String || v.length > 5) throw perr("Value of \"locale\" should be a country code.")
            "birthdate" -> validateBirthdate(v)
            "subscribers", "timestamp", "access_group" -> if (v !is Number) throw perr("$what does not match the type of \"$searchFor\" index.")
            else -> if (v !is String) throw perr("$what does not match the type of \"$searchFor\" index.")
        }
        return v
    }

    val value = params["value"]
    if (value is List<*>) value.forEach { check(it, "Value") } else check(value, "Value")
    val body = jmap("searchFor" to searchFor, "value" to value, "condition" to condition)
    if (params.containsKey("range")) {
        check(params["range"], "Range")
        body["range"] = params["range"]
    }
    if (condition != "=" && params.containsKey("range")) throw perr("Conditions does not apply on range search.")
    if (value is List<*> && (condition != "=" || truthy(params["range"]))) {
        throw perr("Conditions are not allowed on a list of \"$searchFor\" values. Search for a single value to use a condition or range.")
    }
    if (value == "") throw perr("Value should not be an empty string.")
    return call("get-users", body, auth = true, fetchOptions = fetchOptions)
}

// ---- tickets ------------------------------------------------------------------------------------------

/** Calls a ticket of the project (set up on skapi.com) with `data`. Returns its receipt or answer. */
internal fun Core.consumeTicket(ticketId: String, methodIn: String = "POST", data: Any? = null, auth: Boolean = false): Any? {
    ensureConnection()
    if (ticketId.isEmpty()) throw perr("Ticket ID is required.")
    if (!Regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").matches(ticketId)) {
        throw perr("Invalid \"ticket_id\". Use letters, digits, \"_\" and \"-\" (up to 64 chars, starting with a letter or digit).")
    }
    if (methodIn.isEmpty()) throw perr("Method is required. Should be either \"GET\" or \"POST\"")
    val method = methodIn.uppercase()
    if (method != "GET" && method != "POST") throw perr("Method should be either \"GET\" or \"POST\".")
    if (auth && method == "GET") throw perr("Signed-in consumption is POST only.")
    val route = if (auth) "tpa" else if (method == "GET") "tg" else "tp"
    val url = "https://${service.take(4)}.skapi.dev/$route/$service/$ticketId"
    val token = if (auth) freshIdToken() else null
    val reply = requester.request(url, if (truthy(data)) data else jmap(), method = method, token = token, ignoreService = true)
    val rm = reply.asMap()
    if (rm != null && rm.containsKey("stage")) {
        throw skErr((rm["message"] as? String)?.takeIf { it.isNotEmpty() } ?: "Ticket failed.", (rm["code"] as? String)?.takeIf { it.isNotEmpty() } ?: "ERROR", rm)
    }
    if (rm != null && rm["tkid"] is String) return mapTicket(rm)
    return reply
}
