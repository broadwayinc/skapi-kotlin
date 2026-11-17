package com.skapi

import kotlinx.serialization.json.JsonElement

/**
 * Every error skapi-kotlin throws carries a code and a message, the same as skapi-js and skapi-py.
 *
 * code: a short name such as "INVALID_PARAMETER", "INVALID_REQUEST", "NOT_EXISTS",
 * "INCORRECT_USERNAME_OR_PASSWORD" or "MFA_REQUIRED", the same codes skapi-js uses.
 * message: what went wrong, in plain words.
 * cause: the underlying exception, when there is one.
 * details: what the server sent with the error, when it sent more than a message.
 */
public class SkapiException(
    override val message: String,
    public val code: String = "ERROR",
    cause: Throwable? = null,
    public val details: JsonElement? = null,
) : Exception(message, cause) {
    override fun toString(): String = "$code: $message"
}

/** A SkapiException whose cause may be an exception or a server answer (as skapi-py's cause). */
internal fun skErr(message: String, code: String = "ERROR", cause: Any? = null): SkapiException = when (cause) {
    null -> SkapiException(message, code)
    is Throwable -> SkapiException(message, code, cause)
    else -> SkapiException(message, code, null, cause.toJson())
}

/** INVALID_PARAMETER unless another code is given. */
internal fun perr(message: String, code: String = "INVALID_PARAMETER"): SkapiException = SkapiException(message, code)

/** A value as it appears in an error message. */
internal fun jd(v: Any?): String = jsJson(v)
