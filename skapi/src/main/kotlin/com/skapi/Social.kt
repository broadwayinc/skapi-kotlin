package com.skapi

/*
 * User-side newsletters, subscriptions between users, the feed, and ticket listings, ported from
 * skapi-py (_social.py), itself a port of skapi-js (src/methods/subscription.ts, src/methods/user.ts).
 */

private val RESERVED_GROUPS = setOf("tp", "admin", "public", "authorized", "newsletter", "forward", "all", "true", "false", "null")

private val TICKET_KEYS = mapOf(
    "tkid" to "ticket_id", "cond" to "condition", "stmp" to "timestamp", "upd" to "updated", "acts" to "actions", "actn" to "action",
    "cnt" to "count", "ttl" to "time_to_live", "plch" to "placeholder", "hash" to "hash", "desc" to "description", "pmc" to "limit_per_user",
    "fail" to "failed", "rv" to "rules_version", "on" to "enabled", "qn" to "queued", "qdue" to "queued_due", "cc" to "concurrency",
    "cf" to "when_full", "cn" to "running", "ln" to "waiting", "sc" to "self_calling",
)

private val GROUP_NAME = Regex("^[a-z0-9]{2,20}$")
private val HAS_LETTER = Regex("[a-z]")
private val EXPONENT_LIKE = Regex("^[0-9]+e[0-9]+$")
private val DIGITS = Regex("^[0-9]+$")

/** "public" -> 0, "authorized" -> 1, an integer 0..99, or a newsletter group name. */
internal fun newsletterGroup(group: Any?, allowNull: Boolean = false): Any? {
    if (group == null) {
        if (allowNull) return null
        throw perr("\"group\" is required.")
    }
    if (group == "public") return 0L
    if (group == "authorized") return 1L
    if (group is Number) {
        val d = group.toDouble()
        if (d != Math.floor(d) || d < 0 || d > 99) throw perr("\"group\" should be an integer between 0 and 99.")
        return d.toLong()
    }
    if (group is String && GROUP_NAME.matches(group) && HAS_LETTER.containsMatchIn(group)
        && !EXPONENT_LIKE.matches(group) && group !in RESERVED_GROUPS) {
        return group
    }
    throw perr("Newsletter group name must be 2-20 lowercase alphanumeric characters, contain a letter, and not be a reserved name.")
}

/** A ticket row as skapi-js returns it (short server keys renamed, consume ids split). */
internal fun mapTicket(t: JMap): JMap {
    val out = LinkedHashMap<String, Any?>()
    for ((k, v) in t) {
        if (k == "tkid" && v is String) {
            val parts = v.split("#")
            if (parts.size == 1) {
                out["ticket_id"] = parts[0]
            } else {
                out["ticket_id"] = parts[1]
                val consumeId = if (parts.size > 2) parts[2] else ""
                out["consume_id"] = consumeId
                out["user_id"] = parts.drop(3).joinToString("#")
                out["is_test"] = consumeId.takeLast(4) == ":CHK"
                if (!truthy(t["stmp"])) {
                    val ts = if (consumeId.length >= 4) consumeId.substring(0, consumeId.length - 4) else ""
                    out["timestamp"] = if (DIGITS.matches(ts)) (ts.toLongOrNull() ?: fromBase62(ts)) else fromBase62(ts)
                }
            }
        } else if (k in TICKET_KEYS) {
            out[TICKET_KEYS.getValue(k)] = v
        } else {
            out[k] = v
        }
    }
    return out
}

private fun subscriptionRow(s: JMap): JMap {
    val sub = s["sub"]
    val grp = (s["grp"] as? String) ?: ""
    val parts = if (sub is String) sub.split("#") else emptyList()
    val row = jmap(
        "subscriber" to (if (parts.size > 2) parts[2] else s["subscriber"]),
        "subscription" to (if (parts.isNotEmpty()) parts[0] else s["subscription"]),
        "timestamp" to (if (truthy(s["timestamp"])) s["timestamp"] else s["stmp"]),
        "blocked" to (truthy(s["blocked"]) || grp.take(1) == "N"),
    )
    s.m("opt")?.let { row.putAll(it) }
    return row
}

private fun Core.target(params: Any?): String {
    val p = params.asMap()
    if (p == null || !p.containsKey("user_id")) throw perr("Key \"user_id\" is required.")
    return notSelf(p["user_id"])
}

private fun Core.notSelf(uid: Any?, field: String = "\"user_id\""): String {
    val u = user
    if (u != null && uid == u["user_id"]) throw perr("\"user_id\" cannot be the user's own ID.")
    return validateUserId(uid, field)
}

private fun Core.myAccessGroup(): Long = toLongOrNull(user?.get("access_group")) ?: 0L

// ---- newsletters ------------------------------------------------------------------------------

/**
 * Subscribes to the project's newsletters of one group. Signed in: the user's verified e-mail.
 * Signed out: params["email"], which gets a confirmation e-mail first.
 */
internal fun Core.subscribeNewsletter(params: JMap): Any? {
    ensureConnection()
    refuseAnonymous("subscribe to newsletters")
    val p = params.copyMap()
    val signedIn = signedIn()
    if (!p.containsKey("group")) throw perr("Key \"group\" is required.")
    if (!signedIn && !p.containsKey("email")) throw perr("Key \"email\" is required.")
    val body = LinkedHashMap<String, Any?>()
    if (p.containsKey("email")) {
        val e = p["email"]
        body["email"] = if (e is List<*> && e.isNotEmpty()) {
            if (e.size == 1) validateEmail(e[0]) else e.map { validateEmail(it) }.toMutableList<Any?>()
        } else if (e is List<*>) {
            validateEmail("")
        } else {
            validateEmail(e)
        }
    }
    body["group"] = newsletterGroup(p["group"])
    if (p.containsKey("redirect")) body["redirect"] = validateUrl(p["redirect"])
    val path = if (signedIn) "subscribe-newsletter" else "subscribe-public-newsletter"
    return call(path, body, auth = signedIn)
}

/** Unsubscribes the signed-in user from one group, or from every group with group = null. */
internal fun Core.unsubscribeNewsletter(group: Any?): Any? {
    ensureConnection()
    refuseAnonymous("subscribe to newsletters")
    return call("subscribe-newsletter", jmap("action" to "unsubscribe", "group" to newsletterGroup(group, allowNull = true)), auth = true)
}

/** Newsletters sent to a group, newest first by default. Each has a url to its content. */
internal fun Core.getNewsletters(params: JMap?, fetchOptions: JMap?): Any? {
    ensureConnection()
    val isAdmin = isAdmin()
    var fo = fetchOptions.copyMap()
    var p = params
    if (p == null) {
        val withDefault = jmap("ascending" to false)
        withDefault.putAll(fo)
        fo = withDefault
        p = jmap("searchFor" to "timestamp", "value" to System.currentTimeMillis(), "condition" to "<", "group" to "public")
    }
    p = p.copyMap()
    for (key in listOf("searchFor", "value", "group")) {
        if (!p.containsKey(key)) throw perr("Key \"$key\" is required.")
    }
    val fields = listOf("message_id", "timestamp", "subject", "complaint", "read", "bounced")
    val searchFor = p["searchFor"]
    if (searchFor !in fields) {
        throw perr("${jd(searchFor)} is invalid in \"searchFor\". allowed types or values are: " + fields.joinToString(", ") { jd(it) } + ".")
    }
    val value = p["value"]
    val wantsStr = searchFor == "message_id" || searchFor == "subject"
    if ((wantsStr && value !is String) || (!wantsStr && value !is Number)) {
        throw perr("\"value\" type does not match the type of \"$searchFor\" index.")
    }
    if (value == "") throw perr("\"value\" should not be empty string.")
    val body = jmap("searchFor" to searchFor, "value" to value)
    if (p.containsKey("range")) {
        val r = p["range"]
        val sameType = (r is Number && value is Number) || (r is String && value is String)
        if (!sameType) throw perr("\"range\" should match type of \"value\".")
        body["range"] = r
    }
    val conditions = listOf(">", ">=", "=", "<", "<=", "gt", "gte", "eq", "lt", "lte")
    body["condition"] = if (p["condition"] in conditions) p["condition"] else "="
    val group = newsletterGroup(p["group"])
    if (group is Long && group >= 1) {
        if (!signedIn()) throw perr("User should be logged in.")
        if (!isAdmin && group > myAccessGroup()) throw perr("User has no access.")
    }
    body["group"] = group
    val signedIn = signedIn()
    val res = if (group == 0L || (group is String && !signedIn)) {
        call("get-public-newsletters", body, auth = signedIn, method = "GET", fetchOptions = fo)
    } else {
        call("get-newsletters", body, auth = true, method = "GET", fetchOptions = fo)
    }
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        val defaults = jmap(
            "message_id" to "", "timestamp" to 0L, "complaint" to 0L, "read" to 0L, "subject" to "", "bounced" to "", "url" to "",
            "delivered" to 0L, "group" to group, "dry" to false, "sent" to 0L,
        )
        val source = linkedMapOf(
            "message_id" to "mid", "timestamp" to "stmp", "complaint" to "cmpl", "read" to "read", "subject" to "subj", "bounced" to "bnce",
            "url" to "url", "delivered" to "delv", "group" to "grp", "dry" to "dry", "sent" to "sent",
        )
        val out = jlist()
        for (rowAny in list) {
            val row = rowAny.asMap() ?: LinkedHashMap()
            val item = LinkedHashMap<String, Any?>()
            for ((k, src) in source) {
                val v = row[src]
                item[k] = if (truthy(v)) v else defaults[k]
            }
            val bounced = item["bounced"]
            item["bounced"] = if (bounced is String) bounced else jsJson(bounced)
            item["dry"] = truthy(item["dry"])
            if (!truthy(item["sent"])) item.remove("sent")
            out.add(item)
        }
        rm["list"] = out
    }
    return res
}

/** The signed-in user's newsletter subscriptions: [{timestamp, group, subscribed_email, active}]. */
internal fun Core.getNewsletterSubscription(params: JMap?, fetchOptions: JMap?): Any? {
    ensureConnection()
    refuseAnonymous("subscribe to newsletters")
    val p = params.copyMap()
    val body = LinkedHashMap<String, Any?>()
    if (p.containsKey("user_id")) {
        if (p["user_id"] != user?.get("user_id") && !isAdmin()) throw perr("No access.")
        body["user_id"] = p["user_id"]
    }
    if (p.containsKey("group")) body["group"] = newsletterGroup(p["group"], allowNull = true)
    val data = call("get-newsletter-subscription", body, auth = true, fetchOptions = fetchOptions)
    val dm = data.asMap()
    val rows = if (dm != null && dm.containsKey("list")) dm["list"] else data
    val out = jlist()
    for (rAny in rows.asList() ?: emptyList<Any?>()) {
        val r = rAny.asMap() ?: continue
        val subt = r["subt"]
        val parts = (if (subt is String) subt else if (subt == null) "" else jsJson(subt)).split("#")
        var token = parts[0]
        val active = !token.startsWith("@")
        token = token.trimStart('@')
        val item = jmap(
            "timestamp" to r["stmp"],
            "group" to (if (Regex("^\\d+$").matches(token)) (token.toLongOrNull() ?: token) else token),
            "subscribed_email" to (if (parts.size > 1) parts[1] else ""),
            "active" to active,
        )
        val et = r["email_token"]
        if (et is String && et.isNotEmpty()) item["subscriber_token"] = et
        out.add(item)
    }
    if (dm != null && dm.containsKey("list")) {
        dm["list"] = out
        return dm
    }
    return out
}

// ---- subscriptions between users -------------------------------------------------------------

/** Subscribes the signed-in user to another user: {"user_id", "get_feed"?, "get_notified"?, "get_email"?}. */
internal fun Core.subscribe(params: JMap): JMap {
    requireSession()
    val p = params.copyMap()
    if (!p.containsKey("user_id")) throw perr("Key \"user_id\" is required.")
    val target = notSelf(p["user_id"])
    val option = LinkedHashMap<String, Any?>()
    for (k in listOf("get_feed", "get_notified")) {
        if (p.containsKey(k)) {
            if (p[k] !is Boolean) throw perr("${jd(p[k])} is invalid in \"$k\". allowed type or value is: Type<boolean>.")
            option[k] = p[k]
        }
    }
    if (p.containsKey("get_email")) {
        val u = user
        if (truthy(p["get_email"]) && !(truthy(u?.get("email")) && truthy(u?.get("email_verified")))) {
            throw perr("User has no verified email address.")
        }
        option["get_email"] = truthy(p["get_email"])
    }
    val s = call("subscription", jmap("subscribe" to target, "option" to option), auth = true).asMap()
        ?: throw skErr("The subscription is blocked.", "INVALID_REQUEST")
    return subscriptionRow(s)
}

internal fun Core.unsubscribe(params: JMap): Any? {
    requireSession()
    return call("subscription", jmap("unsubscribe" to target(params)), auth = true)
}

/** Stops a user from subscribing to the signed-in user (and from getting their feed). */
internal fun Core.blockSubscriber(params: JMap): Any? {
    requireSession()
    return call("subscription", jmap("block" to target(params)), auth = true)
}

internal fun Core.unblockSubscriber(params: JMap): Any? {
    requireSession()
    return call("subscription", jmap("unblock" to target(params)), auth = true)
}

/** Who a user subscribes to (subscriber=...) or who subscribes to a user (subscription=...). */
internal fun Core.getSubscriptions(params: JMap, fetchOptions: JMap?): Any? {
    requireSession()
    val p = params.copyMap()
    val body = LinkedHashMap<String, Any?>()
    if (p.containsKey("subscriber")) body["subscriber"] = validateUserId(p["subscriber"], "User ID in \"subscriber\"")
    if (p.containsKey("subscription")) {
        // any user, yourself included: your own id lists your own subscribers
        body["subscription"] = validateUserId(p["subscription"], "User ID in \"subscription\"")
    }
    if (p.containsKey("blocked")) {
        if (p["blocked"] !is Boolean) throw perr("${jd(p["blocked"])} is invalid in \"blocked\". allowed type or value is: Type<boolean>.")
        body["blocked"] = p["blocked"]
    }
    if (!truthy(body["subscriber"]) && !truthy(body["subscription"])) {
        throw perr("At least either \"subscriber\" or \"subscription\" should have a value.")
    }
    val res = call("get-subscription", body, auth = true, fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { r -> r.asMap()?.let { subscriptionRow(it) } ?: r }.toMutableList()
    }
    return res
}

/** Records the users you subscribe to (with get_feed on) posted to their feed, newest first. */
internal fun Core.getFeed(params: JMap?, fetchOptions: JMap?): Any? {
    requireSession()
    val p = params.copyMap()
    val body = LinkedHashMap<String, Any?>()
    if (p.containsKey("access_group")) {
        val v = p["access_group"]
        val g = if (v == "authorized") 1L else if (v == "public") 0L else v
        if (g !is Number) throw perr("\"access_group\" should be type number.")
        if (g.toDouble() < 0) throw perr("\"access_group\" should be zero or a positive number.")
        if (g.toDouble() > myAccessGroup()) throw perr("User has no access.")
        body["access_group"] = g
    }
    val res = call("get-feed", body, auth = true, fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { normalizeRecord(it) }.toMutableList()
    }
    return res
}

// ---- tickets ------------------------------------------------------------------------------------

private fun Core.ticketList(exec: String, params: JMap?, fetchOptions: JMap?): Any? {
    val body = jmap("exec" to exec)
    if (params != null) body.putAll(params)
    val res = call("ticket", body, auth = true, fetchOptions = fetchOptions)
    val rm = res.asMap()
    val list = rm.l("list")
    if (rm != null && list != null) {
        rm["list"] = list.map { r -> r.asMap()?.let { mapTicket(it) } ?: r }.toMutableList()
    }
    return res
}

/** The project's tickets (or one, with {"ticket_id": ...}) as a signed-in user sees them. */
internal fun Core.getTickets(params: JMap?, fetchOptions: JMap?): Any? = ticketList("list", params, fetchOptions)

/** The signed-in user's own ticket calls (each with ticket_id, consume_id and timestamp). */
internal fun Core.getConsumedTickets(params: JMap?, fetchOptions: JMap?): Any? = ticketList("consumed", params, fetchOptions)
