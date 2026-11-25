// Offline checks for the 2.5.0 record changes (version check: current release): source.can_modify_referencing_records,
// record "updated_by" (prv_acs.upb) and the redacted "ip" field. No network calls.
//
// The repo has no test source set, so this is a single-file Java program run against the built
// skapi-kotlin jar. It calls the internal postRecord validation (setupPostConfig) and the record
// decoder (normalizeRecord) directly: Kotlin "internal" is public in the bytecode.
//
//   ./tests/referencing-owner-rights.sh

import com.skapi.Core;
import com.skapi.DatabaseKt;
import com.skapi.Skapi;
import com.skapi.SkapiException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ReferencingOwnerRights {
    // A long-form Project ID that decodes offline: "<id>-<region char><id>-<owner uuid>".
    static final String PROJECT_ID = "abcdefgh-0ijkl-11111111-2222-3333-4444-555555555555";

    interface Body { void run() throws Exception; }

    static final List<Object[]> TESTS = new ArrayList<>();

    static void test(String name, Body body) { TESTS.add(new Object[]{name, body}); }

    static void eq(Object got, Object want, String what) {
        if (!Objects.equals(got, want)) throw new AssertionError(what + ": expected " + want + ", got " + got);
    }

    static void ok(boolean cond, String what) {
        if (!cond) throw new AssertionError(what);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    static Core core;

    static Map<String, Object> config(Map<String, Object> c) {
        return m(DatabaseKt.setupPostConfig(core, c).getFirst());
    }

    static Map<String, Object> baseRecord(Object... extra) {
        Map<String, Object> r = map(
            "rec", "1AbCdEfGh12345abcd",
            "usr", "user-b",
            "tbl", "comments/service-id/00",
            "ip", "203.0.113.5#",
            "prv_acs", map());
        r.putAll(map(extra));
        return r;
    }

    static Map<String, Object> normalize(Map<String, Object> raw) {
        return m(DatabaseKt.normalizeRecord(core, raw, true, true, true));
    }

    public static void main(String[] args) {
        core = new Skapi(PROJECT_ID).getCore$skapi_kotlin();
        // Signed in as user-a without a server: the update checks only look for a user and a session.
        core.setRestored(true);
        core.setUser(map("user_id", "user-a"));
        core.setSession(new com.skapi.Session(null, null, null, 0L));

        test("version is 2.7.0", () -> eq(com.skapi.CoreKt.SKAPI_VERSION, "2.7.0", "SKAPI_VERSION"));

        test("postRecord accepts source.can_modify_referencing_records as a boolean", () -> {
            Map<String, Object> on = config(map(
                "table", map("name", "posts", "access_group", "public"),
                "source", map("can_modify_referencing_records", true)));
            eq(m(on.get("source")).get("can_modify_referencing_records"), true, "on");
            Map<String, Object> off = config(map(
                "record_id", "rec1",
                "source", map("can_modify_referencing_records", false)));
            eq(m(off.get("source")).get("can_modify_referencing_records"), false, "off");
        });

        test("postRecord rejects a non-boolean can_modify_referencing_records", () -> {
            try {
                config(map("table", map("name", "posts"), "source", map("can_modify_referencing_records", "yes")));
                throw new AssertionError("no error");
            } catch (Exception thrown) { // Kotlin declares no checked exceptions, so javac needs the supertype here
                ok(thrown instanceof SkapiException, "SkapiException, got " + thrown);
                SkapiException e = (SkapiException) thrown;
                ok(e.getMessage().contains("can_modify_referencing_records") && e.getMessage().contains("boolean"), e.getMessage());
                eq(e.getCode(), "INVALID_PARAMETER", "code");
            }
        });

        test("reference: null still unlinks", () -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("record_id", "rec1");
            c.put("reference", null);
            eq(config(c).get("reference"), map("record_id", null), "reference");
        });

        test("source defaults include can_modify_referencing_records: false", () -> {
            Map<String, Object> r = normalize(baseRecord());
            eq(m(r.get("source")).get("can_modify_referencing_records"), false, "default");
            ok(!r.containsKey("updated_by"), "no updated_by");
        });

        test("prv_acs.can_modify_referencing_records is returned in source", () -> {
            Map<String, Object> r = normalize(baseRecord("prv_acs", map("can_modify_referencing_records", true)));
            eq(m(r.get("source")).get("can_modify_referencing_records"), true, "source");
        });

        test("prv_acs.upb becomes updated_by and never a source setting", () -> {
            Map<String, Object> r = normalize(baseRecord("prv_acs", map("upb", "user-a", "can_remove_referencing_records", true)));
            eq(r.get("updated_by"), "user-a", "updated_by");
            ok(!m(r.get("source")).containsKey("upb"), "upb not in source");
            eq(m(r.get("source")).get("can_remove_referencing_records"), true, "other settings kept");
            eq(r.get("user_id"), "user-b", "user_id unchanged");
            Map<String, Object> empty = normalize(baseRecord("prv_acs", map("upb", "")));
            ok(!empty.containsKey("updated_by") && !m(empty.get("source")).containsKey("upb"), "empty upb ignored");
        });

        test("full ip is kept for the uploader / admins", () -> {
            Map<String, Object> r = normalize(baseRecord("ip", "203.0.113.5R#my-id"));
            eq(r.get("ip"), "203.0.113.5", "ip");
            eq(r.get("readonly"), true, "readonly");
            eq(r.get("unique_id"), "my-id", "unique_id");
        });

        test("redacted ip of a signed-in uploader: empty address, flags kept", () -> {
            Object[][] cases = {
                {"R#my#id", "", true, "my#id"},
                {"#my-id", "", false, "my-id"},
                {"R", "", true, null},
                {"", "", false, null},
                {null, "", false, null},
            };
            for (Object[] c : cases) {
                Map<String, Object> raw = baseRecord();
                raw.put("ip", c[0]);
                Map<String, Object> r = normalize(raw);
                eq(r.get("ip"), c[1], "ip for " + c[0]);
                eq(r.get("readonly"), c[2], "readonly for " + c[0]);
                eq(r.get("unique_id"), c[3], "unique_id for " + c[0]);
                eq(r.get("user_id"), "user-b", "user_id for " + c[0]);
            }
        });

        test("redacted ip of an anonymous uploader is still detected as anonymous", () -> {
            Map<String, Object> r = normalize(baseRecord("ip", "0-0-0-0R#anon-id"));
            eq(r.get("ip"), "0.0.0.0", "ip");
            eq(r.get("readonly"), true, "readonly");
            eq(r.get("unique_id"), "anon-id", "unique_id");
            eq(r.get("user_id"), "anonymous:user-b", "user_id");
            Map<String, Object> full = normalize(baseRecord("ip", "1-2-3-4#"));
            eq(full.get("ip"), "1.2.3.4", "unredacted anonymous ip");
            eq(full.get("user_id"), "anonymous:user-b", "unredacted anonymous user_id");
        });

        int failed = 0;
        for (Object[] t : TESTS) {
            try {
                ((Body) t[1]).run();
                System.out.println("ok   " + t[0]);
            } catch (Throwable e) {
                failed++;
                System.out.println("FAIL " + t[0] + "\n     " + e);
            }
        }
        System.out.println((TESTS.size() - failed) + "/" + TESTS.size() + " passed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
