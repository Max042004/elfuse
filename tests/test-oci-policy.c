/* OCI policy.json schema and loader unit tests (Plan 6 C6.1)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives oci_policy_load against a per-test scratch HOME under /tmp, with
 * env vars (ELFUSE_POLICY_FILE / XDG_CONFIG_HOME / HOME) snapshotted at
 * setup and restored at teardown so the suite never bleeds state into
 * the user's actual config. Each test owns its own scratch tree wiped
 * via nftw on the way out.
 *
 * Cases:
 *   1. empty_chain_returns_default
 *   2. override_wins_over_fallbacks
 *   3. override_miss_is_hard_error
 *   4. override_empty_string_falls_through
 *   5. xdg_fallback
 *   6. home_config_fallback (XDG unset)
 *   7. library_fallback (XDG and HOME/.config missing)
 *   8. full_schema_round_trip
 *   9. path_expansion_tilde
 *  10. unknown_keys_tolerated
 *  11. invalid_shapes (4 sub-cases)
 *  12. ca_bundle_missing_is_hard_error
 *  13. ca_bundle_null_inherits_default
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/policy.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int g_total = 0;
static int g_passed = 0;

static void report_pass(const char *name)
{
    g_total++;
    g_passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void report_fail(const char *name, const char *fmt, ...)
{
    g_total++;
    printf("  " RED "FAIL" RESET " %s", name);
    if (fmt && *fmt) {
        printf(": ");
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
}

static int remove_entry(const char *path, const struct stat *st, int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

static void wipe_dir(const char *root)
{
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

typedef struct {
    char *scratch;       /* per-test root, mkdtemp'd under /tmp */
    char *home_dir;      /* scratch/home (used as HOME during the test) */
    char *xdg_dir;       /* scratch/xdg  (used as XDG_CONFIG_HOME) */
    char *saved_home;
    bool had_home;
    char *saved_xdg;
    bool had_xdg;
    char *saved_override;
    bool had_override;
} fx_t;

static int mkdir_p(const char *path)
{
    char buf[1024];
    size_t n = strlen(path);
    if (n >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, path, n + 1);
    for (size_t i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0700) < 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0700) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int write_file(const char *path, const char *body)
{
    char dir[1024];
    size_t n = strlen(path);
    if (n >= sizeof(dir)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(dir, path, n + 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir_p(dir) < 0)
            return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    size_t blen = strlen(body);
    size_t off = 0;
    while (off < blen) {
        ssize_t w = write(fd, body + off, blen - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        off += (size_t) w;
    }
    close(fd);
    return 0;
}

static char *path_join(const char *a, const char *b)
{
    size_t al = strlen(a);
    size_t bl = strlen(b);
    char *r = malloc(al + 1 + bl + 1);
    if (!r)
        return NULL;
    memcpy(r, a, al);
    r[al] = '/';
    memcpy(r + al + 1, b, bl);
    r[al + 1 + bl] = '\0';
    return r;
}

static char *dup_env(const char *name, bool *had)
{
    const char *v = getenv(name);
    *had = v != NULL;
    return v ? strdup(v) : NULL;
}

static void restore_env(const char *name, char *saved, bool had)
{
    if (had)
        setenv(name, saved, 1);
    else
        unsetenv(name);
    free(saved);
}

static int fx_setup(fx_t *fx)
{
    memset(fx, 0, sizeof(*fx));
    char tmpl[] = "/tmp/elfuse-test-oci-policy-XXXXXX";
    if (!mkdtemp(tmpl))
        return -1;
    fx->scratch = strdup(tmpl);
    if (!fx->scratch)
        return -1;
    fx->home_dir = path_join(fx->scratch, "home");
    fx->xdg_dir = path_join(fx->scratch, "xdg");
    if (!fx->home_dir || !fx->xdg_dir)
        return -1;
    if (mkdir(fx->home_dir, 0700) < 0)
        return -1;
    if (mkdir(fx->xdg_dir, 0700) < 0)
        return -1;
    fx->saved_home = dup_env("HOME", &fx->had_home);
    fx->saved_xdg = dup_env("XDG_CONFIG_HOME", &fx->had_xdg);
    fx->saved_override = dup_env("ELFUSE_POLICY_FILE", &fx->had_override);
    /* Default: every test starts with HOME pointing at scratch and no
     * XDG / override. Individual tests opt in to other shapes.
     */
    setenv("HOME", fx->home_dir, 1);
    unsetenv("XDG_CONFIG_HOME");
    unsetenv("ELFUSE_POLICY_FILE");
    return 0;
}

static void fx_teardown(fx_t *fx)
{
    if (!fx)
        return;
    restore_env("HOME", fx->saved_home, fx->had_home);
    restore_env("XDG_CONFIG_HOME", fx->saved_xdg, fx->had_xdg);
    restore_env("ELFUSE_POLICY_FILE", fx->saved_override, fx->had_override);
    free(fx->home_dir);
    free(fx->xdg_dir);
    if (fx->scratch) {
        wipe_dir(fx->scratch);
        free(fx->scratch);
    }
    memset(fx, 0, sizeof(*fx));
}

static char *touch_ca_file(const fx_t *fx, const char *relpath)
{
    char *path = path_join(fx->scratch, relpath);
    if (!path)
        return NULL;
    if (write_file(path, "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n") < 0) {
        free(path);
        return NULL;
    }
    return path;
}

/* ---------- cases ---------- */

static void case_empty_chain_returns_default(void)
{
    const char *name = "empty_chain_returns_default";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), "") != 0) {
        report_fail(name, "expected empty source, got '%s'", oci_policy_source(p));
        goto done;
    }
    oci_policy_effective_t eff;
    oci_policy_lookup(p, "ghcr.io", &eff);
    if (eff.insecure || eff.ca_bundle || eff.auth_file || eff.sigstore_public_key) {
        report_fail(name, "expected zero-value effective view");
        goto done;
    }
    report_pass(name);
done:
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_override_wins_over_fallbacks(void)
{
    const char *name = "override_wins_over_fallbacks";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;

    char *override_path = path_join(fx.scratch, "override.json");
    char *xdg_path = path_join(fx.xdg_dir, "elfuse/policy.json");
    char *home_cfg = path_join(fx.home_dir, ".config/elfuse/policy.json");
    char *library = path_join(fx.home_dir,
                              "Library/Application Support/elfuse/policy.json");
    if (!override_path || !xdg_path || !home_cfg || !library) {
        report_fail(name, "path_join OOM"); goto done;
    }
    (void) write_file(override_path,
                      "{\"registries\":{\"override.example\":{\"insecure\":true}}}");
    (void) write_file(xdg_path,
                      "{\"registries\":{\"xdg.example\":{\"insecure\":true}}}");
    (void) write_file(home_cfg,
                      "{\"registries\":{\"home.example\":{\"insecure\":true}}}");
    (void) write_file(library,
                      "{\"registries\":{\"library.example\":{\"insecure\":true}}}");
    setenv("ELFUSE_POLICY_FILE", override_path, 1);
    setenv("XDG_CONFIG_HOME", fx.xdg_dir, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), override_path) != 0) {
        report_fail(name, "expected source=%s, got %s", override_path,
                    oci_policy_source(p));
        goto done;
    }
    oci_policy_effective_t eff;
    oci_policy_lookup(p, "override.example", &eff);
    if (!eff.insecure) {
        report_fail(name, "override entry not present");
        goto done;
    }
    oci_policy_lookup(p, "xdg.example", &eff);
    if (eff.insecure) {
        report_fail(name, "fallback was consulted despite override");
        goto done;
    }
    report_pass(name);
done:
    free(override_path);
    free(xdg_path);
    free(home_cfg);
    free(library);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_override_miss_is_hard_error(void)
{
    const char *name = "override_miss_is_hard_error";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *bogus = path_join(fx.scratch, "missing/policy.json");
    setenv("ELFUSE_POLICY_FILE", bogus, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc == 0) { report_fail(name, "expected failure"); goto done; }
    if (!err || !strstr(err, "ELFUSE_POLICY_FILE")) {
        report_fail(name, "diagnostic missing or wrong: %s", err ? err : "(none)");
        goto done;
    }
    report_pass(name);
done:
    free(bogus);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_override_empty_string_falls_through(void)
{
    const char *name = "override_empty_string_falls_through";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    setenv("ELFUSE_POLICY_FILE", "", 1);

    char *xdg_path = path_join(fx.xdg_dir, "elfuse/policy.json");
    (void) write_file(xdg_path,
                      "{\"registries\":{\"xdg.example\":{\"insecure\":true}}}");
    setenv("XDG_CONFIG_HOME", fx.xdg_dir, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), xdg_path) != 0) {
        report_fail(name, "expected XDG fallback, got source=%s",
                    oci_policy_source(p));
        goto done;
    }
    report_pass(name);
done:
    free(xdg_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_xdg_fallback(void)
{
    const char *name = "xdg_fallback";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *xdg_path = path_join(fx.xdg_dir, "elfuse/policy.json");
    (void) write_file(xdg_path, "{\"default\":{\"insecure\":true}}");
    setenv("XDG_CONFIG_HOME", fx.xdg_dir, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), xdg_path) != 0) {
        report_fail(name, "expected source=%s, got %s", xdg_path,
                    oci_policy_source(p));
        goto done;
    }
    oci_policy_effective_t eff;
    oci_policy_lookup(p, "any.example", &eff);
    if (!eff.insecure) { report_fail(name, "default.insecure=true not honored"); goto done; }
    report_pass(name);
done:
    free(xdg_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_home_config_fallback(void)
{
    const char *name = "home_config_fallback";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *home_cfg = path_join(fx.home_dir, ".config/elfuse/policy.json");
    (void) write_file(home_cfg, "{\"default\":{\"insecure\":true}}");

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), home_cfg) != 0) {
        report_fail(name, "expected source=%s, got %s", home_cfg,
                    oci_policy_source(p));
        goto done;
    }
    report_pass(name);
done:
    free(home_cfg);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_library_fallback(void)
{
    const char *name = "library_fallback";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *library = path_join(fx.home_dir,
                              "Library/Application Support/elfuse/policy.json");
    (void) write_file(library, "{\"default\":{\"insecure\":true}}");

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    if (strcmp(oci_policy_source(p), library) != 0) {
        report_fail(name, "expected source=%s, got %s", library,
                    oci_policy_source(p));
        goto done;
    }
    report_pass(name);
done:
    free(library);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_full_schema_round_trip(void)
{
    const char *name = "full_schema_round_trip";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *ca_path = touch_ca_file(&fx, "ca/ghcr.pem");
    char *override_path = path_join(fx.scratch, "policy.json");
    if (!ca_path || !override_path) { report_fail(name, "fixture OOM"); goto done; }
    char body[2048];
    snprintf(body, sizeof(body),
             "{"
             "\"default\":{\"insecure\":false,\"ca_bundle\":null},"
             "\"registries\":{"
             " \"ghcr.io\":{\"auth_file\":\"%s/auth/ghcr.json\",\"ca_bundle\":\"%s\"},"
             " \"127.0.0.1:5000\":{\"insecure\":true},"
             " \"quay.io\":{\"sigstore\":{\"publicKey\":\"%s/keys/quay.pem\"}}"
             "}}",
             fx.scratch, ca_path, fx.scratch);
    if (write_file(override_path, body) < 0) {
        report_fail(name, "write override: %s", strerror(errno)); goto done;
    }
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }

    oci_policy_effective_t eff;

    oci_policy_lookup(p, "ghcr.io", &eff);
    if (eff.insecure) { report_fail(name, "ghcr.io insecure should be false"); goto done; }
    if (!eff.ca_bundle || strcmp(eff.ca_bundle, ca_path) != 0) {
        report_fail(name, "ghcr.io ca_bundle wrong: %s",
                    eff.ca_bundle ? eff.ca_bundle : "(null)");
        goto done;
    }
    if (!eff.auth_file || !strstr(eff.auth_file, "/auth/ghcr.json")) {
        report_fail(name, "ghcr.io auth_file wrong: %s",
                    eff.auth_file ? eff.auth_file : "(null)");
        goto done;
    }

    oci_policy_lookup(p, "127.0.0.1:5000", &eff);
    if (!eff.insecure) { report_fail(name, "loopback insecure should be true"); goto done; }
    if (eff.ca_bundle) { report_fail(name, "loopback ca_bundle should inherit null default"); goto done; }

    oci_policy_lookup(p, "quay.io", &eff);
    if (!eff.sigstore_public_key || !strstr(eff.sigstore_public_key, "/keys/quay.pem")) {
        report_fail(name, "quay.io sigstore key not surfaced: %s",
                    eff.sigstore_public_key ? eff.sigstore_public_key : "(null)");
        goto done;
    }

    /* Unknown host falls back to default block (insecure=false, ca=null). */
    oci_policy_lookup(p, "unknown.example", &eff);
    if (eff.insecure || eff.ca_bundle || eff.auth_file || eff.sigstore_public_key) {
        report_fail(name, "unknown host did not fall back to default");
        goto done;
    }

    report_pass(name);
done:
    free(ca_path);
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_path_expansion_tilde(void)
{
    const char *name = "path_expansion_tilde";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *override_path = path_join(fx.scratch, "policy.json");
    /* Drop a CA file at $HOME/ca/test.pem so the loader's stat passes. */
    char *abs_ca = path_join(fx.home_dir, "ca/test.pem");
    if (write_file(abs_ca, "PEM") < 0) { report_fail(name, "write ca: %s", strerror(errno)); goto done; }
    const char *body =
        "{\"registries\":{\"example.com\":{"
        "\"ca_bundle\":\"~/ca/test.pem\","
        "\"auth_file\":\"~/auth/example.json\""
        "}}}";
    if (write_file(override_path, body) < 0) {
        report_fail(name, "write override: %s", strerror(errno)); goto done;
    }
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    oci_policy_effective_t eff;
    oci_policy_lookup(p, "example.com", &eff);
    if (!eff.ca_bundle || strcmp(eff.ca_bundle, abs_ca) != 0) {
        report_fail(name, "ca_bundle expansion wrong: %s vs %s",
                    eff.ca_bundle ? eff.ca_bundle : "(null)", abs_ca);
        goto done;
    }
    char *expected_auth = path_join(fx.home_dir, "auth/example.json");
    if (!eff.auth_file || strcmp(eff.auth_file, expected_auth) != 0) {
        report_fail(name, "auth_file expansion wrong: %s vs %s",
                    eff.auth_file ? eff.auth_file : "(null)", expected_auth);
        free(expected_auth);
        goto done;
    }
    free(expected_auth);
    report_pass(name);
done:
    free(abs_ca);
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_unknown_keys_tolerated(void)
{
    const char *name = "unknown_keys_tolerated";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *override_path = path_join(fx.scratch, "policy.json");
    const char *body =
        "{"
        "\"mirrors\":{\"docker.io\":[\"mirror.example\"]},"
        "\"registries\":{"
        " \"ghcr.io\":{\"insecure\":true,\"some_future_field\":42}"
        "}}";
    if (write_file(override_path, body) < 0) {
        report_fail(name, "write override: %s", strerror(errno)); goto done;
    }
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "expected success, got rc=%d err=%s", rc, err ? err : "(none)"); goto done; }
    oci_policy_effective_t eff;
    oci_policy_lookup(p, "ghcr.io", &eff);
    if (!eff.insecure) { report_fail(name, "known field not parsed"); goto done; }
    report_pass(name);
done:
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void invalid_subcase(const char *label, const char *body)
{
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(label, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *override_path = path_join(fx.scratch, "policy.json");
    (void) write_file(override_path, body);
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc == 0) {
        report_fail(label, "expected failure, got success");
        goto done;
    }
    if (!err || !*err) {
        report_fail(label, "no diagnostic on failure");
        goto done;
    }
    report_pass(label);
done:
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_invalid_shapes(void)
{
    invalid_subcase("invalid_shapes/top_not_object", "[1,2,3]");
    invalid_subcase("invalid_shapes/registries_not_object",
                    "{\"registries\":\"oops\"}");
    invalid_subcase("invalid_shapes/registry_entry_not_object",
                    "{\"registries\":{\"ghcr.io\":\"oops\"}}");
    invalid_subcase("invalid_shapes/malformed_json",
                    "{this is not json");
}

static void case_ca_bundle_missing_is_hard_error(void)
{
    const char *name = "ca_bundle_missing_is_hard_error";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *override_path = path_join(fx.scratch, "policy.json");
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"registries\":{\"ghcr.io\":{\"ca_bundle\":\"%s/missing/ca.pem\"}}}",
             fx.scratch);
    (void) write_file(override_path, body);
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc == 0) { report_fail(name, "expected failure"); goto done; }
    if (!err || !strstr(err, "ca_bundle")) {
        report_fail(name, "diagnostic wrong: %s", err ? err : "(none)");
        goto done;
    }
    report_pass(name);
done:
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

static void case_ca_bundle_null_inherits_default(void)
{
    const char *name = "ca_bundle_null_inherits_default";
    fx_t fx;
    if (fx_setup(&fx) < 0) { report_fail(name, "fx_setup: %s", strerror(errno)); return; }
    oci_policy_t *p = NULL;
    const char *err = NULL;
    char *default_ca = touch_ca_file(&fx, "ca/default.pem");
    char *override_path = path_join(fx.scratch, "policy.json");
    if (!default_ca || !override_path) { report_fail(name, "fixture OOM"); goto done; }
    char body[2048];
    snprintf(body, sizeof(body),
             "{"
             "\"default\":{\"ca_bundle\":\"%s\"},"
             "\"registries\":{"
             " \"ghcr.io\":{\"ca_bundle\":null},"
             " \"quay.io\":{\"insecure\":true}"
             "}}",
             default_ca);
    (void) write_file(override_path, body);
    setenv("ELFUSE_POLICY_FILE", override_path, 1);

    int rc = oci_policy_load(&p, &err);
    if (rc != 0) { report_fail(name, "load rc=%d err=%s", rc, err ? err : "(none)"); goto done; }

    oci_policy_effective_t eff;
    /* ghcr.io explicitly set ca_bundle:null -> inherits default. */
    oci_policy_lookup(p, "ghcr.io", &eff);
    if (!eff.ca_bundle || strcmp(eff.ca_bundle, default_ca) != 0) {
        report_fail(name, "ghcr.io did not inherit default ca: %s",
                    eff.ca_bundle ? eff.ca_bundle : "(null)");
        goto done;
    }
    /* quay.io did not mention ca_bundle -> also inherits default. */
    oci_policy_lookup(p, "quay.io", &eff);
    if (!eff.ca_bundle || strcmp(eff.ca_bundle, default_ca) != 0) {
        report_fail(name, "quay.io did not inherit default ca: %s",
                    eff.ca_bundle ? eff.ca_bundle : "(null)");
        goto done;
    }
    report_pass(name);
done:
    free(default_ca);
    free(override_path);
    oci_policy_free(p);
    fx_teardown(&fx);
}

int main(void)
{
    printf("== test-oci-policy ==\n");
    case_empty_chain_returns_default();
    case_override_wins_over_fallbacks();
    case_override_miss_is_hard_error();
    case_override_empty_string_falls_through();
    case_xdg_fallback();
    case_home_config_fallback();
    case_library_fallback();
    case_full_schema_round_trip();
    case_path_expansion_tilde();
    case_unknown_keys_tolerated();
    case_invalid_shapes();
    case_ca_bundle_missing_is_hard_error();
    case_ca_bundle_null_inherits_default();
    printf("\n%d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
