/* OCI policy.json schema and loader (C6.1)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Walks the documented config-path chain, parses the JSON body via the
 * vendored cJSON, and produces an oci_policy_t the fetcher consults via
 * oci_policy_lookup. Implementation notes:
 *
 *   - The loader is lenient on unknown keys (top-level and per-host). Each
 *     unknown key is recorded so a future audit / debug surface can
 *     surface it; the load itself never fails because of a key the
 *     reader has not learned about yet. This is what makes the C6.3
 *     sigstore.publicKey reservation work without a coordinated rollout.
 *   - Known fields with wrong types are a hard error. The diagnostic
 *     spells out the JSON pointer-like path so an operator can fix the
 *     offending node directly.
 *   - String fields starting with "~/" or equal to "~" expand against
 *     $HOME at load time. "~user/" forms pass through verbatim (no
 *     getpwnam dependency, no surprise expansions). Other paths stay as
 *     authored.
 *   - ca_bundle existence is checked at load time so a fetcher that
 *     consults the policy never races a deleted file mid-pull. auth_file
 *     existence and 0600 mode are deferred to C6.2 because they share
 *     failure-mode ergonomics with the fetcher's credential loader.
 */

#include "policy.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../externals/cjson/cJSON.h"

#define POLICY_ERR_CAP 512

/* has_* flags drive the C6.3 overlay field-level merge: an overlay file only
 * carries the fields the operator chose to override, so the merge step must
 * distinguish "field was declared (possibly as null)" from "field omitted".
 * For base entries the flags are set as side-effects of parsing and the
 * lookup path keeps using the NULL-pointer check it already had; the flags
 * are only consulted during overlay merge.
 */
typedef struct {
    char *host;
    bool has_insecure;
    bool insecure;
    bool has_ca_bundle;
    char *ca_bundle;
    bool has_auth_file;
    char *auth_file;
    bool has_sigstore_public_key;
    char *sigstore_public_key;
    char **unknown_keys;
    size_t n_unknown_keys;
} policy_entry_t;

struct oci_policy {
    bool default_insecure;
    char *default_ca_bundle;
    policy_entry_t *entries;
    size_t n_entries;
    char *source_path;
    char **unknown_top_keys;
    size_t n_unknown_top_keys;
    char *err_buf;
};

static char *xstrdup(const char *s)
{
    if (!s)
        return NULL;
    char *r = strdup(s);
    if (!r)
        errno = ENOMEM;
    return r;
}

/* Set p->err_buf to a printf-formatted message and return -1. Allocates the
 * scratch buffer lazily so a load that never errors out does not pay for
 * one. The caller propagates the pointer through *err_msg.
 */
static int set_err(oci_policy_t *p, const char **err_msg, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int set_err(oci_policy_t *p, const char **err_msg, const char *fmt, ...)
{
    if (p) {
        if (!p->err_buf) {
            p->err_buf = malloc(POLICY_ERR_CAP);
            if (!p->err_buf) {
                if (err_msg)
                    *err_msg = "out of memory formatting policy error";
                errno = ENOMEM;
                return -1;
            }
        }
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(p->err_buf, POLICY_ERR_CAP, fmt, ap);
        va_end(ap);
        if (err_msg)
            *err_msg = p->err_buf;
    } else if (err_msg) {
        *err_msg = "policy load failed";
    }
    return -1;
}

/* Compose a per-field diagnostic that adapts to whether the field came from
 * the base policy (host-scoped) or a registries.d overlay (file-scoped). The
 * "what" suffix is whatever follows the field name in the message; callers
 * pre-format the strerror tail when they need one so this stays plain
 * non-variadic.
 */
static int field_err(oci_policy_t *p, const char *src_path, const char *host,
                     const char *field, const char *what, const char **err_msg)
{
    if (src_path)
        return set_err(p, err_msg, "policy overlay '%s': '%s' %s",
                       src_path, field, what);
    return set_err(p, err_msg, "policy 'registries[\"%s\"].%s' %s",
                   host, field, what);
}

/* Append s (copied) to *arr / *n. Returns 0 on success, -1 on ENOMEM. */
static int strarr_push(char ***arr, size_t *n, const char *s)
{
    char **next = (char **) realloc((void *) *arr, (*n + 1) * sizeof(char *));
    if (!next) {
        errno = ENOMEM;
        return -1;
    }
    *arr = next;
    next[*n] = xstrdup(s);
    if (!next[*n])
        return -1;
    (*n)++;
    return 0;
}

static void strarr_free(char **arr, size_t n)
{
    if (!arr)
        return;
    for (size_t i = 0; i < n; i++)
        free(arr[i]);
    free((void *) arr);
}

static void entry_free(policy_entry_t *e)
{
    if (!e)
        return;
    free(e->host);
    free(e->ca_bundle);
    free(e->auth_file);
    free(e->sigstore_public_key);
    strarr_free(e->unknown_keys, e->n_unknown_keys);
}

void oci_policy_free(oci_policy_t *p)
{
    if (!p)
        return;
    free(p->default_ca_bundle);
    for (size_t i = 0; i < p->n_entries; i++)
        entry_free(&p->entries[i]);
    free(p->entries);
    free(p->source_path);
    strarr_free(p->unknown_top_keys, p->n_unknown_top_keys);
    free(p->err_buf);
    free(p);
}

const char *oci_policy_source(const oci_policy_t *p)
{
    return p && p->source_path ? p->source_path : "";
}

/* Expand a "~/..." prefix against $HOME. Pure "~" maps to $HOME. Other
 * inputs (including "~user/...") pass through verbatim. Returns a heap-
 * owned string the caller frees, or NULL on ENOMEM / missing $HOME.
 */
static char *expand_home(const char *in)
{
    if (!in) {
        errno = EINVAL;
        return NULL;
    }
    if (in[0] != '~')
        return xstrdup(in);
    if (in[1] != '/' && in[1] != '\0')
        return xstrdup(in);
    const char *home = getenv("HOME");
    if (!home || !*home) {
        errno = ENOENT;
        return NULL;
    }
    if (in[1] == '\0')
        return xstrdup(home);
    /* in[1] == '/': join home + (in + 1). The "~" replacement removes one
     * byte; the joined string occupies strlen(home) + strlen(in + 1) + 1.
     */
    size_t hl = strlen(home);
    size_t tl = strlen(in + 1);
    char *r = malloc(hl + tl + 1);
    if (!r) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(r, home, hl);
    memcpy(r + hl, in + 1, tl);
    r[hl + tl] = '\0';
    return r;
}

/* Join two path components with a single '/'. Returns a heap string or
 * NULL on ENOMEM. Either arg may be empty; an empty base just yields
 * "/" + tail which is sufficient for the fallback chain (HOME/XDG are
 * never empty when present).
 */
static char *path_join(const char *a, const char *b)
{
    size_t al = a ? strlen(a) : 0;
    size_t bl = b ? strlen(b) : 0;
    char *r = malloc(al + 1 + bl + 1);
    if (!r) {
        errno = ENOMEM;
        return NULL;
    }
    if (al)
        memcpy(r, a, al);
    r[al] = '/';
    if (bl)
        memcpy(r + al + 1, b, bl);
    r[al + 1 + bl] = '\0';
    return r;
}

/* Slurp a file into a heap buffer. Returns a NUL-terminated string and
 * writes the byte count to *out_len. Caller frees. On failure returns
 * NULL with errno preserved.
 */
static char *slurp_file(const char *path, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    if (st.st_size < 0 || (uint64_t) st.st_size >= (uint64_t) SIZE_MAX) {
        close(fd);
        errno = EFBIG;
        return NULL;
    }
    size_t len = (size_t) st.st_size;
    char *buf = malloc(len + 1);
    if (!buf) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            free(buf);
            close(fd);
            errno = e;
            return NULL;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    close(fd);
    buf[off] = '\0';
    if (out_len)
        *out_len = off;
    return buf;
}

/* Resolve the candidate path chain. On success writes a heap-owned
 * absolute path into *out and returns 0; *out is NULL when no candidate
 * exists (caller uses built-in default). Returns -1 on hard errors:
 * $ELFUSE_POLICY_FILE points at a missing file, a fallback path fails to
 * open with errno != ENOENT, or allocation fails. Diagnostic messages
 * go through set_err on the caller-supplied policy.
 */
static int resolve_path(oci_policy_t *p, char **out, const char **err_msg)
{
    *out = NULL;
    const char *env_override = getenv("ELFUSE_POLICY_FILE");
    if (env_override && *env_override) {
        struct stat st;
        if (stat(env_override, &st) < 0) {
            int e = errno;
            int rc = set_err(p, err_msg,
                             "ELFUSE_POLICY_FILE='%s' does not exist: %s",
                             env_override, strerror(e));
            errno = e;
            return rc;
        }
        if (!S_ISREG(st.st_mode)) {
            errno = EINVAL;
            return set_err(p, err_msg,
                           "ELFUSE_POLICY_FILE='%s' is not a regular file",
                           env_override);
        }
        *out = xstrdup(env_override);
        if (!*out)
            return set_err(p, err_msg,
                           "out of memory recording ELFUSE_POLICY_FILE path");
        return 0;
    }

    const char *home = getenv("HOME");

    /* Fallback 1: XDG_CONFIG_HOME or $HOME/.config */
    const char *xdg = getenv("XDG_CONFIG_HOME");
    char *xdg_root = NULL;
    if (xdg && *xdg) {
        xdg_root = xstrdup(xdg);
    } else if (home && *home) {
        xdg_root = path_join(home, ".config");
    }
    if (xdg_root) {
        char *elf_dir = path_join(xdg_root, "elfuse");
        free(xdg_root);
        char *candidate = NULL;
        if (elf_dir) {
            candidate = path_join(elf_dir, "policy.json");
            free(elf_dir);
        }
        if (!candidate)
            return set_err(p, err_msg,
                           "out of memory composing XDG policy path");
        struct stat st;
        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            *out = candidate;
            return 0;
        }
        if (errno != ENOENT) {
            int e = errno;
            int rc = set_err(p, err_msg,
                             "policy candidate '%s' could not be stat'd: %s",
                             candidate, strerror(e));
            free(candidate);
            errno = e;
            return rc;
        }
        free(candidate);
    }

    /* Fallback 2: $HOME/Library/Application Support/elfuse/policy.json */
    if (home && *home) {
        const char *suffix = "/Library/Application Support/elfuse/policy.json";
        size_t n = strlen(home) + strlen(suffix) + 1;
        char *candidate = malloc(n);
        if (!candidate) {
            errno = ENOMEM;
            return set_err(p, err_msg,
                           "out of memory composing Library policy path");
        }
        snprintf(candidate, n, "%s%s", home, suffix);
        struct stat st;
        if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
            *out = candidate;
            return 0;
        }
        if (errno != ENOENT) {
            int e = errno;
            int rc = set_err(p, err_msg,
                             "policy candidate '%s' could not be stat'd: %s",
                             candidate, strerror(e));
            free(candidate);
            errno = e;
            return rc;
        }
        free(candidate);
    }

    /* Empty chain: caller falls back to built-in default. */
    return 0;
}

/* Type checks used while walking the schema. cJSON treats true/false as
 * separate node types so the unified bool predicate calls both probes.
 */
static bool json_is_bool(const cJSON *n)
{
    return n && (cJSON_IsBool(n) || cJSON_IsTrue(n) || cJSON_IsFalse(n));
}

static bool known_default_key(const char *k)
{
    return !strcmp(k, "insecure") || !strcmp(k, "ca_bundle");
}

static bool known_entry_key(const char *k)
{
    return !strcmp(k, "insecure") || !strcmp(k, "ca_bundle") ||
           !strcmp(k, "auth_file") || !strcmp(k, "sigstore");
}

static bool known_top_key(const char *k)
{
    return !strcmp(k, "default") || !strcmp(k, "registries");
}

/* Parse a "default" block. Missing block leaves the policy on its
 * zero-value defaults. Bad shapes raise hard errors via set_err.
 */
static int parse_default_block(oci_policy_t *p, cJSON *node,
                               const char **err_msg)
{
    if (!cJSON_IsObject(node))
        return set_err(p, err_msg, "policy 'default' must be a JSON object");
    cJSON *child;
    cJSON_ArrayForEach(child, node) {
        const char *k = child->string;
        if (!k)
            continue;
        if (!strcmp(k, "insecure")) {
            if (!json_is_bool(child))
                return set_err(p, err_msg,
                               "policy 'default.insecure' must be boolean");
            p->default_insecure = cJSON_IsTrue(child);
        } else if (!strcmp(k, "ca_bundle")) {
            if (cJSON_IsNull(child)) {
                free(p->default_ca_bundle);
                p->default_ca_bundle = NULL;
            } else if (cJSON_IsString(child) && child->valuestring) {
                char *expanded = expand_home(child->valuestring);
                if (!expanded)
                    return set_err(p, err_msg,
                                   "policy 'default.ca_bundle' expansion failed: %s",
                                   strerror(errno));
                free(p->default_ca_bundle);
                p->default_ca_bundle = expanded;
            } else {
                return set_err(p, err_msg,
                               "policy 'default.ca_bundle' must be a string or null");
            }
        } else if (!known_default_key(k)) {
            /* Forward-compat: future shaped defaults silently accepted.
             * No record on the default block; the per-host slot does.
             */
        }
    }
    if (p->default_ca_bundle) {
        struct stat st;
        if (stat(p->default_ca_bundle, &st) < 0 || !S_ISREG(st.st_mode))
            return set_err(p, err_msg,
                           "policy 'default.ca_bundle' file '%s' is not accessible",
                           p->default_ca_bundle);
    }
    return 0;
}

/* Parse a "sigstore" sub-object. Only publicKey is read; other keys go onto
 * the parent entry's unknown_keys list with a "sigstore." prefix so the
 * diagnostic stays unambiguous. src_path is NULL for base policy parsing and
 * the overlay file path for the registries.d path; field_err picks the right
 * shape.
 */
static int parse_sigstore_fields(oci_policy_t *p, policy_entry_t *e,
                                 cJSON *node, const char *src_path,
                                 const char **err_msg)
{
    if (!cJSON_IsObject(node))
        return field_err(p, src_path, e->host, "sigstore",
                         "must be a JSON object", err_msg);
    cJSON *child;
    cJSON_ArrayForEach(child, node) {
        const char *k = child->string;
        if (!k)
            continue;
        if (!strcmp(k, "publicKey")) {
            if (!cJSON_IsString(child) || !child->valuestring)
                return field_err(p, src_path, e->host, "sigstore.publicKey",
                                 "must be a string", err_msg);
            char *expanded = expand_home(child->valuestring);
            if (!expanded) {
                char what[256];
                snprintf(what, sizeof(what), "expansion failed: %s",
                         strerror(errno));
                return field_err(p, src_path, e->host, "sigstore.publicKey",
                                 what, err_msg);
            }
            free(e->sigstore_public_key);
            e->sigstore_public_key = expanded;
            e->has_sigstore_public_key = true;
        } else {
            char composed[256];
            snprintf(composed, sizeof(composed), "sigstore.%s", k);
            if (strarr_push(&e->unknown_keys, &e->n_unknown_keys, composed) < 0) {
                if (src_path)
                    return set_err(p, err_msg,
                                   "policy overlay '%s' sigstore unknown-key "
                                   "recording failed", src_path);
                return set_err(p, err_msg,
                               "policy 'registries[\"%s\"].sigstore' "
                               "unknown-key recording failed", e->host);
            }
        }
    }
    return 0;
}

/* Shared field parser for per-host entries. Used by the base policy parser
 * (src_path == NULL, e is the live array slot) and by the C6.3 overlay parser
 * (src_path is the overlay file path, e is a scratch policy_entry_t the
 * caller merges into the target). Only sets fields; the ca_bundle stat check
 * is left to the caller so each context can tailor the diagnostic.
 */
static int parse_entry_fields(oci_policy_t *p, policy_entry_t *e,
                              cJSON *node, const char *src_path,
                              const char **err_msg)
{
    cJSON *child;
    cJSON_ArrayForEach(child, node) {
        const char *k = child->string;
        if (!k)
            continue;
        if (!strcmp(k, "insecure")) {
            if (!json_is_bool(child))
                return field_err(p, src_path, e->host, "insecure",
                                 "must be boolean", err_msg);
            e->has_insecure = true;
            e->insecure = cJSON_IsTrue(child);
        } else if (!strcmp(k, "ca_bundle")) {
            if (cJSON_IsNull(child)) {
                free(e->ca_bundle);
                e->ca_bundle = NULL;
                e->has_ca_bundle = true;
            } else if (cJSON_IsString(child) && child->valuestring) {
                char *expanded = expand_home(child->valuestring);
                if (!expanded) {
                    char what[256];
                    snprintf(what, sizeof(what), "expansion failed: %s",
                             strerror(errno));
                    return field_err(p, src_path, e->host, "ca_bundle",
                                     what, err_msg);
                }
                free(e->ca_bundle);
                e->ca_bundle = expanded;
                e->has_ca_bundle = true;
            } else {
                return field_err(p, src_path, e->host, "ca_bundle",
                                 "must be a string or null", err_msg);
            }
        } else if (!strcmp(k, "auth_file")) {
            if (!cJSON_IsString(child) || !child->valuestring)
                return field_err(p, src_path, e->host, "auth_file",
                                 "must be a string", err_msg);
            char *expanded = expand_home(child->valuestring);
            if (!expanded) {
                char what[256];
                snprintf(what, sizeof(what), "expansion failed: %s",
                         strerror(errno));
                return field_err(p, src_path, e->host, "auth_file",
                                 what, err_msg);
            }
            free(e->auth_file);
            e->auth_file = expanded;
            e->has_auth_file = true;
        } else if (!strcmp(k, "sigstore")) {
            if (parse_sigstore_fields(p, e, child, src_path, err_msg) < 0)
                return -1;
        } else if (!known_entry_key(k)) {
            if (strarr_push(&e->unknown_keys, &e->n_unknown_keys, k) < 0) {
                if (src_path)
                    return set_err(p, err_msg,
                                   "policy overlay '%s' unknown-key "
                                   "recording failed", src_path);
                return set_err(p, err_msg,
                               "policy 'registries[\"%s\"]' "
                               "unknown-key recording failed", e->host);
            }
        }
    }
    return 0;
}

static int parse_entry_block(oci_policy_t *p, policy_entry_t *e,
                             cJSON *node, const char **err_msg)
{
    if (!cJSON_IsObject(node))
        return set_err(p, err_msg,
                       "policy 'registries[\"%s\"]' must be a JSON object",
                       e->host);
    if (parse_entry_fields(p, e, node, NULL, err_msg) < 0)
        return -1;
    if (e->ca_bundle) {
        struct stat st;
        if (stat(e->ca_bundle, &st) < 0 || !S_ISREG(st.st_mode))
            return set_err(p, err_msg,
                           "policy 'registries[\"%s\"].ca_bundle' file '%s' "
                           "is not accessible", e->host, e->ca_bundle);
    }
    return 0;
}

static int parse_registries_block(oci_policy_t *p, cJSON *node,
                                  const char **err_msg)
{
    if (!cJSON_IsObject(node))
        return set_err(p, err_msg,
                       "policy 'registries' must be a JSON object");
    size_t n = (size_t) cJSON_GetArraySize(node);
    if (n == 0)
        return 0;
    p->entries = calloc(n, sizeof(policy_entry_t));
    if (!p->entries) {
        errno = ENOMEM;
        return set_err(p, err_msg,
                       "policy 'registries' entry allocation failed");
    }
    cJSON *child;
    cJSON_ArrayForEach(child, node) {
        const char *host = child->string;
        if (!host)
            continue;
        policy_entry_t *e = &p->entries[p->n_entries];
        e->host = xstrdup(host);
        if (!e->host)
            return set_err(p, err_msg,
                           "policy 'registries[\"%s\"]' host copy failed", host);
        p->n_entries++;
        if (parse_entry_block(p, e, child, err_msg) < 0)
            return -1;
    }
    return 0;
}

/* Find an existing entry by host, or grow the entries array by one and
 * initialise a new slot. Returns the slot or NULL on ENOMEM. New slots have
 * host set and all fields zeroed; the caller (overlay merge) fills them via
 * merge_overlay_into_entry. On xstrdup failure for the new slot's host, the
 * grown array stays allocated but n_entries is not bumped, so oci_policy_free
 * walks the same n_entries it already had.
 */
static policy_entry_t *entry_grow_and_get(oci_policy_t *p, const char *host)
{
    for (size_t i = 0; i < p->n_entries; i++) {
        if (p->entries[i].host && !strcmp(p->entries[i].host, host))
            return &p->entries[i];
    }
    policy_entry_t *next = realloc(p->entries,
                                   (p->n_entries + 1) * sizeof(*next));
    if (!next) {
        errno = ENOMEM;
        return NULL;
    }
    p->entries = next;
    policy_entry_t *e = &p->entries[p->n_entries];
    memset(e, 0, sizeof(*e));
    e->host = xstrdup(host);
    if (!e->host)
        return NULL;
    p->n_entries++;
    return e;
}

/* Move declared fields from an overlay-parsed scratch entry into the target
 * entry, freeing whatever the target previously held. Pointer ownership
 * transfers to the target; the overlay's pointers are nulled so the caller's
 * entry_free does not double-free. unknown_keys are appended by copy via
 * strarr_push -- the originals stay in the overlay for entry_free to release.
 */
static int merge_overlay_into_entry(policy_entry_t *tgt, policy_entry_t *ov,
                                    const char **err_msg)
{
    if (ov->has_insecure) {
        tgt->has_insecure = true;
        tgt->insecure = ov->insecure;
    }
    if (ov->has_ca_bundle) {
        free(tgt->ca_bundle);
        tgt->ca_bundle = ov->ca_bundle;
        ov->ca_bundle = NULL;
        tgt->has_ca_bundle = true;
    }
    if (ov->has_auth_file) {
        free(tgt->auth_file);
        tgt->auth_file = ov->auth_file;
        ov->auth_file = NULL;
        tgt->has_auth_file = true;
    }
    if (ov->has_sigstore_public_key) {
        free(tgt->sigstore_public_key);
        tgt->sigstore_public_key = ov->sigstore_public_key;
        ov->sigstore_public_key = NULL;
        tgt->has_sigstore_public_key = true;
    }
    for (size_t i = 0; i < ov->n_unknown_keys; i++) {
        if (strarr_push(&tgt->unknown_keys, &tgt->n_unknown_keys,
                        ov->unknown_keys[i]) < 0) {
            (void) err_msg;
            errno = ENOMEM;
            return -1;
        }
    }
    return 0;
}

/* Parse a single registries.d/<host>.json overlay file and field-merge it
 * into the target entry (created if absent). Failure leaves the target
 * unchanged on any path past the merge call; failures before merge never
 * touched the target. The overlay scratch entry is always released here.
 */
static int parse_overlay_file(oci_policy_t *p, const char *host,
                              const char *file_path, const char **err_msg)
{
    size_t body_len = 0;
    char *body = slurp_file(file_path, &body_len);
    if (!body)
        return set_err(p, err_msg,
                       "policy overlay '%s' could not be read: %s",
                       file_path, strerror(errno));
    cJSON *root = cJSON_ParseWithLength(body, body_len);
    free(body);
    if (!root)
        return set_err(p, err_msg,
                       "policy overlay '%s' is not valid JSON", file_path);

    int rc = -1;
    policy_entry_t overlay;
    memset(&overlay, 0, sizeof(overlay));

    if (!cJSON_IsObject(root)) {
        (void) set_err(p, err_msg,
                       "policy overlay '%s' must be a JSON object", file_path);
        goto out;
    }
    overlay.host = xstrdup(host);
    if (!overlay.host) {
        (void) set_err(p, err_msg,
                       "out of memory parsing policy overlay '%s'", file_path);
        goto out;
    }
    if (parse_entry_fields(p, &overlay, root, file_path, err_msg) < 0)
        goto out;
    if (overlay.has_ca_bundle && overlay.ca_bundle) {
        struct stat st;
        if (stat(overlay.ca_bundle, &st) < 0 || !S_ISREG(st.st_mode)) {
            (void) set_err(p, err_msg,
                           "policy overlay '%s': ca_bundle file '%s' "
                           "is not accessible", file_path, overlay.ca_bundle);
            goto out;
        }
    }
    policy_entry_t *target = entry_grow_and_get(p, host);
    if (!target) {
        (void) set_err(p, err_msg,
                       "policy overlay '%s' target entry allocation failed",
                       file_path);
        goto out;
    }
    if (merge_overlay_into_entry(target, &overlay, err_msg) < 0) {
        (void) set_err(p, err_msg,
                       "policy overlay '%s' merge failed: out of memory",
                       file_path);
        goto out;
    }
    rc = 0;
out:
    entry_free(&overlay);
    cJSON_Delete(root);
    return rc;
}

static int overlay_name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *) a, *(const char *const *) b);
}

/* Scan <base_dir>/registries.d/ for *.json overlay files and merge each into
 * the policy. The directory itself is optional: opendir returning ENOENT is
 * silent; any other errno (ENOTDIR, EACCES, ...) is a hard error so an
 * operator pointing at an unreadable overlay tree learns about it. Each
 * filename minus the .json suffix is the target host. Files are processed
 * in lexicographic order for determinism; same-host duplicates cannot exist
 * on POSIX filesystems so the order is mostly observable in diagnostics.
 */
static int load_overlay_dir(oci_policy_t *p, const char *base_path,
                            const char **err_msg)
{
    if (!base_path || !*base_path)
        return 0;
    const char *last_slash = strrchr(base_path, '/');
    if (!last_slash)
        return 0;
    size_t parent_len = (size_t) (last_slash - base_path);
    static const char overlay_suffix[] = "/registries.d";
    size_t suffix_len = sizeof(overlay_suffix) - 1;
    char *dir_path = malloc(parent_len + suffix_len + 1);
    if (!dir_path)
        return set_err(p, err_msg,
                       "out of memory composing policy overlay path");
    memcpy(dir_path, base_path, parent_len);
    memcpy(dir_path + parent_len, overlay_suffix, suffix_len);
    dir_path[parent_len + suffix_len] = '\0';

    DIR *d = opendir(dir_path);
    if (!d) {
        int e = errno;
        if (e == ENOENT) {
            free(dir_path);
            return 0;
        }
        int rc = set_err(p, err_msg,
                         "policy overlay directory '%s' cannot be opened: %s",
                         dir_path, strerror(e));
        free(dir_path);
        errno = e;
        return rc;
    }

    char **names = NULL;
    size_t n_names = 0;
    size_t cap_names = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *n = de->d_name;
        if (n[0] == '.')
            continue;
        size_t nl = strlen(n);
        if (nl <= 5)
            continue;
        if (strcmp(n + nl - 5, ".json") != 0)
            continue;
        if (n_names == cap_names) {
            size_t new_cap = cap_names ? cap_names * 2 : 8;
            char **next = (char **) realloc((void *) names,
                                            new_cap * sizeof(char *));
            if (!next) {
                closedir(d);
                strarr_free(names, n_names);
                int rc = set_err(p, err_msg,
                                 "policy overlay '%s' name-list allocation "
                                 "failed", dir_path);
                free(dir_path);
                return rc;
            }
            names = next;
            cap_names = new_cap;
        }
        names[n_names] = strdup(n);
        if (!names[n_names]) {
            closedir(d);
            strarr_free(names, n_names);
            int rc = set_err(p, err_msg,
                             "policy overlay '%s' name copy failed",
                             dir_path);
            free(dir_path);
            return rc;
        }
        n_names++;
    }
    closedir(d);

    qsort((void *) names, n_names, sizeof(char *), overlay_name_cmp);

    int rc = 0;
    for (size_t i = 0; i < n_names; i++) {
        const char *fname = names[i];
        size_t nl = strlen(fname);
        size_t host_len = nl - 5; /* trim ".json" */
        if (host_len == 0)
            continue;            /* literal ".json" filename: not a host */
        char *host = malloc(host_len + 1);
        if (!host) {
            rc = set_err(p, err_msg,
                         "out of memory composing overlay host name");
            goto cleanup;
        }
        memcpy(host, fname, host_len);
        host[host_len] = '\0';
        char *file_path = malloc(strlen(dir_path) + 1 + nl + 1);
        if (!file_path) {
            free(host);
            rc = set_err(p, err_msg,
                         "out of memory composing overlay file path");
            goto cleanup;
        }
        sprintf(file_path, "%s/%s", dir_path, fname);
        struct stat st;
        if (stat(file_path, &st) < 0 || !S_ISREG(st.st_mode)) {
            /* Filename ending in .json that turned out not to be a regular
             * file (e.g. a directory named "foo.json"). Silently skip:
             * defensive, leaves base policy load undisturbed.
             */
            free(file_path);
            free(host);
            continue;
        }
        rc = parse_overlay_file(p, host, file_path, err_msg);
        free(file_path);
        free(host);
        if (rc < 0)
            goto cleanup;
    }

cleanup:
    strarr_free(names, n_names);
    free(dir_path);
    return rc;
}

static int parse_body(oci_policy_t *p, const char *body, size_t body_len,
                      const char **err_msg)
{
    cJSON *root = cJSON_ParseWithLength(body, body_len);
    if (!root)
        return set_err(p, err_msg, "policy file '%s' is not valid JSON",
                       p->source_path ? p->source_path : "(stdin)");
    int rc = -1;
    if (!cJSON_IsObject(root)) {
        (void) set_err(p, err_msg, "policy root must be a JSON object");
        goto out;
    }
    cJSON *child;
    cJSON_ArrayForEach(child, root) {
        const char *k = child->string;
        if (!k)
            continue;
        if (!strcmp(k, "default")) {
            if (parse_default_block(p, child, err_msg) < 0)
                goto out;
        } else if (!strcmp(k, "registries")) {
            if (parse_registries_block(p, child, err_msg) < 0)
                goto out;
        } else if (!known_top_key(k)) {
            if (strarr_push(&p->unknown_top_keys, &p->n_unknown_top_keys, k) < 0) {
                (void) set_err(p, err_msg,
                               "policy unknown-key recording failed");
                goto out;
            }
        }
    }
    rc = 0;
out:
    cJSON_Delete(root);
    return rc;
}

int oci_policy_load(oci_policy_t **out, const char **err_msg)
{
    if (!out) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    *out = NULL;

    oci_policy_t *p = calloc(1, sizeof(*p));
    if (!p) {
        if (err_msg)
            *err_msg = "out of memory allocating policy";
        errno = ENOMEM;
        return -1;
    }
    p->err_buf = malloc(POLICY_ERR_CAP);
    if (!p->err_buf) {
        free(p);
        if (err_msg)
            *err_msg = "out of memory allocating policy diagnostic";
        errno = ENOMEM;
        return -1;
    }
    p->err_buf[0] = '\0';

    /* On every failure past this point, *out keeps the partially built
     * policy so the caller can free it (and the err_buf the diagnostic
     * lives in) via oci_policy_free. The policy.h contract requires
     * exactly this shape for diagnostic lifetime.
     */
    *out = p;

    char *path = NULL;
    if (resolve_path(p, &path, err_msg) < 0)
        return -1;

    if (!path) {
        /* Empty chain: built-in default. source_path stays empty. */
        p->source_path = xstrdup("");
        if (!p->source_path)
            return set_err(p, err_msg, "out of memory recording source path");
        return 0;
    }

    p->source_path = path; /* takes ownership */

    size_t body_len = 0;
    char *body = slurp_file(p->source_path, &body_len);
    if (!body)
        return set_err(p, err_msg,
                       "policy file '%s' could not be read: %s",
                       p->source_path, strerror(errno));
    int rc = parse_body(p, body, body_len, err_msg);
    free(body);
    if (rc < 0)
        return rc;
    return load_overlay_dir(p, p->source_path, err_msg);
}

void oci_policy_lookup(const oci_policy_t *p, const char *host,
                       oci_policy_effective_t *eff)
{
    if (!eff)
        return;
    eff->insecure = p ? p->default_insecure : false;
    eff->ca_bundle = p ? p->default_ca_bundle : NULL;
    eff->auth_file = NULL;
    eff->sigstore_public_key = NULL;
    if (!p || !host)
        return;
    for (size_t i = 0; i < p->n_entries; i++) {
        const policy_entry_t *e = &p->entries[i];
        if (strcmp(e->host, host) != 0)
            continue;
        if (e->has_insecure)
            eff->insecure = e->insecure;
        if (e->ca_bundle)
            eff->ca_bundle = e->ca_bundle;
        if (e->auth_file)
            eff->auth_file = e->auth_file;
        if (e->sigstore_public_key)
            eff->sigstore_public_key = e->sigstore_public_key;
        return;
    }
}

/* Static error literals. The auth-file load path has no policy_t err_buf to
 * share, and the diagnostic is short enough that a fixed table beats a
 * dynamic format. The caller composes the final user-facing message with
 * the path it already knows.
 */
static const char AUTH_ERR_OPEN[]      = "auth file could not be opened";
static const char AUTH_ERR_FSTAT[]     = "auth file could not be stat'd";
static const char AUTH_ERR_NOT_REG[]   = "auth file is not a regular file";
static const char AUTH_ERR_MODE[]      = "auth file has insecure mode (must be 0600)";
static const char AUTH_ERR_TOO_BIG[]   = "auth file is too large";
static const char AUTH_ERR_READ[]      = "auth file could not be read";
static const char AUTH_ERR_NOMEM[]     = "out of memory parsing auth file";
static const char AUTH_ERR_BAD_JSON[]  = "auth file is not valid JSON";
static const char AUTH_ERR_NOT_OBJ[]   = "auth file body must be a JSON object";
static const char AUTH_ERR_NO_USER[]   = "auth file missing required string field 'username'";
static const char AUTH_ERR_NO_PASS[]   = "auth file missing required string field 'password'";

int oci_policy_load_auth(const char *path, char **out_user, char **out_pass,
                         const char **err_msg)
{
    if (!path || !out_user || !out_pass) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    *out_user = NULL;
    *out_pass = NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno;
        if (err_msg)
            *err_msg = AUTH_ERR_OPEN;
        errno = e;
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int e = errno;
        close(fd);
        if (err_msg)
            *err_msg = AUTH_ERR_FSTAT;
        errno = e;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        if (err_msg)
            *err_msg = AUTH_ERR_NOT_REG;
        errno = EINVAL;
        return -1;
    }
    /* Mode must grant access to the owner only. 0600 is the canonical
     * shape; 0400 (read-only) is also accepted. Any bit in the group or
     * other triad fails the check.
     */
    if ((st.st_mode & 077) != 0) {
        close(fd);
        if (err_msg)
            *err_msg = AUTH_ERR_MODE;
        errno = EPERM;
        return -1;
    }
    if (st.st_size < 0 || (uint64_t) st.st_size >= (uint64_t) SIZE_MAX) {
        close(fd);
        if (err_msg)
            *err_msg = AUTH_ERR_TOO_BIG;
        errno = EFBIG;
        return -1;
    }
    size_t len = (size_t) st.st_size;
    char *buf = malloc(len + 1);
    if (!buf) {
        close(fd);
        if (err_msg)
            *err_msg = AUTH_ERR_NOMEM;
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            free(buf);
            close(fd);
            if (err_msg)
                *err_msg = AUTH_ERR_READ;
            errno = e;
            return -1;
        }
        if (n == 0)
            break;
        off += (size_t) n;
    }
    close(fd);
    buf[off] = '\0';

    cJSON *json = cJSON_ParseWithLength(buf, off);
    free(buf);
    if (!json) {
        if (err_msg)
            *err_msg = AUTH_ERR_BAD_JSON;
        errno = EINVAL;
        return -1;
    }
    if (!cJSON_IsObject(json)) {
        cJSON_Delete(json);
        if (err_msg)
            *err_msg = AUTH_ERR_NOT_OBJ;
        errno = EINVAL;
        return -1;
    }
    cJSON *ju = cJSON_GetObjectItemCaseSensitive(json, "username");
    if (!cJSON_IsString(ju) || !ju->valuestring) {
        cJSON_Delete(json);
        if (err_msg)
            *err_msg = AUTH_ERR_NO_USER;
        errno = EINVAL;
        return -1;
    }
    cJSON *jp = cJSON_GetObjectItemCaseSensitive(json, "password");
    if (!cJSON_IsString(jp) || !jp->valuestring) {
        cJSON_Delete(json);
        if (err_msg)
            *err_msg = AUTH_ERR_NO_PASS;
        errno = EINVAL;
        return -1;
    }
    *out_user = xstrdup(ju->valuestring);
    *out_pass = xstrdup(jp->valuestring);
    cJSON_Delete(json);
    if (!*out_user || !*out_pass) {
        if (err_msg)
            *err_msg = AUTH_ERR_NOMEM;
        errno = ENOMEM;
        return -1;
    }
    return 0;
}
