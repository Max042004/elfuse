/* OCI registry HTTPS client
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements anonymous and bearer-challenge HTTPS pulls against the OCI
 * distribution-spec /v2/ endpoints. Manifest fetches return body bytes plus a
 * captured Content-Type and Docker-Content-Digest so the slice-3 parser and
 * future tag-to-digest pinning can consume them directly. Blob fetches stream
 * the response body into the slice-2 blob store, capping the running byte
 * count at the descriptor's declared size and letting the writer's digest
 * check reject any payload that hashes to anything other than the descriptor
 * hex.
 *
 * The 401 retry path is "try anonymous first, then parse Www-Authenticate,
 * fetch a token, retry once". A second 401 propagates as a fetch failure; the
 * caller decides whether to surface authorization-failed or treat it as a
 * transient network error. The cached bearer token is invalidated by any 401
 * but otherwise reused across requests on the same fetcher, so a pull of an
 * image with N layers makes one token call rather than N+1.
 */

#include "fetch.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../externals/cjson/cJSON.h"
#include "policy.h"

/* Hard ceiling on a single manifest / index / config response. Real-world
 * documents are well under 1 MiB; the limit is here so a misbehaving registry
 * cannot fill memory with an unbounded body. Blob responses do not flow
 * through this buffer; they stream into the blob store.
 */
#define FETCH_BODY_MAX ((size_t) 16 * 1024 * 1024)

typedef struct {
    char *realm;
    char *service;
    char *scope;
} bearer_challenge_t;

struct oci_fetcher {
    CURL *easy;
    char *base_url_override;
    char *bearer_token;
    bearer_challenge_t challenge;
    /* Pre-built "user:pass" string for CURLOPT_USERPWD. NULL when CLI basic
     * auth is disabled. The fetcher attaches it to every easy-handle reset
     * (manifest GET, blob GET, token GET) so a registry that bridges basic
     * and bearer sees the basic credentials on both the manifest probe and
     * the token exchange.
     */
    char *user_pass;
    /* PEM bundle path passed through to CURLOPT_CAINFO. NULL leaves libcurl on
     * its compiled-in trust store.
     */
    char *ca_file;
    bool allow_insecure;
    /* Caller-owned policy. NULL when the caller has not loaded a policy.json.
     * Consulted by resolve_effective on every manifest/blob entry; the
     * fetcher does not take a copy and does not free it.
     */
    const oci_policy_t *policy;
};

/* Per-request merge of CLI-supplied options and the policy lookup for the
 * current ref->registry. resolve_effective produces one of these and the
 * request paths read it instead of f->{user_pass,ca_file,allow_insecure}.
 * Strings are borrowed (point into f->* or into the policy_t entry) except
 * user_pass_loaded, which holds a heap "user:pass" built from a policy
 * auth_file. effective_free releases that one allocation.
 */
typedef struct {
    const char *user_pass;
    const char *ca_file;
    bool allow_insecure;
    char *user_pass_loaded;
} effective_opts_t;

static void effective_free(effective_opts_t *eff)
{
    if (!eff)
        return;
    free(eff->user_pass_loaded);
    eff->user_pass_loaded = NULL;
    eff->user_pass = NULL;
    eff->ca_file = NULL;
    eff->allow_insecure = false;
}

/* Build the per-request effective options from the fetcher's CLI defaults and
 * any policy entry matching ref->registry. CLI flags win: a CLI-supplied
 * user_pass / ca_file / allow_insecure shadows the policy value for the same
 * field. A policy auth_file is loaded via oci_policy_load_auth, which
 * enforces 0600 mode and the {username,password} JSON shape. Returns 0 on
 * success, -1 with errno + *err_msg on auth_file load failure. The caller
 * always invokes effective_free, including on rc != 0.
 */
static int resolve_effective(const oci_fetcher_t *f, const oci_ref_t *ref,
                             effective_opts_t *eff, const char **err_msg)
{
    memset(eff, 0, sizeof(*eff));
    eff->user_pass = f->user_pass;
    eff->ca_file = f->ca_file;
    eff->allow_insecure = f->allow_insecure;

    if (!f->policy || !ref || !ref->registry)
        return 0;

    oci_policy_effective_t pol;
    oci_policy_lookup(f->policy, ref->registry, &pol);

    if (!eff->allow_insecure && pol.insecure)
        eff->allow_insecure = true;
    if (!eff->ca_file && pol.ca_bundle)
        eff->ca_file = pol.ca_bundle;

    /* Only consult policy auth_file when the caller did not supply CLI
     * credentials. The load happens per-request; auth files are small and
     * mode-checked each time, which avoids any cache-vs-disk consistency
     * worry at the cost of re-parsing a sub-kilobyte JSON document.
     */
    if (!eff->user_pass && pol.auth_file) {
        char *user = NULL;
        char *pass = NULL;
        const char *aerr = NULL;
        if (oci_policy_load_auth(pol.auth_file, &user, &pass, &aerr) < 0) {
            int e = errno;
            free(user);
            free(pass);
            if (err_msg)
                *err_msg = aerr ? aerr : "policy auth file load failed";
            errno = e ? e : EINVAL;
            return -1;
        }
        size_t ul = strlen(user);
        size_t pl = strlen(pass);
        char *up = malloc(ul + 1 + pl + 1);
        if (!up) {
            free(user);
            free(pass);
            if (err_msg)
                *err_msg = "out of memory composing policy credentials";
            errno = ENOMEM;
            return -1;
        }
        memcpy(up, user, ul);
        up[ul] = ':';
        memcpy(up + ul + 1, pass, pl);
        up[ul + 1 + pl] = '\0';
        free(user);
        free(pass);
        eff->user_pass_loaded = up;
        eff->user_pass = up;
    }
    return 0;
}

static pthread_once_t g_curl_init_once = PTHREAD_ONCE_INIT;
static int g_curl_init_rc = -1;

static void curl_global_once(void)
{
    g_curl_init_rc = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

int oci_fetch_global_init(void)
{
    pthread_once(&g_curl_init_once, curl_global_once);
    if (g_curl_init_rc < 0)
        errno = EIO;
    return g_curl_init_rc;
}

void oci_fetch_global_cleanup(void)
{
    /* curl_global_cleanup is not safe under threading. elfuse process lives
     * for the duration of one pull so leaving libcurl initialized is fine.
     */
}

static void bearer_challenge_free(bearer_challenge_t *c)
{
    if (!c)
        return;
    free(c->realm);
    free(c->service);
    free(c->scope);
    c->realm = NULL;
    c->service = NULL;
    c->scope = NULL;
}

static char *build_user_pass(const char *user, const char *pass)
{
    if (!user)
        return NULL;
    size_t ul = strlen(user);
    size_t pl = pass ? strlen(pass) : 0;
    char *out = malloc(ul + 1 + pl + 1);
    if (!out)
        return NULL;
    memcpy(out, user, ul);
    out[ul] = ':';
    if (pl)
        memcpy(out + ul + 1, pass, pl);
    out[ul + 1 + pl] = '\0';
    return out;
}

oci_fetcher_t *oci_fetcher_new(const oci_fetcher_options_t *opts)
{
    if (oci_fetch_global_init() < 0)
        return NULL;
    oci_fetcher_t *f = calloc(1, sizeof(*f));
    if (!f) {
        errno = ENOMEM;
        return NULL;
    }
    f->easy = curl_easy_init();
    if (!f->easy) {
        free(f);
        errno = EIO;
        return NULL;
    }
    if (opts && opts->base_url_override) {
        f->base_url_override = strdup(opts->base_url_override);
        if (!f->base_url_override) {
            curl_easy_cleanup(f->easy);
            free(f);
            errno = ENOMEM;
            return NULL;
        }
    }
    if (opts && opts->username) {
        f->user_pass = build_user_pass(opts->username, opts->password);
        if (!f->user_pass) {
            curl_easy_cleanup(f->easy);
            free(f->base_url_override);
            free(f);
            errno = ENOMEM;
            return NULL;
        }
    }
    if (opts && opts->ca_file) {
        f->ca_file = strdup(opts->ca_file);
        if (!f->ca_file) {
            curl_easy_cleanup(f->easy);
            free(f->base_url_override);
            free(f->user_pass);
            free(f);
            errno = ENOMEM;
            return NULL;
        }
    }
    if (opts)
        f->allow_insecure = opts->allow_insecure;
    if (opts)
        f->policy = opts->policy;
    return f;
}

void oci_fetcher_free(oci_fetcher_t *f)
{
    if (!f)
        return;
    if (f->easy)
        curl_easy_cleanup(f->easy);
    free(f->base_url_override);
    free(f->bearer_token);
    bearer_challenge_free(&f->challenge);
    free(f->user_pass);
    free(f->ca_file);
    free(f);
}

void oci_fetch_response_free(oci_fetch_response_t *r)
{
    if (!r)
        return;
    free(r->body);
    free(r->content_type);
    free(r->docker_content_digest);
    free(r->etag);
    r->body = NULL;
    r->content_type = NULL;
    r->docker_content_digest = NULL;
    r->etag = NULL;
    r->body_len = 0;
    r->http_status = 0;
}

/* Strip the [bracketed] form of an IPv6 literal and any trailing :port from a
 * registry-shaped string ("127.0.0.1:fake", "ghcr.io", "[::1]:5000",
 * "registry.example.com"). Writes the bare host into out and returns true on
 * success; returns false when out is too small to fit the result.
 *
 * Bracketed IPv6 forms have a colon inside the address, so port-stripping
 * keys off the closing ']'; for non-bracketed registries the rightmost ':'
 * is the port delimiter.
 */
static bool extract_host_from_registry(const char *reg, char *out, size_t cap)
{
    if (!reg || !out || cap == 0)
        return false;
    if (reg[0] == '[') {
        const char *close = strchr(reg, ']');
        if (!close)
            return false;
        size_t n = (size_t) (close - reg - 1);
        if (n + 1 > cap)
            return false;
        memcpy(out, reg + 1, n);
        out[n] = '\0';
        return true;
    }
    const char *colon = strrchr(reg, ':');
    size_t n = colon ? (size_t) (colon - reg) : strlen(reg);
    if (n + 1 > cap)
        return false;
    memcpy(out, reg, n);
    out[n] = '\0';
    return true;
}

static bool is_loopback_host(const char *host)
{
    if (!host)
        return false;
    if (!strcasecmp(host, "127.0.0.1"))
        return true;
    if (!strcasecmp(host, "localhost"))
        return true;
    if (!strcasecmp(host, "::1"))
        return true;
    return false;
}

/* Reject allow_insecure when the registry host is not on the loopback
 * whitelist. Honors ref->registry as the authoritative target even when a
 * test passes base_url_override, so that policy reflects the production
 * surface ("which host am I pulling from?") rather than where the bytes
 * happen to flow during a unit test. The decision is made on the effective
 * opts (CLI || policy), so a policy insecure=true on a non-loopback host
 * fails the same way a CLI --insecure on a non-loopback host fails.
 */
static int check_insecure_policy(const effective_opts_t *eff,
                                 const oci_ref_t *ref, const char **err_msg)
{
    if (!eff->allow_insecure)
        return 0;
    char host[256];
    if (!extract_host_from_registry(ref->registry, host, sizeof(host))) {
        if (err_msg)
            *err_msg = "registry host is malformed";
        errno = EINVAL;
        return -1;
    }
    if (!is_loopback_host(host)) {
        if (err_msg)
            *err_msg = "allow_insecure is restricted to loopback registries";
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* Apply the per-request effective security options to the easy handle in its
 * post-reset state. Called from every GET path (manifest, blob, token) after
 * curl_easy_reset so the option set survives the reset.
 */
static void apply_security_opts(CURL *easy, const effective_opts_t *eff)
{
    if (eff->user_pass) {
        curl_easy_setopt(easy, CURLOPT_USERPWD, eff->user_pass);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, (long) CURLAUTH_BASIC);
    }
    if (eff->ca_file)
        curl_easy_setopt(easy, CURLOPT_CAINFO, eff->ca_file);
    if (eff->allow_insecure) {
        curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

/* docker.io is the canonical registry name from the reference parser; the
 * actual API host is registry-1.docker.io. Every other registry (ghcr.io,
 * quay.io, public.ecr.aws, mirrors) uses its own host directly.
 */
static const char *api_host_for_registry(const char *reg)
{
    if (reg && !strcmp(reg, "docker.io"))
        return "registry-1.docker.io";
    return reg;
}

static char *build_base_url(const oci_fetcher_t *f, const oci_ref_t *ref)
{
    if (f->base_url_override)
        return strdup(f->base_url_override);
    const char *host = api_host_for_registry(ref->registry);
    if (!host)
        return NULL;
    size_t n = strlen(host) + sizeof("https://");
    char *url = malloc(n);
    if (!url)
        return NULL;
    snprintf(url, n, "https://%s", host);
    return url;
}

static char *build_manifest_url(const oci_fetcher_t *f,
                                const oci_ref_t *ref,
                                const char *selector)
{
    char *base = build_base_url(f, ref);
    if (!base)
        return NULL;
    size_t n = strlen(base) + strlen(ref->repository) + strlen(selector) +
               sizeof("/v2//manifests/");
    char *url = malloc(n);
    if (!url) {
        free(base);
        return NULL;
    }
    snprintf(url, n, "%s/v2/%s/manifests/%s", base, ref->repository, selector);
    free(base);
    return url;
}

static char *build_blob_url(const oci_fetcher_t *f,
                            const oci_ref_t *ref,
                            const char *digest_str)
{
    char *base = build_base_url(f, ref);
    if (!base)
        return NULL;
    size_t n = strlen(base) + strlen(ref->repository) + strlen(digest_str) +
               sizeof("/v2//blobs/");
    char *url = malloc(n);
    if (!url) {
        free(base);
        return NULL;
    }
    snprintf(url, n, "%s/v2/%s/blobs/%s", base, ref->repository, digest_str);
    free(base);
    return url;
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    size_t max;
    bool overflow;
} body_buf_t;

static size_t body_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    body_buf_t *b = userdata;
    size_t n = size * nmemb;
    if (b->overflow)
        return 0;
    if (b->len + n + 1 > b->max) {
        b->overflow = true;
        return 0;
    }
    if (b->len + n + 1 > b->cap) {
        size_t newcap = b->cap ? b->cap : 4096;
        while (newcap < b->len + n + 1)
            newcap *= 2;
        if (newcap > b->max + 1)
            newcap = b->max + 1;
        char *r = realloc(b->buf, newcap);
        if (!r) {
            b->overflow = true;
            return 0;
        }
        b->buf = r;
        b->cap = newcap;
    }
    memcpy(b->buf + b->len, ptr, n);
    b->len += n;
    b->buf[b->len] = '\0';
    return n;
}

static char *trim_inplace(char *s)
{
    if (!s)
        return NULL;
    while (*s && isspace((unsigned char) *s))
        s++;
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char) s[n - 1])) {
        s[n - 1] = '\0';
        n--;
    }
    return s;
}

static char *match_header(char *line, const char *key)
{
    size_t klen = strlen(key);
    if (strncasecmp(line, key, klen) != 0)
        return NULL;
    if (line[klen] != ':')
        return NULL;
    char *v = line + klen + 1;
    while (*v == ' ' || *v == '\t')
        v++;
    return v;
}

static char *strdup_range(const char *s, const char *end)
{
    size_t n = (size_t) (end - s);
    char *r = malloc(n + 1);
    if (!r)
        return NULL;
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

/* Parse a Bearer challenge value into realm/service/scope. Accepts unquoted
 * values too (some test fixtures and a few private registries skip the
 * quotes). Returns 0 on success or -1 on malformed input. On success *out is
 * fully owned by the caller; any prior contents are freed.
 */
static int parse_bearer_challenge(const char *value, bearer_challenge_t *out)
{
    bearer_challenge_t tmp = {0};
    const char *p = value;
    while (*p == ' ' || *p == '\t')
        p++;
    if (strncasecmp(p, "Bearer", 6) != 0)
        return -1;
    p += 6;
    while (*p == ' ' || *p == '\t')
        p++;
    while (*p) {
        const char *key_start = p;
        while (*p && *p != '=' && *p != ',')
            p++;
        if (*p != '=') {
            bearer_challenge_free(&tmp);
            return -1;
        }
        const char *key_end = p;
        p++;
        char *value_str;
        if (*p == '"') {
            p++;
            const char *vstart = p;
            while (*p && *p != '"')
                p++;
            if (*p != '"') {
                bearer_challenge_free(&tmp);
                return -1;
            }
            value_str = strdup_range(vstart, p);
            p++;
        } else {
            const char *vstart = p;
            while (*p && *p != ',')
                p++;
            value_str = strdup_range(vstart, p);
        }
        if (!value_str) {
            bearer_challenge_free(&tmp);
            return -1;
        }
        size_t klen = (size_t) (key_end - key_start);
        char **target = NULL;
        if (klen == 5 && !strncasecmp(key_start, "realm", 5))
            target = &tmp.realm;
        else if (klen == 7 && !strncasecmp(key_start, "service", 7))
            target = &tmp.service;
        else if (klen == 5 && !strncasecmp(key_start, "scope", 5))
            target = &tmp.scope;
        if (target) {
            free(*target);
            *target = value_str;
        } else {
            free(value_str);
        }
        while (*p == ',' || *p == ' ' || *p == '\t')
            p++;
    }
    if (!tmp.realm) {
        bearer_challenge_free(&tmp);
        return -1;
    }
    bearer_challenge_free(out);
    *out = tmp;
    return 0;
}

typedef struct {
    char *content_type;
    char *docker_content_digest;
    char *etag;
    bearer_challenge_t *challenge_out;
} headers_ctx_t;

static size_t header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    headers_ctx_t *ctx = userdata;
    size_t n = size * nitems;
    size_t total = n;
    if (n == 0 || n >= 4096)
        return total;
    char line[4096];
    memcpy(line, buffer, n);
    line[n] = '\0';
    while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n'))
        line[--n] = '\0';
    if (n == 0)
        return total;

    char *v = match_header(line, "Content-Type");
    if (v) {
        v = trim_inplace(v);
        char *semi = strchr(v, ';');
        if (semi)
            *semi = '\0';
        v = trim_inplace(v);
        free(ctx->content_type);
        ctx->content_type = strdup(v);
        return total;
    }
    v = match_header(line, "Docker-Content-Digest");
    if (v) {
        v = trim_inplace(v);
        free(ctx->docker_content_digest);
        ctx->docker_content_digest = strdup(v);
        return total;
    }
    v = match_header(line, "ETag");
    if (v) {
        v = trim_inplace(v);
        free(ctx->etag);
        ctx->etag = strdup(v);
        return total;
    }
    if (ctx->challenge_out) {
        v = match_header(line, "Www-Authenticate");
        if (v) {
            v = trim_inplace(v);
            (void) parse_bearer_challenge(v, ctx->challenge_out);
        }
    }
    return total;
}

static struct curl_slist *build_request_headers(const oci_fetcher_t *f,
                                                const char *const *accept_types,
                                                const char *if_none_match)
{
    struct curl_slist *hdrs = NULL;
    if (accept_types) {
        for (const char *const *p = accept_types; *p; p++) {
            char hdr[256];
            snprintf(hdr, sizeof(hdr), "Accept: %s", *p);
            hdrs = curl_slist_append(hdrs, hdr);
        }
    }
    if (f->bearer_token) {
        size_t n = strlen(f->bearer_token) + sizeof("Authorization: Bearer ");
        char *hdr = malloc(n);
        if (hdr) {
            snprintf(hdr, n, "Authorization: Bearer %s", f->bearer_token);
            hdrs = curl_slist_append(hdrs, hdr);
            free(hdr);
        }
    }
    if (if_none_match) {
        size_t n = strlen(if_none_match) + sizeof("If-None-Match: ");
        char *hdr = malloc(n);
        if (hdr) {
            snprintf(hdr, n, "If-None-Match: %s", if_none_match);
            hdrs = curl_slist_append(hdrs, hdr);
            free(hdr);
        }
    }
    return hdrs;
}

static int fetch_token(oci_fetcher_t *f, const effective_opts_t *eff,
                       const char **err_msg)
{
    if (!f->challenge.realm) {
        if (err_msg)
            *err_msg = "no bearer realm to fetch token from";
        errno = EINVAL;
        return -1;
    }

    char *enc_service = f->challenge.service
        ? curl_easy_escape(f->easy, f->challenge.service, 0)
        : NULL;
    char *enc_scope = f->challenge.scope
        ? curl_easy_escape(f->easy, f->challenge.scope, 0)
        : NULL;
    size_t n = strlen(f->challenge.realm) +
               (enc_service ? strlen(enc_service) + 16 : 0) +
               (enc_scope ? strlen(enc_scope) + 16 : 0) + 2;
    char *url = malloc(n);
    if (!url) {
        curl_free(enc_service);
        curl_free(enc_scope);
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        return -1;
    }
    int len = snprintf(url, n, "%s", f->challenge.realm);
    char sep = strchr(f->challenge.realm, '?') ? '&' : '?';
    if (enc_service) {
        len += snprintf(url + len, n - (size_t) len, "%cservice=%s", sep,
                        enc_service);
        sep = '&';
    }
    if (enc_scope) {
        snprintf(url + len, n - (size_t) len, "%cscope=%s", sep, enc_scope);
    }
    curl_free(enc_service);
    curl_free(enc_scope);

    body_buf_t body = {.max = FETCH_BODY_MAX};
    headers_ctx_t hctx = {0};
    curl_easy_reset(f->easy);
    apply_security_opts(f->easy, eff);
    curl_easy_setopt(f->easy, CURLOPT_URL, url);
    curl_easy_setopt(f->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(f->easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(f->easy, CURLOPT_USERAGENT, "elfuse-oci/1");
    curl_easy_setopt(f->easy, CURLOPT_WRITEFUNCTION, body_write_cb);
    curl_easy_setopt(f->easy, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(f->easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(f->easy, CURLOPT_HEADERDATA, &hctx);

    CURLcode rc = curl_easy_perform(f->easy);
    long status = 0;
    curl_easy_getinfo(f->easy, CURLINFO_RESPONSE_CODE, &status);
    free(url);
    free(hctx.content_type);
    free(hctx.docker_content_digest);

    if (rc != CURLE_OK) {
        free(body.buf);
        if (err_msg)
            *err_msg = curl_easy_strerror(rc);
        errno = EIO;
        return -1;
    }
    if (status < 200 || status >= 300) {
        free(body.buf);
        if (err_msg)
            *err_msg = "token endpoint returned non-2xx status";
        errno = EPROTO;
        return -1;
    }
    if (!body.buf || body.len == 0) {
        free(body.buf);
        if (err_msg)
            *err_msg = "token endpoint returned empty body";
        errno = EPROTO;
        return -1;
    }

    cJSON *json = cJSON_ParseWithLength(body.buf, body.len);
    free(body.buf);
    if (!json) {
        if (err_msg)
            *err_msg = "token endpoint returned invalid JSON";
        errno = EPROTO;
        return -1;
    }
    cJSON *t = cJSON_GetObjectItemCaseSensitive(json, "token");
    if (!cJSON_IsString(t) || !t->valuestring)
        t = cJSON_GetObjectItemCaseSensitive(json, "access_token");
    if (!cJSON_IsString(t) || !t->valuestring) {
        cJSON_Delete(json);
        if (err_msg)
            *err_msg = "token endpoint response lacks 'token' field";
        errno = EPROTO;
        return -1;
    }
    free(f->bearer_token);
    f->bearer_token = strdup(t->valuestring);
    cJSON_Delete(json);
    if (!f->bearer_token) {
        if (err_msg)
            *err_msg = "out of memory caching token";
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

static int perform_manifest_get(oci_fetcher_t *f,
                                const effective_opts_t *eff,
                                const char *url,
                                const char *const *accept_types,
                                const char *if_none_match,
                                oci_fetch_response_t *out,
                                bearer_challenge_t *challenge_out,
                                const char **err_msg)
{
    body_buf_t body = {.max = FETCH_BODY_MAX};
    headers_ctx_t hctx = {.challenge_out = challenge_out};
    if (challenge_out)
        bearer_challenge_free(challenge_out);

    curl_easy_reset(f->easy);
    apply_security_opts(f->easy, eff);
    curl_easy_setopt(f->easy, CURLOPT_URL, url);
    curl_easy_setopt(f->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(f->easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(f->easy, CURLOPT_USERAGENT, "elfuse-oci/1");
    curl_easy_setopt(f->easy, CURLOPT_WRITEFUNCTION, body_write_cb);
    curl_easy_setopt(f->easy, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(f->easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(f->easy, CURLOPT_HEADERDATA, &hctx);
    struct curl_slist *hdrs =
        build_request_headers(f, accept_types, if_none_match);
    if (hdrs)
        curl_easy_setopt(f->easy, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(f->easy);
    long status = 0;
    curl_easy_getinfo(f->easy, CURLINFO_RESPONSE_CODE, &status);
    if (hdrs)
        curl_slist_free_all(hdrs);

    out->http_status = status;
    if (rc != CURLE_OK) {
        free(body.buf);
        free(hctx.content_type);
        free(hctx.docker_content_digest);
        free(hctx.etag);
        if (err_msg)
            *err_msg = curl_easy_strerror(rc);
        errno = EIO;
        return -1;
    }
    if (body.overflow) {
        free(body.buf);
        free(hctx.content_type);
        free(hctx.docker_content_digest);
        free(hctx.etag);
        if (err_msg)
            *err_msg = "response body exceeded max size";
        errno = EFBIG;
        return -1;
    }
    out->body = body.buf;
    out->body_len = body.len;
    out->content_type = hctx.content_type;
    out->docker_content_digest = hctx.docker_content_digest;
    out->etag = hctx.etag;
    return 0;
}

int oci_fetch_manifest(oci_fetcher_t *f,
                       const oci_ref_t *ref,
                       const char *digest_or_tag,
                       const char *const *accept_types,
                       const char *if_none_match,
                       oci_fetch_response_t *out,
                       const char **err_msg)
{
    if (!f || !ref || !out) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    effective_opts_t eff;
    if (resolve_effective(f, ref, &eff, err_msg) < 0)
        return -1;
    if (check_insecure_policy(&eff, ref, err_msg) < 0) {
        effective_free(&eff);
        return -1;
    }
    const char *selector = digest_or_tag;
    if (!selector)
        selector = ref->digest;
    if (!selector)
        selector = ref->tag;
    if (!selector) {
        if (err_msg)
            *err_msg = "reference has no tag or digest";
        errno = EINVAL;
        effective_free(&eff);
        return -1;
    }
    char *url = build_manifest_url(f, ref, selector);
    if (!url) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        effective_free(&eff);
        return -1;
    }

    bearer_challenge_t challenge = {0};
    int rc = perform_manifest_get(f, &eff, url, accept_types, if_none_match,
                                  out,
                                  f->bearer_token ? NULL : &challenge,
                                  err_msg);
    if (rc < 0) {
        free(url);
        bearer_challenge_free(&challenge);
        effective_free(&eff);
        return -1;
    }

    if (out->http_status == 401 && challenge.realm) {
        bearer_challenge_free(&f->challenge);
        f->challenge = challenge;
        memset(&challenge, 0, sizeof(challenge));
        oci_fetch_response_free(out);
        memset(out, 0, sizeof(*out));
        if (fetch_token(f, &eff, err_msg) < 0) {
            free(url);
            effective_free(&eff);
            return -1;
        }
        rc = perform_manifest_get(f, &eff, url, accept_types, if_none_match,
                                  out, NULL, err_msg);
        if (rc < 0) {
            free(url);
            effective_free(&eff);
            return -1;
        }
    } else {
        bearer_challenge_free(&challenge);
    }

    free(url);
    effective_free(&eff);

    /* 304 Not Modified is a success path for conditional revalidation: the
     * caller asked the registry whether the pinned digest still matches and
     * the answer is yes. The body is intentionally empty; the etag (when the
     * server emitted one) stays attached for caller diagnostics.
     */
    if (out->http_status == 304)
        return 0;
    if (out->http_status < 200 || out->http_status >= 300) {
        if (err_msg)
            *err_msg = "manifest fetch returned non-2xx status";
        errno = EPROTO;
        return -1;
    }
    return 0;
}

typedef struct {
    oci_blob_writer_t *w;
    /* The easy handle this stream feeds. Needed so the body callback can
     * peek CURLINFO_RESPONSE_CODE on the first chunk and notice when a
     * server ignored the Range header (200 instead of 206) before any
     * bytes get committed to the writer.
     */
    CURL *easy;
    int64_t bytes_seen;
    int64_t bytes_expected;
    /* Bytes already present on disk in the writer's partial. Zero on a
     * fresh fetch. Drives the body-callback's status peek.
     */
    int64_t resume_offset;
    bool overflow;
    bool write_failed;
    /* Set when the body callback observes a non-206 status while the
     * request carried a Range header. Triggers BH_NEEDS_RESTART in the
     * score path; the writer's polluted digester state is discarded
     * along with the partial when the restart re-arms a fresh writer.
     */
    bool range_rejected;
} blob_stream_ctx_t;

static size_t blob_stream_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    blob_stream_ctx_t *ctx = userdata;
    size_t n = size * nmemb;
    if (ctx->overflow || ctx->write_failed || ctx->range_rejected)
        return 0;
    /* First chunk on a resumed transfer: if the server replied with
     * anything other than 206 Partial Content, the Range header was
     * ignored or rejected. Surface the restart signal here rather than
     * letting the size cap trip on the full-body retransmission.
     */
    if (ctx->resume_offset > 0 && ctx->bytes_seen == ctx->resume_offset &&
        ctx->easy) {
        long status = 0;
        curl_easy_getinfo(ctx->easy, CURLINFO_RESPONSE_CODE, &status);
        if (status != 206) {
            ctx->range_rejected = true;
            return 0;
        }
    }
    int64_t projected = ctx->bytes_seen + (int64_t) n;
    if (projected > ctx->bytes_expected) {
        ctx->overflow = true;
        return 0;
    }
    if (!oci_blob_writer_write(ctx->w, ptr, n)) {
        ctx->write_failed = true;
        return 0;
    }
    ctx->bytes_seen = projected;
    return n;
}

/* Per-handle state for a batch transfer. The handle owns its easy handle,
 * staging writer, URL string, request-header slist, and any captured bearer
 * challenge / response headers. batch_handle_free is safe to call on a
 * zero-initialised slot, and safe to call multiple times.
 */
typedef enum {
    BH_ACTIVE,         /* enqueueable: not yet completed this round */
    BH_NEEDS_RETRY,    /* first round hit 401 + Bearer challenge */
    BH_NEEDS_RESTART,  /* server ignored Range or replied 416; refetch fresh */
    BH_DONE_OK,        /* transfer completed; writer holds verified bytes */
    BH_FAILED,         /* transport / status / size error; err_msg populated */
} batch_state_t;

typedef struct {
    const oci_descriptor_t *desc;
    oci_blob_writer_t *w;
    char *url;
    CURL *easy;
    blob_stream_ctx_t bctx;
    bearer_challenge_t challenge;
    headers_ctx_t hctx;
    struct curl_slist *hdrs;
    long http_status;
    CURLcode last_curl_rc;
    batch_state_t state;
    bool added;
    /* Bytes already present on disk from a prior interrupted fetch. Zero on
     * a fresh start; positive when oci_blob_writer_resume_named picked up a
     * partial. Drives the per-handle Range header and the score-side detection
     * of a server that ignored the Range request.
     */
    int64_t resume_offset;
    /* Per-blob progress callback. Borrowed from the batch entry's argument;
     * NULL when the caller did not request progress. The xferinfo wrapper
     * forwards into this callback with bytes_dl adjusted to total-blob
     * progress (libcurl's dlnow + resume_offset) so the renderer can pair
     * bytes_dl with desc->size as a true completion ratio.
     */
    oci_fetch_blob_batch_progress_cb_t progress_cb;
    void *progress_user;
    const char *err_msg;
} batch_handle_t;

/* libcurl xferinfo wrapper. clientp is the owning batch_handle_t so the
 * callback can look up the descriptor and the resume offset without a
 * separate context struct. dltotal is ignored because resumed transfers
 * report dltotal == remaining bytes, not the full blob size -- desc->size
 * is the authoritative total. The return value propagates from the
 * caller's progress_cb so a future renderer can abort a transfer by
 * returning non-zero, matching libcurl's xferinfo contract.
 */
static int batch_xferinfo_cb(void *clientp, curl_off_t dltotal,
                             curl_off_t dlnow, curl_off_t ultotal,
                             curl_off_t ulnow)
{
    (void) dltotal;
    (void) ultotal;
    (void) ulnow;
    batch_handle_t *h = clientp;
    if (!h || !h->progress_cb)
        return 0;
    int64_t bytes_dl = (int64_t) dlnow + h->resume_offset;
    return h->progress_cb(h->desc, bytes_dl, h->desc->size,
                          h->progress_user);
}

static int batch_max_concurrent(void)
{
    const char *e = getenv("OCI_FETCH_MAX_CONCURRENT");
    if (!e || !*e)
        return 4;
    long n = strtol(e, NULL, 10);
    if (n < 1)
        n = 1;
    if (n > 16)
        n = 16;
    return (int) n;
}

static void batch_handle_free(batch_handle_t *h)
{
    if (h->w) {
        oci_blob_writer_abort(h->w);
        h->w = NULL;
    }
    if (h->easy) {
        curl_easy_cleanup(h->easy);
        h->easy = NULL;
    }
    if (h->hdrs) {
        curl_slist_free_all(h->hdrs);
        h->hdrs = NULL;
    }
    free(h->url);
    h->url = NULL;
    bearer_challenge_free(&h->challenge);
    free(h->hctx.content_type);
    h->hctx.content_type = NULL;
    free(h->hctx.docker_content_digest);
    h->hctx.docker_content_digest = NULL;
    free(h->hctx.etag);
    h->hctx.etag = NULL;
}

/* Configure an easy handle for a blob fetch. Used both at initial prepare
 * time and (after a writer + slist reset) during the post-401 retry round.
 * The challenge capture slot is wired only on round 0 since the existing
 * single-blob path only attempts one refresh.
 */
static void batch_configure_easy(oci_fetcher_t *f, const effective_opts_t *eff,
                                 batch_handle_t *h, bool capture_challenge)
{
    h->bctx.w = h->w;
    h->bctx.easy = h->easy;
    /* Seed bytes_seen with the partial bytes the writer already absorbed so
     * the streaming overflow gate measures total-blob progress against
     * desc->size, not just the bytes the server returned on this leg.
     */
    h->bctx.bytes_seen = h->resume_offset;
    h->bctx.bytes_expected = h->desc->size;
    h->bctx.resume_offset = h->resume_offset;
    h->bctx.overflow = false;
    h->bctx.write_failed = false;
    h->bctx.range_rejected = false;
    h->hctx.challenge_out = capture_challenge ? &h->challenge : NULL;

    apply_security_opts(h->easy, eff);
    curl_easy_setopt(h->easy, CURLOPT_URL, h->url);
    curl_easy_setopt(h->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h->easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(h->easy, CURLOPT_USERAGENT, "elfuse-oci/1");
    curl_easy_setopt(h->easy, CURLOPT_WRITEFUNCTION, blob_stream_cb);
    curl_easy_setopt(h->easy, CURLOPT_WRITEDATA, &h->bctx);
    curl_easy_setopt(h->easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(h->easy, CURLOPT_HEADERDATA, &h->hctx);
    if (h->resume_offset > 0) {
        char range[64];
        snprintf(range, sizeof(range), "%lld-", (long long) h->resume_offset);
        curl_easy_setopt(h->easy, CURLOPT_RANGE, range);
    }
    if (h->progress_cb) {
        curl_easy_setopt(h->easy, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(h->easy, CURLOPT_XFERINFOFUNCTION,
                         batch_xferinfo_cb);
        curl_easy_setopt(h->easy, CURLOPT_XFERINFODATA, h);
    }
    h->hdrs = build_request_headers(f, NULL, NULL);
    if (h->hdrs)
        curl_easy_setopt(h->easy, CURLOPT_HTTPHEADER, h->hdrs);
}

static int batch_prepare_handle(oci_fetcher_t *f, const effective_opts_t *eff,
                                const oci_ref_t *ref, batch_handle_t *h,
                                oci_blob_store_t *store, const char **err_msg)
{
    h->w = oci_blob_writer_resume_named(store, h->desc->algo, h->desc->hex,
                                        h->desc->size, &h->resume_offset);
    if (!h->w) {
        if (err_msg)
            *err_msg = "failed to start blob writer";
        return -1;
    }
    h->url = build_blob_url(f, ref, h->desc->digest_str);
    if (!h->url) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        return -1;
    }
    h->easy = curl_easy_init();
    if (!h->easy) {
        if (err_msg)
            *err_msg = "curl_easy_init failed";
        errno = EIO;
        return -1;
    }
    h->state = BH_ACTIVE;
    h->added = false;
    h->http_status = 0;
    h->last_curl_rc = CURLE_OK;
    h->err_msg = NULL;
    batch_configure_easy(f, eff, h, !f->bearer_token);
    return 0;
}

/* Re-arm a handle for a fresh transfer attempt: token-refresh retry after a
 * 401 + Bearer challenge, or restart-from-zero after a server ignored the
 * Range header (200 instead of 206) or replied 416. The original writer is
 * aborted (its staging file gets unlinked) and a brand-new one starts at
 * byte zero, with resume_offset reset so batch_configure_easy emits no
 * Range header on the next attempt. The easy handle is reset and re-wired
 * with the current bearer token. Challenge capture is disabled so any
 * second-round 401 falls straight through to FAILED, and a second-round
 * 200-after-Range cannot reoccur because resume_offset is now zero.
 */
static int batch_reset_handle_fresh(oci_fetcher_t *f, const effective_opts_t *eff,
                                    batch_handle_t *h, oci_blob_store_t *store)
{
    oci_blob_writer_abort(h->w);
    h->w = NULL;
    if (h->hdrs) {
        curl_slist_free_all(h->hdrs);
        h->hdrs = NULL;
    }
    free(h->hctx.content_type);
    h->hctx.content_type = NULL;
    free(h->hctx.docker_content_digest);
    h->hctx.docker_content_digest = NULL;
    free(h->hctx.etag);
    h->hctx.etag = NULL;
    bearer_challenge_free(&h->challenge);

    h->w = oci_blob_writer_begin_named(store, h->desc->algo, h->desc->hex);
    if (!h->w)
        return -1;
    h->resume_offset = 0;
    curl_easy_reset(h->easy);
    h->state = BH_ACTIVE;
    h->added = false;
    h->http_status = 0;
    h->last_curl_rc = CURLE_OK;
    h->err_msg = NULL;
    batch_configure_easy(f, eff, h, false);
    return 0;
}

/* Score a completed CURLMSG_DONE entry. Translates a curl + HTTP status pair
 * into a batch_state_t transition, mirroring the diagnostic strings the
 * single-blob path historically produced so the test suite's err_msg
 * assertions stay byte-identical.
 */
static void batch_score_done(batch_handle_t *h, CURLcode crc, long status,
                             int round)
{
    h->http_status = status;
    h->last_curl_rc = crc;
    /* The body callback flagged a non-206 response to a Range request.
     * Surface the restart intent before any size / digest / curl-error
     * diagnostics: the discarded bytes would otherwise look like an
     * overflow, and a 416 with a small error body would look like a
     * payload write failure.
     */
    if (h->bctx.range_rejected) {
        h->state = BH_NEEDS_RESTART;
        return;
    }
    if (crc != CURLE_OK) {
        if (h->bctx.overflow) {
            h->err_msg = "blob exceeded declared size";
            errno = EPROTO;
        } else if (h->bctx.write_failed) {
            h->err_msg = "blob writer rejected payload";
            errno = EIO;
        } else {
            h->err_msg = curl_easy_strerror(crc);
            errno = EIO;
        }
        h->state = BH_FAILED;
        return;
    }
    if (status == 401 && h->challenge.realm && round == 0) {
        h->state = BH_NEEDS_RETRY;
        return;
    }
    /* A 416 with an empty body never reached blob_stream_cb, so the
     * range_rejected flag above did not fire. Catch that path here.
     * status == 200 with resume_offset > 0 also belongs to this restart
     * arm, though in practice the body callback catches it first.
     */
    if (h->resume_offset > 0 && (status == 200 || status == 416)) {
        h->state = BH_NEEDS_RESTART;
        return;
    }
    if (status < 200 || status >= 300) {
        h->err_msg = "blob fetch returned non-2xx status";
        errno = EPROTO;
        h->state = BH_FAILED;
        return;
    }
    if (h->bctx.bytes_seen != h->desc->size) {
        h->err_msg = "blob size mismatch";
        errno = EPROTO;
        h->state = BH_FAILED;
        return;
    }
    h->state = BH_DONE_OK;
    /* libcurl's xferinfo does not guarantee a final dlnow == dltotal tick,
     * so the renderer would otherwise stall one update short of "done".
     * One explicit invocation at the score boundary normalises the
     * sequence the user-side callback sees, regardless of socket pacing.
     */
    if (h->progress_cb)
        (void) h->progress_cb(h->desc, h->desc->size, h->desc->size,
                              h->progress_user);
}

int oci_fetch_blob_batch(oci_fetcher_t *f,
                         const oci_ref_t *ref,
                         const oci_descriptor_t *const *descs,
                         size_t n_descs,
                         oci_blob_store_t *store,
                         oci_fetch_blob_batch_progress_cb_t progress_cb,
                         void *cb_user_data,
                         const char **err_msg)
{
    if (!f || !ref || !descs || !store) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    if (n_descs == 0)
        return 0;

    effective_opts_t eff;
    if (resolve_effective(f, ref, &eff, err_msg) < 0)
        return -1;
    if (check_insecure_policy(&eff, ref, err_msg) < 0) {
        effective_free(&eff);
        return -1;
    }

    /* Drop stale tmp partials that no surviving batch can resume from. A
     * week is long enough to let an interrupted multi-day pull finish on
     * the next attempt while still keeping the staging area bounded for
     * caches that see frequent unique blobs. The blob-store guards the
     * tmp/ namespace, so the wide blob-* prefix cannot touch unrelated
     * files.
     */
    oci_blob_store_sweep_partials(store, 7L * 86400);

    int rc = -1;
    int max_concurrent = batch_max_concurrent();
    bool any_failed = false;
    CURLM *multi = NULL;

    batch_handle_t *handles = calloc(n_descs, sizeof(*handles));
    if (!handles) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        goto cleanup;
    }

    /* Dedup pass: drop blobs already in the store, collapse same-digest
     * entries (the layers array can repeat a digest legitimately). nh is
     * the number of handles that actually need a transfer.
     */
    size_t nh = 0;
    for (size_t i = 0; i < n_descs; i++) {
        const oci_descriptor_t *d = descs[i];
        if (!d || d->size < 0) {
            if (err_msg)
                *err_msg = "descriptor size is negative";
            errno = EINVAL;
            goto cleanup;
        }
        if (oci_blob_store_has(store, d->algo, d->hex))
            continue;
        bool dup = false;
        for (size_t j = 0; j < nh; j++) {
            if (handles[j].desc->algo == d->algo &&
                strcmp(handles[j].desc->hex, d->hex) == 0) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        handles[nh].desc = d;
        handles[nh].progress_cb = progress_cb;
        handles[nh].progress_user = cb_user_data;
        nh++;
    }
    if (nh == 0) {
        rc = 0;
        goto cleanup;
    }

    for (size_t i = 0; i < nh; i++) {
        if (batch_prepare_handle(f, &eff, ref, &handles[i], store, err_msg) < 0)
            goto cleanup;
    }

    multi = curl_multi_init();
    if (!multi) {
        if (err_msg)
            *err_msg = "curl_multi_init failed";
        errno = EIO;
        goto cleanup;
    }

    int round = 0;
    /* Outer loop: each iteration tops up the multi up to max_concurrent
     * ACTIVE handles and drains them until still_running hits zero. When no
     * ACTIVE remain the loop checks for NEEDS_RETRY (single token refresh
     * per batch) and either restarts those handles or exits.
     */
    while (1) {
        size_t added_count = 0;
        for (size_t i = 0; i < nh; i++) {
            if (handles[i].added)
                added_count++;
        }
        for (size_t i = 0;
             i < nh && added_count < (size_t) max_concurrent; i++) {
            if (handles[i].state == BH_ACTIVE && !handles[i].added) {
                if (curl_multi_add_handle(multi, handles[i].easy) == CURLM_OK) {
                    handles[i].added = true;
                    added_count++;
                }
            }
        }
        if (added_count == 0)
            break;

        int still_running = 0;
        do {
            int num_fds = 0;
            CURLMcode mrc = curl_multi_poll(multi, NULL, 0, 1000, &num_fds);
            if (mrc != CURLM_OK) {
                if (err_msg)
                    *err_msg = curl_multi_strerror(mrc);
                errno = EIO;
                any_failed = true;
                goto drained;
            }
            curl_multi_perform(multi, &still_running);
            CURLMsg *msg;
            int n_msgs = 0;
            while ((msg = curl_multi_info_read(multi, &n_msgs)) != NULL) {
                if (msg->msg != CURLMSG_DONE)
                    continue;
                batch_handle_t *h = NULL;
                for (size_t i = 0; i < nh; i++) {
                    if (handles[i].easy == msg->easy_handle) {
                        h = &handles[i];
                        break;
                    }
                }
                if (!h)
                    continue;
                CURLcode crc = msg->data.result;
                long status = 0;
                curl_easy_getinfo(h->easy, CURLINFO_RESPONSE_CODE, &status);
                curl_multi_remove_handle(multi, h->easy);
                h->added = false;
                batch_score_done(h, crc, status, round);
            }
        } while (still_running > 0);
drained:
        ;
        /* If there are still ACTIVE slots not yet enqueued, fall back into
         * the outer loop to add them; otherwise check for retries.
         */
        bool more_active = false;
        for (size_t i = 0; i < nh; i++)
            if (handles[i].state == BH_ACTIVE) {
                more_active = true;
                break;
            }
        if (more_active)
            continue;

        bool any_retry = false;
        bool any_restart = false;
        for (size_t i = 0; i < nh; i++) {
            if (handles[i].state == BH_NEEDS_RETRY)
                any_retry = true;
            else if (handles[i].state == BH_NEEDS_RESTART)
                any_restart = true;
        }
        if (!any_retry && !any_restart)
            break;
        if (any_failed)
            break;

        if (any_retry) {
            /* Single token refresh per batch. Steal one retry handle's
             * challenge onto f->challenge so fetch_token sees the
             * realm/service/scope, then re-arm every NEEDS_RETRY handle
             * with the new bearer.
             */
            for (size_t i = 0; i < nh; i++) {
                if (handles[i].state == BH_NEEDS_RETRY) {
                    bearer_challenge_free(&f->challenge);
                    f->challenge = handles[i].challenge;
                    memset(&handles[i].challenge, 0,
                           sizeof(handles[i].challenge));
                    break;
                }
            }
            if (fetch_token(f, &eff, err_msg) < 0) {
                for (size_t i = 0; i < nh; i++) {
                    if (handles[i].state == BH_NEEDS_RETRY) {
                        handles[i].state = BH_FAILED;
                        handles[i].err_msg = "token refresh failed";
                    }
                }
                any_failed = true;
                break;
            }
            round++;
            for (size_t i = 0; i < nh; i++) {
                if (handles[i].state == BH_NEEDS_RETRY) {
                    if (batch_reset_handle_fresh(f, &eff, &handles[i],
                                                 store) < 0) {
                        handles[i].state = BH_FAILED;
                        handles[i].err_msg =
                            "failed to reset writer for retry";
                        any_failed = true;
                    }
                }
            }
            if (any_failed)
                break;
        }

        if (any_restart) {
            /* Range-resume retry: no token refresh, just a fresh writer
             * with resume_offset cleared so the next attempt fetches the
             * full blob without a Range header. The reset itself zeroes
             * resume_offset, so a second 200-after-Range / 416 cannot
             * pick the restart branch again -- the handle either
             * succeeds or falls into BH_FAILED on the next score.
             */
            for (size_t i = 0; i < nh; i++) {
                if (handles[i].state == BH_NEEDS_RESTART) {
                    if (batch_reset_handle_fresh(f, &eff, &handles[i],
                                                 store) < 0) {
                        handles[i].state = BH_FAILED;
                        handles[i].err_msg =
                            "failed to reset writer for restart";
                        any_failed = true;
                    }
                }
            }
            if (any_failed)
                break;
        }
    }

    for (size_t i = 0; i < nh; i++) {
        if (handles[i].state == BH_FAILED) {
            any_failed = true;
            if (err_msg && !*err_msg && handles[i].err_msg)
                *err_msg = handles[i].err_msg;
        } else if (handles[i].state == BH_ACTIVE ||
                   handles[i].state == BH_NEEDS_RETRY ||
                   handles[i].state == BH_NEEDS_RESTART) {
            /* Should be unreachable: the loop only exits when nothing is
             * still queued. Defensive: treat as failure rather than
             * silently dropping the slot.
             */
            any_failed = true;
            handles[i].state = BH_FAILED;
            if (err_msg && !*err_msg)
                *err_msg = "batch left a handle in a non-terminal state";
        }
    }
    if (any_failed) {
        if (err_msg && !*err_msg)
            *err_msg = "batch blob fetch failed";
        goto cleanup;
    }

    /* Commit only after every transfer succeeded. Commit consumes the writer
     * (frees on success), so clear h->w to suppress the batch_handle_free
     * abort. A digest mismatch here aborts any remaining unflushed writers
     * and surfaces the historical "blob digest mismatch on commit" string.
     */
    for (size_t i = 0; i < nh; i++) {
        if (handles[i].state != BH_DONE_OK)
            continue;
        if (oci_blob_writer_commit(handles[i].w) < 0) {
            handles[i].w = NULL;
            if (err_msg)
                *err_msg = "blob digest mismatch on commit";
            for (size_t j = i + 1; j < nh; j++) {
                if (handles[j].state == BH_DONE_OK && handles[j].w) {
                    oci_blob_writer_abort(handles[j].w);
                    handles[j].w = NULL;
                }
            }
            goto cleanup;
        }
        handles[i].w = NULL;
    }
    rc = 0;

cleanup:
    if (multi)
        curl_multi_cleanup(multi);
    if (handles) {
        for (size_t i = 0; i < n_descs; i++)
            batch_handle_free(&handles[i]);
        free(handles);
    }
    effective_free(&eff);
    return rc;
}

int oci_fetch_blob(oci_fetcher_t *f,
                   const oci_ref_t *ref,
                   const oci_descriptor_t *desc,
                   oci_blob_store_t *store,
                   const char **err_msg)
{
    if (!desc) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    return oci_fetch_blob_batch(f, ref, &desc, 1, store, NULL, NULL, err_msg);
}
