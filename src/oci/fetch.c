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
};

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
    free(f);
}

void oci_fetch_response_free(oci_fetch_response_t *r)
{
    if (!r)
        return;
    free(r->body);
    free(r->content_type);
    free(r->docker_content_digest);
    r->body = NULL;
    r->content_type = NULL;
    r->docker_content_digest = NULL;
    r->body_len = 0;
    r->http_status = 0;
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
                                                const char *const *accept_types)
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
    return hdrs;
}

static int fetch_token(oci_fetcher_t *f, const char **err_msg)
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
                                const char *url,
                                const char *const *accept_types,
                                oci_fetch_response_t *out,
                                bearer_challenge_t *challenge_out,
                                const char **err_msg)
{
    body_buf_t body = {.max = FETCH_BODY_MAX};
    headers_ctx_t hctx = {.challenge_out = challenge_out};
    if (challenge_out)
        bearer_challenge_free(challenge_out);

    curl_easy_reset(f->easy);
    curl_easy_setopt(f->easy, CURLOPT_URL, url);
    curl_easy_setopt(f->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(f->easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(f->easy, CURLOPT_USERAGENT, "elfuse-oci/1");
    curl_easy_setopt(f->easy, CURLOPT_WRITEFUNCTION, body_write_cb);
    curl_easy_setopt(f->easy, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(f->easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(f->easy, CURLOPT_HEADERDATA, &hctx);
    struct curl_slist *hdrs = build_request_headers(f, accept_types);
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
        if (err_msg)
            *err_msg = curl_easy_strerror(rc);
        errno = EIO;
        return -1;
    }
    if (body.overflow) {
        free(body.buf);
        free(hctx.content_type);
        free(hctx.docker_content_digest);
        if (err_msg)
            *err_msg = "response body exceeded max size";
        errno = EFBIG;
        return -1;
    }
    out->body = body.buf;
    out->body_len = body.len;
    out->content_type = hctx.content_type;
    out->docker_content_digest = hctx.docker_content_digest;
    return 0;
}

int oci_fetch_manifest(oci_fetcher_t *f,
                       const oci_ref_t *ref,
                       const char *digest_or_tag,
                       const char *const *accept_types,
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
    const char *selector = digest_or_tag;
    if (!selector)
        selector = ref->digest;
    if (!selector)
        selector = ref->tag;
    if (!selector) {
        if (err_msg)
            *err_msg = "reference has no tag or digest";
        errno = EINVAL;
        return -1;
    }
    char *url = build_manifest_url(f, ref, selector);
    if (!url) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        return -1;
    }

    bearer_challenge_t challenge = {0};
    int rc = perform_manifest_get(f, url, accept_types, out,
                                  f->bearer_token ? NULL : &challenge,
                                  err_msg);
    if (rc < 0) {
        free(url);
        bearer_challenge_free(&challenge);
        return -1;
    }

    if (out->http_status == 401 && challenge.realm) {
        bearer_challenge_free(&f->challenge);
        f->challenge = challenge;
        memset(&challenge, 0, sizeof(challenge));
        oci_fetch_response_free(out);
        memset(out, 0, sizeof(*out));
        if (fetch_token(f, err_msg) < 0) {
            free(url);
            return -1;
        }
        rc = perform_manifest_get(f, url, accept_types, out, NULL, err_msg);
        if (rc < 0) {
            free(url);
            return -1;
        }
    } else {
        bearer_challenge_free(&challenge);
    }

    free(url);

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
    int64_t bytes_seen;
    int64_t bytes_expected;
    bool overflow;
    bool write_failed;
} blob_stream_ctx_t;

static size_t blob_stream_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    blob_stream_ctx_t *ctx = userdata;
    size_t n = size * nmemb;
    if (ctx->overflow || ctx->write_failed)
        return 0;
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

static int perform_blob_get(oci_fetcher_t *f,
                            const char *url,
                            blob_stream_ctx_t *bctx,
                            long *out_status,
                            bearer_challenge_t *challenge_out,
                            const char **err_msg)
{
    headers_ctx_t hctx = {.challenge_out = challenge_out};
    if (challenge_out)
        bearer_challenge_free(challenge_out);

    curl_easy_reset(f->easy);
    curl_easy_setopt(f->easy, CURLOPT_URL, url);
    curl_easy_setopt(f->easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(f->easy, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(f->easy, CURLOPT_USERAGENT, "elfuse-oci/1");
    curl_easy_setopt(f->easy, CURLOPT_WRITEFUNCTION, blob_stream_cb);
    curl_easy_setopt(f->easy, CURLOPT_WRITEDATA, bctx);
    curl_easy_setopt(f->easy, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(f->easy, CURLOPT_HEADERDATA, &hctx);
    struct curl_slist *hdrs = build_request_headers(f, NULL);
    if (hdrs)
        curl_easy_setopt(f->easy, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(f->easy);
    long status = 0;
    curl_easy_getinfo(f->easy, CURLINFO_RESPONSE_CODE, &status);
    if (hdrs)
        curl_slist_free_all(hdrs);
    free(hctx.content_type);
    free(hctx.docker_content_digest);

    *out_status = status;
    if (rc != CURLE_OK) {
        if (bctx->overflow) {
            if (err_msg)
                *err_msg = "blob exceeded declared size";
            errno = EPROTO;
            return -1;
        }
        if (bctx->write_failed) {
            if (err_msg)
                *err_msg = "blob writer rejected payload";
            errno = EIO;
            return -1;
        }
        if (err_msg)
            *err_msg = curl_easy_strerror(rc);
        errno = EIO;
        return -1;
    }
    return 0;
}

int oci_fetch_blob(oci_fetcher_t *f,
                   const oci_ref_t *ref,
                   const oci_descriptor_t *desc,
                   oci_blob_store_t *store,
                   const char **err_msg)
{
    if (!f || !ref || !desc || !store) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    if (desc->size < 0) {
        if (err_msg)
            *err_msg = "descriptor size is negative";
        errno = EINVAL;
        return -1;
    }
    if (oci_blob_store_has(store, desc->algo, desc->hex))
        return 0;

    char *url = build_blob_url(f, ref, desc->digest_str);
    if (!url) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        return -1;
    }

    oci_blob_writer_t *w = oci_blob_writer_begin(store, desc->algo, desc->hex);
    if (!w) {
        free(url);
        if (err_msg)
            *err_msg = "failed to start blob writer";
        return -1;
    }
    blob_stream_ctx_t bctx = {.w = w, .bytes_expected = desc->size};

    bearer_challenge_t challenge = {0};
    long status = 0;
    int rc = perform_blob_get(f, url, &bctx, &status,
                              f->bearer_token ? NULL : &challenge, err_msg);
    if (rc < 0) {
        free(url);
        oci_blob_writer_abort(w);
        bearer_challenge_free(&challenge);
        return -1;
    }

    if (status == 401 && challenge.realm) {
        oci_blob_writer_abort(w);
        bearer_challenge_free(&f->challenge);
        f->challenge = challenge;
        memset(&challenge, 0, sizeof(challenge));
        if (fetch_token(f, err_msg) < 0) {
            free(url);
            return -1;
        }
        w = oci_blob_writer_begin(store, desc->algo, desc->hex);
        if (!w) {
            free(url);
            if (err_msg)
                *err_msg = "failed to restart blob writer";
            return -1;
        }
        bctx = (blob_stream_ctx_t){.w = w, .bytes_expected = desc->size};
        rc = perform_blob_get(f, url, &bctx, &status, NULL, err_msg);
        if (rc < 0) {
            free(url);
            oci_blob_writer_abort(w);
            return -1;
        }
    } else {
        bearer_challenge_free(&challenge);
    }

    free(url);

    if (status < 200 || status >= 300) {
        oci_blob_writer_abort(w);
        if (err_msg)
            *err_msg = "blob fetch returned non-2xx status";
        errno = EPROTO;
        return -1;
    }
    if (bctx.bytes_seen != desc->size) {
        oci_blob_writer_abort(w);
        if (err_msg)
            *err_msg = "blob size mismatch";
        errno = EPROTO;
        return -1;
    }
    if (oci_blob_writer_commit(w) < 0) {
        if (err_msg)
            *err_msg = "blob digest mismatch on commit";
        return -1;
    }
    return 0;
}
