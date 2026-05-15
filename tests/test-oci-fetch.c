/* OCI registry HTTPS client unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Spawns a TLS-terminated HTTP/1.1 mock server on 127.0.0.1:<ephemeral> backed
 * by a fresh self-signed RSA certificate generated at startup. The certificate
 * is written to a scratch CA PEM that the fetcher receives via opts.ca_file;
 * negative cases drop the option to force a trust failure. Each test installs
 * a handler that scripts the desired response (200, 401 with Bearer challenge,
 * 401 demanding Basic auth, 404, oversize blob, digest mismatch, ...) and the
 * test verifies fetcher response state plus blob store side effects.
 *
 * libcurl's SSL backend is forced to OpenSSL (LibreSSL on macOS) via
 * curl_global_sslset() before init. The macOS system libcurl ships as a
 * multi-SSL build and ignores CURLOPT_CAINFO under its default Secure
 * Transport backend, which would defeat the ca_file negative cases. The
 * OpenSSL backend honours CAINFO and gives consistent behaviour across macOS
 * and Linux.
 *
 * OCI_FETCH_ONLINE=1 enables one extra case that pulls alpine:3.20 from
 * Docker Hub anonymously. It shares the LibreSSL backend selected here and
 * relies on its default trust roots; it is gated behind
 * make test-oci-fetch-online and is not part of make check.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/fetch.h"
#include "oci/manifest.h"
#include "oci/ref.h"

#include "lib/oci-mock.h"

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

/* Mock server infrastructure lives in tests/lib/oci-mock.{c,h}. This file now
 * only carries the test-specific handlers and assertions.
 */

static void fill_descriptor(oci_descriptor_t *desc,
                            char *digest_str_buf, size_t digest_str_cap,
                            oci_digest_algo_t algo, const char *hex,
                            int64_t size, oci_media_type_t mt)
{
    memset(desc, 0, sizeof(*desc));
    desc->algo = algo;
    snprintf(digest_str_buf, digest_str_cap, "%s:%s",
             oci_digest_algo_name(algo), hex);
    desc->digest_str = digest_str_buf;
    memcpy(desc->hex, hex, strlen(hex) + 1);
    desc->size = size;
    desc->media_type = mt;
}

/* ── Handlers ────────────────────────────────────────────────────── */

typedef struct {
    const char *manifest_path;
    const char *body;
    size_t body_len;
    const char *content_type;
    const char *docker_digest;
} handler_anonymous_manifest_t;

static void h_anonymous_manifest(oci_mock_server_t *s, oci_mock_io_t *io,
                                 const oci_mock_request_t *req)
{
    handler_anonymous_manifest_t *ctx = s->ctx;
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, ctx->docker_digest,
                       ctx->body, ctx->body_len);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
}

typedef struct {
    const char *manifest_path;
    const char *expected_token;
    const char *manifest_body;
    size_t manifest_body_len;
    const char *content_type;
    char base_url[64];
} handler_bearer_t;

static void h_bearer_flow(oci_mock_server_t *s, oci_mock_io_t *io, const oci_mock_request_t *req)
{
    handler_bearer_t *ctx = s->ctx;
    if (strncmp(req->path, "/token", 6) == 0) {
        char body[256];
        int n = snprintf(body, sizeof(body),
                         "{\"token\":\"%s\",\"expires_in\":300}",
                         ctx->expected_token);
        oci_mock_send_full(io, 200, "OK", "application/json", NULL, NULL, body,
                       (size_t) n);
        return;
    }
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        char want_auth[256];
        snprintf(want_auth, sizeof(want_auth), "Bearer %s", ctx->expected_token);
        if (strcmp(req->authorization, want_auth) == 0) {
            oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                           ctx->manifest_body, ctx->manifest_body_len);
            return;
        }
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\","
                 "scope=\"repository:private/secret:pull\"",
                 ctx->base_url);
        oci_mock_send_full(io, 401, "Unauthorized", "application/json", challenge,
                       NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
}

typedef struct {
    const char *blob_path;
    const void *body;
    size_t body_len;
    int status; /* override; 0 = 200 */
    bool oversize; /* if true, send body_len + 5 bytes */
} handler_blob_t;

static void h_blob(oci_mock_server_t *s, oci_mock_io_t *io, const oci_mock_request_t *req)
{
    handler_blob_t *ctx = s->ctx;
    if (strcmp(req->path, ctx->blob_path) != 0) {
        oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
        return;
    }
    int status = ctx->status ? ctx->status : 200;
    if (status != 200) {
        oci_mock_send_full(io, status, "Error", "text/plain", NULL, NULL, "err", 3);
        return;
    }
    if (ctx->oversize) {
        size_t pad_len = ctx->body_len + 5;
        char *buf = malloc(pad_len);
        memcpy(buf, ctx->body, ctx->body_len);
        memset(buf + ctx->body_len, 'X', 5);
        oci_mock_send_full(io, 200, "OK", "application/octet-stream", NULL, NULL,
                       buf, pad_len);
        free(buf);
        return;
    }
    oci_mock_send_full(io, 200, "OK", "application/octet-stream", NULL, NULL,
                   ctx->body, ctx->body_len);
}

typedef struct {
    const char *manifest_path;
    const char *expected_authorization;
    const char *body;
    size_t body_len;
    const char *content_type;
} handler_basic_auth_t;

static void h_basic_auth(oci_mock_server_t *s, oci_mock_io_t *io,
                         const oci_mock_request_t *req)
{
    handler_basic_auth_t *ctx = s->ctx;
    if (strcmp(req->path, ctx->manifest_path) != 0) {
        oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
        return;
    }
    if (strcmp(req->authorization, ctx->expected_authorization) != 0) {
        oci_mock_send_full(io, 401, "Unauthorized", "application/json",
                       "Basic realm=\"reg\"", NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                   ctx->body, ctx->body_len);
}

typedef struct {
    const char *manifest_path;
    const char *expected_basic;
    const char *expected_token;
    const char *manifest_body;
    size_t manifest_body_len;
    const char *content_type;
    char base_url[64];
} handler_basic_then_bearer_t;

static void h_basic_then_bearer(oci_mock_server_t *s, oci_mock_io_t *io,
                                const oci_mock_request_t *req)
{
    handler_basic_then_bearer_t *ctx = s->ctx;
    if (strncmp(req->path, "/token", 6) == 0) {
        if (strcmp(req->authorization, ctx->expected_basic) != 0) {
            oci_mock_send_full(io, 401, "Unauthorized", "application/json", NULL,
                           NULL, "{}", 2);
            return;
        }
        char body[256];
        int n = snprintf(body, sizeof(body),
                         "{\"token\":\"%s\",\"expires_in\":300}",
                         ctx->expected_token);
        oci_mock_send_full(io, 200, "OK", "application/json", NULL, NULL, body,
                       (size_t) n);
        return;
    }
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        char want_bearer[256];
        snprintf(want_bearer, sizeof(want_bearer), "Bearer %s",
                 ctx->expected_token);
        if (strcmp(req->authorization, want_bearer) == 0) {
            oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                           ctx->manifest_body, ctx->manifest_body_len);
            return;
        }
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\","
                 "scope=\"repository:private/secret:pull\"",
                 ctx->base_url);
        oci_mock_send_full(io, 401, "Unauthorized", "application/json", challenge,
                       NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_anonymous_manifest(oci_mock_server_t *server, oci_fetcher_t *f)
{
    static const char BODY[] = "{\"schemaVersion\":2}";
    static const char DIGEST[] =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/alpine/manifests/3.20",
        .body = BODY,
        .body_len = strlen(BODY),
        .content_type = "application/vnd.oci.image.manifest.v1+json",
        .docker_digest = DIGEST,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("anonymous manifest GET", "rc=%d err=%s", rc,
                    err ? err : "(none)");
    } else if (resp.http_status != 200) {
        report_fail("anonymous manifest GET", "status=%ld", resp.http_status);
    } else if (resp.body_len != strlen(BODY) ||
               memcmp(resp.body, BODY, resp.body_len) != 0) {
        report_fail("anonymous manifest GET", "body mismatch");
    } else if (!resp.content_type ||
               strcmp(resp.content_type,
                      "application/vnd.oci.image.manifest.v1+json") != 0) {
        report_fail("anonymous manifest GET", "content_type=%s",
                    resp.content_type ? resp.content_type : "(null)");
    } else if (!resp.docker_content_digest ||
               strcmp(resp.docker_content_digest, DIGEST) != 0) {
        report_fail("anonymous manifest GET", "docker_digest=%s",
                    resp.docker_content_digest ? resp.docker_content_digest
                                               : "(null)");
    } else {
        report_pass("anonymous manifest GET");
    }
    oci_fetch_response_free(&resp);
}

static void test_manifest_404(oci_mock_server_t *server, oci_fetcher_t *f)
{
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/missing/manifests/v9",
        .body = "{}",
        .body_len = 2,
        .content_type = "application/json",
        .docker_digest = NULL,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/nope",
        .tag = "v0",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc == 0) {
        report_fail("manifest 404 surfaces as error", "rc=0");
    } else if (resp.http_status != 404) {
        report_fail("manifest 404 surfaces as error", "status=%ld",
                    resp.http_status);
    } else {
        report_pass("manifest 404 surfaces as error");
    }
    oci_fetch_response_free(&resp);
}

static void test_bearer_challenge(oci_mock_server_t *server, oci_fetcher_t *f,
                                  handler_bearer_t *ctx)
{
    oci_mock_set_handler(server, h_bearer_flow, ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "private/secret",
        .tag = "v1",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("bearer challenge fetches token and retries", "rc=%d err=%s",
                    rc, err ? err : "(none)");
    } else if (resp.http_status != 200 ||
               resp.body_len != ctx->manifest_body_len ||
               memcmp(resp.body, ctx->manifest_body, resp.body_len) != 0) {
        report_fail("bearer challenge fetches token and retries",
                    "status=%ld body_len=%zu", resp.http_status, resp.body_len);
    } else if (server->n_requests != 3) {
        report_fail("bearer challenge fetches token and retries",
                    "expected 3 requests, got %d", server->n_requests);
    } else if (strncmp(server->log[1].path, "/token", 6) != 0) {
        report_fail("bearer challenge fetches token and retries",
                    "second request was %s, not /token", server->log[1].path);
    } else if (strcmp(server->log[2].authorization,
                      "Bearer testtoken123") != 0) {
        report_fail("bearer challenge fetches token and retries",
                    "retry Authorization=%s", server->log[2].authorization);
    } else {
        report_pass("bearer challenge fetches token and retries");
    }
    oci_fetch_response_free(&resp);
}

static void test_token_reuse(oci_mock_server_t *server, oci_fetcher_t *f)
{
    int before = server->n_requests;
    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "private/secret",
        .tag = "v1",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("cached token reused on subsequent fetch", "rc=%d err=%s",
                    rc, err ? err : "(none)");
    } else if (server->n_requests - before != 1) {
        report_fail("cached token reused on subsequent fetch",
                    "expected 1 extra request, got %d",
                    server->n_requests - before);
    } else if (strcmp(server->log[before].authorization,
                      "Bearer testtoken123") != 0) {
        report_fail("cached token reused on subsequent fetch",
                    "Authorization=%s", server->log[before].authorization);
    } else {
        report_pass("cached token reused on subsequent fetch");
    }
    oci_fetch_response_free(&resp);
}

static const char HELLO_WORLD[] = "hello world";
static const char HELLO_WORLD_SHA256[] =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

static void test_blob_success(oci_mock_server_t *server, oci_fetcher_t *f,
                              const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    if (!store) {
        report_fail("blob fetch success commits to store",
                    "store open: %s", strerror(errno));
        return;
    }

    handler_blob_t ctx = {
        .blob_path = "/v2/library/alpine/blobs/sha256:b94d27b9934d3e08a52e52d7"
                     "da7dabfac484efe37a5380ee9088f7ace2efcde9",
        .body = HELLO_WORLD,
        .body_len = strlen(HELLO_WORLD),
    };
    oci_mock_set_handler(server, h_blob, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    char digest_str[128];
    oci_descriptor_t desc;
    fill_descriptor(&desc, digest_str, sizeof(digest_str), OCI_DIGEST_SHA256,
                    HELLO_WORLD_SHA256, (int64_t) strlen(HELLO_WORLD),
                    OCI_MT_LAYER_OCI_TAR_GZIP);

    const char *err = NULL;
    int rc = oci_fetch_blob(f, &ref, &desc, store, &err);
    if (rc != 0) {
        report_fail("blob fetch success commits to store", "rc=%d err=%s", rc,
                    err ? err : "(none)");
    } else if (!oci_blob_store_has(store, OCI_DIGEST_SHA256,
                                   HELLO_WORLD_SHA256)) {
        report_fail("blob fetch success commits to store",
                    "blob not present after commit");
    } else {
        report_pass("blob fetch success commits to store");
    }
    oci_blob_store_close(store);
}

static void test_blob_already_cached(oci_mock_server_t *server, oci_fetcher_t *f,
                                     const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    if (!store) {
        report_fail("blob fetch skips network when already cached", "store");
        return;
    }
    if (oci_blob_store_put_bytes(store, OCI_DIGEST_SHA256, HELLO_WORLD_SHA256,
                                 HELLO_WORLD, strlen(HELLO_WORLD)) != 0) {
        report_fail("blob fetch skips network when already cached",
                    "put_bytes: %s", strerror(errno));
        oci_blob_store_close(store);
        return;
    }

    handler_blob_t ctx = {
        .blob_path = "/never-called",
        .body = "x",
        .body_len = 1,
    };
    oci_mock_set_handler(server, h_blob, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    char digest_str[128];
    oci_descriptor_t desc;
    fill_descriptor(&desc, digest_str, sizeof(digest_str), OCI_DIGEST_SHA256,
                    HELLO_WORLD_SHA256, (int64_t) strlen(HELLO_WORLD),
                    OCI_MT_LAYER_OCI_TAR_GZIP);

    const char *err = NULL;
    int rc = oci_fetch_blob(f, &ref, &desc, store, &err);
    if (rc != 0) {
        report_fail("blob fetch skips network when already cached", "rc=%d", rc);
    } else if (server->n_requests != 0) {
        report_fail("blob fetch skips network when already cached",
                    "%d unexpected request(s)", server->n_requests);
    } else {
        report_pass("blob fetch skips network when already cached");
    }
    oci_blob_store_close(store);
}

static void test_blob_size_mismatch(oci_mock_server_t *server, oci_fetcher_t *f,
                                    const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    if (!store) {
        report_fail("blob size overflow rejected", "store");
        return;
    }
    handler_blob_t ctx = {
        .blob_path = "/v2/library/alpine/blobs/sha256:b94d27b9934d3e08a52e52d7"
                     "da7dabfac484efe37a5380ee9088f7ace2efcde9",
        .body = HELLO_WORLD,
        .body_len = strlen(HELLO_WORLD),
        .oversize = true,
    };
    oci_mock_set_handler(server, h_blob, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    char digest_str[128];
    oci_descriptor_t desc;
    fill_descriptor(&desc, digest_str, sizeof(digest_str), OCI_DIGEST_SHA256,
                    HELLO_WORLD_SHA256, (int64_t) strlen(HELLO_WORLD),
                    OCI_MT_LAYER_OCI_TAR_GZIP);

    const char *err = NULL;
    int rc = oci_fetch_blob(f, &ref, &desc, store, &err);
    if (rc == 0) {
        report_fail("blob size overflow rejected", "rc=0");
    } else if (oci_blob_store_has(store, OCI_DIGEST_SHA256,
                                  HELLO_WORLD_SHA256)) {
        report_fail("blob size overflow rejected", "blob visible after failure");
    } else {
        report_pass("blob size overflow rejected");
    }
    oci_blob_store_close(store);
}

static void test_blob_digest_mismatch(oci_mock_server_t *server, oci_fetcher_t *f,
                                      const char *store_root)
{
    static const char WRONG_HEX[] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    if (!store) {
        report_fail("blob digest mismatch rejected", "store");
        return;
    }
    char wrong_path[256];
    snprintf(wrong_path, sizeof(wrong_path),
             "/v2/library/alpine/blobs/sha256:%s", WRONG_HEX);
    handler_blob_t ctx = {
        .blob_path = wrong_path,
        .body = HELLO_WORLD,
        .body_len = strlen(HELLO_WORLD),
    };
    oci_mock_set_handler(server, h_blob, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    char digest_str[128];
    oci_descriptor_t desc;
    fill_descriptor(&desc, digest_str, sizeof(digest_str), OCI_DIGEST_SHA256,
                    WRONG_HEX, (int64_t) strlen(HELLO_WORLD),
                    OCI_MT_LAYER_OCI_TAR_GZIP);

    const char *err = NULL;
    int rc = oci_fetch_blob(f, &ref, &desc, store, &err);
    if (rc == 0) {
        report_fail("blob digest mismatch rejected", "rc=0");
    } else if (oci_blob_store_has(store, OCI_DIGEST_SHA256, WRONG_HEX)) {
        report_fail("blob digest mismatch rejected", "blob visible");
    } else {
        report_pass("blob digest mismatch rejected");
    }
    oci_blob_store_close(store);
}

static void test_blob_404(oci_mock_server_t *server, oci_fetcher_t *f,
                          const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    handler_blob_t ctx = {
        .blob_path = "/never-matches",
        .body = "x",
        .body_len = 1,
    };
    oci_mock_set_handler(server, h_blob, &ctx);

    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    char digest_str[128];
    oci_descriptor_t desc;
    fill_descriptor(&desc, digest_str, sizeof(digest_str), OCI_DIGEST_SHA256,
                    HELLO_WORLD_SHA256, (int64_t) strlen(HELLO_WORLD),
                    OCI_MT_LAYER_OCI_TAR_GZIP);

    const char *err = NULL;
    int rc = oci_fetch_blob(f, &ref, &desc, store, &err);
    if (rc == 0)
        report_fail("blob 404 rejected", "rc=0");
    else if (oci_blob_store_has(store, OCI_DIGEST_SHA256, HELLO_WORLD_SHA256))
        report_fail("blob 404 rejected", "blob visible after 404");
    else
        report_pass("blob 404 rejected");
    oci_blob_store_close(store);
}

/* ── Slice 4b cases ──────────────────────────────────────────────── */

static void test_basic_auth_success(oci_mock_server_t *server, const char *base_url,
                                    const char *ca_pem)
{
    /* alice:secret encoded as base64. */
    handler_basic_auth_t ctx = {
        .manifest_path = "/v2/private/area/manifests/v1",
        .expected_authorization = "Basic YWxpY2U6c2VjcmV0",
        .body = "{\"schemaVersion\":2}",
        .body_len = strlen("{\"schemaVersion\":2}"),
        .content_type = "application/vnd.oci.image.manifest.v1+json",
    };
    oci_mock_set_handler(server, h_basic_auth, &ctx);

    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_pem,
        .username = "alice",
        .password = "secret",
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("basic auth: server accepts credentials", "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "private/area",
        .tag = "v1",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("basic auth: server accepts credentials", "rc=%d err=%s",
                    rc, err ? err : "(none)");
    } else if (resp.http_status != 200) {
        report_fail("basic auth: server accepts credentials", "status=%ld",
                    resp.http_status);
    } else if (oci_mock_request_count(server) != 1) {
        report_fail("basic auth: server accepts credentials",
                    "expected 1 request, got %d", oci_mock_request_count(server));
    } else if (strcmp(server->log[0].authorization,
                      "Basic YWxpY2U6c2VjcmV0") != 0) {
        report_fail("basic auth: server accepts credentials",
                    "Authorization=%s", server->log[0].authorization);
    } else {
        report_pass("basic auth: server accepts credentials");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

static void test_basic_then_bearer(oci_mock_server_t *server, const char *base_url,
                                   const char *ca_pem)
{
    static const char BODY[] = "{\"schemaVersion\":2,\"mixed\":true}";
    handler_basic_then_bearer_t ctx = {
        .manifest_path = "/v2/private/secret/manifests/v1",
        .expected_basic = "Basic Ym9iOmh1bnRlcjI=",
        .expected_token = "mixedtoken456",
        .manifest_body = BODY,
        .manifest_body_len = strlen(BODY),
        .content_type = "application/vnd.oci.image.manifest.v1+json",
    };
    snprintf(ctx.base_url, sizeof(ctx.base_url), "%s", base_url);
    oci_mock_set_handler(server, h_basic_then_bearer, &ctx);

    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_pem,
        .username = "bob",
        .password = "hunter2",
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("basic auth carried into bearer token endpoint",
                    "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "private/secret",
        .tag = "v1",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("basic auth carried into bearer token endpoint",
                    "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (resp.http_status != 200 ||
               resp.body_len != strlen(BODY) ||
               memcmp(resp.body, BODY, resp.body_len) != 0) {
        report_fail("basic auth carried into bearer token endpoint",
                    "status=%ld body_len=%zu", resp.http_status, resp.body_len);
    } else if (server->n_requests != 3) {
        report_fail("basic auth carried into bearer token endpoint",
                    "expected 3 requests, got %d", server->n_requests);
    } else if (strncmp(server->log[1].path, "/token", 6) != 0) {
        report_fail("basic auth carried into bearer token endpoint",
                    "second request path=%s", server->log[1].path);
    } else if (strcmp(server->log[1].authorization,
                      "Basic Ym9iOmh1bnRlcjI=") != 0) {
        report_fail("basic auth carried into bearer token endpoint",
                    "token endpoint Authorization=%s",
                    server->log[1].authorization);
    } else if (strcmp(server->log[2].authorization,
                      "Bearer mixedtoken456") != 0) {
        report_fail("basic auth carried into bearer token endpoint",
                    "retry Authorization=%s", server->log[2].authorization);
    } else {
        report_pass("basic auth carried into bearer token endpoint");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

static void test_insecure_loopback_allowed(oci_mock_server_t *server,
                                           const char *base_url)
{
    static const char BODY[] = "{\"schemaVersion\":2}";
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/alpine/manifests/3.20",
        .body = BODY,
        .body_len = strlen(BODY),
        .content_type = "application/vnd.oci.image.manifest.v1+json",
        .docker_digest = NULL,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    /* No ca_file: verification is suppressed via allow_insecure. The loopback
     * registry host (127.0.0.1) is on the whitelist so policy lets the request
     * through.
     */
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .allow_insecure = true,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("insecure: loopback host bypasses TLS verify",
                    "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "127.0.0.1:5000",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc != 0) {
        report_fail("insecure: loopback host bypasses TLS verify",
                    "rc=%d err=%s", rc, err ? err : "(none)");
    } else if (resp.http_status != 200) {
        report_fail("insecure: loopback host bypasses TLS verify",
                    "status=%ld", resp.http_status);
    } else if (oci_mock_request_count(server) != 1) {
        report_fail("insecure: loopback host bypasses TLS verify",
                    "expected 1 request, got %d", oci_mock_request_count(server));
    } else {
        report_pass("insecure: loopback host bypasses TLS verify");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

static void test_insecure_non_loopback_rejected(oci_mock_server_t *server,
                                                const char *base_url,
                                                const char *ca_pem)
{
    /* Install a handler that would respond 200 if reached, so a leak is
     * loud. The policy must block the request before any byte goes out and
     * leave the request log empty.
     */
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/evil/path/manifests/v1",
        .body = "{}",
        .body_len = 2,
        .content_type = "application/json",
        .docker_digest = NULL,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_pem,
        .allow_insecure = true,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("insecure: non-loopback host rejected", "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "evil.example.com",
        .repository = "evil/path",
        .tag = "v1",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    errno = 0;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    int saved_errno = errno;
    if (rc != -1) {
        report_fail("insecure: non-loopback host rejected", "rc=%d", rc);
    } else if (saved_errno != EPERM) {
        report_fail("insecure: non-loopback host rejected", "errno=%d (%s)",
                    saved_errno, strerror(saved_errno));
    } else if (oci_mock_request_count(server) != 0) {
        report_fail("insecure: non-loopback host rejected",
                    "%d request(s) leaked to server", oci_mock_request_count(server));
    } else {
        report_pass("insecure: non-loopback host rejected");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

static void test_ca_file_missing_rejected(oci_mock_server_t *server,
                                          const char *base_url)
{
    /* No ca_file at all: the mock's self-signed certificate cannot be
     * verified by LibreSSL's default trust roots, so the TLS handshake must
     * fail. Confirms ca_file is the trust pivot.
     */
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/alpine/manifests/3.20",
        .body = "{}",
        .body_len = 2,
        .content_type = "application/json",
        .docker_digest = NULL,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    oci_fetcher_options_t opts = {.base_url_override = base_url};
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("ca_file unset: TLS verify fails on self-signed mock",
                    "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc == 0) {
        report_fail("ca_file unset: TLS verify fails on self-signed mock",
                    "rc=0 (verify should have failed)");
    } else if (resp.http_status != 0) {
        report_fail("ca_file unset: TLS verify fails on self-signed mock",
                    "got http_status=%ld; handshake should have aborted",
                    resp.http_status);
    } else {
        report_pass("ca_file unset: TLS verify fails on self-signed mock");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

static void test_ca_file_wrong_rejected(oci_mock_server_t *server,
                                        const char *base_url,
                                        const char *scratch_root)
{
    /* ca_file points at a syntactically valid but different self-signed
     * cert. libcurl must reject the mock's certificate because it does not
     * chain to the supplied CA, proving ca_file is the trust source rather
     * than a no-op.
     */
    char wrong_path[300];
    snprintf(wrong_path, sizeof(wrong_path), "%s/wrong-ca.pem", scratch_root);

    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    X509 *cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 42);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24);
    X509_set_pubkey(cert, pkey);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) "wrong.example",
                               -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_sign(cert, pkey, EVP_sha256());
    FILE *fp = fopen(wrong_path, "w");
    if (fp) {
        PEM_write_X509(fp, cert);
        fclose(fp);
    }
    X509_free(cert);
    EVP_PKEY_free(pkey);

    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/alpine/manifests/3.20",
        .body = "{}",
        .body_len = 2,
        .content_type = "application/json",
        .docker_digest = NULL,
    };
    oci_mock_set_handler(server, h_anonymous_manifest, &ctx);

    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = wrong_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    if (!f) {
        report_fail("ca_file wrong: TLS verify fails", "fetcher new");
        return;
    }
    oci_ref_t ref = {
        .registry = "127.0.0.1:fake",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, &resp, &err);
    if (rc == 0) {
        report_fail("ca_file wrong: TLS verify fails",
                    "rc=0 (verify should have failed)");
    } else if (resp.http_status != 0) {
        report_fail("ca_file wrong: TLS verify fails",
                    "got http_status=%ld; handshake should have aborted",
                    resp.http_status);
    } else {
        report_pass("ca_file wrong: TLS verify fails");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
    unlink(wrong_path);
}

/* ── Online smoke (opt-in) ───────────────────────────────────────── */

static void test_online_dockerhub(void)
{
    static const char *accept[] = {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        NULL,
    };
    oci_fetcher_t *f = oci_fetcher_new(NULL);
    if (!f) {
        report_fail("online docker.io alpine:3.20", "fetcher new: %s",
                    strerror(errno));
        return;
    }
    oci_ref_t ref = {
        .registry = "docker.io",
        .repository = "library/alpine",
        .tag = "3.20",
    };
    oci_fetch_response_t resp = {0};
    const char *err = NULL;
    int rc = oci_fetch_manifest(f, &ref, NULL, accept, &resp, &err);
    if (rc != 0) {
        report_fail("online docker.io alpine:3.20", "rc=%d err=%s status=%ld",
                    rc, err ? err : "(none)", resp.http_status);
    } else if (resp.http_status != 200 || resp.body_len == 0) {
        report_fail("online docker.io alpine:3.20", "status=%ld body_len=%zu",
                    resp.http_status, resp.body_len);
    } else {
        report_pass("online docker.io alpine:3.20");
    }
    oci_fetch_response_free(&resp);
    oci_fetcher_free(f);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void)
{
    /* Force libcurl onto the OpenSSL (LibreSSL on macOS) backend before the
     * fetcher's pthread_once runs curl_global_init. macOS Secure Transport
     * ignores CURLOPT_CAINFO, which would silently turn ca_file into a no-op
     * and let trust-failure cases pass for the wrong reason. Must be called
     * before any other libcurl function in the process.
     */
    if (curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL) !=
        CURLSSLSET_OK) {
        fprintf(stderr,
                "libcurl OpenSSL backend not available; ca_file negative cases "
                "would be vacuously true\n");
        return 1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    char *scratch = oci_mock_make_scratch_root("elfuse-oci-fetch");
    if (!scratch) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    oci_mock_server_t server;
    if (oci_mock_server_start(&server, scratch) != 0) {
        fprintf(stderr, "mock server start failed: %s\n", strerror(errno));
        oci_mock_wipe_dir(scratch);
        free(scratch);
        return 1;
    }
    char *base_url = oci_mock_make_base_url(server.port);
    if (!base_url) {
        fprintf(stderr, "oom on base url\n");
        oci_mock_server_stop(&server);
        oci_mock_wipe_dir(scratch);
        free(scratch);
        return 1;
    }

    printf("oci_fetch (mock HTTPS @ %s, CA=%s)\n", base_url, server.ca_pem_path);

    {
        oci_fetcher_options_t opts = {
            .base_url_override = base_url,
            .ca_file = server.ca_pem_path,
        };
        oci_fetcher_t *f = oci_fetcher_new(&opts);
        if (!f) {
            fprintf(stderr, "oci_fetcher_new failed\n");
            free(base_url);
            oci_mock_server_stop(&server);
            oci_mock_wipe_dir(scratch);
            free(scratch);
            return 1;
        }
        test_anonymous_manifest(&server, f);
        test_manifest_404(&server, f);

        static const char BEARER_BODY[] =
            "{\"schemaVersion\":2,\"secret\":true}";
        handler_bearer_t bearer_ctx = {
            .manifest_path = "/v2/private/secret/manifests/v1",
            .expected_token = "testtoken123",
            .manifest_body = BEARER_BODY,
            .manifest_body_len = strlen(BEARER_BODY),
            .content_type = "application/vnd.oci.image.manifest.v1+json",
        };
        snprintf(bearer_ctx.base_url, sizeof(bearer_ctx.base_url), "%s",
                 base_url);
        test_bearer_challenge(&server, f, &bearer_ctx);
        test_token_reuse(&server, f);
        oci_fetcher_free(f);
    }

    {
        oci_fetcher_options_t opts = {
            .base_url_override = base_url,
            .ca_file = server.ca_pem_path,
        };
        oci_fetcher_t *f = oci_fetcher_new(&opts);
        char dir[512];

        snprintf(dir, sizeof(dir), "%s/blob-success", scratch);
        test_blob_success(&server, f, dir);

        snprintf(dir, sizeof(dir), "%s/blob-cached", scratch);
        test_blob_already_cached(&server, f, dir);

        snprintf(dir, sizeof(dir), "%s/blob-oversize", scratch);
        test_blob_size_mismatch(&server, f, dir);

        snprintf(dir, sizeof(dir), "%s/blob-digest-bad", scratch);
        test_blob_digest_mismatch(&server, f, dir);

        snprintf(dir, sizeof(dir), "%s/blob-404", scratch);
        test_blob_404(&server, f, dir);

        oci_fetcher_free(f);
    }

    /* Slice 4b cases: each builds its own fetcher so the auth/trust options
     * under test are scoped to a single case.
     */
    test_basic_auth_success(&server, base_url, server.ca_pem_path);
    test_basic_then_bearer(&server, base_url, server.ca_pem_path);
    test_insecure_loopback_allowed(&server, base_url);
    test_insecure_non_loopback_rejected(&server, base_url, server.ca_pem_path);
    test_ca_file_missing_rejected(&server, base_url);
    test_ca_file_wrong_rejected(&server, base_url, scratch);

    free(base_url);
    oci_mock_server_stop(&server);

    if (getenv("OCI_FETCH_ONLINE")) {
        printf("oci_fetch (online docker.io)\n");
        test_online_dockerhub();
    }

    oci_mock_wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
