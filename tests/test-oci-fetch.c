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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
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
                       NULL, NULL, ctx->body, ctx->body_len);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL, "nope", 4);
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
        oci_mock_send_full(io, 200, "OK", "application/json", NULL, NULL, NULL, NULL,
                       body, (size_t) n);
        return;
    }
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        char want_auth[256];
        snprintf(want_auth, sizeof(want_auth), "Bearer %s", ctx->expected_token);
        if (strcmp(req->authorization, want_auth) == 0) {
            oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                           NULL, NULL, ctx->manifest_body, ctx->manifest_body_len);
            return;
        }
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\","
                 "scope=\"repository:private/secret:pull\"",
                 ctx->base_url);
        oci_mock_send_full(io, 401, "Unauthorized", "application/json", challenge,
                       NULL, NULL, NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL, "nope", 4);
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
        oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL, "nope", 4);
        return;
    }
    int status = ctx->status ? ctx->status : 200;
    if (status != 200) {
        oci_mock_send_full(io, status, "Error", "text/plain", NULL, NULL, NULL, NULL, "err", 3);
        return;
    }
    if (ctx->oversize) {
        size_t pad_len = ctx->body_len + 5;
        char *buf = malloc(pad_len);
        memcpy(buf, ctx->body, ctx->body_len);
        memset(buf + ctx->body_len, 'X', 5);
        oci_mock_send_full(io, 200, "OK", "application/octet-stream", NULL, NULL,
                       NULL, NULL, buf, pad_len);
        free(buf);
        return;
    }
    oci_mock_send_full(io, 200, "OK", "application/octet-stream", NULL, NULL,
                   NULL, NULL, ctx->body, ctx->body_len);
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
        oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL, "nope", 4);
        return;
    }
    if (strcmp(req->authorization, ctx->expected_authorization) != 0) {
        oci_mock_send_full(io, 401, "Unauthorized", "application/json",
                       "Basic realm=\"reg\"", NULL, NULL, NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                   NULL, NULL, ctx->body, ctx->body_len);
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
                           NULL, NULL, NULL, "{}", 2);
            return;
        }
        char body[256];
        int n = snprintf(body, sizeof(body),
                         "{\"token\":\"%s\",\"expires_in\":300}",
                         ctx->expected_token);
        oci_mock_send_full(io, 200, "OK", "application/json", NULL, NULL, NULL, NULL,
                       body, (size_t) n);
        return;
    }
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        char want_bearer[256];
        snprintf(want_bearer, sizeof(want_bearer), "Bearer %s",
                 ctx->expected_token);
        if (strcmp(req->authorization, want_bearer) == 0) {
            oci_mock_send_full(io, 200, "OK", ctx->content_type, NULL, NULL,
                           NULL, NULL, ctx->manifest_body, ctx->manifest_body_len);
            return;
        }
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\","
                 "scope=\"repository:private/secret:pull\"",
                 ctx->base_url);
        oci_mock_send_full(io, 401, "Unauthorized", "application/json", challenge,
                       NULL, NULL, NULL, "{}", 2);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL, "nope", 4);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, NULL, NULL, &resp, &err);
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

/* ── Batch fetch (oci_fetch_blob_batch / curl_multi) ─────────────── */

/* Per-blob scripted response. The handler thread looks the request up by
 * path and either returns the configured body (200) or one of the failure
 * modes set by the test: a forced status code or a count of leading
 * requests that should respond 401 + Bearer challenge so the batch path
 * can exercise its token-refresh round.
 */
typedef struct {
    char digest_str[80];
    char hex[OCI_DIGEST_HEX_MAX + 1];
    char path[256];
    char body[64];
    size_t body_len;
    int forced_status;       /* 0 = serve normally */
    int return_401_first_n;  /* nonzero -> first N requests return 401 */
    int call_count;          /* updated atomically by handler */
} batch_blob_t;

typedef enum {
    BATCH_RANGE_HONOUR = 0,  /* 206 Partial Content with Content-Range */
    BATCH_RANGE_IGNORE,      /* return 200 + full body even when Range present */
    BATCH_RANGE_416,         /* return 416 when Range is present */
} batch_range_mode_t;

typedef struct {
    batch_blob_t *blobs;
    size_t n_blobs;
    char base_url[80];
    int token_call_count;    /* updated atomically by handler */
    const char *token_value;
    batch_range_mode_t range_mode;
} batch_ctx_t;

static batch_blob_t *batch_find_by_path(batch_ctx_t *ctx, const char *path)
{
    for (size_t i = 0; i < ctx->n_blobs; i++) {
        if (strcmp(ctx->blobs[i].path, path) == 0)
            return &ctx->blobs[i];
    }
    return NULL;
}

static void h_batch(oci_mock_server_t *s, oci_mock_io_t *io,
                    const oci_mock_request_t *req)
{
    batch_ctx_t *ctx = s->ctx;
    if (strncmp(req->path, "/token", 6) == 0) {
        __sync_fetch_and_add(&ctx->token_call_count, 1);
        char body[256];
        int n = snprintf(body, sizeof(body),
                         "{\"token\":\"%s\",\"expires_in\":300}",
                         ctx->token_value);
        oci_mock_send_full(io, 200, "OK", "application/json", NULL, NULL, NULL, NULL,
                           body, (size_t) n);
        return;
    }
    batch_blob_t *b = batch_find_by_path(ctx, req->path);
    if (!b) {
        oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL,
                           "nope", 4);
        return;
    }
    int n = __sync_add_and_fetch(&b->call_count, 1);
    if (b->forced_status) {
        oci_mock_send_full(io, b->forced_status, "Error", "text/plain",
                           NULL, NULL, NULL, NULL, "err", 3);
        return;
    }
    if (b->return_401_first_n > 0 && n <= b->return_401_first_n) {
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\"",
                 ctx->base_url);
        oci_mock_send_full(io, 401, "Unauthorized", "application/json",
                           challenge, NULL, NULL, NULL, "{}", 2);
        return;
    }
    if (req->has_range && ctx->range_mode == BATCH_RANGE_416) {
        oci_mock_send_full(io, 416, "Range Not Satisfiable", "text/plain",
                           NULL, NULL, NULL, NULL, "out", 3);
        return;
    }
    if (req->has_range && ctx->range_mode == BATCH_RANGE_HONOUR &&
        req->range_start >= 0 && (size_t) req->range_start < b->body_len) {
        size_t start = (size_t) req->range_start;
        size_t end = b->body_len - 1;
        size_t len = b->body_len - start;
        char cr[64];
        snprintf(cr, sizeof(cr), "bytes %zu-%zu/%zu", start, end, b->body_len);
        oci_mock_send_full(io, 206, "Partial Content",
                           "application/octet-stream",
                           NULL, NULL, NULL, cr, b->body + start, len);
        return;
    }
    /* BATCH_RANGE_IGNORE and BATCH_RANGE_HONOUR with no Range request both
     * reach here. Send a full 200 so the fetcher's restart path can absorb
     * the body when the partial was already on disk.
     */
    oci_mock_send_full(io, 200, "OK", "application/octet-stream",
                       NULL, NULL, NULL, NULL, b->body, b->body_len);
}

static void batch_blob_init(batch_blob_t *b, const char *repo, int seed)
{
    memset(b, 0, sizeof(*b));
    int n = snprintf(b->body, sizeof(b->body), "blob-%02d-content-bytes", seed);
    b->body_len = (size_t) n;
    if (oci_digest_bytes(OCI_DIGEST_SHA256, b->body, b->body_len, b->hex) == 0) {
        b->hex[0] = '\0';
    }
    snprintf(b->digest_str, sizeof(b->digest_str), "sha256:%s", b->hex);
    snprintf(b->path, sizeof(b->path), "/v2/%s/blobs/%s", repo, b->digest_str);
}

static void batch_fill_descriptor(oci_descriptor_t *desc, batch_blob_t *b)
{
    memset(desc, 0, sizeof(*desc));
    desc->algo = OCI_DIGEST_SHA256;
    memcpy(desc->hex, b->hex, OCI_DIGEST_HEX_MAX + 1);
    desc->digest_str = b->digest_str;
    desc->size = (int64_t) b->body_len;
    desc->media_type = OCI_MT_LAYER_OCI_TAR_GZIP;
}

/* Counts tmp files left in a store's tmp/ directory. The C5.1 batch must
 * not leak partial files when it aborts. (C5.2 will deliberately keep
 * partials around for resume; until then, tmp must end empty.)
 */
static int count_tmp_files(const char *store_root)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/tmp", store_root);
    DIR *d = opendir(path);
    if (!d)
        return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        n++;
    }
    closedir(d);
    return n;
}

static double wall_seconds_since(const struct timespec *t0)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (double) (t1.tv_sec - t0->tv_sec) +
           (double) (t1.tv_nsec - t0->tv_nsec) / 1e9;
}

static double run_batch_under_concurrency(oci_mock_server_t *server,
                                          const char *base_url,
                                          const char *ca_path,
                                          const char *store_root,
                                          batch_ctx_t *ctx,
                                          int concurrency,
                                          int *out_rc,
                                          const char **out_err)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", concurrency);
    setenv("OCI_FETCH_MAX_CONCURRENT", buf, 1);
    oci_mock_set_handler(server, h_batch, ctx);

    oci_blob_store_t *store = oci_blob_store_open(store_root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {
        .registry = "test.local",
        .repository = "test",
    };
    oci_descriptor_t *ds = calloc(ctx->n_blobs, sizeof(*ds));
    const oci_descriptor_t **dp = calloc(ctx->n_blobs, sizeof(*dp));
    for (size_t i = 0; i < ctx->n_blobs; i++) {
        batch_fill_descriptor(&ds[i], &ctx->blobs[i]);
        dp[i] = &ds[i];
    }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = oci_fetch_blob_batch(f, &ref, dp, ctx->n_blobs, store, NULL, NULL,
                                  out_err);
    double wall = wall_seconds_since(&t0);
    if (out_rc)
        *out_rc = rc;
    free(ds);
    free(dp);
    oci_fetcher_free(f);
    oci_blob_store_close(store);
    unsetenv("OCI_FETCH_MAX_CONCURRENT");
    return wall;
}

static void test_batch_parallel_wall_time(oci_mock_server_t *server,
                                          const char *base_url,
                                          const char *ca_path,
                                          const char *scratch_root)
{
    const char *name = "batch: parallel wall time beats serial by >=1.5x";
    enum { NBLOBS = 8 };
    batch_blob_t blobs[NBLOBS];
    for (int i = 0; i < NBLOBS; i++)
        batch_blob_init(&blobs[i], "test", i);
    batch_ctx_t ctx = {.blobs = blobs, .n_blobs = NBLOBS};

    oci_mock_set_response_delay_ms(server, 150);

    char serial_root[512];
    snprintf(serial_root, sizeof(serial_root), "%s/batch-wall-serial",
             scratch_root);
    char parallel_root[512];
    snprintf(parallel_root, sizeof(parallel_root), "%s/batch-wall-parallel",
             scratch_root);

    int rc_serial = 0;
    const char *err_serial = NULL;
    double t_serial = run_batch_under_concurrency(server, base_url, ca_path,
                                                  serial_root, &ctx, 1,
                                                  &rc_serial, &err_serial);
    if (rc_serial != 0) {
        oci_mock_set_response_delay_ms(server, 0);
        report_fail(name, "serial rc=%d err=%s", rc_serial,
                    err_serial ? err_serial : "(none)");
        return;
    }

    for (int i = 0; i < NBLOBS; i++)
        blobs[i].call_count = 0;
    int rc_parallel = 0;
    const char *err_parallel = NULL;
    double t_parallel = run_batch_under_concurrency(server, base_url, ca_path,
                                                    parallel_root, &ctx, 4,
                                                    &rc_parallel,
                                                    &err_parallel);
    oci_mock_set_response_delay_ms(server, 0);
    if (rc_parallel != 0) {
        report_fail(name, "parallel rc=%d err=%s", rc_parallel,
                    err_parallel ? err_parallel : "(none)");
        return;
    }
    double ratio = t_parallel > 0 ? t_serial / t_parallel : 0.0;
    if (ratio < 1.5) {
        report_fail(name,
                    "speedup %.2fx (serial %.3fs vs parallel %.3fs) < 1.5x",
                    ratio, t_serial, t_parallel);
        return;
    }
    report_pass(name);
}

static void test_batch_atomic_abort(oci_mock_server_t *server,
                                    const char *base_url,
                                    const char *ca_path,
                                    const char *scratch_root)
{
    const char *name = "batch: any blob fail aborts the whole batch";
    enum { NBLOBS = 4 };
    batch_blob_t blobs[NBLOBS];
    for (int i = 0; i < NBLOBS; i++)
        batch_blob_init(&blobs[i], "atomic", i + 50);
    blobs[2].forced_status = 500;
    batch_ctx_t ctx = {.blobs = blobs, .n_blobs = NBLOBS};
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-atomic", scratch_root);
    oci_blob_store_t *store = oci_blob_store_open(root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {.registry = "test.local", .repository = "atomic"};
    oci_descriptor_t ds[NBLOBS];
    const oci_descriptor_t *dp[NBLOBS];
    for (int i = 0; i < NBLOBS; i++) {
        batch_fill_descriptor(&ds[i], &blobs[i]);
        dp[i] = &ds[i];
    }
    const char *err = NULL;
    int rc = oci_fetch_blob_batch(f, &ref, dp, NBLOBS, store, NULL, NULL, &err);
    if (rc == 0) {
        report_fail(name, "rc=0 (expected failure)");
        goto cleanup;
    }
    for (int i = 0; i < NBLOBS; i++) {
        if (oci_blob_store_has(store, OCI_DIGEST_SHA256, blobs[i].hex)) {
            report_fail(name, "blob %d unexpectedly committed", i);
            goto cleanup;
        }
    }
    int leaked = count_tmp_files(root);
    if (leaked != 0) {
        report_fail(name, "tmp/ has %d leaked file(s)", leaked);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_fetcher_free(f);
    oci_blob_store_close(store);
}

static void test_batch_dedup_same_digest(oci_mock_server_t *server,
                                         const char *base_url,
                                         const char *ca_path,
                                         const char *scratch_root)
{
    const char *name = "batch: duplicate digests fetch once";
    batch_blob_t b;
    batch_blob_init(&b, "dedup", 7);
    batch_ctx_t ctx = {.blobs = &b, .n_blobs = 1};
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-dedup", scratch_root);
    oci_blob_store_t *store = oci_blob_store_open(root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {.registry = "test.local", .repository = "dedup"};
    oci_descriptor_t d;
    batch_fill_descriptor(&d, &b);
    const oci_descriptor_t *dp[2] = {&d, &d};
    const char *err = NULL;
    int rc = oci_fetch_blob_batch(f, &ref, dp, 2, store, NULL, NULL, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    if (!oci_blob_store_has(store, OCI_DIGEST_SHA256, b.hex)) {
        report_fail(name, "blob missing after dedup batch");
        goto cleanup;
    }
    if (b.call_count != 1) {
        report_fail(name, "blob fetched %d times (want 1)", b.call_count);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_fetcher_free(f);
    oci_blob_store_close(store);
}

static void test_batch_token_refresh_under_parallel(oci_mock_server_t *server,
                                                    const char *base_url,
                                                    const char *ca_path,
                                                    const char *scratch_root)
{
    const char *name = "batch: single token refresh covers all 401s";
    enum { NBLOBS = 4 };
    batch_blob_t blobs[NBLOBS];
    for (int i = 0; i < NBLOBS; i++) {
        batch_blob_init(&blobs[i], "private", i + 100);
        blobs[i].return_401_first_n = 1;
    }
    batch_ctx_t ctx = {
        .blobs = blobs,
        .n_blobs = NBLOBS,
        .token_value = "batchtoken42",
    };
    snprintf(ctx.base_url, sizeof(ctx.base_url), "%s", base_url);
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-token-refresh", scratch_root);
    oci_blob_store_t *store = oci_blob_store_open(root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {.registry = "test.local", .repository = "private"};
    oci_descriptor_t ds[NBLOBS];
    const oci_descriptor_t *dp[NBLOBS];
    for (int i = 0; i < NBLOBS; i++) {
        batch_fill_descriptor(&ds[i], &blobs[i]);
        dp[i] = &ds[i];
    }
    setenv("OCI_FETCH_MAX_CONCURRENT", "4", 1);
    const char *err = NULL;
    int rc = oci_fetch_blob_batch(f, &ref, dp, NBLOBS, store, NULL, NULL, &err);
    unsetenv("OCI_FETCH_MAX_CONCURRENT");
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    for (int i = 0; i < NBLOBS; i++) {
        if (!oci_blob_store_has(store, OCI_DIGEST_SHA256, blobs[i].hex)) {
            report_fail(name, "blob %d missing after retry round", i);
            goto cleanup;
        }
    }
    if (ctx.token_call_count != 1) {
        report_fail(name, "token endpoint hit %d times (want 1)",
                    ctx.token_call_count);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_fetcher_free(f);
    oci_blob_store_close(store);
}

static void test_batch_concurrency_cap_respected(oci_mock_server_t *server,
                                                 const char *base_url,
                                                 const char *ca_path,
                                                 const char *scratch_root)
{
    const char *name = "batch: OCI_FETCH_MAX_CONCURRENT caps in-flight";
    enum { NBLOBS = 6 };
    batch_blob_t blobs[NBLOBS];
    for (int i = 0; i < NBLOBS; i++)
        batch_blob_init(&blobs[i], "cap", i + 200);
    batch_ctx_t ctx = {.blobs = blobs, .n_blobs = NBLOBS};

    oci_mock_set_handler(server, h_batch, &ctx);
    oci_mock_set_response_delay_ms(server, 80);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-cap", scratch_root);
    oci_blob_store_t *store = oci_blob_store_open(root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {.registry = "test.local", .repository = "cap"};
    oci_descriptor_t ds[NBLOBS];
    const oci_descriptor_t *dp[NBLOBS];
    for (int i = 0; i < NBLOBS; i++) {
        batch_fill_descriptor(&ds[i], &blobs[i]);
        dp[i] = &ds[i];
    }
    setenv("OCI_FETCH_MAX_CONCURRENT", "2", 1);
    const char *err = NULL;
    int rc = oci_fetch_blob_batch(f, &ref, dp, NBLOBS, store, NULL, NULL, &err);
    unsetenv("OCI_FETCH_MAX_CONCURRENT");
    oci_mock_set_response_delay_ms(server, 0);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    int high = oci_mock_in_flight_max(server);
    if (high > 2) {
        report_fail(name, "in_flight_max=%d > 2", high);
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_fetcher_free(f);
    oci_blob_store_close(store);
}

/* ── C5.2 Range-resume + sweep cases ─────────────────────────────── */

/* Plant a partial blob staging file under store_root/tmp/. The filename
 * follows the digest-prefix pattern that oci_blob_writer_resume_named
 * scans for: blob-<first 16 hex chars>-<test-supplied suffix>. Returns 0
 * on success or -1 on failure.
 */
static int make_partial_file(const char *store_root, const char *hex,
                             const char *suffix, const void *bytes,
                             size_t len)
{
    char path[1024];
    char prefix[17];
    memcpy(prefix, hex, 16);
    prefix[16] = '\0';
    snprintf(path, sizeof(path), "%s/tmp/blob-%s-%s", store_root, prefix,
             suffix);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    ssize_t got = write(fd, bytes, len);
    close(fd);
    return (got == (ssize_t) len) ? 0 : -1;
}

/* Push mtime backward by `days` days so oci_blob_store_sweep_partials's
 * seven-day TTL classifies the file as stale. Touches atime too because
 * utimes does both with the same buffer.
 */
static void set_mtime_days_ago(const char *path, int days)
{
    struct timeval tv[2];
    tv[0].tv_sec = time(NULL) - (time_t) days * 86400;
    tv[0].tv_usec = 0;
    tv[1] = tv[0];
    (void) utimes(path, tv);
}

static int run_batch_one(const char *base_url, const char *ca_path,
                         const char *store_root, batch_ctx_t *ctx,
                         batch_blob_t *blob, const char **out_err)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    oci_fetcher_options_t opts = {
        .base_url_override = base_url,
        .ca_file = ca_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&opts);
    oci_ref_t ref = {.registry = "test.local", .repository = "resume"};
    oci_descriptor_t d;
    batch_fill_descriptor(&d, blob);
    const oci_descriptor_t *dp[1] = {&d};
    (void) ctx;
    int rc = oci_fetch_blob_batch(f, &ref, dp, 1, store, NULL, NULL, out_err);
    oci_fetcher_free(f);
    oci_blob_store_close(store);
    return rc;
}

static void test_batch_resume_completes_from_partial(oci_mock_server_t *server,
                                                    const char *base_url,
                                                    const char *ca_path,
                                                    const char *scratch_root)
{
    const char *name = "batch: Range resume completes from partial";
    batch_blob_t b;
    batch_blob_init(&b, "resume", 300);
    batch_ctx_t ctx = {
        .blobs = &b, .n_blobs = 1,
        .range_mode = BATCH_RANGE_HONOUR,
    };
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-resume-honour", scratch_root);
    (void) mkdir(root, 0755);
    /* Pre-create the layout so make_partial_file's tmp/ path exists. */
    oci_blob_store_t *seed = oci_blob_store_open(root);
    oci_blob_store_close(seed);

    /* Plant the first three bytes of the body; the resume must fetch the
     * remaining 19 bytes (body_len = strlen("blob-300-content-bytes") == 22).
     */
    if (make_partial_file(root, b.hex, "aa", b.body, 3) < 0) {
        report_fail(name, "make_partial_file failed: %s", strerror(errno));
        return;
    }

    const char *err = NULL;
    int rc = run_batch_one(base_url, ca_path, root, &ctx, &b, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        return;
    }
    if (!oci_blob_store_has(oci_blob_store_open(root), OCI_DIGEST_SHA256,
                            b.hex)) {
        /* leaked store handle is fine in failure path; cleanup below wipes. */
        report_fail(name, "blob missing after resume");
        return;
    }
    if (b.call_count != 1) {
        report_fail(name, "call_count=%d (want 1)", b.call_count);
        return;
    }
    if (oci_mock_request_count(server) < 1 ||
        !server->log[0].has_range ||
        server->log[0].range_start != 3) {
        report_fail(name,
                    "request log: count=%d has_range=%d range_start=%ld",
                    oci_mock_request_count(server),
                    server->log[0].has_range ? 1 : 0,
                    server->log[0].range_start);
        return;
    }
    report_pass(name);
}

static void test_batch_resume_server_ignores_range(oci_mock_server_t *server,
                                                   const char *base_url,
                                                   const char *ca_path,
                                                   const char *scratch_root)
{
    const char *name = "batch: server ignores Range falls back to full fetch";
    batch_blob_t b;
    batch_blob_init(&b, "resume", 301);
    batch_ctx_t ctx = {
        .blobs = &b, .n_blobs = 1,
        .range_mode = BATCH_RANGE_IGNORE,
    };
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-resume-ignore", scratch_root);
    (void) mkdir(root, 0755);
    oci_blob_store_t *seed = oci_blob_store_open(root);
    oci_blob_store_close(seed);

    if (make_partial_file(root, b.hex, "bb", b.body, 5) < 0) {
        report_fail(name, "make_partial_file failed: %s", strerror(errno));
        return;
    }

    const char *err = NULL;
    int rc = run_batch_one(base_url, ca_path, root, &ctx, &b, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        return;
    }
    /* Two HTTP transfers: the Range request that the server ignores, then
     * the restart-from-zero full fetch.
     */
    if (b.call_count != 2) {
        report_fail(name, "call_count=%d (want 2)", b.call_count);
        return;
    }
    int rcount = oci_mock_request_count(server);
    if (rcount < 2 ||
        !server->log[0].has_range ||
        server->log[1].has_range) {
        report_fail(name,
                    "request log: count=%d req0.has_range=%d req1.has_range=%d",
                    rcount,
                    server->log[0].has_range ? 1 : 0,
                    rcount > 1 ? (server->log[1].has_range ? 1 : 0) : -1);
        return;
    }
    oci_blob_store_t *check = oci_blob_store_open(root);
    bool present = oci_blob_store_has(check, OCI_DIGEST_SHA256, b.hex);
    oci_blob_store_close(check);
    if (!present) {
        report_fail(name, "blob missing after restart");
        return;
    }
    report_pass(name);
}

static void test_batch_resume_server_416_restarts(oci_mock_server_t *server,
                                                  const char *base_url,
                                                  const char *ca_path,
                                                  const char *scratch_root)
{
    const char *name = "batch: server 416 forces restart fresh";
    batch_blob_t b;
    batch_blob_init(&b, "resume", 302);
    batch_ctx_t ctx = {
        .blobs = &b, .n_blobs = 1,
        .range_mode = BATCH_RANGE_416,
    };
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-resume-416", scratch_root);
    (void) mkdir(root, 0755);
    oci_blob_store_t *seed = oci_blob_store_open(root);
    oci_blob_store_close(seed);

    if (make_partial_file(root, b.hex, "cc", b.body, 4) < 0) {
        report_fail(name, "make_partial_file failed: %s", strerror(errno));
        return;
    }

    const char *err = NULL;
    int rc = run_batch_one(base_url, ca_path, root, &ctx, &b, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        return;
    }
    if (b.call_count != 2) {
        report_fail(name, "call_count=%d (want 2)", b.call_count);
        return;
    }
    int rcount = oci_mock_request_count(server);
    if (rcount < 2 ||
        !server->log[0].has_range ||
        server->log[1].has_range) {
        report_fail(name,
                    "request log: count=%d req0.has_range=%d req1.has_range=%d",
                    rcount,
                    server->log[0].has_range ? 1 : 0,
                    rcount > 1 ? (server->log[1].has_range ? 1 : 0) : -1);
        return;
    }
    oci_blob_store_t *check = oci_blob_store_open(root);
    bool present = oci_blob_store_has(check, OCI_DIGEST_SHA256, b.hex);
    oci_blob_store_close(check);
    if (!present) {
        report_fail(name, "blob missing after 416 restart");
        return;
    }
    report_pass(name);
}

static void test_batch_sweep_stale_partial(oci_mock_server_t *server,
                                           const char *base_url,
                                           const char *ca_path,
                                           const char *scratch_root)
{
    const char *name = "batch: stale tmp partial swept on batch entry";
    /* The blob being pulled is fresh: no resume planned for it. The stale
     * partial belongs to a different digest and exists only to be swept.
     */
    batch_blob_t b;
    batch_blob_init(&b, "resume", 303);
    batch_ctx_t ctx = {
        .blobs = &b, .n_blobs = 1,
        .range_mode = BATCH_RANGE_HONOUR,
    };
    oci_mock_set_handler(server, h_batch, &ctx);

    char root[512];
    snprintf(root, sizeof(root), "%s/batch-sweep", scratch_root);
    (void) mkdir(root, 0755);
    oci_blob_store_t *seed = oci_blob_store_open(root);
    oci_blob_store_close(seed);

    /* Plant a stale partial under an unrelated digest prefix and backdate
     * it by eight days so the seven-day TTL sweep fires.
     */
    static const char STALE_HEX[] =
        "cafef00d000000000000000000000000000000000000000000000000deadc0de";
    char stale_path[1024];
    snprintf(stale_path, sizeof(stale_path), "%s/tmp/blob-cafef00d00000000-old",
             root);
    if (make_partial_file(root, STALE_HEX, "old", "junk", 4) < 0) {
        report_fail(name, "make_partial_file failed: %s", strerror(errno));
        return;
    }
    set_mtime_days_ago(stale_path, 8);

    const char *err = NULL;
    int rc = run_batch_one(base_url, ca_path, root, &ctx, &b, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        return;
    }
    struct stat st;
    if (stat(stale_path, &st) == 0) {
        report_fail(name, "stale partial survived sweep");
        return;
    }
    if (b.call_count != 1) {
        report_fail(name, "call_count=%d (want 1)", b.call_count);
        return;
    }
    if (oci_mock_request_count(server) < 1 ||
        server->log[0].has_range) {
        report_fail(name, "unexpected Range request on fresh blob");
        return;
    }
    oci_blob_store_t *check = oci_blob_store_open(root);
    bool present = oci_blob_store_has(check, OCI_DIGEST_SHA256, b.hex);
    oci_blob_store_close(check);
    if (!present) {
        report_fail(name, "blob missing after sweep + fetch");
        return;
    }
    report_pass(name);
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
    int rc = oci_fetch_manifest(f, &ref, NULL, accept, NULL, &resp, &err);
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

    /* Plan 5 C5.1 batch fetch cases. Each builds its own store under a
     * fresh subdir of `scratch` so the per-test setup never sees blobs left
     * by a prior test, and toggles OCI_FETCH_MAX_CONCURRENT inline. The
     * mock's thread-per-connection path is what makes the parallel
     * wall-time assertion meaningful; the response_delay setter scopes the
     * latency to the cases that actually want it.
     */
    test_batch_parallel_wall_time(&server, base_url, server.ca_pem_path, scratch);
    test_batch_atomic_abort(&server, base_url, server.ca_pem_path, scratch);
    test_batch_dedup_same_digest(&server, base_url, server.ca_pem_path, scratch);
    test_batch_token_refresh_under_parallel(&server, base_url,
                                            server.ca_pem_path, scratch);
    test_batch_concurrency_cap_respected(&server, base_url, server.ca_pem_path,
                                         scratch);

    /* Plan 5 C5.2 Range-resume + sweep cases. Each plants its own staged
     * partial under store_root/tmp/ and toggles the handler's range_mode
     * via batch_ctx_t so a single h_batch covers honour / ignore / 416
     * responses to the Range header. The sweep case backdates an
     * unrelated partial's mtime via utimes to drive the TTL gate.
     */
    test_batch_resume_completes_from_partial(&server, base_url,
                                             server.ca_pem_path, scratch);
    test_batch_resume_server_ignores_range(&server, base_url,
                                           server.ca_pem_path, scratch);
    test_batch_resume_server_416_restarts(&server, base_url,
                                          server.ca_pem_path, scratch);
    test_batch_sweep_stale_partial(&server, base_url, server.ca_pem_path,
                                   scratch);

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
