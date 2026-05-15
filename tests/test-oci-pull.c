/* elfuse oci pull pipeline unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives end-to-end pulls against the shared TLS mock server (tests/lib/
 * oci-mock). Each case scripts a router that maps URI -> canned response and
 * runs oci_pull, then inspects the resulting blob store and pin file to
 * verify:
 *
 *   - tag -> index -> linux/arm64 sub-manifest -> config + layers, with pin
 *   - tag -> direct manifest (no index) -> config + layers, with pin
 *   - digest-only ref -> manifest -> config + layers, no pin
 *   - re-pull short-circuits: no extra blob downloads
 *   - body digest mismatching Docker-Content-Digest aborts the pull
 *   - index without linux/arm64 aborts the pull
 *
 * Manifest, index, and config JSON are generated at runtime so the embedded
 * digests stay consistent with the actual bytes the mock will serve.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/fetch.h"
#include "oci/manifest.h"
#include "oci/pull.h"
#include "oci/ref.h"
#include "oci/store.h"

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

/* ── Synthetic image generator ───────────────────────────────────── */

/* Caller-owned bytes; populated by build_image. layer_bodies stay alive for
 * the lifetime of the image_t.
 */
typedef struct {
    char *config_json;
    size_t config_len;
    char config_hex[OCI_DIGEST_HEX_MAX + 1];

    char *layer_bodies[3];
    size_t layer_lens[3];
    char layer_hex[3][OCI_DIGEST_HEX_MAX + 1];
    size_t nlayers;

    char *manifest_json;
    size_t manifest_len;
    char manifest_hex[OCI_DIGEST_HEX_MAX + 1];

    char *index_json;
    size_t index_len;
    char index_hex[OCI_DIGEST_HEX_MAX + 1];
} image_t;

static char *xstrdup_with_len(const char *s, size_t *out_len)
{
    char *r = strdup(s);
    *out_len = strlen(s);
    return r;
}

static char *vformat(size_t *out_len, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static char *vformat(size_t *out_len, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0)
        return NULL;
    char *r = malloc((size_t) n + 1);
    if (!r)
        return NULL;
    va_start(ap, fmt);
    vsnprintf(r, (size_t) n + 1, fmt, ap);
    va_end(ap);
    *out_len = (size_t) n;
    return r;
}

static void hash_bytes(const void *buf, size_t len, char *out_hex)
{
    oci_digest_bytes(OCI_DIGEST_SHA256, buf, len, out_hex);
}

static int build_image(image_t *img)
{
    memset(img, 0, sizeof(*img));

    img->layer_bodies[0] = xstrdup_with_len("LAYER-ONE-bytes",
                                            &img->layer_lens[0]);
    img->layer_bodies[1] = xstrdup_with_len("LAYER-TWO-bytes-larger-payload",
                                            &img->layer_lens[1]);
    img->layer_bodies[2] = xstrdup_with_len("L3", &img->layer_lens[2]);
    img->nlayers = 3;
    for (size_t i = 0; i < img->nlayers; i++)
        hash_bytes(img->layer_bodies[i], img->layer_lens[i], img->layer_hex[i]);

    char *cfg = vformat(
        &img->config_len,
        "{\"architecture\":\"arm64\",\"os\":\"linux\","
        "\"rootfs\":{\"type\":\"layers\","
        "\"diff_ids\":[\"sha256:%s\",\"sha256:%s\",\"sha256:%s\"]}}",
        img->layer_hex[0], img->layer_hex[1], img->layer_hex[2]);
    if (!cfg)
        return -1;
    img->config_json = cfg;
    hash_bytes(cfg, img->config_len, img->config_hex);

    char *manifest = vformat(
        &img->manifest_len,
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
            "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
            "\"digest\":\"sha256:%s\",\"size\":%zu},"
        "\"layers\":["
            "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
             "\"digest\":\"sha256:%s\",\"size\":%zu},"
            "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
             "\"digest\":\"sha256:%s\",\"size\":%zu},"
            "{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\","
             "\"digest\":\"sha256:%s\",\"size\":%zu}]}",
        img->config_hex, img->config_len,
        img->layer_hex[0], img->layer_lens[0],
        img->layer_hex[1], img->layer_lens[1],
        img->layer_hex[2], img->layer_lens[2]);
    if (!manifest)
        return -1;
    img->manifest_json = manifest;
    hash_bytes(manifest, img->manifest_len, img->manifest_hex);

    char *index = vformat(
        &img->index_len,
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
        "\"manifests\":[{"
            "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
            "\"digest\":\"sha256:%s\",\"size\":%zu,"
            "\"platform\":{\"architecture\":\"arm64\",\"os\":\"linux\","
            "\"variant\":\"v8\"}}]}",
        img->manifest_hex, img->manifest_len);
    if (!index)
        return -1;
    img->index_json = index;
    hash_bytes(index, img->index_len, img->index_hex);
    return 0;
}

static void free_image(image_t *img)
{
    free(img->config_json);
    for (size_t i = 0; i < img->nlayers; i++)
        free(img->layer_bodies[i]);
    free(img->manifest_json);
    free(img->index_json);
    memset(img, 0, sizeof(*img));
}

/* ── Mock router ─────────────────────────────────────────────────── */

typedef struct {
    char path[256];
    int status;
    const char *content_type;
    char docker_digest[80];
    const void *body;
    size_t body_len;
    bool has_docker_digest;
} route_t;

#define ROUTES_MAX 16

typedef struct {
    route_t routes[ROUTES_MAX];
    size_t nroutes;
    /* When non-NULL, the router returns this body in place of routes[0]. Used
     * to inject a digest-mismatch case where the registry serves bytes that do
     * not hash to the Docker-Content-Digest header.
     */
    const void *override_body;
    size_t override_body_len;
} router_ctx_t;

static void router_add(router_ctx_t *ctx, const char *path, int status,
                       const char *content_type, const char *docker_digest,
                       const void *body, size_t body_len)
{
    if (ctx->nroutes >= ROUTES_MAX)
        return;
    route_t *r = &ctx->routes[ctx->nroutes++];
    snprintf(r->path, sizeof(r->path), "%s", path);
    r->status = status;
    r->content_type = content_type;
    r->body = body;
    r->body_len = body_len;
    if (docker_digest) {
        snprintf(r->docker_digest, sizeof(r->docker_digest), "%s",
                 docker_digest);
        r->has_docker_digest = true;
    } else {
        r->has_docker_digest = false;
    }
}

static void router_handler(oci_mock_server_t *s, oci_mock_io_t *io,
                           const oci_mock_request_t *req)
{
    router_ctx_t *ctx = oci_mock_handler_ctx(s);
    for (size_t i = 0; i < ctx->nroutes; i++) {
        const route_t *r = &ctx->routes[i];
        if (strcmp(req->path, r->path) != 0)
            continue;
        const void *body = r->body;
        size_t body_len = r->body_len;
        if (i == 0 && ctx->override_body) {
            body = ctx->override_body;
            body_len = ctx->override_body_len;
        }
        oci_mock_send_full(io, r->status,
                           r->status == 200 ? "OK" : "Error",
                           r->content_type, NULL,
                           r->has_docker_digest ? r->docker_digest : NULL,
                           body, body_len);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL,
                       "nope", 4);
}

/* ── Fixture helpers ─────────────────────────────────────────────── */

typedef struct {
    char ca_pem_path[256];
    char base_url[64];
    oci_mock_server_t *server;
    image_t *img;
    char *store_root;
} fixture_t;

static void populate_routes_index(router_ctx_t *ctx, const image_t *img,
                                  const char *index_dc_digest)
{
    char path[256];
    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/3.20");
    router_add(ctx, path, 200,
               "application/vnd.oci.image.index.v1+json",
               index_dc_digest, img->index_json, img->index_len);

    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/sha256:%s",
             img->manifest_hex);
    router_add(ctx, path, 200,
               "application/vnd.oci.image.manifest.v1+json", NULL,
               img->manifest_json, img->manifest_len);

    snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
             img->config_hex);
    router_add(ctx, path, 200, "application/octet-stream", NULL,
               img->config_json, img->config_len);

    for (size_t i = 0; i < img->nlayers; i++) {
        snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
                 img->layer_hex[i]);
        router_add(ctx, path, 200, "application/octet-stream", NULL,
                   img->layer_bodies[i], img->layer_lens[i]);
    }
}

static bool blob_present(oci_store_t *store, const char *hex)
{
    return oci_blob_store_has(oci_store_blobs(store), OCI_DIGEST_SHA256, hex);
}

static bool all_blobs_present(oci_store_t *store, const image_t *img)
{
    if (!blob_present(store, img->index_hex))
        return false;
    if (!blob_present(store, img->manifest_hex))
        return false;
    if (!blob_present(store, img->config_hex))
        return false;
    for (size_t i = 0; i < img->nlayers; i++)
        if (!blob_present(store, img->layer_hex[i]))
            return false;
    return true;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_pull_index_arm64(fixture_t *fx)
{
    image_t *img = fx->img;
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->index_hex);
    router_ctx_t ctx = {0};
    populate_routes_index(&ctx, img, dc);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-idx", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    if (!store) {
        report_fail("pull: tag -> index -> arm64 manifest", "store open");
        return;
    }
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    if (!f) {
        report_fail("pull: tag -> index -> arm64 manifest", "fetcher new");
        oci_store_close(store);
        return;
    }
    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse("alpine:3.20", &ref, &err) < 0) {
        report_fail("pull: tag -> index -> arm64 manifest", "ref parse");
        oci_fetcher_free(f);
        oci_store_close(store);
        return;
    }
    oci_pull_options_t popts = {.quiet = true};
    err = NULL;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc != 0) {
        report_fail("pull: tag -> index -> arm64 manifest", "rc=%d err=%s", rc,
                    err ? err : "(none)");
        goto cleanup;
    }
    if (!all_blobs_present(store, img)) {
        report_fail("pull: tag -> index -> arm64 manifest",
                    "store missing one or more blobs");
        goto cleanup;
    }
    char *pin = NULL;
    if (oci_store_get_ref(store, &ref, &pin, &err) < 0) {
        report_fail("pull: tag -> index -> arm64 manifest", "no pin: %s",
                    err ? err : "?");
        goto cleanup;
    }
    char want_pin[80];
    snprintf(want_pin, sizeof(want_pin), "sha256:%s", img->index_hex);
    if (strcmp(pin, want_pin) != 0) {
        report_fail("pull: tag -> index -> arm64 manifest",
                    "pin=%s want=%s", pin, want_pin);
        free(pin);
        goto cleanup;
    }
    free(pin);
    report_pass("pull: tag -> index -> arm64 manifest");

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_direct_manifest(fixture_t *fx)
{
    image_t *img = fx->img;
    /* Tag resolves directly to a manifest, no index. */
    router_ctx_t ctx = {0};
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->manifest_hex);
    char path[256];
    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/3.20");
    router_add(&ctx, path, 200,
               "application/vnd.oci.image.manifest.v1+json", dc,
               img->manifest_json, img->manifest_len);
    snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
             img->config_hex);
    router_add(&ctx, path, 200, "application/octet-stream", NULL,
               img->config_json, img->config_len);
    for (size_t i = 0; i < img->nlayers; i++) {
        snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
                 img->layer_hex[i]);
        router_add(&ctx, path, 200, "application/octet-stream", NULL,
                   img->layer_bodies[i], img->layer_lens[i]);
    }
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-direct", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &err);
    oci_pull_options_t popts = {.quiet = true};
    err = NULL;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc != 0) {
        report_fail("pull: tag -> direct manifest (no index)", "rc=%d err=%s",
                    rc, err ? err : "(none)");
    } else if (!blob_present(store, img->manifest_hex)) {
        report_fail("pull: tag -> direct manifest (no index)",
                    "manifest blob missing");
    } else if (blob_present(store, img->index_hex)) {
        /* No index was served; the index blob hex must not coincidentally land
         * in the store.
         */
        report_fail("pull: tag -> direct manifest (no index)",
                    "index blob unexpectedly present");
    } else {
        char *pin = NULL;
        char want[80];
        snprintf(want, sizeof(want), "sha256:%s", img->manifest_hex);
        if (oci_store_get_ref(store, &ref, &pin, &err) < 0 ||
            strcmp(pin, want) != 0) {
            report_fail("pull: tag -> direct manifest (no index)",
                        "pin mismatch");
            free(pin);
        } else {
            free(pin);
            report_pass("pull: tag -> direct manifest (no index)");
        }
    }
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_digest_only(fixture_t *fx)
{
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    char path[256];
    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/sha256:%s",
             img->manifest_hex);
    router_add(&ctx, path, 200,
               "application/vnd.oci.image.manifest.v1+json", NULL,
               img->manifest_json, img->manifest_len);
    snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
             img->config_hex);
    router_add(&ctx, path, 200, "application/octet-stream", NULL,
               img->config_json, img->config_len);
    for (size_t i = 0; i < img->nlayers; i++) {
        snprintf(path, sizeof(path), "/v2/library/alpine/blobs/sha256:%s",
                 img->layer_hex[i]);
        router_add(&ctx, path, 200, "application/octet-stream", NULL,
                   img->layer_bodies[i], img->layer_lens[i]);
    }
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-digest-only", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);

    char ref_str[256];
    snprintf(ref_str, sizeof(ref_str), "alpine@sha256:%s", img->manifest_hex);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse(ref_str, &ref, &err);
    oci_pull_options_t popts = {.quiet = true};
    err = NULL;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc != 0) {
        report_fail("pull: digest-only ref", "rc=%d err=%s", rc,
                    err ? err : "(none)");
    } else if (!blob_present(store, img->manifest_hex)) {
        report_fail("pull: digest-only ref", "manifest blob missing");
    } else {
        char *pin = NULL;
        errno = 0;
        int gr = oci_store_get_ref(store, &ref, &pin, &err);
        if (gr == 0) {
            report_fail("pull: digest-only ref",
                        "unexpected pin written for digest-only ref");
            free(pin);
        } else if (errno != EINVAL) {
            report_fail("pull: digest-only ref",
                        "expected EINVAL on get_ref, got errno=%d", errno);
        } else {
            report_pass("pull: digest-only ref");
        }
    }
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_repull_caches(fixture_t *fx)
{
    image_t *img = fx->img;
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->index_hex);
    router_ctx_t ctx = {0};
    populate_routes_index(&ctx, img, dc);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-repull", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &err);
    oci_pull_options_t popts = {.quiet = true};

    /* First pull: should download index + manifest + config + 3 layers = 6
     * requests. The mock log clamps at OCI_MOCK_LOG_MAX = 16 so 6 fits.
     */
    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail("pull: re-pull hits cache", "first pull failed: %s",
                    err ? err : "(none)");
        goto cleanup;
    }
    int first_count = oci_mock_request_count(fx->server);

    /* Reset request counter, re-pull. Layers + config should short-circuit
     * via oci_blob_store_has. Manifest documents are still re-fetched (no
     * manifest cache yet). Expect exactly 2 requests: index + sub-manifest.
     */
    oci_mock_set_handler(fx->server, router_handler, &ctx);
    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail("pull: re-pull hits cache", "second pull failed: %s",
                    err ? err : "(none)");
        goto cleanup;
    }
    int second_count = oci_mock_request_count(fx->server);
    if (first_count != 6) {
        report_fail("pull: re-pull hits cache",
                    "first pull made %d requests, expected 6", first_count);
        goto cleanup;
    }
    if (second_count != 2) {
        report_fail("pull: re-pull hits cache",
                    "second pull made %d requests, expected 2 (index + "
                    "manifest)",
                    second_count);
        goto cleanup;
    }
    report_pass("pull: re-pull hits cache");

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_docker_digest_mismatch(fixture_t *fx)
{
    image_t *img = fx->img;
    /* The mock claims index_hex via Docker-Content-Digest but actually serves
     * a different body. The pull must abort before any blob writes happen.
     */
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->index_hex);
    router_ctx_t ctx = {0};
    populate_routes_index(&ctx, img, dc);
    static const char EVIL[] = "{\"schemaVersion\":2,\"evil\":true}";
    ctx.override_body = EVIL;
    ctx.override_body_len = strlen(EVIL);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-mismatch", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &err);
    oci_pull_options_t popts = {.quiet = true};
    err = NULL;
    errno = 0;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc == 0) {
        report_fail("pull: body digest != Docker-Content-Digest",
                    "rc=0 (expected -1)");
    } else if (errno != EPROTO) {
        report_fail("pull: body digest != Docker-Content-Digest",
                    "errno=%d (expected EPROTO)", errno);
    } else {
        char *pin = NULL;
        errno = 0;
        if (oci_store_get_ref(store, &ref, &pin, &err) == 0) {
            report_fail("pull: body digest != Docker-Content-Digest",
                        "pin unexpectedly written");
            free(pin);
        } else if (errno != ENOENT) {
            report_fail("pull: body digest != Docker-Content-Digest",
                        "get_ref errno=%d (expected ENOENT)", errno);
        } else {
            report_pass("pull: body digest != Docker-Content-Digest");
        }
    }
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_index_no_arm64(fixture_t *fx)
{
    /* An index that only lists amd64 has no usable sub-manifest. */
    char index[512];
    int n = snprintf(index, sizeof(index),
                     "{\"schemaVersion\":2,"
                     "\"mediaType\":\"application/vnd.oci.image.index.v1+json\","
                     "\"manifests\":[{"
                       "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
                       "\"digest\":\"sha256:0000000000000000000000000000"
                       "000000000000000000000000000000000000\","
                       "\"size\":1,"
                       "\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"}}]}");
    char hex[OCI_DIGEST_HEX_MAX + 1];
    hash_bytes(index, (size_t) n, hex);
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", hex);

    router_ctx_t ctx = {0};
    router_add(&ctx, "/v2/library/alpine/manifests/3.20", 200,
               "application/vnd.oci.image.index.v1+json", dc, index,
               (size_t) n);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-no-arm64", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &err);
    oci_pull_options_t popts = {.quiet = true};
    err = NULL;
    errno = 0;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc == 0) {
        report_fail("pull: index without linux/arm64", "rc=0");
    } else if (errno != ENOENT) {
        report_fail("pull: index without linux/arm64",
                    "errno=%d (expected ENOENT)", errno);
    } else {
        report_pass("pull: index without linux/arm64");
    }
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void)
{
    if (curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL) !=
        CURLSSLSET_OK) {
        fprintf(stderr,
                "libcurl OpenSSL backend not available; pull tests cannot run\n");
        return 1;
    }
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    char *scratch = oci_mock_make_scratch_root("elfuse-oci-pull");
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

    image_t img;
    if (build_image(&img) < 0) {
        fprintf(stderr, "build_image failed\n");
        oci_mock_server_stop(&server);
        free(base_url);
        oci_mock_wipe_dir(scratch);
        free(scratch);
        return 1;
    }

    fixture_t fx = {0};
    snprintf(fx.ca_pem_path, sizeof(fx.ca_pem_path), "%s", server.ca_pem_path);
    snprintf(fx.base_url, sizeof(fx.base_url), "%s", base_url);
    fx.server = &server;
    fx.img = &img;
    fx.store_root = scratch;

    printf("oci_pull (mock HTTPS @ %s, CA=%s)\n", base_url, server.ca_pem_path);

    test_pull_index_arm64(&fx);
    test_pull_direct_manifest(&fx);
    test_pull_digest_only(&fx);
    test_pull_repull_caches(&fx);
    test_pull_docker_digest_mismatch(&fx);
    test_pull_index_no_arm64(&fx);

    free_image(&img);
    free(base_url);
    oci_mock_server_stop(&server);
    oci_mock_wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
