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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/ssl.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/fetch.h"
#include "oci/manifest.h"
#include "oci/policy.h"
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

static int build_image(image_t *img, const char *variant)
{
    memset(img, 0, sizeof(*img));

    if (!variant)
        variant = "";
    img->layer_bodies[0] = vformat(&img->layer_lens[0], "LAYER-ONE-bytes%s",
                                   variant);
    img->layer_bodies[1] = vformat(&img->layer_lens[1],
                                   "LAYER-TWO-bytes-larger-payload%s",
                                   variant);
    img->layer_bodies[2] = vformat(&img->layer_lens[2], "L3%s", variant);
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
    /* Optional registered ETag for the route. When non-empty the mock emits
     * it on 200 responses. When the inbound request's If-None-Match header
     * matches this value verbatim the mock instead returns 304 with no body
     * but the same ETag header, mirroring how a real OCI registry
     * revalidates a tag.
     */
    char etag[80];
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

/* Register an ETag the mock will echo on the route matching `path`. When the
 * inbound request also carries that exact If-None-Match value the route
 * responds 304 instead of 200, which lets tests assert that --refresh wires
 * up the conditional header end-to-end.
 */
static void router_set_etag(router_ctx_t *ctx, const char *path,
                            const char *etag)
{
    for (size_t i = 0; i < ctx->nroutes; i++) {
        if (strcmp(ctx->routes[i].path, path) == 0) {
            snprintf(ctx->routes[i].etag, sizeof(ctx->routes[i].etag), "%s",
                     etag);
            return;
        }
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
        if (r->etag[0] != '\0' &&
            strcmp(req->if_none_match, r->etag) == 0) {
            oci_mock_send_full(io, 304, "Not Modified", r->content_type, NULL,
                               r->has_docker_digest ? r->docker_digest : NULL,
                               r->etag, NULL, NULL, 0);
            return;
        }
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
                           r->etag[0] ? r->etag : NULL, NULL, body, body_len);
        return;
    }
    oci_mock_send_full(io, 404, "Not Found", "text/plain", NULL, NULL, NULL, NULL,
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

/* ── refresh: shared route population for a direct (no-index) manifest ─ */

static void populate_routes_direct(router_ctx_t *ctx, const image_t *img,
                                   const char *manifest_dc_digest)
{
    char path[256];
    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/3.20");
    router_add(ctx, path, 200,
               "application/vnd.oci.image.manifest.v1+json",
               manifest_dc_digest, img->manifest_json, img->manifest_len);

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

static void test_pull_refresh_unchanged(fixture_t *fx)
{
    const char *name = "pull: --refresh 304 short-circuits blob refetch";
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->manifest_hex);
    populate_routes_direct(&ctx, img, dc);
    char etag[80];
    snprintf(etag, sizeof(etag), "\"sha256:%s\"", img->manifest_hex);
    router_set_etag(&ctx, "/v2/library/alpine/manifests/3.20", etag);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-refresh-304", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    if (!store) {
        report_fail(name, "store open");
        return;
    }
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
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "first pull rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }

    /* Second pull with --refresh: server returns 304, pull short-circuits. */
    oci_mock_set_handler(fx->server, router_handler, &ctx);
    popts.refresh = true;
    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "refresh pull rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }
    int refresh_count = oci_mock_request_count(fx->server);
    if (refresh_count != 1) {
        report_fail(name,
                    "refresh pull made %d requests, expected 1 "
                    "(manifest revalidate only)",
                    refresh_count);
        goto cleanup;
    }
    char *pin = NULL;
    if (oci_store_get_ref(store, &ref, &pin, &err) < 0) {
        report_fail(name, "pin missing after refresh: %s",
                    err ? err : "?");
        goto cleanup;
    }
    char want[80];
    snprintf(want, sizeof(want), "sha256:%s", img->manifest_hex);
    if (strcmp(pin, want) != 0) {
        report_fail(name, "pin=%s want=%s", pin, want);
        free(pin);
        goto cleanup;
    }
    free(pin);
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_refresh_changed(fixture_t *fx)
{
    const char *name =
        "pull: --refresh 200 with new digest re-pulls and keeps old blob";
    image_t *img = fx->img;
    image_t img2;
    if (build_image(&img2, "-v2") < 0) {
        report_fail(name, "build_image variant failed");
        return;
    }

    /* First pull serves the original image. */
    router_ctx_t ctx1 = {0};
    char dc1[80];
    snprintf(dc1, sizeof(dc1), "sha256:%s", img->manifest_hex);
    populate_routes_direct(&ctx1, img, dc1);
    oci_mock_set_handler(fx->server, router_handler, &ctx1);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-refresh-200", fx->store_root);
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
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "first pull rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }

    /* Second pull: same tag, --refresh, but the registry has flipped to img2.
     * The mock declares ETag for img2.manifest_hex; the inbound
     * If-None-Match carries img1.manifest_hex so the server falls through to
     * 200 with the new body. The full pull pipeline must run again.
     */
    router_ctx_t ctx2 = {0};
    char dc2[80];
    snprintf(dc2, sizeof(dc2), "sha256:%s", img2.manifest_hex);
    populate_routes_direct(&ctx2, &img2, dc2);
    char etag2[80];
    snprintf(etag2, sizeof(etag2), "\"sha256:%s\"", img2.manifest_hex);
    router_set_etag(&ctx2, "/v2/library/alpine/manifests/3.20", etag2);
    oci_mock_set_handler(fx->server, router_handler, &ctx2);
    popts.refresh = true;
    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "refresh pull rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }

    if (!blob_present(store, img2.manifest_hex)) {
        report_fail(name, "new manifest blob missing");
        goto cleanup;
    }
    if (!blob_present(store, img2.config_hex)) {
        report_fail(name, "new config blob missing");
        goto cleanup;
    }
    for (size_t i = 0; i < img2.nlayers; i++) {
        if (!blob_present(store, img2.layer_hex[i])) {
            report_fail(name, "new layer %zu missing", i);
            goto cleanup;
        }
    }
    /* Old manifest blob must still be on disk; prune is the one that cleans
     * up old manifests, not refresh.
     */
    if (!blob_present(store, img->manifest_hex)) {
        report_fail(name, "old manifest blob was unlinked by refresh");
        goto cleanup;
    }
    char *pin = NULL;
    if (oci_store_get_ref(store, &ref, &pin, &err) < 0) {
        report_fail(name, "pin missing after refresh: %s",
                    err ? err : "?");
        goto cleanup;
    }
    char want[80];
    snprintf(want, sizeof(want), "sha256:%s", img2.manifest_hex);
    if (strcmp(pin, want) != 0) {
        report_fail(name, "pin=%s want=%s", pin, want);
        free(pin);
        goto cleanup;
    }
    free(pin);
    report_pass(name);

cleanup:
    free_image(&img2);
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_refresh_no_pin_falls_through(fixture_t *fx)
{
    const char *name =
        "pull: --refresh on empty store falls through to normal pull";
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->manifest_hex);
    populate_routes_direct(&ctx, img, dc);
    /* An ETag is registered but the inbound request must NOT carry
     * If-None-Match (no pin yet). The route then serves 200 with body. */
    char etag[80];
    snprintf(etag, sizeof(etag), "\"sha256:%s\"", img->manifest_hex);
    router_set_etag(&ctx, "/v2/library/alpine/manifests/3.20", etag);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-refresh-nopin", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .base_url_override = fx->base_url,
        .ca_file = fx->ca_pem_path,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    const char *err = NULL;
    oci_ref_parse("alpine:3.20", &ref, &err);
    oci_pull_options_t popts = {.quiet = true, .refresh = true};

    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }
    /* No index in this fixture, so all_blobs_present (which also checks the
     * index hex) is the wrong assertion; just verify the bytes the direct
     * route actually serves are persisted. */
    if (!blob_present(store, img->manifest_hex) ||
        !blob_present(store, img->config_hex)) {
        report_fail(name, "manifest or config missing");
        goto cleanup;
    }
    for (size_t i = 0; i < img->nlayers; i++) {
        if (!blob_present(store, img->layer_hex[i])) {
            report_fail(name, "layer %zu missing", i);
            goto cleanup;
        }
    }
    /* The mock's request log captures every request. The first (top-level
     * manifest) one must not have If-None-Match because no pin existed. */
    pthread_mutex_lock(&fx->server->lock);
    bool inm_seen = false;
    for (int i = 0; i < fx->server->n_requests; i++) {
        if (fx->server->log[i].if_none_match[0] != '\0') {
            inm_seen = true;
            break;
        }
    }
    pthread_mutex_unlock(&fx->server->lock);
    if (inm_seen) {
        report_fail(name,
                    "If-None-Match sent on cold store (no pin to revalidate)");
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

static void test_pull_refresh_digest_only_noop(fixture_t *fx)
{
    const char *name = "pull: --refresh on digest-only ref is a noop";
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
    /* Even if an ETag is registered on the digest manifest path, --refresh
     * must not opt into a conditional GET for a digest-only ref (no tag to
     * revalidate against). */
    char etag[80];
    snprintf(etag, sizeof(etag), "\"sha256:%s\"", img->manifest_hex);
    snprintf(path, sizeof(path), "/v2/library/alpine/manifests/sha256:%s",
             img->manifest_hex);
    router_set_etag(&ctx, path, etag);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-refresh-digest", fx->store_root);
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
    oci_pull_options_t popts = {.quiet = true, .refresh = true};

    err = NULL;
    if (oci_pull(f, store, &ref, &popts, &err) != 0) {
        report_fail(name, "rc != 0: %s", err ? err : "(none)");
        goto cleanup;
    }
    if (!blob_present(store, img->manifest_hex)) {
        report_fail(name, "manifest blob missing");
        goto cleanup;
    }
    /* Pin must NOT have been written for a digest-only ref. */
    char *pin = NULL;
    errno = 0;
    if (oci_store_get_ref(store, &ref, &pin, &err) == 0) {
        report_fail(name, "unexpected pin written");
        free(pin);
        goto cleanup;
    }
    if (errno != EINVAL) {
        report_fail(name, "expected EINVAL on get_ref, got errno=%d", errno);
        goto cleanup;
    }
    /* No If-None-Match must have been sent because digest-only refs are
     * content-addressed and cannot drift. */
    pthread_mutex_lock(&fx->server->lock);
    bool inm_seen = false;
    for (int i = 0; i < fx->server->n_requests; i++) {
        if (fx->server->log[i].if_none_match[0] != '\0') {
            inm_seen = true;
            break;
        }
    }
    pthread_mutex_unlock(&fx->server->lock);
    if (inm_seen) {
        report_fail(name,
                    "If-None-Match was sent for a digest-only ref");
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
}

/* ── Policy fixture helpers (C6.2) ────────────────────────────────── */

/* Per-policy-test snapshot of the env vars oci_policy_load consults so each
 * case can scribble a fresh ELFUSE_POLICY_FILE / HOME / XDG without bleeding
 * into the next case or the suite's outer environment.
 */
typedef struct {
    char *saved_policy;
    bool had_policy;
    char *saved_home;
    bool had_home;
    char *saved_xdg;
    bool had_xdg;
    char *scratch;
} policy_env_t;

static char *dup_env_(const char *name, bool *had)
{
    const char *v = getenv(name);
    *had = v != NULL;
    return v ? strdup(v) : NULL;
}

static void restore_env_(const char *name, char *saved, bool had)
{
    if (had)
        setenv(name, saved, 1);
    else
        unsetenv(name);
    free(saved);
}

static int policy_env_setup(policy_env_t *pe)
{
    memset(pe, 0, sizeof(*pe));
    pe->saved_policy = dup_env_("ELFUSE_POLICY_FILE", &pe->had_policy);
    pe->saved_home = dup_env_("HOME", &pe->had_home);
    pe->saved_xdg = dup_env_("XDG_CONFIG_HOME", &pe->had_xdg);
    char tmpl[] = "/tmp/elfuse-test-oci-pull-policy-XXXXXX";
    if (!mkdtemp(tmpl))
        return -1;
    pe->scratch = strdup(tmpl);
    if (!pe->scratch)
        return -1;
    setenv("HOME", pe->scratch, 1);
    unsetenv("XDG_CONFIG_HOME");
    unsetenv("ELFUSE_POLICY_FILE");
    return 0;
}

static void policy_env_teardown(policy_env_t *pe)
{
    restore_env_("ELFUSE_POLICY_FILE", pe->saved_policy, pe->had_policy);
    restore_env_("HOME", pe->saved_home, pe->had_home);
    restore_env_("XDG_CONFIG_HOME", pe->saved_xdg, pe->had_xdg);
    if (pe->scratch) {
        /* Wipe everything we wrote under the scratch dir. The pull tests do
         * not stress the file count so a simple opendir loop suffices, but
         * to stay symmetric with test-oci-policy reuse nftw via the helper
         * exposed by the mock library (it already pulls in ftw.h).
         */
        oci_mock_wipe_dir(pe->scratch);
        free(pe->scratch);
    }
    memset(pe, 0, sizeof(*pe));
}

static int write_policy_file(const policy_env_t *pe, const char *body,
                             char *out_path, size_t cap)
{
    snprintf(out_path, cap, "%s/policy.json", pe->scratch);
    FILE *fp = fopen(out_path, "w");
    if (!fp)
        return -1;
    if (fputs(body, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int write_auth_file_mode(const policy_env_t *pe, const char *body,
                                mode_t mode, char *out_path, size_t cap)
{
    snprintf(out_path, cap, "%s/auth.json", pe->scratch);
    FILE *fp = fopen(out_path, "w");
    if (!fp)
        return -1;
    if (fputs(body, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    if (chmod(out_path, mode) < 0)
        return -1;
    return 0;
}

/* Compose a ref string targeted at the mock server's host:port, then parse it
 * into *ref. Returns 0 on success or -1 with errno set.
 */
static int parse_loopback_ref(const fixture_t *fx, oci_ref_t *ref)
{
    char ref_str[128];
    snprintf(ref_str, sizeof(ref_str),
             "127.0.0.1:%d/library/alpine:3.20", fx->server->port);
    const char *err = NULL;
    return oci_ref_parse(ref_str, ref, &err);
}

/* Build a routes table that serves the synthetic image under the
 * /v2/library/alpine/... prefix. The first route's docker-content-digest is
 * the sub-manifest digest because pulls via the index land there.
 */
static void populate_routes_for_loopback(router_ctx_t *ctx, const image_t *img)
{
    char dc[80];
    snprintf(dc, sizeof(dc), "sha256:%s", img->index_hex);
    populate_routes_index(ctx, img, dc);
}

/* ── Tests (C6.2: policy.json) ────────────────────────────────────── */

static void test_pull_policy_insecure_loopback(fixture_t *fx)
{
    const char *name = "pull: policy insecure=true for loopback host";
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    populate_routes_for_loopback(&ctx, img);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    policy_env_t pe;
    if (policy_env_setup(&pe) < 0) {
        report_fail(name, "policy_env_setup: %s", strerror(errno));
        return;
    }
    char policy_path[256];
    char body[256];
    snprintf(body, sizeof(body),
             "{\"registries\":{\"127.0.0.1:%d\":{\"insecure\":true}}}",
             fx->server->port);
    if (write_policy_file(&pe, body, policy_path, sizeof(policy_path)) < 0) {
        report_fail(name, "write policy: %s", strerror(errno));
        goto teardown_env;
    }
    setenv("ELFUSE_POLICY_FILE", policy_path, 1);

    oci_policy_t *policy = NULL;
    const char *perr = NULL;
    if (oci_policy_load(&policy, &perr) < 0) {
        report_fail(name, "policy load: %s", perr ? perr : "(none)");
        oci_policy_free(policy);
        goto teardown_env;
    }

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-policy-insecure", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    if (!store) {
        report_fail(name, "store open: %s", strerror(errno));
        oci_policy_free(policy);
        goto teardown_env;
    }

    /* Deliberately omit ca_file and allow_insecure. The policy supplies the
     * insecure bit so the pull must succeed against the self-signed mock
     * without the test passing a CA bundle or a CLI flag.
     */
    oci_fetcher_options_t fopts = {
        .policy = policy,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    if (!f) {
        report_fail(name, "fetcher_new: %s", strerror(errno));
        oci_store_close(store);
        oci_policy_free(policy);
        goto teardown_env;
    }

    oci_ref_t ref = {0};
    if (parse_loopback_ref(fx, &ref) < 0) {
        report_fail(name, "ref parse");
        oci_fetcher_free(f);
        oci_store_close(store);
        oci_policy_free(policy);
        goto teardown_env;
    }

    oci_pull_options_t popts = {.quiet = true};
    const char *err = NULL;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    if (!all_blobs_present(store, img)) {
        report_fail(name, "store missing blobs after pull");
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
    oci_policy_free(policy);
teardown_env:
    policy_env_teardown(&pe);
}

static void test_pull_policy_auth_file_bad_mode(fixture_t *fx)
{
    const char *name = "pull: policy auth_file with insecure mode rejected";
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    populate_routes_for_loopback(&ctx, img);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    policy_env_t pe;
    if (policy_env_setup(&pe) < 0) {
        report_fail(name, "policy_env_setup: %s", strerror(errno));
        return;
    }
    char auth_path[256];
    if (write_auth_file_mode(&pe, "{\"username\":\"u\",\"password\":\"p\"}",
                             0644, auth_path, sizeof(auth_path)) < 0) {
        report_fail(name, "write auth: %s", strerror(errno));
        goto teardown_env;
    }
    char policy_path[256];
    char body[512];
    snprintf(body, sizeof(body),
             "{\"registries\":{\"127.0.0.1:%d\":"
             "{\"insecure\":true,\"auth_file\":\"%s\"}}}",
             fx->server->port, auth_path);
    if (write_policy_file(&pe, body, policy_path, sizeof(policy_path)) < 0) {
        report_fail(name, "write policy: %s", strerror(errno));
        goto teardown_env;
    }
    setenv("ELFUSE_POLICY_FILE", policy_path, 1);

    oci_policy_t *policy = NULL;
    const char *perr = NULL;
    if (oci_policy_load(&policy, &perr) < 0) {
        report_fail(name, "policy load: %s", perr ? perr : "(none)");
        oci_policy_free(policy);
        goto teardown_env;
    }

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-policy-authmode", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    oci_fetcher_options_t fopts = {
        .policy = policy,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    if (parse_loopback_ref(fx, &ref) < 0) {
        report_fail(name, "ref parse");
        oci_fetcher_free(f);
        oci_store_close(store);
        oci_policy_free(policy);
        goto teardown_env;
    }
    oci_pull_options_t popts = {.quiet = true};
    const char *err = NULL;
    errno = 0;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc == 0) {
        report_fail(name, "expected failure, got success");
        goto cleanup;
    }
    if (!err || !strstr(err, "mode")) {
        report_fail(name, "expected mode diagnostic, got: %s",
                    err ? err : "(none)");
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
    oci_policy_free(policy);
teardown_env:
    policy_env_teardown(&pe);
}

static void test_pull_cli_overrides_policy_insecure(fixture_t *fx)
{
    const char *name = "pull: CLI --insecure overrides policy insecure=false";
    image_t *img = fx->img;
    router_ctx_t ctx = {0};
    populate_routes_for_loopback(&ctx, img);
    oci_mock_set_handler(fx->server, router_handler, &ctx);

    policy_env_t pe;
    if (policy_env_setup(&pe) < 0) {
        report_fail(name, "policy_env_setup: %s", strerror(errno));
        return;
    }
    char policy_path[256];
    char body[256];
    snprintf(body, sizeof(body),
             "{\"registries\":{\"127.0.0.1:%d\":{\"insecure\":false}}}",
             fx->server->port);
    if (write_policy_file(&pe, body, policy_path, sizeof(policy_path)) < 0) {
        report_fail(name, "write policy: %s", strerror(errno));
        goto teardown_env;
    }
    setenv("ELFUSE_POLICY_FILE", policy_path, 1);

    oci_policy_t *policy = NULL;
    const char *perr = NULL;
    if (oci_policy_load(&policy, &perr) < 0) {
        report_fail(name, "policy load: %s", perr ? perr : "(none)");
        oci_policy_free(policy);
        goto teardown_env;
    }

    char root[1024];
    snprintf(root, sizeof(root), "%s/store-policy-cli-wins", fx->store_root);
    oci_store_t *store = oci_store_open(root);
    /* CLI --insecure=true: should win over policy insecure=false. No ca_file
     * needed because the effective insecure=true turns TLS verify off. */
    oci_fetcher_options_t fopts = {
        .policy = policy,
        .allow_insecure = true,
    };
    oci_fetcher_t *f = oci_fetcher_new(&fopts);
    oci_ref_t ref = {0};
    if (parse_loopback_ref(fx, &ref) < 0) {
        report_fail(name, "ref parse");
        oci_fetcher_free(f);
        oci_store_close(store);
        oci_policy_free(policy);
        goto teardown_env;
    }
    oci_pull_options_t popts = {.quiet = true};
    const char *err = NULL;
    int rc = oci_pull(f, store, &ref, &popts, &err);
    if (rc != 0) {
        report_fail(name, "rc=%d err=%s", rc, err ? err : "(none)");
        goto cleanup;
    }
    if (!all_blobs_present(store, img)) {
        report_fail(name, "store missing blobs after pull");
        goto cleanup;
    }
    report_pass(name);

cleanup:
    oci_ref_free(&ref);
    oci_fetcher_free(f);
    oci_store_close(store);
    oci_policy_free(policy);
teardown_env:
    policy_env_teardown(&pe);
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
    if (build_image(&img, NULL) < 0) {
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
    test_pull_refresh_unchanged(&fx);
    test_pull_refresh_changed(&fx);
    test_pull_refresh_no_pin_falls_through(&fx);
    test_pull_refresh_digest_only_noop(&fx);
    test_pull_policy_insecure_loopback(&fx);
    test_pull_policy_auth_file_bad_mode(&fx);
    test_pull_cli_overrides_policy_insecure(&fx);

    free_image(&img);
    free(base_url);
    oci_mock_server_stop(&server);
    oci_mock_wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
