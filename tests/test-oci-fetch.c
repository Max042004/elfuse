/* OCI registry HTTPS client unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Spawns a single-threaded HTTP/1.1 mock server on 127.0.0.1:<ephemeral> and
 * drives oci_fetch_manifest / oci_fetch_blob against it. The mock server is
 * scripted per request via a handler function pointer: each test installs the
 * behavior it wants (200 OK, 401 with bearer challenge, 404, oversize blob,
 * etc.) and verifies the response captured by the fetcher plus side effects
 * in a temporary blob store directory.
 *
 * No real network is touched. The optional OCI_FETCH_ONLINE=1 environment
 * variable enables a single additional case that pulls alpine:3.20 from
 * Docker Hub anonymously; that path is gated behind make test-oci-fetch-online
 * and is not part of make check.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/fetch.h"
#include "oci/manifest.h"
#include "oci/ref.h"

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

/* ── Mock HTTP server ────────────────────────────────────────────── */

typedef struct {
    char method[8];
    char path[1024];
    char authorization[1024];
    char accept[1024];
} mock_request_t;

#define MOCK_LOG_MAX 16

typedef struct mock_server mock_server_t;
typedef void (*mock_handler_t)(mock_server_t *s, int fd,
                               const mock_request_t *req);

struct mock_server {
    int listen_fd;
    int port;
    pthread_t thread;
    pthread_mutex_t lock;
    bool stop;
    int n_requests;
    mock_request_t log[MOCK_LOG_MAX];
    mock_handler_t handler;
    void *ctx;
};

static ssize_t read_all_until_empty(int fd, char *buf, size_t cap)
{
    size_t off = 0;
    while (off + 1 < cap) {
        ssize_t n = read(fd, buf + off, cap - 1 - off);
        if (n <= 0)
            break;
        off += (size_t) n;
        buf[off] = '\0';
        if (strstr(buf, "\r\n\r\n"))
            break;
    }
    return (ssize_t) off;
}

static void parse_request(const char *raw, mock_request_t *out)
{
    memset(out, 0, sizeof(*out));
    /* Request line: METHOD SP path SP HTTP/x */
    const char *sp1 = strchr(raw, ' ');
    if (!sp1)
        return;
    size_t mlen = (size_t) (sp1 - raw);
    if (mlen >= sizeof(out->method))
        mlen = sizeof(out->method) - 1;
    memcpy(out->method, raw, mlen);
    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2)
        return;
    size_t plen = (size_t) (sp2 - sp1 - 1);
    if (plen >= sizeof(out->path))
        plen = sizeof(out->path) - 1;
    memcpy(out->path, sp1 + 1, plen);

    /* Header scan. */
    const char *line = strstr(raw, "\r\n");
    if (!line)
        return;
    line += 2;
    while (*line && strncmp(line, "\r\n", 2) != 0) {
        const char *eol = strstr(line, "\r\n");
        if (!eol)
            break;
        size_t llen = (size_t) (eol - line);
        if (llen > 13 && !strncasecmp(line, "Authorization:", 14)) {
            const char *v = line + 14;
            while (*v == ' ')
                v++;
            size_t vlen = (size_t) (eol - v);
            if (vlen >= sizeof(out->authorization))
                vlen = sizeof(out->authorization) - 1;
            memcpy(out->authorization, v, vlen);
            out->authorization[vlen] = '\0';
        } else if (llen > 6 && !strncasecmp(line, "Accept:", 7)) {
            const char *v = line + 7;
            while (*v == ' ')
                v++;
            size_t vlen = (size_t) (eol - v);
            if (vlen >= sizeof(out->accept))
                vlen = sizeof(out->accept) - 1;
            memcpy(out->accept, v, vlen);
            out->accept[vlen] = '\0';
        }
        line = eol + 2;
    }
}

static void *mock_server_loop(void *arg)
{
    mock_server_t *s = arg;
    while (1) {
        pthread_mutex_lock(&s->lock);
        bool stop = s->stop;
        pthread_mutex_unlock(&s->lock);
        if (stop)
            break;
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        char buf[8192];
        ssize_t got = read_all_until_empty(cfd, buf, sizeof(buf));
        if (got <= 0) {
            close(cfd);
            continue;
        }
        mock_request_t req;
        parse_request(buf, &req);

        pthread_mutex_lock(&s->lock);
        if (s->n_requests < MOCK_LOG_MAX) {
            s->log[s->n_requests++] = req;
        }
        mock_handler_t h = s->handler;
        pthread_mutex_unlock(&s->lock);

        if (h)
            h(s, cfd, &req);
        close(cfd);
    }
    return NULL;
}

static int mock_server_start(mock_server_t *s)
{
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0)
        return -1;
    int yes = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(s->listen_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(s->listen_fd);
        return -1;
    }
    socklen_t slen = sizeof(sa);
    if (getsockname(s->listen_fd, (struct sockaddr *) &sa, &slen) < 0) {
        close(s->listen_fd);
        return -1;
    }
    s->port = ntohs(sa.sin_port);
    if (listen(s->listen_fd, 8) < 0) {
        close(s->listen_fd);
        return -1;
    }
    if (pthread_create(&s->thread, NULL, mock_server_loop, s) != 0) {
        close(s->listen_fd);
        return -1;
    }
    return 0;
}

static void mock_server_stop(mock_server_t *s)
{
    pthread_mutex_lock(&s->lock);
    s->stop = true;
    pthread_mutex_unlock(&s->lock);
    /* Unblock the accept by connecting to ourselves. */
    int wake = socket(AF_INET, SOCK_STREAM, 0);
    if (wake >= 0) {
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            .sin_port = htons(s->port),
        };
        (void) connect(wake, (struct sockaddr *) &sa, sizeof(sa));
        close(wake);
    }
    pthread_join(s->thread, NULL);
    close(s->listen_fd);
    pthread_mutex_destroy(&s->lock);
}

static void mock_set_handler(mock_server_t *s, mock_handler_t h, void *ctx)
{
    pthread_mutex_lock(&s->lock);
    s->handler = h;
    s->ctx = ctx;
    s->n_requests = 0;
    memset(s->log, 0, sizeof(s->log));
    pthread_mutex_unlock(&s->lock);
}

static void mock_send_full(int fd, int status, const char *status_text,
                           const char *content_type,
                           const char *www_authenticate,
                           const char *docker_digest,
                           const void *body,
                           size_t body_len)
{
    char header[1024];
    int n = snprintf(header, sizeof(header),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Length: %zu\r\n",
                     status, status_text ? status_text : "OK", body_len);
    if (content_type)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Content-Type: %s\r\n", content_type);
    if (www_authenticate)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Www-Authenticate: %s\r\n", www_authenticate);
    if (docker_digest)
        n += snprintf(header + n, sizeof(header) - (size_t) n,
                      "Docker-Content-Digest: %s\r\n", docker_digest);
    n += snprintf(header + n, sizeof(header) - (size_t) n, "\r\n");
    (void) !write(fd, header, (size_t) n);
    if (body_len > 0)
        (void) !write(fd, body, body_len);
}

/* ── Helpers ─────────────────────────────────────────────────────── */

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

static char *make_scratch_root(void)
{
    char *tmpl = strdup("/tmp/elfuse-oci-fetch-XXXXXX");
    if (!tmpl || !mkdtemp(tmpl)) {
        free(tmpl);
        return NULL;
    }
    return tmpl;
}

static char *make_base_url(int port)
{
    char *url = malloc(64);
    if (!url)
        return NULL;
    snprintf(url, 64, "http://127.0.0.1:%d", port);
    return url;
}

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

static void h_anonymous_manifest(mock_server_t *s, int fd,
                                 const mock_request_t *req)
{
    handler_anonymous_manifest_t *ctx = s->ctx;
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        mock_send_full(fd, 200, "OK", ctx->content_type, NULL, ctx->docker_digest,
                       ctx->body, ctx->body_len);
        return;
    }
    mock_send_full(fd, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
}

typedef struct {
    const char *manifest_path;
    const char *expected_token;
    const char *manifest_body;
    size_t manifest_body_len;
    const char *content_type;
    char base_url[64];
} handler_bearer_t;

static void h_bearer_flow(mock_server_t *s, int fd, const mock_request_t *req)
{
    handler_bearer_t *ctx = s->ctx;
    if (strncmp(req->path, "/token", 6) == 0) {
        char body[256];
        int n = snprintf(body, sizeof(body),
                         "{\"token\":\"%s\",\"expires_in\":300}",
                         ctx->expected_token);
        mock_send_full(fd, 200, "OK", "application/json", NULL, NULL, body,
                       (size_t) n);
        return;
    }
    if (strcmp(req->path, ctx->manifest_path) == 0) {
        char want_auth[256];
        snprintf(want_auth, sizeof(want_auth), "Bearer %s", ctx->expected_token);
        if (strcmp(req->authorization, want_auth) == 0) {
            mock_send_full(fd, 200, "OK", ctx->content_type, NULL, NULL,
                           ctx->manifest_body, ctx->manifest_body_len);
            return;
        }
        char challenge[512];
        snprintf(challenge, sizeof(challenge),
                 "Bearer realm=\"%s/token\",service=\"reg\","
                 "scope=\"repository:private/secret:pull\"",
                 ctx->base_url);
        mock_send_full(fd, 401, "Unauthorized", "application/json", challenge,
                       NULL, "{}", 2);
        return;
    }
    mock_send_full(fd, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
}

typedef struct {
    const char *blob_path;
    const void *body;
    size_t body_len;
    int status; /* override; 0 = 200 */
    bool oversize; /* if true, send body_len + 5 bytes */
} handler_blob_t;

static void h_blob(mock_server_t *s, int fd, const mock_request_t *req)
{
    handler_blob_t *ctx = s->ctx;
    if (strcmp(req->path, ctx->blob_path) != 0) {
        mock_send_full(fd, 404, "Not Found", "text/plain", NULL, NULL, "nope", 4);
        return;
    }
    int status = ctx->status ? ctx->status : 200;
    if (status != 200) {
        mock_send_full(fd, status, "Error", "text/plain", NULL, NULL, "err", 3);
        return;
    }
    if (ctx->oversize) {
        size_t pad_len = ctx->body_len + 5;
        char *buf = malloc(pad_len);
        memcpy(buf, ctx->body, ctx->body_len);
        memset(buf + ctx->body_len, 'X', 5);
        mock_send_full(fd, 200, "OK", "application/octet-stream", NULL, NULL,
                       buf, pad_len);
        free(buf);
        return;
    }
    mock_send_full(fd, 200, "OK", "application/octet-stream", NULL, NULL,
                   ctx->body, ctx->body_len);
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_anonymous_manifest(mock_server_t *server, oci_fetcher_t *f)
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
    mock_set_handler(server, h_anonymous_manifest, &ctx);

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

static void test_manifest_404(mock_server_t *server, oci_fetcher_t *f)
{
    handler_anonymous_manifest_t ctx = {
        .manifest_path = "/v2/library/missing/manifests/v9",
        .body = "{}",
        .body_len = 2,
        .content_type = "application/json",
        .docker_digest = NULL,
    };
    mock_set_handler(server, h_anonymous_manifest, &ctx);

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

static void test_bearer_challenge(mock_server_t *server, oci_fetcher_t *f,
                                  handler_bearer_t *ctx)
{
    mock_set_handler(server, h_bearer_flow, ctx);

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

static void test_token_reuse(mock_server_t *server, oci_fetcher_t *f)
{
    /* Second fetch on the same fetcher after a successful bearer flow should
     * attach the cached token straight away and skip the 401 dance. The mock
     * keeps the same handler from the bearer test in the parent, so a single
     * 200 response is expected.
     */
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

static void test_blob_success(mock_server_t *server, oci_fetcher_t *f,
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
    mock_set_handler(server, h_blob, &ctx);

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

static void test_blob_already_cached(mock_server_t *server, oci_fetcher_t *f,
                                     const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    if (!store) {
        report_fail("blob fetch skips network when already cached", "store");
        return;
    }
    /* Pre-populate via put_bytes so the fetch hits the store has() short
     * circuit.
     */
    if (oci_blob_store_put_bytes(store, OCI_DIGEST_SHA256, HELLO_WORLD_SHA256,
                                 HELLO_WORLD, strlen(HELLO_WORLD)) != 0) {
        report_fail("blob fetch skips network when already cached",
                    "put_bytes: %s", strerror(errno));
        oci_blob_store_close(store);
        return;
    }

    /* Install a handler that would 404 every request, so any contact is a bug. */
    handler_blob_t ctx = {
        .blob_path = "/never-called",
        .body = "x",
        .body_len = 1,
    };
    mock_set_handler(server, h_blob, &ctx);

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

static void test_blob_size_mismatch(mock_server_t *server, oci_fetcher_t *f,
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
    mock_set_handler(server, h_blob, &ctx);

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

static void test_blob_digest_mismatch(mock_server_t *server, oci_fetcher_t *f,
                                      const char *store_root)
{
    /* Server returns "hello world" but the descriptor declares a different
     * digest hex. Bytes-in matches declared size exactly, so the only
     * mismatch is at commit time.
     */
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
    mock_set_handler(server, h_blob, &ctx);

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

static void test_blob_404(mock_server_t *server, oci_fetcher_t *f,
                          const char *store_root)
{
    oci_blob_store_t *store = oci_blob_store_open(store_root);
    handler_blob_t ctx = {
        .blob_path = "/never-matches",
        .body = "x",
        .body_len = 1,
    };
    mock_set_handler(server, h_blob, &ctx);

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
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    mock_server_t server;
    if (mock_server_start(&server) != 0) {
        fprintf(stderr, "mock server start failed: %s\n", strerror(errno));
        wipe_dir(scratch);
        free(scratch);
        return 1;
    }
    char *base_url = make_base_url(server.port);
    if (!base_url) {
        fprintf(stderr, "oom on base url\n");
        mock_server_stop(&server);
        wipe_dir(scratch);
        free(scratch);
        return 1;
    }

    printf("oci_fetch (mock HTTP @ %s)\n", base_url);

    {
        oci_fetcher_options_t opts = {.base_url_override = base_url};
        oci_fetcher_t *f = oci_fetcher_new(&opts);
        if (!f) {
            fprintf(stderr, "oci_fetcher_new failed\n");
            free(base_url);
            mock_server_stop(&server);
            wipe_dir(scratch);
            free(scratch);
            return 1;
        }
        test_anonymous_manifest(&server, f);
        test_manifest_404(&server, f);

        /* bearer_ctx must outlive both bearer tests because the server thread
         * holds a pointer to it via mock_set_handler.
         */
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

    /* Each blob test gets its own store directory so dedup short-circuit and
     * abort-leaves-no-leftover assertions are independent.
     */
    {
        oci_fetcher_options_t opts = {.base_url_override = base_url};
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

    free(base_url);
    mock_server_stop(&server);

    if (getenv("OCI_FETCH_ONLINE")) {
        printf("oci_fetch (online docker.io)\n");
        test_online_dockerhub();
    }

    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
