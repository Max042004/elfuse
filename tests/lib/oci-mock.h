/* Shared TLS-terminated HTTP mock server for OCI test suites
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps a pthread-driven socket listener plus an OpenSSL session terminator on
 * 127.0.0.1:<ephemeral>. Each accepted connection is handed to a user-supplied
 * handler that reads the parsed mock_request_t and writes a canned response
 * via mock_send_full. A fresh self-signed RSA certificate is generated at
 * mock_server_start time so callers can feed it to the fetcher as opts.ca_file
 * and exercise a real TLS handshake.
 *
 * The mock predates this header (the original lived inline in
 * tests/test-oci-fetch.c). It moved out so both the fetch and the pull suites
 * can share the same scaffolding without duplicating ~400 LOC of OpenSSL +
 * socket plumbing. Test-specific request handlers and assertion helpers stay
 * in their respective .c files.
 *
 * Threading model: each mock_server_t owns one accept thread plus one short
 * worker per accepted connection. Handlers run on the accept thread sequence;
 * mock_set_handler is safe to call between requests. mock_request_count
 * reports the cumulative count since the last mock_set_handler.
 */

#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <openssl/ssl.h>

/* IO abstraction: every handler reads and writes through an io_t so the
 * underlying transport (an SSL session here) is swappable.
 */
typedef struct {
    SSL *ssl;
} oci_mock_io_t;

typedef struct {
    char method[8];
    char path[1024];
    char authorization[1024];
    char accept[1024];
} oci_mock_request_t;

#define OCI_MOCK_LOG_MAX 16

typedef struct oci_mock_server oci_mock_server_t;

typedef void (*oci_mock_handler_t)(oci_mock_server_t *s, oci_mock_io_t *io,
                                   const oci_mock_request_t *req);

struct oci_mock_server {
    int listen_fd;
    int port;
    pthread_t thread;
    pthread_mutex_t lock;
    bool stop;
    int n_requests;
    oci_mock_request_t log[OCI_MOCK_LOG_MAX];
    oci_mock_handler_t handler;
    void *ctx;
    SSL_CTX *ssl_ctx;
    char ca_pem_path[256];
};

/* Start the mock server. scratch_root is a writable directory used as the
 * destination for the generated self-signed certificate PEM (path captured in
 * s->ca_pem_path). Returns 0 on success and -1 on socket / TLS / pthread
 * failure with errno preserved.
 */
int oci_mock_server_start(oci_mock_server_t *s, const char *scratch_root);

/* Stop the server. Joins the accept thread, frees the SSL_CTX, and closes the
 * listening socket. Safe to call once on a successfully started server.
 */
void oci_mock_server_stop(oci_mock_server_t *s);

/* Install a request handler and reset the request log. The handler runs once
 * per accepted connection inside the server's accept thread.
 */
void oci_mock_set_handler(oci_mock_server_t *s, oci_mock_handler_t h,
                          void *ctx);

/* Returns the number of requests captured in the log since the last
 * mock_set_handler. The handler may receive more than OCI_MOCK_LOG_MAX
 * requests but the count is clamped to the log capacity.
 */
int oci_mock_request_count(oci_mock_server_t *s);

/* Per-connection ctx accessor used by handlers. Equivalent to s->ctx but
 * documents the intent in handler bodies.
 */
void *oci_mock_handler_ctx(oci_mock_server_t *s);

/* Read from / write to the TLS session. Handlers normally use mock_send_full
 * for canned responses; raw io_read / io_write exists for custom flows.
 */
ssize_t oci_mock_io_read(oci_mock_io_t *io, void *buf, size_t cap);
void    oci_mock_io_write(oci_mock_io_t *io, const void *buf, size_t n);

/* Compose and send a complete HTTP/1.1 response. status_text defaults to "OK"
 * when NULL. content_type / www_authenticate / docker_digest are added to the
 * header block only when non-NULL. body may be NULL when body_len is 0.
 */
void oci_mock_send_full(oci_mock_io_t *io, int status, const char *status_text,
                        const char *content_type,
                        const char *www_authenticate,
                        const char *docker_digest,
                        const void *body,
                        size_t body_len);

/* Recursively wipe a directory tree (depth-first remove). Convenience for
 * tests that mkdtemp a scratch root and clean it up on exit.
 */
void oci_mock_wipe_dir(const char *root);

/* mkdtemp helper: create a directory under /tmp matching the given template
 * suffix and return a heap-allocated path. Returns NULL on failure with errno
 * preserved.
 */
char *oci_mock_make_scratch_root(const char *prefix);

/* Build "https://127.0.0.1:<port>" into a heap-allocated string for the
 * fetcher's base_url_override option. Returns NULL on oom.
 */
char *oci_mock_make_base_url(int port);
