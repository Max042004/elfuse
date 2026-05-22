/* OCI registry HTTPS client
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps libcurl for the subset of the OCI distribution-spec that elfuse needs
 * to pull an image:
 *
 *   - Anonymous GET against /v2/<repo>/manifests/<ref> and /v2/<repo>/blobs/<digest>
 *   - 401 + Www-Authenticate: Bearer challenge: fetch a token from the realm
 *     advertised by the registry, then retry the original request with
 *     Authorization: Bearer <token>
 *   - Blob streaming: pipe the response body into the slice-2 blob store with
 *     digest and declared-size verification, so a hostile or truncated layer
 *     never produces a visible-complete blob
 *
 * Future slices extend the options struct with basic auth credentials,
 * custom CA bundle, and a loopback-gated TLS verify-off path
 * (oci-roadmap.md Q7 ship list). The public entry points stay stable.
 *
 * Thread safety: oci_fetch_global_init must run once before any fetcher is
 * created. Each oci_fetcher_t holds its own libcurl easy handle and is not
 * safe to share across threads; create one per worker.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "blob-store.h"
#include "manifest.h"
#include "ref.h"

typedef struct {
    /* Optional override of the registry base URL. When non-NULL, the fetcher
     * uses this prefix for every /v2/... request instead of computing one
     * from ref->registry. Test scaffolding sets this to a local mock
     * (https://127.0.0.1:<port>); production callers leave it NULL.
     */
    const char *base_url_override;

    /* HTTP Basic authentication. When username is non-NULL, libcurl produces
     * Authorization: Basic <b64(user:pass)> on every request the fetcher
     * issues, including the token endpoint when the registry also requires a
     * Bearer flow. password may be NULL for an empty secret.
     */
    const char *username;
    const char *password;

    /* Path to a PEM-encoded CA bundle. When non-NULL the fetcher passes it to
     * libcurl as CURLOPT_CAINFO, replacing the system trust store for that
     * connection. Effective only with an OpenSSL-style SSL backend (the
     * default macOS Secure Transport backend ignores CAINFO).
     */
    const char *ca_file;

    /* Disable TLS verification. Honored only when the resolved registry host
     * is on the loopback whitelist (127.0.0.1, localhost, ::1). Any other
     * host with allow_insecure=true causes oci_fetch_manifest /
     * oci_fetch_blob to fail with errno=EPERM before a single byte is sent.
     */
    bool allow_insecure;
} oci_fetcher_options_t;

typedef struct oci_fetcher oci_fetcher_t;

/* Per-process libcurl global init. Safe to call multiple times; only the
 * first call performs work. Returns 0 on success or -1 with errno=EIO if
 * libcurl rejects the initialization.
 */
int oci_fetch_global_init(void);

/* Counterpart of oci_fetch_global_init. The caller may invoke it on shutdown
 * but elfuse runs short enough that leaving libcurl initialized until process
 * exit is acceptable.
 */
void oci_fetch_global_cleanup(void);

/* Allocate a fetcher. opts may be NULL for defaults. Returns NULL on
 * allocation failure with errno preserved.
 */
oci_fetcher_t *oci_fetcher_new(const oci_fetcher_options_t *opts);

/* Release the fetcher. Safe on NULL. */
void oci_fetcher_free(oci_fetcher_t *f);

typedef struct {
    /* Heap-allocated response body. NUL-terminated so callers can pass it
     * directly to JSON parsers that expect a C string, while body_len is the
     * authoritative byte count.
     */
    char *body;
    size_t body_len;
    /* Content-Type header value with parameters stripped (everything before
     * the first ';'). NULL if the server omitted the header.
     */
    char *content_type;
    /* Docker-Content-Digest header value verbatim, e.g. "sha256:abc...".
     * NULL if the server omitted it. Useful for tag-to-digest pinning.
     */
    char *docker_content_digest;
    /* ETag header verbatim, including any surrounding quotes or weak prefix
     * (e.g. "sha256:abc..." or W/"..."). NULL if the server omitted it.
     * Captured so conditional-GET callers can echo it back without parsing.
     */
    char *etag;
    long http_status;
} oci_fetch_response_t;

/* Release any heap fields. Safe on a zero-initialised struct. */
void oci_fetch_response_free(oci_fetch_response_t *r);

/* Fetch a manifest, image index, or image config blob by reference.
 *
 *   ref            registry/repository, plus optional default tag/digest
 *   digest_or_tag  the actual GET selector ("sha256:..." or a tag string).
 *                  NULL means: use ref->digest if set, otherwise ref->tag.
 *   accept_types   NULL-terminated list of media types to advertise in the
 *                  Accept header. Pass NULL to suppress the Accept header.
 *   if_none_match  optional If-None-Match value sent verbatim. Pass the
 *                  registry-style strong quoted form ("sha256:...") to ask
 *                  the registry for 304 Not Modified when the upstream
 *                  manifest still hashes to the pinned digest. NULL skips
 *                  the conditional header entirely.
 *
 * On success returns 0 and fills *out (caller frees via
 * oci_fetch_response_free). A 304 response is success: out->http_status is
 * 304, out->body is NULL, out->body_len is 0, and out->etag may still be
 * populated. On HTTP error (other non-2xx) returns -1 with out->http_status
 * populated and errno=EPROTO; the body may still be present for
 * diagnostics. On transport / auth failure returns -1 with errno preserved
 * and *err_msg (when non-NULL) pointing at a static description.
 */
int oci_fetch_manifest(oci_fetcher_t *f,
                       const oci_ref_t *ref,
                       const char *digest_or_tag,
                       const char *const *accept_types,
                       const char *if_none_match,
                       oci_fetch_response_t *out,
                       const char **err_msg);

/* Fetch a blob into the local store. The descriptor's algo, hex, and size
 * fields drive verification: incoming bytes feed an oci_blob_writer keyed by
 * the digest, the running byte count is capped at desc->size so a hostile
 * server cannot stream forever, and the writer's own digest check at commit
 * rejects any payload that hashes to anything other than desc->hex.
 *
 * Returns 0 on success, -1 with errno set on failure. err_msg points at a
 * static description for the common diagnostic modes (digest mismatch,
 * size mismatch, transport error, HTTP status).
 *
 * Already-present blobs are an immediate success (store-side has() check)
 * with no network call.
 */
int oci_fetch_blob(oci_fetcher_t *f,
                   const oci_ref_t *ref,
                   const oci_descriptor_t *desc,
                   oci_blob_store_t *store,
                   const char **err_msg);
