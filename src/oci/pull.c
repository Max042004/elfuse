/* elfuse oci pull pipeline
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The pull function is intentionally linear: every state transition (top-level
 * fetch, index recurse, config fetch, layer fetch, pin write) flows top-to-
 * bottom in oci_pull below. Helpers exist only to remove pure boilerplate
 * (response cleanup, hex equality, progress prints), so that a reader of
 * oci_pull can follow the registry round trips without chasing through
 * indirection.
 */

#include "pull.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blob-store.h"
#include "digest.h"
#include "manifest.h"
#include "media-type.h"

static const char *const PULL_ACCEPT[] = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    NULL,
};

static FILE *pick_progress(const oci_pull_options_t *opts)
{
    if (!opts)
        return stderr;
    if (opts->quiet)
        return NULL;
    return opts->progress ? opts->progress : stderr;
}

static void progress_line(FILE *fp, const char *kind, const char *digest_str,
                          int64_t size, const char *state,
                          const char *media_type)
{
    if (!fp)
        return;
    /* Truncated digest keeps the line readable; full hex still goes into the
     * pin file and the blob store for verification.
     */
    char short_digest[24];
    snprintf(short_digest, sizeof(short_digest), "%.19s...", digest_str);
    fprintf(fp, "  %-9s %-22s %12lldB  %-11s %s\n", kind, short_digest,
            (long long) size, state ? state : "",
            media_type ? media_type : "");
    fflush(fp);
}

/* Case-insensitive prefix check for "sha256:" / "sha512:". */
static bool digest_str_matches(const char *want, const char *got)
{
    if (!want || !got)
        return false;
    return strcasecmp(want, got) == 0;
}

/* Cross-check the manifest body against the registry-supplied
 * Docker-Content-Digest header. Servers usually emit one; when they do not,
 * trust the body's local SHA-256. The local hex is what we use to address the
 * blob in the store regardless, so a missing header degrades to local-only
 * verification but not to silent corruption.
 */
static int verify_manifest_digest(const oci_fetch_response_t *resp,
                                  const char *expected_digest_str,
                                  char *out_digest_str, size_t out_cap,
                                  const char **err_msg)
{
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digest_bytes(OCI_DIGEST_SHA256, resp->body, resp->body_len, hex) ==
        0) {
        if (err_msg)
            *err_msg = "failed to hash manifest body";
        errno = EIO;
        return -1;
    }
    int n = snprintf(out_digest_str, out_cap, "sha256:%s", hex);
    if (n < 0 || (size_t) n >= out_cap) {
        if (err_msg)
            *err_msg = "manifest digest buffer too small";
        errno = ENAMETOOLONG;
        return -1;
    }
    if (resp->docker_content_digest &&
        !digest_str_matches(resp->docker_content_digest, out_digest_str)) {
        if (err_msg)
            *err_msg = "manifest body digest does not match "
                       "Docker-Content-Digest header";
        errno = EPROTO;
        return -1;
    }
    if (expected_digest_str &&
        !digest_str_matches(expected_digest_str, out_digest_str)) {
        if (err_msg)
            *err_msg = "manifest body digest does not match expected digest";
        errno = EPROTO;
        return -1;
    }
    return 0;
}

/* Fetch a manifest document (image index, image manifest, or sub-manifest) by
 * selector, hash its body, cross-check against expected_digest_str (when
 * non-NULL), and write it into the local blob store. Returns 0 on success and
 * fills *out_digest_str with the canonical "sha256:<hex>" representation. The
 * caller frees *out_response via oci_fetch_response_free.
 *
 * if_none_match is forwarded as the conditional GET header; when set and the
 * registry responds 304 Not Modified the helper returns 0, writes nothing to
 * the store, leaves *out_digest_str empty, and sets *out_unchanged (when
 * non-NULL). The caller seeds the digest string from the pin before calling.
 */
static int fetch_and_persist_manifest(oci_fetcher_t *f,
                                      oci_store_t *store,
                                      const oci_ref_t *ref,
                                      const char *selector,
                                      const char *expected_digest_str,
                                      const char *if_none_match,
                                      oci_fetch_response_t *out_resp,
                                      char *out_digest_str, size_t out_cap,
                                      bool *out_unchanged,
                                      const char **err_msg)
{
    if (out_unchanged)
        *out_unchanged = false;
    memset(out_resp, 0, sizeof(*out_resp));
    if (oci_fetch_manifest(f, ref, selector, PULL_ACCEPT, if_none_match,
                           out_resp, err_msg) < 0) {
        return -1;
    }
    if (out_resp->http_status == 304) {
        if (out_unchanged)
            *out_unchanged = true;
        return 0;
    }
    if (out_resp->body_len == 0 || !out_resp->body) {
        if (err_msg)
            *err_msg = "manifest response had an empty body";
        errno = EPROTO;
        return -1;
    }
    if (verify_manifest_digest(out_resp, expected_digest_str, out_digest_str,
                               out_cap, err_msg) < 0) {
        return -1;
    }
    char hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digest_algo_t algo;
    if (!oci_digest_parse(out_digest_str, &algo, hex)) {
        if (err_msg)
            *err_msg = "computed manifest digest is malformed";
        errno = EINVAL;
        return -1;
    }
    if (oci_blob_store_put_bytes(oci_store_blobs(store), OCI_DIGEST_SHA256, hex,
                                 out_resp->body, out_resp->body_len) < 0) {
        if (err_msg)
            *err_msg = "failed to persist manifest body to local store";
        return -1;
    }
    return 0;
}

/* Load a manifest blob already present in the local store into a heap buffer.
 * Used by the refresh path after the registry confirms an unchanged digest:
 * the manifest body must still be parsed (to drive the layer-cache sweep)
 * but no network round trip is needed because the bytes are already on disk.
 * Returns 0 on success with *out_buf newly malloc'd (caller frees) and
 * *out_len set; -1 on IO failure with errno preserved.
 */
static int load_manifest_blob(oci_blob_store_t *blobs,
                              oci_digest_algo_t algo, const char *hex,
                              char **out_buf, size_t *out_len,
                              const char **err_msg)
{
    char path[1024];
    int n = oci_blob_store_path(blobs, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path)) {
        if (err_msg)
            *err_msg = "manifest blob path overflow";
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (err_msg)
            *err_msg = "failed to open cached manifest blob";
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int e = errno;
        close(fd);
        if (err_msg)
            *err_msg = "failed to stat cached manifest blob";
        errno = e;
        return -1;
    }
    if (st.st_size <= 0 || (uintmax_t) st.st_size > (uintmax_t) SIZE_MAX - 1) {
        close(fd);
        if (err_msg)
            *err_msg = "cached manifest blob has an unreasonable size";
        errno = EFBIG;
        return -1;
    }
    size_t want = (size_t) st.st_size;
    char *buf = malloc(want + 1);
    if (!buf) {
        close(fd);
        if (err_msg)
            *err_msg = "out of memory loading cached manifest";
        errno = ENOMEM;
        return -1;
    }
    size_t got = 0;
    while (got < want) {
        ssize_t r = read(fd, buf + got, want - got);
        if (r < 0) {
            int e = errno;
            free(buf);
            close(fd);
            if (err_msg)
                *err_msg = "read failed on cached manifest blob";
            errno = e;
            return -1;
        }
        if (r == 0)
            break;
        got += (size_t) r;
    }
    close(fd);
    if (got != want) {
        free(buf);
        if (err_msg)
            *err_msg = "cached manifest blob truncated mid-read";
        errno = EIO;
        return -1;
    }
    buf[want] = '\0';
    *out_buf = buf;
    *out_len = want;
    return 0;
}

static int parse_top_level(const oci_fetch_response_t *resp,
                           oci_media_type_t *out_mt,
                           const char **err_msg)
{
    oci_media_type_t mt = oci_media_type_parse(resp->content_type);
    if (mt == OCI_MT_UNKNOWN) {
        if (err_msg)
            *err_msg = "registry returned an unrecognized Content-Type";
        errno = EPROTO;
        return -1;
    }
    if (!oci_media_type_is_index(mt) && !oci_media_type_is_manifest(mt)) {
        if (err_msg)
            *err_msg = "registry returned a non-manifest Content-Type";
        errno = EPROTO;
        return -1;
    }
    *out_mt = mt;
    return 0;
}

int oci_pull(oci_fetcher_t *fetcher,
             oci_store_t *store,
             const oci_ref_t *ref,
             const oci_pull_options_t *opts,
             const char **err_msg)
{
    if (!fetcher || !store || !ref) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }

    FILE *progress = pick_progress(opts);
    int rc = -1;
    oci_fetch_response_t top_resp = {0};
    oci_fetch_response_t sub_resp = {0};
    oci_index_t idx_doc = {0};
    oci_manifest_t manifest = {0};
    bool have_sub = false;
    bool top_unchanged = false;
    char top_digest_str[OCI_DIGEST_HEX_MAX + 16];
    char sub_digest_str[OCI_DIGEST_HEX_MAX + 16];
    top_digest_str[0] = '\0';
    sub_digest_str[0] = '\0';
    char *cached_top_body = NULL;
    size_t cached_top_body_len = 0;
    char *pin_digest_for_refresh = NULL;
    char if_none_match_buf[OCI_DIGEST_HEX_MAX + 32];
    const char *if_none_match = NULL;

    /* 0. Refresh prologue. Only fires when --refresh is set, the ref carries
     * a tag (digest-only refs are content-addressed and cannot drift), the
     * pin exists, and the pinned manifest blob is still on disk. Otherwise
     * the call falls through to the normal pull path.
     */
    if (opts && opts->refresh && ref->tag) {
        const char *pin_err = NULL;
        if (oci_store_get_ref(store, ref, &pin_digest_for_refresh,
                              &pin_err) == 0 && pin_digest_for_refresh) {
            oci_digest_algo_t pin_algo;
            char pin_hex[OCI_DIGEST_HEX_MAX + 1];
            if (oci_digest_parse(pin_digest_for_refresh, &pin_algo, pin_hex) &&
                oci_blob_store_has(oci_store_blobs(store), pin_algo, pin_hex)) {
                snprintf(if_none_match_buf, sizeof(if_none_match_buf),
                         "\"%s\"", pin_digest_for_refresh);
                if_none_match = if_none_match_buf;
                /* Seed top_digest_str so the 304 path can echo the pin into
                 * progress and the layer-cache sweep without re-deriving it
                 * from a body that the registry just omitted.
                 */
                snprintf(top_digest_str, sizeof(top_digest_str), "%s",
                         pin_digest_for_refresh);
            }
        }
    }

    /* 1. Top-level fetch. Selector defaults to ref->digest, falling through
     * to ref->tag, inside oci_fetch_manifest. When the user pulled by digest,
     * expected_digest_str is the locked target; pulls by tag accept whatever
     * the server resolves the tag to. if_none_match is set only by the
     * refresh prologue above; a 304 response keeps the pin and re-uses the
     * cached manifest body from the local store.
     */
    if (fetch_and_persist_manifest(fetcher, store, ref, NULL, ref->digest,
                                   if_none_match, &top_resp, top_digest_str,
                                   sizeof(top_digest_str), &top_unchanged,
                                   err_msg) < 0) {
        goto out;
    }

    const char *manifest_body = NULL;
    size_t manifest_body_len = 0;
    oci_media_type_t top_mt = OCI_MT_UNKNOWN;
    const char *pin_digest_str = top_digest_str;

    if (top_unchanged) {
        /* Registry confirmed the pinned digest still matches. Load the
         * persisted manifest blob and run the rest of the pipeline against
         * it so the layer-cache sweep can re-fetch any blob the user has
         * pruned since the last pull.
         */
        oci_digest_algo_t cached_algo;
        char cached_hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(top_digest_str, &cached_algo, cached_hex)) {
            if (err_msg)
                *err_msg = "pinned manifest digest is malformed";
            errno = EINVAL;
            goto out;
        }
        if (load_manifest_blob(oci_store_blobs(store), cached_algo, cached_hex,
                               &cached_top_body, &cached_top_body_len,
                               err_msg) < 0) {
            goto out;
        }
        /* The persisted manifest blob has no Content-Type header. Try the
         * image-index media type first, fall back to image-manifest. The
         * parse step below is the actual gate; this only steers the index
         * drill decision.
         */
        oci_index_t probe = {0};
        if (oci_index_parse(cached_top_body, cached_top_body_len, &probe,
                            NULL) == 0) {
            top_mt = OCI_MT_INDEX_OCI;
            oci_index_free(&probe);
        } else {
            top_mt = OCI_MT_MANIFEST_OCI;
        }
        manifest_body = cached_top_body;
        manifest_body_len = cached_top_body_len;
        progress_line(progress, "manifest", top_digest_str,
                      (int64_t) cached_top_body_len, "unchanged",
                      oci_media_type_name(top_mt));
    } else {
        if (parse_top_level(&top_resp, &top_mt, err_msg) < 0)
            goto out;
        progress_line(progress, "manifest", top_digest_str,
                      (int64_t) top_resp.body_len, "downloaded",
                      oci_media_type_name(top_mt));
        manifest_body = top_resp.body;
        manifest_body_len = top_resp.body_len;
    }

    /* 2. If top-level was an image index, pick linux/arm64 and refetch. */
    if (oci_media_type_is_index(top_mt)) {
        if (oci_index_parse(manifest_body, manifest_body_len, &idx_doc,
                            err_msg) < 0) {
            goto out;
        }
        const oci_index_entry_t *entry = oci_index_pick_linux_arm64(&idx_doc);
        if (!entry) {
            if (err_msg)
                *err_msg = "image index has no linux/arm64 entry";
            errno = ENOENT;
            goto out;
        }
        if (progress) {
            fprintf(progress, "  picked    %-22s %12lldB  linux/arm64%s%s\n",
                    entry->desc.digest_str, (long long) entry->desc.size,
                    entry->platform.variant && *entry->platform.variant
                        ? " "
                        : "",
                    entry->platform.variant ? entry->platform.variant : "");
            fflush(progress);
        }

        /* Sub-manifest fetch never carries If-None-Match: the index drill
         * targets a specific digest, so a conditional GET there has no
         * semantic anchor (the local blob, if cached, is already the answer
         * by content-address). When the sub-manifest blob is already in the
         * store oci_fetch_manifest would still re-GET; the linear shape
         * leaves that as future work because manifests are small.
         */
        if (fetch_and_persist_manifest(fetcher, store, ref,
                                       entry->desc.digest_str,
                                       entry->desc.digest_str, NULL,
                                       &sub_resp, sub_digest_str,
                                       sizeof(sub_digest_str), NULL,
                                       err_msg) < 0) {
            goto out;
        }
        have_sub = true;
        oci_media_type_t sub_mt = OCI_MT_UNKNOWN;
        if (parse_top_level(&sub_resp, &sub_mt, err_msg) < 0)
            goto out;
        if (!oci_media_type_is_manifest(sub_mt)) {
            if (err_msg)
                *err_msg = "index entry resolved to a non-manifest document";
            errno = EPROTO;
            goto out;
        }
        progress_line(progress, "manifest", sub_digest_str,
                      (int64_t) sub_resp.body_len, "downloaded",
                      oci_media_type_name(sub_mt));

        manifest_body = sub_resp.body;
        manifest_body_len = sub_resp.body_len;
        /* pin_digest_str stays as top_digest_str: the user pulled the tag,
         * the registry resolved that tag to the index, so the pin records the
         * index digest. Future inspect re-walks index -> manifest.
         */
    }

    /* 3. Parse the manifest body. */
    if (oci_manifest_parse(manifest_body, manifest_body_len, &manifest,
                           err_msg) < 0) {
        goto out;
    }

    /* 4+5. Fetch config + every layer blob in parallel via the batch fetcher
     * (oci-improvements-plan Plan 5 C5.1). The progress lines below are
     * still per-blob and still preserve the cached/downloaded annotation,
     * so the store-has lookup is captured before the batch call hides the
     * transfer / cache decision behind the multi event loop. The batch is
     * atomic: any blob fail aborts every writer and the function bails.
     */
    {
        bool batch_ok = false;
        size_t batch_n = 1 + manifest.nlayers;
        const oci_descriptor_t **batch_descs =
            calloc(batch_n, sizeof(*batch_descs));
        bool *cached = calloc(batch_n, sizeof(*cached));
        if (!batch_descs || !cached) {
            free(batch_descs);
            free(cached);
            if (err_msg)
                *err_msg = "out of memory composing blob batch";
            errno = ENOMEM;
            goto out;
        }
        batch_descs[0] = &manifest.config;
        cached[0] = oci_blob_store_has(oci_store_blobs(store),
                                       manifest.config.algo,
                                       manifest.config.hex);
        for (size_t i = 0; i < manifest.nlayers; i++) {
            batch_descs[1 + i] = &manifest.layers[i];
            cached[1 + i] = oci_blob_store_has(oci_store_blobs(store),
                                               manifest.layers[i].algo,
                                               manifest.layers[i].hex);
        }
        if (oci_fetch_blob_batch(fetcher, ref, batch_descs, batch_n,
                                 oci_store_blobs(store), NULL, NULL,
                                 err_msg) == 0) {
            batch_ok = true;
        }
        if (batch_ok) {
            progress_line(progress, "config", manifest.config.digest_str,
                          manifest.config.size,
                          cached[0] ? "cached" : "downloaded",
                          oci_media_type_name(manifest.config.media_type));
            for (size_t i = 0; i < manifest.nlayers; i++) {
                const oci_descriptor_t *layer = &manifest.layers[i];
                progress_line(progress, "layer", layer->digest_str,
                              layer->size,
                              cached[1 + i] ? "cached" : "downloaded",
                              oci_media_type_name(layer->media_type));
            }
        }
        free(batch_descs);
        free(cached);
        if (!batch_ok)
            goto out;
    }

    /* 6. Pin tag -> top-level digest. Digest-only refs are self-pinning and
     * skip this step (oci_store_put_ref refuses them). On 304 the pin is
     * already at the right digest, so the put_ref call is skipped to avoid
     * an unnecessary tmp + rename round trip.
     */
    if (ref->tag) {
        if (!top_unchanged) {
            if (oci_store_put_ref(store, ref, pin_digest_str, err_msg) < 0)
                goto out;
        }
        if (progress) {
            fprintf(progress, "  pin       %s:%s -> %s%s\n", ref->repository,
                    ref->tag, pin_digest_str,
                    top_unchanged ? " (unchanged)" : "");
            fflush(progress);
        }
    }

    rc = 0;

out:
    /* Preserve the caller-visible errno across cleanup. free / fclose can
     * stomp on errno even when they succeed, which would defeat callers that
     * key tests off specific values (EPROTO / ENOENT / EINVAL).
     */
    {
        int saved_errno = errno;
        oci_manifest_free(&manifest);
        oci_index_free(&idx_doc);
        if (have_sub)
            oci_fetch_response_free(&sub_resp);
        oci_fetch_response_free(&top_resp);
        free(cached_top_body);
        free(pin_digest_for_refresh);
        if (rc != 0)
            errno = saved_errno;
    }
    return rc;
}
