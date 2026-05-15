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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

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
 */
static int fetch_and_persist_manifest(oci_fetcher_t *f,
                                      oci_store_t *store,
                                      const oci_ref_t *ref,
                                      const char *selector,
                                      const char *expected_digest_str,
                                      oci_fetch_response_t *out_resp,
                                      char *out_digest_str, size_t out_cap,
                                      const char **err_msg)
{
    memset(out_resp, 0, sizeof(*out_resp));
    if (oci_fetch_manifest(f, ref, selector, PULL_ACCEPT, out_resp, err_msg) <
        0) {
        return -1;
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
    char top_digest_str[OCI_DIGEST_HEX_MAX + 16];
    char sub_digest_str[OCI_DIGEST_HEX_MAX + 16];
    top_digest_str[0] = '\0';
    sub_digest_str[0] = '\0';

    /* 1. Top-level fetch. Selector defaults to ref->digest, falling through
     * to ref->tag, inside oci_fetch_manifest. When the user pulled by digest,
     * expected_digest_str is the locked target; pulls by tag accept whatever
     * the server resolves the tag to.
     */
    if (fetch_and_persist_manifest(fetcher, store, ref, NULL, ref->digest,
                                   &top_resp, top_digest_str,
                                   sizeof(top_digest_str), err_msg) < 0) {
        goto out;
    }
    oci_media_type_t top_mt = OCI_MT_UNKNOWN;
    if (parse_top_level(&top_resp, &top_mt, err_msg) < 0)
        goto out;

    progress_line(progress, "manifest", top_digest_str,
                  (int64_t) top_resp.body_len, "downloaded",
                  oci_media_type_name(top_mt));

    const char *manifest_body = top_resp.body;
    size_t manifest_body_len = top_resp.body_len;
    const char *pin_digest_str = top_digest_str;

    /* 2. If top-level was an image index, pick linux/arm64 and refetch. */
    if (oci_media_type_is_index(top_mt)) {
        if (oci_index_parse(top_resp.body, top_resp.body_len, &idx_doc,
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

        if (fetch_and_persist_manifest(fetcher, store, ref,
                                       entry->desc.digest_str,
                                       entry->desc.digest_str, &sub_resp,
                                       sub_digest_str, sizeof(sub_digest_str),
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

    /* 4. Fetch config blob. */
    bool config_cached = oci_blob_store_has(oci_store_blobs(store),
                                            manifest.config.algo,
                                            manifest.config.hex);
    if (oci_fetch_blob(fetcher, ref, &manifest.config, oci_store_blobs(store),
                       err_msg) < 0) {
        goto out;
    }
    progress_line(progress, "config", manifest.config.digest_str,
                  manifest.config.size,
                  config_cached ? "cached" : "downloaded",
                  oci_media_type_name(manifest.config.media_type));

    /* 5. Fetch each layer blob in manifest order. */
    for (size_t i = 0; i < manifest.nlayers; i++) {
        const oci_descriptor_t *layer = &manifest.layers[i];
        bool cached = oci_blob_store_has(oci_store_blobs(store), layer->algo,
                                         layer->hex);
        if (oci_fetch_blob(fetcher, ref, layer, oci_store_blobs(store),
                           err_msg) < 0) {
            goto out;
        }
        progress_line(progress, "layer", layer->digest_str, layer->size,
                      cached ? "cached" : "downloaded",
                      oci_media_type_name(layer->media_type));
    }

    /* 6. Pin tag -> top-level digest. Digest-only refs are self-pinning and
     * skip this step (oci_store_put_ref refuses them).
     */
    if (ref->tag) {
        if (oci_store_put_ref(store, ref, pin_digest_str, err_msg) < 0)
            goto out;
        if (progress) {
            fprintf(progress, "  pin       %s:%s -> %s\n", ref->repository,
                    ref->tag, pin_digest_str);
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
        if (rc != 0)
            errno = saved_errno;
    }
    return rc;
}
