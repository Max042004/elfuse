/* elfuse oci pull pipeline
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Glues the slice 4a/4b fetcher and the slice 3 manifest parser to the
 * slice 5a local store. One call to oci_pull resolves an image reference into
 * a fully populated blob graph on disk:
 *
 *   1. Fetch the top-level descriptor by ref->digest or ref->tag.
 *   2. Cross-check the response Docker-Content-Digest against a local SHA-256
 *      of the body; a mismatch is a hostile-registry signal and aborts.
 *   3. If the response is an image index, parse it, pick the linux/arm64
 *      sub-manifest (oci-roadmap Q3), and re-fetch by that digest.
 *   4. Parse the manifest, fetch the config blob, fetch each layer blob.
 *   5. Write the tag-to-manifest-digest pin so the next pull or inspect for
 *      the same tag is reproducible.
 *
 * The function is best-effort idempotent: a re-pull of the same reference
 * short-circuits all already-present blobs through the slice 4a oci_fetch_blob
 * cache check, only the top-level manifest is re-fetched (small bytes; future
 * slice can add a manifest cache).
 *
 * Foreign / nondistributable layers and schema v1 manifests are rejected by
 * the parsers in slice 3; oci_pull surfaces the diagnostic and aborts before
 * any partial layer hits the store.
 */

#pragma once

#include <stdio.h>

#include "fetch.h"
#include "ref.h"
#include "store.h"

typedef struct {
    /* Per-blob progress is written here as one line per descriptor. Set to
     * NULL to suppress all output. Defaults to stderr when opts is NULL or
     * progress is NULL but suppress_progress is not requested explicitly.
     */
    FILE *progress;
    /* When true, suppress progress output even if progress is NULL (the
     * NULL/default interpretation lands on stderr). Used by elfuse oci
     * pull -q.
     */
    bool quiet;
    /* Opt-in tag revalidation. When the pinned manifest digest and its blob
     * are both already in the store, the top-level manifest GET carries
     * If-None-Match: "<pinned-digest>"; on 304 Not Modified the pull
     * short-circuits without re-fetching layer blobs and leaves the pin in
     * place. Without this flag the default pull re-runs every step (never
     * trusts the pin), which keeps stale-tag detection responsive but pays
     * the network cost.
     *
     * The flag is a no-op for digest-only refs (no tag to revalidate
     * against), and silently falls through to a normal pull when no pin
     * exists yet or the pinned manifest blob has been pruned from the
     * store. Servers may ignore If-None-Match and respond 200 with a new
     * digest; the pull then runs the full pipeline against the new
     * manifest. The previous manifest blob stays in the store until prune
     * collects it.
     */
    bool refresh;
} oci_pull_options_t;

/* Run the pull pipeline. Returns 0 on success, -1 on failure with errno
 * preserved and *err_msg (when non-NULL) pointing at a static description.
 * The store and fetcher must outlive the call; both are reused across phases.
 */
int oci_pull(oci_fetcher_t *fetcher,
             oci_store_t *store,
             const oci_ref_t *ref,
             const oci_pull_options_t *opts,
             const char **err_msg);
