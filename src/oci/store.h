/* Local OCI image store: blobs + tag-to-digest pinning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps the slice-2 content-addressable blob store with a tag-to-digest pin
 * table so that elfuse oci pull / inspect can reproduce a pull by name. The
 * on-disk layout under <root> is:
 *
 *   oci-layout                               OCI image-layout 1.0.0 marker
 *   blobs/<algo>/<hex>                       finalized blob (immutable)
 *   tmp/blob-<pid>-<seq>-XXXXXX              in-flight staging
 *   refs/<registry>/<repository>/<tag>       pin file (one line: "<algo>:<hex>")
 *
 * The pin file contains the manifest digest captured at pull time so a
 * subsequent pull by tag can short-circuit when the blob is already present,
 * and elfuse oci inspect can render the manifest offline. The oci-layout
 * marker advertises the store as a standards-compliant image layout so that
 * external tools (skopeo, umoci) can consume the directory as oci:<root>.
 *
 * Phase 1 keeps <root> as a plain directory. The sparse case-sensitive APFS
 * volume bootstrap (oci-roadmap Q1) is a Phase 2 concern; the volume mount
 * point will sit at the same default path so this API does not change.
 */

#pragma once

#include "blob-store.h"
#include "ref.h"

typedef struct oci_store oci_store_t;

/* Open or create the store rooted at `root`. Ensures blobs/<algo>/, tmp/,
 * refs/, and the OCI image-layout 1.0.0 marker exist. Marker writes are
 * idempotent: a pre-existing oci-layout file is never rewritten so a third
 * party that bumped the imageLayoutVersion is preserved. Returns NULL on
 * failure with errno preserved.
 */
oci_store_t *oci_store_open(const char *root);

/* Close the store handle. Does not delete on-disk state. Safe on NULL. */
void oci_store_close(oci_store_t *s);

/* Return the store root path. The returned pointer is owned by the store and
 * is valid until oci_store_close.
 */
const char *oci_store_root(const oci_store_t *s);

/* Return the underlying blob store handle. The returned pointer is owned by
 * the store; do not close it directly.
 */
oci_blob_store_t *oci_store_blobs(oci_store_t *s);

/* Return the default store root for the current user. macOS XDG-ish:
 *   $XDG_DATA_HOME/elfuse/store           when XDG_DATA_HOME is set
 *   $HOME/Library/Application Support/elfuse/store   otherwise
 * Returns a heap-allocated string the caller must free, or NULL on env miss
 * (errno=ENOENT) or oom (errno=ENOMEM).
 */
char *oci_store_default_root(void);

/* Write a tag-to-digest pin for ref. ref->tag must be set; refs without a tag
 * are self-pinning by their digest field and putting a pin for them is an
 * EINVAL. digest_str is the canonical "<algo>:<hex>" form of the manifest
 * digest captured at pull time. Atomically replaces any existing pin via
 * write-to-temp + rename. Creates the refs/<registry>/<repository>/ prefix
 * directories on demand.
 *
 * Returns 0 on success, -1 with errno preserved and *err_msg (when non-NULL)
 * pointing at a static description on failure.
 */
int oci_store_put_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      const char *digest_str,
                      const char **err_msg);

/* Read the pinned manifest digest for ref. ref->tag must be set; digest-only
 * refs are self-pinning and trigger EINVAL. On hit returns 0 and writes a
 * heap-allocated "<algo>:<hex>" string into *out_digest (caller frees). On
 * miss returns -1 with errno=ENOENT and *out_digest=NULL. Other IO errors
 * return -1 with errno preserved. *err_msg (when non-NULL) is populated on
 * any non-success path.
 */
int oci_store_get_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      char **out_digest,
                      const char **err_msg);
