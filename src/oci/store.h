/* Local OCI image store: blobs + tag-to-digest pinning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps the slice-2 content-addressable blob store with a tag-to-digest pin
 * table so that elfuse oci pull / inspect can reproduce a pull by name. The
 * on-disk layout under <root> follows the OCI image-layout spec (v1.0.0) so
 * external tools (skopeo, umoci, crane) can consume the store directly:
 *
 *   oci-layout                               OCI image-layout 1.0.0 marker
 *   index.json                               OCI image-index of all pins
 *   index.json.lock                          flock target for serializing writers
 *   blobs/<algo>/<hex>                       finalized blob (immutable)
 *   tmp/blob-<pid>-<seq>-XXXXXX              in-flight blob staging
 *
 * Each pin is one descriptor in index.json's manifests[] array. The pin name
 * (canonical "<registry>/<repository>:<tag>") is stored in the descriptor's
 * org.opencontainers.image.ref.name annotation. The descriptor's mediaType,
 * digest, and size mirror the manifest blob in blobs/<algo>/<hex>. Writers
 * serialize through flock(<root>/index.json.lock, LOCK_EX) and publish via
 * tmp + rename so a concurrent reader always observes a complete document.
 * Readers parse the snapshot lock-free: rename is atomic and cJSON consumes
 * the file in one open + read.
 *
 * Pre-C2.2 stores used a refs/<registry>/<repository>/<tag> flat-file layout
 * instead of index.json. oci_store_open auto-migrates such stores: refs/ is
 * scanned recursively, every well-formed pin file becomes a manifests[]
 * descriptor in a freshly written index.json, and refs/ is kept on disk for
 * one release so a downgrade still finds the legacy data. Pins whose
 * manifest blob is missing from blobs/ are skipped with a warning rather
 * than aborting the open. Migration is suppressed when the environment
 * variable ELFUSE_OCI_NO_MIGRATE is set to any non-empty value, which lets
 * a downgrade test or recovery workflow inspect the legacy layout.
 *
 * Phase 1 keeps <root> as a plain directory. The sparse case-sensitive APFS
 * volume bootstrap (oci-roadmap Q1) is a Phase 2 concern; the volume mount
 * point will sit at the same default path so this API does not change.
 */

#pragma once

#include <stddef.h>

#include "blob-store.h"
#include "ref.h"

typedef struct oci_store oci_store_t;

/* One pin entry produced by oci_store_list_refs. name is the canonical
 * "<registry>/<repository>:<tag>" string captured from the descriptor's
 * org.opencontainers.image.ref.name annotation; digest is the manifest
 * digest in "<algo>:<hex>" form. Both fields are heap-allocated and owned
 * by the enclosing oci_pin_list_t.
 */
typedef struct {
    char *name;
    char *digest;
} oci_pin_entry_t;

typedef struct {
    oci_pin_entry_t *items;
    size_t count;
} oci_pin_list_t;

/* Open or create the store rooted at `root`. Ensures blobs/<algo>/, tmp/,
 * and the OCI image-layout 1.0.0 marker exist. Marker writes are idempotent:
 * a pre-existing oci-layout file is never rewritten so a third party that
 * bumped the imageLayoutVersion is preserved. The index.json file is not
 * materialized until the first oci_store_put_ref so an empty store stays
 * literally empty on disk.
 *
 * If the root contains a pre-C2.2 refs/ tree but no index.json, this call
 * also rebuilds index.json from refs/ contents under flock(index.json.lock,
 * LOCK_EX) so a concurrent put_ref cannot race the migration. refs/ is
 * preserved on disk for a downgrade fallback. Set ELFUSE_OCI_NO_MIGRATE to
 * any non-empty value to skip the migration on this open. Migration failure
 * is propagated through this call (NULL return with errno preserved); per-pin
 * issues (missing blob, malformed pin file) are logged to stderr and skipped
 * without failing the open.
 *
 * Returns NULL on failure with errno preserved.
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

/* Upsert a tag-to-digest pin for ref. ref->tag must be set; digest-only refs
 * are self-pinning by their digest field and putting a pin for them is an
 * EINVAL. digest_str is the canonical "<algo>:<hex>" form of the manifest
 * digest captured at pull time; the manifest blob must already be present
 * under <root>/blobs/<algo>/<hex> so the descriptor's size and mediaType
 * can be derived from the on-disk blob (mediaType is read from the JSON
 * body and inferred from structure when absent).
 *
 * Concurrency: the write is serialized by flock(<root>/index.json.lock,
 * LOCK_EX) and published via tmp + rename so a concurrent reader never
 * observes a partial index.json. Re-pinning the same canonical name
 * replaces the existing descriptor in place rather than appending a
 * duplicate entry.
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
 *
 * The read is lock-free: tmp + rename in oci_store_put_ref makes the
 * index.json switch atomic so a single open + read snapshots a complete
 * document.
 */
int oci_store_get_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      char **out_digest,
                      const char **err_msg);

/* Enumerate every pin currently recorded in index.json. On success returns
 * 0 and populates *out with a heap-allocated array of (name, digest)
 * entries; an empty store yields count == 0 and items == NULL. The caller
 * releases the result via oci_pin_list_free. Missing index.json is treated
 * as an empty store, not as an error. Other IO or schema errors return -1
 * with errno preserved and *err_msg (when non-NULL) populated.
 *
 * The order of returned entries matches the order in index.json; callers
 * that need a stable sort must impose it themselves.
 */
int oci_store_list_refs(oci_store_t *s,
                        oci_pin_list_t *out,
                        const char **err_msg);

/* Release every name / digest string in list and zero the struct. Safe on
 * a zero-initialised list and on NULL.
 */
void oci_pin_list_free(oci_pin_list_t *list);
