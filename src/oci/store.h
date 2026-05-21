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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "blob-store.h"
#include "digest-set.h"
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

/* Mark phase of the Plan 1 garbage collector: enumerate every blob
 * digest still reachable from on-disk state and accumulate them in
 * *out. Two sources are walked:
 *
 *   1. Pins in index.json. For each pin's manifest digest, the
 *      manifest blob is read and parsed; the config descriptor and
 *      every layer descriptor are added to the set. If the pinned
 *      blob is an OCI image-index instead of an image manifest, every
 *      sub-manifest descriptor digest is added, and for each
 *      sub-manifest whose blob is on disk the walk recurses into its
 *      config + layers. Sub-manifests not on disk (the multi-arch
 *      case where only one platform was fetched) are still added to
 *      the keep set so a sweep does not delete a sub-manifest blob
 *      that did materialise locally.
 *
 *   2. Unpacked image trees under <volume_root>/images/sha256-<hex>/.
 *      Each tree's .elfuse-origin.json is parsed; its manifest_digest
 *      drives the same manifest/config/layer expansion as a pin.
 *
 * Failure policy is fail-fast on anything that would let prune later
 * delete a reachable blob: a missing manifest blob, an unparseable
 * manifest, a missing or malformed .elfuse-origin.json, or a missing
 * image-config blob all return -1 with *err populated so the operator
 * can repair the store before retrying. A missing
 * <volume_root>/images/ tree is treated as the fresh-store case
 * (count == 0 contribution from that source) and not an error.
 *
 * volume_root may be NULL, in which case the unpacked-tree walk is
 * skipped entirely. The pin walk runs unconditionally.
 *
 * Returns 0 on success; on failure returns -1 with errno preserved
 * and *err (when non-NULL) pointing at a static description. On
 * failure *out is left in a freed-empty state.
 */
int oci_store_collect_roots(oci_store_t *s,
                            oci_digest_set_t *out,
                            const char *volume_root,
                            const char **err);

/* Options + stats for oci_store_prune. Output fields are filled
 * regardless of dry-run vs commit so callers can render a uniform
 * report from the same struct.
 */
typedef struct {
    /* Inputs */
    bool commit;             /* false (default) = dry-run; true = unlink */
    const char *volume_root; /* NULL = pin-only walk (see collect_roots) */

    /* Outputs */
    size_t kept_blobs;
    size_t pruned_blobs;
    uint64_t pruned_bytes;
} oci_store_prune_options_t;

/* Garbage-collect dangling blobs from <root>/blobs/<algo>/. The mark
 * phase calls oci_store_collect_roots(s, &set, opts->volume_root, ...)
 * so the keep semantics match exactly: pinned manifests plus the
 * config + layer blobs they reference, image-index sub-manifests,
 * and every blob reachable from an unpacked sysroot's
 * .elfuse-origin.json. The sweep phase walks blobs/sha256/ and
 * blobs/sha512/, comparing each <algo>:<hex> against the keep set;
 * any blob whose digest is not reachable is counted as
 * pruned_blobs and (when opts->commit is true) unlinked.
 *
 * The whole operation runs under flock(<root>/index.json.lock,
 * LOCK_EX), which is the same write lock oci_store_put_ref holds.
 * That bounds the race where a concurrent pull writes a new pin
 * after collect_roots already snapshotted index.json: the pull
 * cannot acquire the lock until prune releases it, so a pinned
 * manifest is either visible to mark or its put_ref has not started
 * yet (and the corresponding blob commit either has not happened or
 * is treated as a transient resource the caller will re-fetch).
 *
 * On entry opts->kept_blobs / pruned_blobs / pruned_bytes are reset
 * to zero so the caller does not have to memset between invocations.
 * Subdirectories under blobs/<algo>/ and files whose names are not
 * valid lowercase hex for that algorithm are skipped without
 * surfacing as errors (the directory is part of the OCI image-layout
 * spec only for regular blob files; anything else is treated as
 * foreign state we must not touch).
 *
 * Returns 0 on success and -1 on failure with errno preserved and
 * *err (when non-NULL) populated. Mark-phase failure is fatal and
 * aborts before any unlink so a corrupt or torn manifest cannot
 * cause prune to delete reachable blobs.
 */
int oci_store_prune(oci_store_t *s,
                    oci_store_prune_options_t *opts,
                    const char **err);
