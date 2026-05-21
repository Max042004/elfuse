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
 * The Plan 3 C3.3b layer cache schema marker at <root>/layers/.schema is
 * also written or validated here. A v1 store (no marker but an existing
 * layers/sha256/ subtree from C3.2) has its layers/sha256/ children wiped
 * before the v2 marker is published; the wipe is scoped to layers/sha256/
 * only so blobs/, images/, refs/, index.json, and layers/.staging/ are
 * never touched. A marker whose schemaVersion is unknown to this build
 * (forward incompatibility, corruption, or an experimental schema) is
 * fatal and returns NULL with errno=EINVAL. ELFUSE_OCI_NO_MIGRATE gates
 * this migration too: when set and the marker is absent, the wipe and
 * the marker write are both skipped so a downgrade test can inspect any
 * v1 entries on disk.
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
 *
 * older_than_sec and keep_bytes shape which dangling blobs survive
 * the sweep. Both default to 0 with the documented meaning of "no
 * filter" so the C1.3 behaviour (every dangling blob is pruned) is
 * preserved when the caller does not opt in.
 *
 *   older_than_sec > 0 vetoes per-blob: a dangling blob whose mtime
 *   is younger than (now - older_than_sec) is reported in
 *   skipped_blobs / skipped_bytes and left on disk. This is the
 *   grace window for a half-completed pull whose blob has been
 *   committed but whose put_ref has not landed yet.
 *
 *   keep_bytes > 0 enforces a global LRU budget over the candidates
 *   that survive the older-than veto: candidates are sorted by mtime
 *   ascending and walked newest-first, the newest blobs whose
 *   cumulative size fits under keep_bytes are reclassified as
 *   skipped, the rest stay pruned. A single candidate that does not
 *   fit the budget terminates the keep walk so older candidates are
 *   always evicted first even when an older blob would fit alone.
 *
 * The two filters compose by running older-than first and keep-bytes
 * second: a transient just-pulled blob never enters the LRU budget
 * computation so the grace window holds. skipped_blobs counts the
 * union of both filter outcomes.
 */
typedef struct {
    /* Inputs */
    bool commit;             /* false (default) = dry-run; true = unlink */
    const char *volume_root; /* NULL = pin-only walk (see collect_roots) */
    uint64_t older_than_sec; /* 0 = no mtime filter */
    uint64_t keep_bytes;     /* 0 = no size budget (no filter) */

    /* Outputs */
    size_t kept_blobs;
    size_t pruned_blobs;
    uint64_t pruned_bytes;
    size_t skipped_blobs;   /* dangling but spared by older_than_sec or keep_bytes */
    uint64_t skipped_bytes; /* sum of st_size for skipped_blobs */
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
 * On entry opts->kept_blobs / pruned_blobs / pruned_bytes /
 * skipped_blobs / skipped_bytes are reset to zero so the caller does
 * not have to memset between invocations. Subdirectories under
 * blobs/<algo>/ and files whose names are not valid lowercase hex for
 * that algorithm are skipped without surfacing as errors (the
 * directory is part of the OCI image-layout spec only for regular
 * blob files; anything else is treated as foreign state we must not
 * touch).
 *
 * When opts->older_than_sec or opts->keep_bytes is set, the sweep
 * gathers dangling-blob candidates first and then applies the
 * filters (older-than veto, then keep-bytes LRU budget) before any
 * unlink. Candidates spared by either filter contribute to
 * skipped_blobs / skipped_bytes rather than pruned_blobs /
 * pruned_bytes so the caller can render a three-way kept/pruned/
 * skipped split.
 *
 * Returns 0 on success and -1 on failure with errno preserved and
 * *err (when non-NULL) populated. Mark-phase failure is fatal and
 * aborts before any unlink so a corrupt or torn manifest cannot
 * cause prune to delete reachable blobs.
 */
int oci_store_prune(oci_store_t *s,
                    oci_store_prune_options_t *opts,
                    const char **err);

/* Plan 3 C3.2: per-layer unpack snapshot cache.
 *
 * Layer caches live under <root>/layers/<algo>/<hex>/ in the same content-
 * addressed shape as <root>/blobs/<algo>/<hex>. Each cache directory holds a
 * snapshot of the unpack stage_dir state immediately after applying that
 * layer's tar payload. clonefile(2) populates and consumes the snapshots so
 * the cache and the live unpack stage must live on the same APFS volume; an
 * EXDEV during snapshot is propagated as a hard error rather than silently
 * falling back to a copy.
 *
 * Cache semantics are CUMULATIVE: the directory at layers/sha256/<hex>/
 * holds the stage_dir state assembled by the unpacker WHEN this layer was
 * applied, which means it includes every prior layer's contribution along
 * with the current layer. A second unpack of the same image short-circuits
 * the extract loop entirely. Cross-image dedup (two images sharing a base
 * layer prefix but diverging upstream) is NOT yet correct under this scheme;
 * Plan 3 C3.3 introduces raw-tar staging + clonefile-stack assembly to fix
 * the cross-image case. C3.2 lands the directory layout, the path helpers,
 * and the per-image fast path the C3.3 rewrite will build on.
 *
 * C3.2 deliberately does NOT extend oci_store_collect_roots / oci_store_prune
 * to walk layers/. The cache grows monotonically until C3.5's
 * `oci image rebuild-cache` (or C3.3's prune work) consumes it. Skipping the
 * keep-set walk now keeps this commit focused on the layout invariants.
 *
 * No refcount sidecar is written. Reachability is recomputed at GC time from
 * each manifest's image-config rootfs.diff_ids list, mirroring how blobs/
 * reachability is recomputed by oci_store_collect_roots.
 *
 * Concurrency: cache_has is a single stat(2) and is inherently racy with
 * concurrent writers, but the worst outcome is a redundant extract.
 * oci_store_layer_commit publishes via rename(2) (atomic) and treats
 * EEXIST / ENOTEMPTY at the destination as a benign loss to a racing
 * winner: the loser's staging directory is removed and 0 is returned so the
 * caller can proceed as though the entry was already on disk. No store-wide
 * lock is required.
 */

/* Probe whether <root>/layers/<algo>/<hex>/ exists. diff_id is in canonical
 * "<algo>:<hex>" form. Returns 1 (present, is a directory), 0 (absent), or
 * -1 with errno preserved on any unexpected IO error. A malformed diff_id
 * returns -1 with errno=EINVAL.
 */
int oci_store_layer_has(oci_store_t *s, const char *diff_id);

/* Compose <root>/layers/<algo>/<hex>/ for diff_id into out. Trailing slash
 * included so a downstream strcat(child) composes cleanly. Pure path
 * computation; does not stat or mkdir. Returns 0 on success, -1 with errno
 * EINVAL on malformed diff_id, ENAMETOOLONG on buffer overflow.
 */
int oci_store_layer_resolve(oci_store_t *s,
                            const char *diff_id,
                            char *out, size_t cap);

/* Compose <root>/layers/.staging/<algo>-<hex>-<rand12> for diff_id into out.
 * The path is unique per call; the directory is NOT created (clonefile(2)
 * creates it as a side effect). Returns 0 on success, -1 with errno EINVAL
 * on malformed diff_id, ENAMETOOLONG on overflow, or other errno values
 * propagated from getentropy(2).
 */
int oci_store_layer_stage_path(oci_store_t *s,
                               const char *diff_id,
                               char *out, size_t cap);

/* Atomically publish a populated staging directory as the layer cache entry
 * for diff_id via rename(stage_path, <root>/layers/<algo>/<hex>/). If the
 * destination already exists (EEXIST / ENOTEMPTY: a concurrent writer landed
 * the same entry first) the staging directory is removed and 0 is returned.
 * Any other failure returns -1 with errno preserved and *err (when non-NULL)
 * populated; the staging directory is left in place so the caller can retry
 * or inspect it.
 */
int oci_store_layer_commit(oci_store_t *s,
                           const char *stage_path,
                           const char *diff_id,
                           const char **err);
