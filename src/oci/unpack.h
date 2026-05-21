/* OCI layer unpack orchestrator
 *
 * Drives the full Phase 2 pipeline: resolve a ref to a manifest digest
 * through oci_store, read the manifest from the blob store, walk its
 * layers, re-verify each layer blob's digest, decompress, and apply
 * via oci_layer_apply into a staging directory under the sysroot
 * volume's images/.staging/ subtree. Successful unpack commits via
 * atomic rename into images/sha256-<hex>/.
 *
 * Phase 3 will consume the resulting directory via `elfuse run IMAGE`.
 * Phase 2 stops at producing the directory; the user wires it manually
 * through `elfuse --sysroot <path>`.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>

#include "oci/blob-store.h"
#include "oci/layer-apply.h"
#include "oci/layer-meta.h"
#include "oci/manifest.h"
#include "oci/ref.h"
#include "oci/store.h"

typedef struct {
    const char *volume_root; /* NULL -> default sparse APFS volume */
    bool quiet;
    bool force_relayer;
} oci_unpack_options_t;

/* Plan 3 C3.2: per-layer snapshot cache control for oci_unpack_layer.
 *
 * When BOTH cache_store and diff_id are set the helper consults / populates
 * <root>/layers/<algo>/<hex>/ in cache_store. NULL on either field bypasses
 * the cache and produces the C3.1 behaviour (always extract, no snapshot).
 *
 * Cache semantics are cumulative: a snapshot captures stage_dir state right
 * after this layer's tar payload was applied (i.e. it includes the prior
 * layers' contributions assembled into stage_dir). A second unpack of the
 * same image stack therefore short-circuits the per-layer extract by
 * clonefile-restoring the cached snapshot directly over stage_dir. Cross-
 * image dedup (different prefix, shared upstream diff_id) is NOT correct
 * under this scheme; C3.3 introduces raw-tar staging plus clonefile-stack
 * assembly to address that case. C3.2 lands the layout and the same-image
 * fast path the C3.3 rewrite will build on.
 *
 * The cache and stage_dir must live on the same APFS volume; the helper
 * propagates EXDEV from clonefile(2) as a hard failure rather than silently
 * falling back to a recursive copy. The user-visible mitigation is to keep
 * --store and --volume on the same filesystem (the default layout already
 * does so).
 */
typedef struct {
    oci_store_t *cache_store; /* NULL -> disable cache */
    const char *diff_id;      /* canonical "<algo>:<hex>"; NULL -> disable */
} oci_unpack_layer_options_t;

/* Apply one OCI layer's tar payload into stage_dir.
 *
 * Re-verifies the compressed blob digest against desc, opens the blob
 * via the running blob store, decompresses per desc->media_type, then
 * drives oci_layer_apply against stage_dir. stage_dir must already
 * exist and be writable; the helper does not mkdir it.
 *
 * Whiteout and opaque tar entries are processed by oci_layer_apply
 * with current semantics: ".wh.<name>" deletes upper-layer state in
 * stage_dir; ".wh..wh..opq" clears the containing directory.
 * Plan 3 C3.3 will introduce a raw-tar extraction mode for the
 * per-layer cache layout; this C3.1 helper preserves the layer-apply
 * contract used by oci_unpack so the multi-layer assembly produces
 * a byte-for-byte identical result to the legacy code path.
 *
 * When opts->cache_store and opts->diff_id are both set the helper short-
 * circuits on a cache hit (rm stage_dir, clonefile(layers/<algo>/<hex>/,
 * stage_dir)) instead of the reverify + decompress + apply sequence; the
 * compressed-blob digest is NOT re-verified on hit because the cache entry
 * was integrity-checked when it was populated. On a cache miss the helper
 * runs the normal extract, then snapshots stage_dir into the layer cache
 * via clonefile(stage_dir, layers/.staging/<algo>-<hex>-<rand>/) +
 * oci_store_layer_commit. The cache content is cumulative-through-this-
 * layer; cross-image dedup is C3.3's concern.
 *
 * Parameters:
 *   bs         - blob store backing the layer payload.
 *   desc       - layer descriptor; algo / hex / media_type / size used.
 *   stage_dir  - destination directory, absolute path, no trailing '/'.
 *   opts       - optional cache control; NULL or both fields NULL = no cache.
 *   stats      - optional; per-layer counters are summed when non-NULL.
 *                On a cache hit stats are left unchanged (the snapshot does
 *                not expose per-entry tar counters).
 *   meta       - optional; tar uid/gid/mode entries recorded when non-NULL.
 *                On a cache hit meta is left unchanged for the same reason.
 *   log_label  - optional; when non-NULL the helper prints "<label>: <digest>"
 *                (and a "+files=... dirs=..." stats line on a cache miss, or
 *                a "(cached)" marker on a cache hit) to stderr so multi-layer
 *                driver loops do not re-implement the format.
 *   err        - on failure receives a static diagnostic string.
 *
 * Returns 0 on success, -1 with errno set on failure. Notable errno values:
 *   ENOTSUP    foreign / nondistributable layer media type
 *   EINVAL     compressed blob digest mismatch, malformed media type, or
 *              malformed cache diff_id
 *   ENOENT     blob missing from store
 *   ELOOP      tar entry escapes stage_dir via symlink
 *   ENOLINK    tar hardlink target not seen
 *   ENAMETOOLONG  assembled path overflow
 *   EXDEV      cache enabled but store and stage_dir live on different
 *              filesystems (clonefile cannot cross APFS volumes)
 */
int oci_unpack_layer(oci_blob_store_t *bs,
                     const oci_descriptor_t *desc,
                     const char *stage_dir,
                     const oci_unpack_layer_options_t *opts,
                     oci_layer_apply_stats_t *stats,
                     oci_meta_table_t *meta,
                     const char *log_label,
                     const char **err);

/* Unpack the manifest pinned by ref into the sysroot volume's images/
 * subtree. The pin must already exist (set by a prior `oci pull`).
 *
 * Returns 0 on success and writes a heap-allocated absolute path to
 * the unpacked image sysroot into *out_image_dir (caller frees). The
 * path always ends with '/' so a downstream
 *
 *   strcat(out_image_dir, "lib/...")
 *
 * composes cleanly.
 *
 * Returns -1 with errno set and *err pointing to a static description
 * on failure. Notable errno values surfaced to the CLI:
 *   ENOENT      pin missing (caller should suggest `oci pull` first)
 *   EINVAL      manifest malformed, override volume not case-sensitive,
 *               or layer digest re-verify mismatch
 *   ENOTSUP    unsupported tar entry type in a layer
 *   ELOOP       symlink escape detected during apply
 *   ENOLINK    hardlink target missing
 *   EPROTONOSUPPORT  tar PAX records encountered
 */
int oci_unpack(oci_store_t *store,
               const oci_ref_t *ref,
               const oci_unpack_options_t *opts,
               char **out_image_dir,
               const char **err);
