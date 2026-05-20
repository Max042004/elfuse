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

#include "oci/ref.h"
#include "oci/store.h"

typedef struct {
    const char *volume_root; /* NULL -> default sparse APFS volume */
    bool quiet;
    bool force_relayer;
} oci_unpack_options_t;

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
