/* OCI unpacked-tree provenance sidecar
 *
 * Records which manifest produced an unpacked image directory so the
 * Plan 1 garbage collector can walk unpacked sysroots and recover the
 * full set of blobs (manifest, image-config, layer tars + diff-id
 * pre-images) still referenced by on-disk state. Without this file the
 * mark phase has no way to attribute an unpacked tree back to a stored
 * manifest, and a prune sweep would happily delete layer blobs that are
 * still backing a live sysroot.
 *
 * Serialization format: <root_dir>/.elfuse-origin.json with the shape
 *   { "manifest_digest": "sha256:...",
 *     "config_digest":   "sha256:...",
 *     "layer_diffids":   ["sha256:...", "sha256:..."] }
 *
 * The diff_ids come from the image-config blob's rootfs.diff_ids field,
 * not from the manifest's layer descriptors: per the OCI image spec a
 * diff_id is the digest of the uncompressed layer tar, while the
 * manifest's layer.digest references the (possibly compressed) blob on
 * disk. Recording both lets C1.2's root-set walker map each unpacked
 * tree back to every blob it depends on regardless of layer media
 * type.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/* Write <root_dir>/.elfuse-origin.json via atomic rename. manifest_digest
 * and config_digest are NUL-terminated "<algo>:<hex>" strings; diff_ids
 * is a NULL-terminated array of the same form (an empty array is
 * permitted and serializes to []). Returns 0 on success, -1 on failure
 * with errno set and *err pointing to a static diagnostic. err may be
 * NULL.
 */
int oci_origin_write(const char *root_dir,
                     const char *manifest_digest,
                     const char *config_digest,
                     char *const *diff_ids,
                     const char **err);
