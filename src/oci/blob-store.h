/* Content-addressable blob store for OCI image data
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Layout matches the OCI image-layout convention:
 *
 *   <root>/blobs/<algo>/<hex>     finalized blob, immutable
 *   <root>/tmp/blob-<pid>-<seq>   in-flight staging file
 *
 * Every blob is committed by writing the staging file, fsync'ing it, hashing
 * the bytes as they stream through the writer, comparing the actual hex to
 * the expected hex from the manifest descriptor, and then atomically renaming
 * the staging file into its final blobs/<algo>/<hex> slot. A digest mismatch
 * unlinks the staging file before returning -1, so an interrupted or hostile
 * pull leaves no visible-complete blob behind. Repeated commits of the same
 * digest are dedup'd in place (final path already exists -> drop staging,
 * report success).
 *
 * The store path is opaque to this module; the caller picks it. Phase 1
 * targets ~/Library/Application Support/elfuse/blobs/ on macOS; a later
 * slice moves the root onto a case-sensitive APFS sparse volume (oci-roadmap
 * Q1) but the store API does not change.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "digest.h"

typedef struct oci_blob_store oci_blob_store_t;
typedef struct oci_blob_writer oci_blob_writer_t;

/* Open or create the store rooted at `root`. The directory tree (root,
 * blobs/<algo>, tmp) is created with mode 0755 if missing. Returns NULL on
 * failure with errno preserved.
 */
oci_blob_store_t *oci_blob_store_open(const char *root);

/* Release the store handle. Does not delete on-disk state. Safe on NULL. */
void oci_blob_store_close(oci_blob_store_t *s);

/* Resolve the final on-disk path for algo:hex. Returns the number of bytes
 * the full path occupies excluding the trailing NUL, or -1 if algo or hex
 * is malformed. Always writes a NUL terminator when out_size > 0; if the
 * full path does not fit, out is truncated but still NUL-terminated and the
 * caller can detect overflow by comparing the return value to out_size.
 */
int oci_blob_store_path(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex,
                        char *out,
                        size_t out_size);

/* True when blobs/<algo>/<hex> exists as a regular file. */
bool oci_blob_store_has(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex);

/* Begin a streaming write keyed by the descriptor digest. The writer hashes
 * payload bytes as they stream and verifies the result against expected_hex
 * during commit. Returns NULL on failure with errno preserved. expected_hex
 * must be lowercase and the correct length for algo.
 */
oci_blob_writer_t *oci_blob_writer_begin(oci_blob_store_t *s,
                                         oci_digest_algo_t algo,
                                         const char *expected_hex);

/* Append data to the staging file and the running digest. Returns true on
 * success or false on a short write / I/O error with errno preserved. On
 * failure the writer is left in a state where the only valid next call is
 * oci_blob_writer_abort.
 */
bool oci_blob_writer_write(oci_blob_writer_t *w, const void *buf, size_t len);

/* Finalize the digest, fsync, verify against expected_hex, then atomically
 * rename into place. On success returns 0 and releases the writer. On digest
 * mismatch returns -1 with errno set to EINVAL. On I/O failure returns -1
 * with errno preserved. The staging file is always unlinked on failure so
 * an aborted pull never leaves a visible-complete blob.
 */
int oci_blob_writer_commit(oci_blob_writer_t *w);

/* Discard the staging file and release the writer. Always succeeds; safe on
 * NULL.
 */
void oci_blob_writer_abort(oci_blob_writer_t *w);

/* One-shot helper: write a memory buffer into the store. Returns 0 on
 * success or -1 on failure (errno preserved); semantics match the streaming
 * commit path including dedup and atomic rename.
 */
int oci_blob_store_put_bytes(oci_blob_store_t *s,
                             oci_digest_algo_t algo,
                             const char *expected_hex,
                             const void *buf,
                             size_t len);
