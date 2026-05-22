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
#include <stdint.h>

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

/* Same contract as oci_blob_writer_begin but stages into
 * tmp/blob-<hex prefix 16>-XXXXXX. The digest prefix in the filename lets
 * parallel batch callers find their in-flight partials by digest (used by
 * the curl_multi pull path's resume + sweep, plan-doc Plan 5). Both writer
 * entry points produce final blobs at the same blobs/<algo>/<hex> path and
 * are otherwise interchangeable; pickers can choose based on whether they
 * need digest-keyed staging.
 */
oci_blob_writer_t *oci_blob_writer_begin_named(oci_blob_store_t *s,
                                               oci_digest_algo_t algo,
                                               const char *expected_hex);

/* Open a writer that resumes from an existing tmp/blob-<hex prefix 16>-*
 * partial when one is present. Scans tmp/ for files whose name starts with
 * the digest prefix; selects the largest matching file; reopens it O_RDWR,
 * re-hashes the bytes that are already on disk into the digester, and
 * positions the fd at end-of-file so the next write appends. The selected
 * partial keeps its name; siblings with the same prefix are unlinked.
 *
 * Falls back to oci_blob_writer_begin_named (fresh mkstemp staging file,
 * offset 0) when any of these holds:
 *   - tmp/ has no matching partial
 *   - partial size >= expected_size (corrupt or stale; would defeat the
 *     descriptor size cap during the resumed transfer)
 *   - partial size is zero
 *   - reopen / re-hash fails for any reason
 *
 * On success returns a writer and, when out_resume_offset is non-NULL,
 * writes the partial byte count there (0 on the fallback paths). Returns
 * NULL only on the hard-error conditions that oci_blob_writer_begin_named
 * also returns NULL for (EINVAL on bad arguments, ENOMEM on calloc, etc.).
 *
 * expected_size must be the descriptor's declared blob size in bytes. The
 * store does not know what the caller will subsequently issue as a Range
 * request; the parameter is here so the store can pre-reject partials that
 * are at or past the declared size (which would tip the streaming overflow
 * gate downstream into a "blob exceeded declared size" failure rather than
 * a clean restart).
 */
oci_blob_writer_t *oci_blob_writer_resume_named(oci_blob_store_t *s,
                                                oci_digest_algo_t algo,
                                                const char *expected_hex,
                                                int64_t expected_size,
                                                int64_t *out_resume_offset);

/* Delete tmp/ partials whose mtime is older than ttl_secs seconds ago.
 * Matches any file in tmp/ whose name starts with "blob-"; non-matching
 * names and subdirectories are skipped. Errors during the scan are
 * silent: a missing tmp/ directory, a permission denial, or a per-file
 * unlink failure leaves the rest of the sweep running.
 *
 * The store retains exclusive ownership of tmp/, so an aggressive prefix
 * filter would not catch any third-party content. ttl_secs is the caller's
 * choice; the fetcher invokes this once per batch with seven days.
 */
void oci_blob_store_sweep_partials(oci_blob_store_t *s, long ttl_secs);

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
