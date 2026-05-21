/* OCI sidecar metadata for unpacked layers
 *
 * elfuse unpacks layers as the invoking macOS user; it cannot chown to
 * arbitrary uids/gids, and the host inode mode cannot always carry the
 * full set of permission bits Linux expects. The sidecar records the
 * authoritative uid/gid/mode per guest path so Phase 3's syscall layer
 * can present the guest with the original Linux view.
 *
 * Serialization format: <root_dir>/.elfuse-meta.json with the shape
 *   { "version": 1,
 *     "entries": [ { "p": "/path", "u": NNN, "g": NNN, "m": NNN } ] }
 * Mode bits are stored decimal (cJSON has no native octal). Setuid,
 * setgid, and sticky bits are encoded in the bottom 12 bits along with
 * the rwx triplets, per oci-roadmap.md Q3.
 *
 * xattrs are intentionally absent: Q3 commits Phase 2 to ignore-with-
 * warning on xattr entries rather than fabricate a half-supported
 * namespace mapping between Linux user/security/system xattrs and the
 * macOS extended-attribute domain.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct oci_meta_table oci_meta_table_t;

/* Allocate an empty table. Returns NULL on OOM. */
oci_meta_table_t *oci_meta_table_new(void);

/* Release the table and all owned strings. Safe on NULL. */
void oci_meta_table_free(oci_meta_table_t *t);

/* Insert or update an entry. Idempotent: re-recording the same path
 * overwrites the previous tuple. Returns 0 on success, -1 with errno
 * set on allocation failure.
 */
int oci_meta_record(oci_meta_table_t *t,
                    const char *guest_path,
                    uint64_t uid,
                    uint64_t gid,
                    uint32_t mode);

/* Remove a path from the table. No-op if the path is not recorded.
 * Whiteouts and tar-overwrites both rely on this so the persisted
 * sidecar does not accumulate stale tuples for files that no longer
 * exist in the unpacked tree.
 */
void oci_meta_remove(oci_meta_table_t *t, const char *guest_path);

/* Look up a path. Returns 0 with out-params filled, or -1 with
 * errno=ENOENT if the path was never recorded. Any out param may be
 * NULL to discard that field.
 */
int oci_meta_lookup(const oci_meta_table_t *t,
                    const char *guest_path,
                    uint64_t *out_uid,
                    uint64_t *out_gid,
                    uint32_t *out_mode);

/* Number of live entries. */
size_t oci_meta_count(const oci_meta_table_t *t);

/* Serialize the table to <root_dir>/.elfuse-meta.json via atomic
 * rename. Returns 0 on success, -1 on failure with errno and *err
 * set. Passing an empty table writes a valid file containing an empty
 * entries array.
 */
int oci_meta_write(const oci_meta_table_t *t,
                   const char *root_dir,
                   const char **err);

/* Parse <root_dir>/.elfuse-meta.json and populate a fresh table.
 * Caller takes ownership via *out (freed with oci_meta_table_free).
 * Missing file returns -1 with errno=ENOENT; malformed JSON or
 * version mismatch returns -1 with errno=EINVAL.
 */
int oci_meta_read(const char *root_dir,
                  oci_meta_table_t **out,
                  const char **err);

/* Copy every entry from src into dst via oci_meta_record. Existing dst
 * entries with the same guest path are overwritten (record's idempotent
 * upsert semantics). Used by the Plan 3 C3.2 unpack layer cache hit path
 * so a clonefile-restored layer's persisted sidecar repopulates the in-
 * memory meta table that subsequent layer applies extend. Returns 0 on
 * success or -1 with errno set (EINVAL on NULL inputs, ENOMEM on record
 * allocation failure). Partial merges may leave dst with a subset of src
 * already applied; the caller treats this as a fatal error.
 */
int oci_meta_merge(oci_meta_table_t *dst, const oci_meta_table_t *src);
