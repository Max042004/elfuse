/* Content digests for OCI image blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Wraps macOS CommonCrypto SHA-256 and SHA-512 in a streaming API so the
 * blob store and registry client can hash gigabyte-class layer downloads
 * without ever buffering the full payload in memory.
 *
 * Hex output is always lowercase; the OCI image reference parser already
 * rejects uppercase digest hex (see src/oci/ref.c), so every digest hex that
 * flows between the parser, the manifest fetcher, and the local store must
 * stay in the same canonical encoding to avoid silent dedup misses.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    OCI_DIGEST_SHA256,
    OCI_DIGEST_SHA512,
} oci_digest_algo_t;

/* Hex length per algorithm, excluding the trailing NUL. */
#define OCI_DIGEST_SHA256_HEX_LEN 64
#define OCI_DIGEST_SHA512_HEX_LEN 128
#define OCI_DIGEST_HEX_MAX OCI_DIGEST_SHA512_HEX_LEN

/* Opaque streaming digest. Allocated on the heap because the underlying
 * CommonCrypto context is moderately sized (SHA-512 keeps an 80-word state)
 * and callers tend to thread a digester pointer through several modules.
 */
typedef struct oci_digester oci_digester_t;

/* Allocate a streaming digester for algo. Returns NULL on bad enum or oom. */
oci_digester_t *oci_digester_new(oci_digest_algo_t algo);

/* Release a digester. Safe on NULL. */
void oci_digester_free(oci_digester_t *d);

/* Append data. Splits large buffers into CC_LONG-sized chunks internally
 * because CommonCrypto's update takes a uint32_t length and OCI layers can
 * exceed 4 GiB.
 */
void oci_digester_update(oci_digester_t *d, const void *buf, size_t len);

/* Finalize and write the lowercase hex string to out_hex. out_hex must hold
 * at least OCI_DIGEST_HEX_MAX + 1 bytes. Returns the hex length on success
 * (without trailing NUL) or 0 if d is NULL. The digester is consumed by this
 * call: the only valid next operation is oci_digester_free.
 */
size_t oci_digester_finish_hex(oci_digester_t *d, char *out_hex);

/* Lookup the algorithm name string ("sha256" / "sha512"). Returns NULL when
 * algo is out of range. The returned pointer is to static storage.
 */
const char *oci_digest_algo_name(oci_digest_algo_t algo);

/* Expected hex length for an algorithm (without trailing NUL). Returns 0 on
 * bad enum.
 */
size_t oci_digest_hex_len(oci_digest_algo_t algo);

/* Parse an algorithm name. Returns true and writes algo on match; false on
 * unknown name.
 */
bool oci_digest_algo_from_name(const char *name, oci_digest_algo_t *algo);

/* Validate that hex is exactly oci_digest_hex_len(algo) characters and that
 * every character is a lowercase hex digit. Rejects NULL.
 */
bool oci_digest_hex_valid(oci_digest_algo_t algo, const char *hex);

/* Parse "<algo>:<hex>" into algo and a canonical lowercase hex copy. The
 * input hex must already be lowercase; mixed case is rejected to match the
 * reference parser. out_hex must hold OCI_DIGEST_HEX_MAX + 1 bytes. On
 * success returns true; otherwise returns false and out_hex is left zeroed.
 */
bool oci_digest_parse(const char *colon_form,
                      oci_digest_algo_t *out_algo,
                      char *out_hex);

/* One-shot helper: compute algo over buf/len and emit lowercase hex into
 * out_hex (which must hold OCI_DIGEST_HEX_MAX + 1 bytes). Returns the hex
 * length on success or 0 on bad enum / NULL output.
 */
size_t oci_digest_bytes(oci_digest_algo_t algo,
                        const void *buf,
                        size_t len,
                        char *out_hex);
