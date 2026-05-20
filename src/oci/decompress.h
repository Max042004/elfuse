/* OCI layer-blob decompression dispatch
 *
 * Wraps zlib (gzip), libzstd (vendored decode-only), and a passthrough
 * stream behind one read-only oci_stream_t. The tar reader is
 * compression-agnostic; oci/decompress.c is the only translation unit
 * in the project that includes externals/zstd/lib/zstd.h, so any
 * future swap-out of the compression backend is local to this module.
 *
 * The zstd backend caps the decoder window log at 27 (128 MiB) so a
 * hostile or unintentionally fat layer cannot exhaust host memory.
 * Real-world OCI registry layers stay well below this; the regression
 * test pins the boundary at 28-bit windows rejecting with EINVAL.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "oci/media-type.h"

typedef struct oci_stream oci_stream_t;

/* Open a decompression stream over fd. The caller retains fd ownership;
 * oci_stream_close does NOT close it. On error returns NULL and sets
 * *err to a static description string plus errno.
 *
 * For OCI_COMPRESSION_NONE this is a thin passthrough wrapper; for GZIP
 * the implementation uses zlib's inflate (auto-detecting raw vs gzip
 * via inflateInit2 with windowBits=47); for ZSTD it uses libzstd's
 * streaming ZSTD_DCtx capped to a 128 MiB decoder window.
 */
oci_stream_t *oci_decompress_open(int fd,
                                  oci_compression_t alg,
                                  const char **err);

/* Read up to cap bytes. Returns:
 *    >0  bytes copied into buf (may be a short read; caller loops)
 *     0  end of compressed stream (clean)
 *    -1  decompression or I/O error; errno set, callers may surface
 *        EIO with the decoder error string
 */
ssize_t oci_stream_read(oci_stream_t *s, void *buf, size_t cap);

/* Release decoder state. Does NOT close the underlying fd. Safe on NULL. */
void oci_stream_close(oci_stream_t *s);

/* For diagnostics only: last static error string the decoder produced.
 * Returns NULL if the stream has not failed. The string is owned by
 * the stream and remains valid until oci_stream_close.
 */
const char *oci_stream_last_error(const oci_stream_t *s);
