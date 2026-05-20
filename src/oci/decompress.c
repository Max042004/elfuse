/* OCI decompression dispatch (gzip + zstd + passthrough)
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

/* Opt into the libzstd static-only interface to access ZSTD_ErrorCode
 * and the named constants (ZSTD_error_frameParameter_windowTooLarge in
 * particular). The decoder still goes through the public symbols; only
 * the error classification consults the static-only enum.
 */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <zstd_errors.h>

#include "oci/decompress.h"

/* 128 MiB; rejects pathological zstd headers without hurting real layers. */
#define OCI_ZSTD_MAX_WINDOW_LOG 27

/* Decoder-side input buffer. Sized to one host page so libcurl-style
 * pipelines do not pay extra syscalls per read.
 */
#define OCI_DECOMPRESS_IBUF 65536

typedef enum {
    OCI_STREAM_NONE,
    OCI_STREAM_GZIP,
    OCI_STREAM_ZSTD,
} oci_stream_kind_t;

struct oci_stream {
    oci_stream_kind_t kind;
    int fd;
    bool eof;
    const char *last_err;

    /* zlib backend */
    z_stream zs;
    bool zs_inited;

    /* zstd backend */
    ZSTD_DCtx *zd;

    /* Shared input buffer; both backends pull from it. The position
     * advances as the decoder consumes input, and refill_input pulls
     * from fd when it is exhausted.
     */
    uint8_t *ibuf;
    size_t ibuf_len;
    size_t ibuf_pos;
};

static ssize_t read_some(int fd, void *buf, size_t cap)
{
    while (1) {
        ssize_t n = read(fd, buf, cap);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

static int refill_input(oci_stream_t *s)
{
    if (s->ibuf_pos < s->ibuf_len)
        return 0;
    ssize_t n = read_some(s->fd, s->ibuf, OCI_DECOMPRESS_IBUF);
    if (n < 0) {
        s->last_err = "decompress: input read failed";
        return -1;
    }
    s->ibuf_pos = 0;
    s->ibuf_len = (size_t) n;
    return 0;
}

oci_stream_t *oci_decompress_open(int fd,
                                  oci_compression_t alg,
                                  const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;

    if (fd < 0) {
        errno = EBADF;
        *err = "decompress: invalid fd";
        return NULL;
    }

    oci_stream_t *s = calloc(1, sizeof(*s));
    if (!s) {
        errno = ENOMEM;
        *err = "decompress: state allocation failed";
        return NULL;
    }
    s->fd = fd;

    s->ibuf = malloc(OCI_DECOMPRESS_IBUF);
    if (!s->ibuf) {
        free(s);
        errno = ENOMEM;
        *err = "decompress: input buffer allocation failed";
        return NULL;
    }

    switch (alg) {
    case OCI_COMPRESSION_NONE:
        s->kind = OCI_STREAM_NONE;
        return s;
    case OCI_COMPRESSION_GZIP: {
        s->kind = OCI_STREAM_GZIP;
        /* windowBits=15 + 32 enables gzip + zlib header auto-detection;
         * raw deflate without a header is NOT accepted because real OCI
         * gzip layers always carry the standard gzip wrapper.
         */
        int zrc = inflateInit2(&s->zs, 15 + 32);
        if (zrc != Z_OK) {
            free(s->ibuf);
            free(s);
            errno = EINVAL;
            *err = "decompress: zlib inflateInit2 failed";
            return NULL;
        }
        s->zs_inited = true;
        return s;
    }
    case OCI_COMPRESSION_ZSTD: {
        s->kind = OCI_STREAM_ZSTD;
        s->zd = ZSTD_createDCtx();
        if (!s->zd) {
            free(s->ibuf);
            free(s);
            errno = ENOMEM;
            *err = "decompress: ZSTD_createDCtx failed";
            return NULL;
        }
        size_t prc = ZSTD_DCtx_setParameter(s->zd, ZSTD_d_windowLogMax,
                                            OCI_ZSTD_MAX_WINDOW_LOG);
        if (ZSTD_isError(prc)) {
            ZSTD_freeDCtx(s->zd);
            free(s->ibuf);
            free(s);
            errno = EINVAL;
            *err = "decompress: ZSTD_d_windowLogMax rejected";
            return NULL;
        }
        return s;
    }
    default:
        free(s->ibuf);
        free(s);
        errno = EINVAL;
        *err = "decompress: unsupported compression";
        return NULL;
    }
}

static ssize_t read_passthrough(oci_stream_t *s, void *buf, size_t cap)
{
    if (s->ibuf_pos < s->ibuf_len) {
        size_t left = s->ibuf_len - s->ibuf_pos;
        size_t take = left < cap ? left : cap;
        memcpy(buf, s->ibuf + s->ibuf_pos, take);
        s->ibuf_pos += take;
        return (ssize_t) take;
    }
    /* The passthrough does not buffer beyond what was pre-read; once
     * exhausted, hand the caller's buf directly to read(2) so a tar
     * driver can stream large payloads without an extra copy.
     */
    return read_some(s->fd, buf, cap);
}

static ssize_t read_gzip(oci_stream_t *s, void *buf, size_t cap)
{
    if (s->eof)
        return 0;
    s->zs.next_out = buf;
    s->zs.avail_out = (uInt) (cap > UINT32_MAX ? UINT32_MAX : cap);

    while (s->zs.avail_out > 0) {
        if (s->ibuf_pos == s->ibuf_len) {
            if (refill_input(s) < 0) {
                errno = EIO;
                return -1;
            }
            if (s->ibuf_len == 0) {
                /* Source EOF before zlib reported Z_STREAM_END means
                 * the gzip frame was truncated.
                 */
                if (s->zs.avail_out == cap) {
                    s->eof = true;
                    return 0;
                }
                s->last_err = "decompress: gzip stream truncated";
                errno = EIO;
                return -1;
            }
        }
        s->zs.next_in = s->ibuf + s->ibuf_pos;
        s->zs.avail_in = (uInt) (s->ibuf_len - s->ibuf_pos);

        int zrc = inflate(&s->zs, Z_NO_FLUSH);
        size_t consumed = (s->ibuf_len - s->ibuf_pos) - s->zs.avail_in;
        s->ibuf_pos += consumed;
        if (zrc == Z_STREAM_END) {
            s->eof = true;
            break;
        }
        if (zrc == Z_OK || zrc == Z_BUF_ERROR) {
            /* Z_BUF_ERROR with no progress just means the decoder wants
             * more input next call; loop and refill.
             */
            continue;
        }
        s->last_err = s->zs.msg ? s->zs.msg : "decompress: zlib inflate failed";
        errno = EIO;
        return -1;
    }
    return (ssize_t) (cap - s->zs.avail_out);
}

static ssize_t read_zstd(oci_stream_t *s, void *buf, size_t cap)
{
    if (s->eof)
        return 0;
    ZSTD_outBuffer out = {.dst = buf, .size = cap, .pos = 0};

    while (out.pos < out.size) {
        if (s->ibuf_pos == s->ibuf_len) {
            if (refill_input(s) < 0) {
                errno = EIO;
                return -1;
            }
            if (s->ibuf_len == 0) {
                /* libzstd returns 0 from decompressStream when it
                 * finishes a frame; if the caller sees source EOF here
                 * with no output produced yet, it is a clean end.
                 */
                if (out.pos == 0) {
                    s->eof = true;
                    return 0;
                }
                s->last_err = "decompress: zstd stream truncated";
                errno = EIO;
                return -1;
            }
        }
        ZSTD_inBuffer in = {
            .src = s->ibuf + s->ibuf_pos,
            .size = s->ibuf_len - s->ibuf_pos,
            .pos = 0,
        };
        size_t rrc = ZSTD_decompressStream(s->zd, &out, &in);
        s->ibuf_pos += in.pos;
        if (ZSTD_isError(rrc)) {
            ZSTD_ErrorCode ec = ZSTD_getErrorCode(rrc);
            if (ec == ZSTD_error_frameParameter_windowTooLarge) {
                s->last_err = "decompress: zstd window exceeds cap";
                errno = EINVAL;
            } else {
                s->last_err = ZSTD_getErrorName(rrc);
                errno = EIO;
            }
            return -1;
        }
        if (rrc == 0) {
            /* Frame complete; libzstd may still accept more frames, but
             * OCI layers ship single-frame so the reader treats this as
             * EOF.
             */
            s->eof = true;
            break;
        }
    }
    return (ssize_t) out.pos;
}

ssize_t oci_stream_read(oci_stream_t *s, void *buf, size_t cap)
{
    if (!s || !buf) {
        errno = EINVAL;
        return -1;
    }
    if (cap == 0)
        return 0;
    switch (s->kind) {
    case OCI_STREAM_NONE:
        return read_passthrough(s, buf, cap);
    case OCI_STREAM_GZIP:
        return read_gzip(s, buf, cap);
    case OCI_STREAM_ZSTD:
        return read_zstd(s, buf, cap);
    }
    errno = EINVAL;
    return -1;
}

void oci_stream_close(oci_stream_t *s)
{
    if (!s)
        return;
    if (s->zs_inited)
        inflateEnd(&s->zs);
    if (s->zd)
        ZSTD_freeDCtx(s->zd);
    free(s->ibuf);
    free(s);
}

const char *oci_stream_last_error(const oci_stream_t *s)
{
    return s ? s->last_err : NULL;
}
