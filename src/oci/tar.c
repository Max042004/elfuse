/* OCI tar reader implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "oci/tar.h"

#define TAR_BLOCK_SIZE 512
#define TAR_PATH_MAX 4096
#define TAR_LINKNAME_MAX 4096
#define TAR_MAX_LONG_RECORD (TAR_PATH_MAX * 4)

/* POSIX 1003.1-1990 ustar header offsets and lengths. The reader does
 * not synthesize the struct; it indexes the raw block directly to
 * avoid any padding/alignment ambiguity.
 */
#define OFF_NAME 0
#define OFF_MODE 100
#define OFF_UID 108
#define OFF_GID 116
#define OFF_SIZE 124
#define OFF_MTIME 136
#define OFF_CHKSUM 148
#define OFF_TYPEFLAG 156
#define OFF_LINKNAME 157
#define OFF_MAGIC 257
#define OFF_VERSION 263
#define OFF_PREFIX 345

#define LEN_NAME 100
#define LEN_MODE 8
#define LEN_UID 8
#define LEN_GID 8
#define LEN_SIZE 12
#define LEN_MTIME 12
#define LEN_CHKSUM 8
#define LEN_LINKNAME 100
#define LEN_MAGIC 6
#define LEN_VERSION 2
#define LEN_PREFIX 155

struct oci_tar_reader {
    oci_tar_read_fn read_fn;
    void *ctx;

    /* Current entry buffers. path and linkname are reused across
     * entries; they grow on demand up to TAR_PATH_MAX / TAR_LINKNAME_MAX.
     */
    char *path;
    size_t path_cap;
    char *linkname;
    size_t linkname_cap;

    /* GNU long-name pending payload. When the previous block was an 'L'
     * or 'K' typeflag, the next non-extension entry consumes this
     * buffer instead of the in-header name/linkname.
     */
    char *pending_long_name;
    char *pending_long_link;

    /* Payload tracking for the current entry. bytes_remaining counts
     * unread payload bytes; padding_remaining is the trailing zero
     * padding the reader must consume before the next header.
     */
    uint64_t bytes_remaining;
    uint32_t padding_remaining;

    /* Two consecutive zero blocks terminate the archive. */
    bool saw_first_zero_block;
};

static int read_full(oci_tar_reader_t *r, void *buf, size_t want)
{
    uint8_t *p = buf;
    size_t got = 0;
    while (got < want) {
        ssize_t n = r->read_fn(r->ctx, p + got, want - got);
        if (n < 0)
            return -1;
        if (n == 0)
            return 0;
        got += (size_t) n;
    }
    return 1;
}

static int fill_block(oci_tar_reader_t *r, uint8_t *block)
{
    return read_full(r, block, TAR_BLOCK_SIZE);
}

static int discard_bytes(oci_tar_reader_t *r, uint64_t bytes)
{
    uint8_t scratch[TAR_BLOCK_SIZE];
    while (bytes > 0) {
        size_t take = bytes > TAR_BLOCK_SIZE ? TAR_BLOCK_SIZE : (size_t) bytes;
        int rc = read_full(r, scratch, take);
        if (rc <= 0)
            return -1;
        bytes -= take;
    }
    return 0;
}

static bool is_zero_block(const uint8_t *block)
{
    for (size_t i = 0; i < TAR_BLOCK_SIZE; i++)
        if (block[i] != 0)
            return false;
    return true;
}

/* Parse a NUL- or space-terminated octal field. Returns -1 on
 * unparseable input. Empty (all-zero) fields read as 0, which is the
 * tar convention for fields the writer left unset.
 */
static int parse_octal(const uint8_t *field, size_t len, uint64_t *out)
{
    /* GNU base-256 extension: high bit set in the first byte means the
     * remaining bytes are a big-endian binary integer. tar uses this
     * for sizes that overflow the 11-octal-digit ceiling (~8 GiB).
     */
    if (field[0] & 0x80) {
        uint64_t v = 0;
        for (size_t i = 1; i < len; i++) {
            if (v > (UINT64_MAX >> 8))
                return -1;
            v = (v << 8) | field[i];
        }
        /* The first byte's low 7 bits also belong to the integer. */
        v |= (uint64_t) (field[0] & 0x7f) << ((len - 1) * 8);
        *out = v;
        return 0;
    }

    uint64_t v = 0;
    size_t i = 0;
    while (i < len && (field[i] == ' ' || field[i] == '\0'))
        i++;
    if (i == len) {
        *out = 0;
        return 0;
    }
    for (; i < len; i++) {
        uint8_t c = field[i];
        if (c == ' ' || c == '\0')
            break;
        if (c < '0' || c > '7')
            return -1;
        if (v > (UINT64_MAX >> 3))
            return -1;
        v = (v << 3) | (uint64_t) (c - '0');
    }
    *out = v;
    return 0;
}

static bool verify_chksum(const uint8_t *block)
{
    /* The chksum field itself is included in the sum as 8 spaces. */
    uint64_t parsed = 0;
    if (parse_octal(block + OFF_CHKSUM, LEN_CHKSUM, &parsed) < 0)
        return false;
    uint32_t expected = (uint32_t) parsed;

    uint32_t sum_unsigned = 0;
    int32_t sum_signed = 0;
    for (size_t i = 0; i < TAR_BLOCK_SIZE; i++) {
        uint8_t b = block[i];
        if (i >= OFF_CHKSUM && i < OFF_CHKSUM + LEN_CHKSUM)
            b = ' ';
        sum_unsigned += b;
        sum_signed += (int8_t) b;
    }
    /* Historical tar implementations used signed bytes when computing
     * the checksum; accept either to interop with both.
     */
    return sum_unsigned == expected || (uint32_t) sum_signed == expected;
}

static bool is_ustar_magic(const uint8_t *block)
{
    /* POSIX "ustar\0" version "00", or GNU "ustar  \0" (space-space-NUL
     * starting at OFF_MAGIC). Both shapes are common in real images.
     */
    if (memcmp(block + OFF_MAGIC, "ustar", 5) != 0)
        return false;
    return true;
}

static int copy_field_string(const uint8_t *field,
                             size_t field_len,
                             char *out,
                             size_t out_cap)
{
    /* Tar fields are NUL-terminated only when shorter than the slot.
     * Truncation is normal: copy up to the first NUL (or field_len),
     * then NUL-terminate the destination.
     */
    size_t n = 0;
    while (n < field_len && field[n] != '\0')
        n++;
    if (n + 1 > out_cap)
        return -1;
    memcpy(out, field, n);
    out[n] = '\0';
    return 0;
}

static int build_path_from_header(const uint8_t *block,
                                  char *out,
                                  size_t out_cap)
{
    char name[LEN_NAME + 1];
    char prefix[LEN_PREFIX + 1];
    if (copy_field_string(block + OFF_NAME, LEN_NAME, name, sizeof(name)) < 0)
        return -1;
    if (copy_field_string(block + OFF_PREFIX, LEN_PREFIX, prefix,
                          sizeof(prefix)) < 0)
        return -1;
    if (prefix[0] == '\0') {
        if (strlen(name) + 1 > out_cap)
            return -1;
        memcpy(out, name, strlen(name) + 1);
        return 0;
    }
    /* ustar joins prefix + '/' + name. */
    size_t pn = strlen(prefix);
    size_t nn = strlen(name);
    if (pn + 1 + nn + 1 > out_cap)
        return -1;
    memcpy(out, prefix, pn);
    out[pn] = '/';
    memcpy(out + pn + 1, name, nn);
    out[pn + 1 + nn] = '\0';
    return 0;
}

static int ensure_capacity(char **buf, size_t *cap, size_t want)
{
    if (*cap >= want)
        return 0;
    size_t new_cap = *cap == 0 ? 256 : *cap;
    while (new_cap < want)
        new_cap *= 2;
    char *grown = realloc(*buf, new_cap);
    if (!grown)
        return -1;
    *buf = grown;
    *cap = new_cap;
    return 0;
}

static const char *strip_trailing_slash(char *s)
{
    size_t n = strlen(s);
    while (n > 1 && s[n - 1] == '/')
        s[--n] = '\0';
    return s;
}

static void apply_whiteout_flags(oci_tar_entry_t *e)
{
    e->is_whiteout = false;
    e->is_opaque_whiteout = false;
    if (!e->path)
        return;
    const char *slash = strrchr(e->path, '/');
    const char *base = slash ? slash + 1 : e->path;
    if (strcmp(base, ".wh..wh..opq") == 0)
        e->is_opaque_whiteout = true;
    else if (strncmp(base, ".wh.", 4) == 0)
        e->is_whiteout = true;
}

oci_tar_reader_t *oci_tar_reader_new(oci_tar_read_fn read_fn, void *ctx)
{
    if (!read_fn)
        return NULL;
    oci_tar_reader_t *r = calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->read_fn = read_fn;
    r->ctx = ctx;
    return r;
}

void oci_tar_reader_free(oci_tar_reader_t *r)
{
    if (!r)
        return;
    free(r->path);
    free(r->linkname);
    free(r->pending_long_name);
    free(r->pending_long_link);
    free(r);
}

/* Consume a GNU 'L' or 'K' typeflag payload into a freshly allocated
 * buffer that will be claimed by the next non-extension entry.
 */
static int consume_long_record(oci_tar_reader_t *r,
                               uint64_t size,
                               char **out,
                               const char **err)
{
    if (size == 0 || size > TAR_MAX_LONG_RECORD) {
        *err = "tar GNU long-name record out of bounds";
        errno = ENAMETOOLONG;
        return -1;
    }
    char *buf = malloc((size_t) size + 1);
    if (!buf) {
        *err = "tar long-name buffer allocation failed";
        errno = ENOMEM;
        return -1;
    }
    int rc = read_full(r, buf, (size_t) size);
    if (rc <= 0) {
        free(buf);
        *err = "tar GNU long-name record truncated";
        errno = EIO;
        return -1;
    }
    /* Padding alignment is computed against the on-wire record length,
     * NOT the C-string length after stripping trailing NULs. Doing the
     * trim before discard_bytes would drift the source position by the
     * trim count and misalign the next header read.
     */
    uint64_t pad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    if (pad > 0 && discard_bytes(r, pad) < 0) {
        free(buf);
        *err = "tar GNU long-name padding truncated";
        errno = EIO;
        return -1;
    }
    /* GNU records are NUL-terminated on the wire, but defensively
     * ensure the caller-visible string has a terminator regardless of
     * the in-record byte layout.
     */
    buf[size] = '\0';
    free(*out);
    *out = buf;
    return 0;
}

/* Consume an 'x' (per-file) or 'g' (global) PAX extended-header
 * payload. Per POSIX.1-2001 the payload is a stream of records of
 * the form "<len> <key>=<value>\n" where <len> is the total byte
 * count of the record including its own length digits and trailing
 * newline. The unpack pipeline cares only about long names: `path`
 * overrides the next entry's name and `linkpath` overrides its
 * linkname. Both are promoted into the same pending buffers the GNU
 * 'L'/'K' path uses so downstream code stays unaware of the format.
 *
 * Global ('g') records establish defaults for all subsequent
 * entries; container builders almost never set path / linkpath
 * defaults globally (the use case is local mtime / atime / uid
 * defaults), so the implementation discards the payload bytes-
 * correctly without parsing. Other PAX keys (size, mtime, atime,
 * uid, gid, xattrs) are not tracked by the unpack pipeline and are
 * silently ignored from per-file records as well.
 */
static int consume_pax_record(oci_tar_reader_t *r,
                              uint64_t size,
                              int is_global,
                              const char **err)
{
    if (size > TAR_MAX_LONG_RECORD) {
        *err = "tar PAX record out of bounds";
        errno = ENAMETOOLONG;
        return -1;
    }
    char *buf = NULL;
    if (size > 0) {
        buf = malloc((size_t) size + 1);
        if (!buf) {
            *err = "tar PAX buffer allocation failed";
            errno = ENOMEM;
            return -1;
        }
        int rc = read_full(r, buf, (size_t) size);
        if (rc <= 0) {
            free(buf);
            *err = "tar PAX record truncated";
            errno = EIO;
            return -1;
        }
        buf[size] = '\0';
    }
    /* Padding alignment is computed against the on-wire record length,
     * matching consume_long_record so the next header read stays
     * aligned even when size is not a multiple of TAR_BLOCK_SIZE.
     */
    uint64_t pad = (TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) % TAR_BLOCK_SIZE;
    if (pad > 0 && discard_bytes(r, pad) < 0) {
        free(buf);
        *err = "tar PAX padding truncated";
        errno = EIO;
        return -1;
    }

    if (is_global || size == 0) {
        free(buf);
        return 0;
    }

    char *p = buf;
    char *end = buf + size;
    while (p < end) {
        char *space = memchr(p, ' ', (size_t) (end - p));
        if (!space) {
            free(buf);
            *err = "tar PAX record missing length terminator";
            errno = EINVAL;
            return -1;
        }
        char *endp = NULL;
        long len = strtol(p, &endp, 10);
        if (endp != space || len <= 0) {
            free(buf);
            *err = "tar PAX record length unparseable";
            errno = EINVAL;
            return -1;
        }
        char *record_end = p + len;
        if (record_end > end || record_end[-1] != '\n') {
            free(buf);
            *err = "tar PAX record framing invalid";
            errno = EINVAL;
            return -1;
        }
        char *kvp = space + 1;
        char *eq = memchr(kvp, '=', (size_t) (record_end - 1 - kvp));
        if (eq) {
            size_t key_len = (size_t) (eq - kvp);
            const char *val = eq + 1;
            size_t val_len = (size_t) (record_end - 1 - val);
            char **slot = NULL;
            if (key_len == 4 && memcmp(kvp, "path", 4) == 0)
                slot = &r->pending_long_name;
            else if (key_len == 8 && memcmp(kvp, "linkpath", 8) == 0)
                slot = &r->pending_long_link;
            if (slot) {
                char *copy = malloc(val_len + 1);
                if (!copy) {
                    free(buf);
                    *err = "tar PAX value allocation failed";
                    errno = ENOMEM;
                    return -1;
                }
                memcpy(copy, val, val_len);
                copy[val_len] = '\0';
                free(*slot);
                *slot = copy;
            }
        }
        p = record_end;
    }
    free(buf);
    return 0;
}

static int classify_typeflag(uint8_t flag, oci_tar_type_t *out)
{
    switch (flag) {
    case '\0':
    case '0':
    case '7': /* contiguous file: treat as regular */
        *out = OCI_TAR_REG;
        return 0;
    case '1':
        *out = OCI_TAR_HARDLINK;
        return 0;
    case '2':
        *out = OCI_TAR_SYMLINK;
        return 0;
    case '3':
    case '4':
    case '6':
        *out = OCI_TAR_UNSUPPORTED; /* char/block/fifo */
        return 0;
    case '5':
        *out = OCI_TAR_DIR;
        return 0;
    case 'L':
    case 'K':
        return 1; /* GNU long-name extension; caller handles payload */
    case 'x':
    case 'g':
        return 2; /* PAX extended; caller rejects */
    default:
        return -1; /* unknown */
    }
}

int oci_tar_next(oci_tar_reader_t *r, oci_tar_entry_t *out, const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;

    if (!r || !out) {
        *err = "tar next called with NULL argument";
        errno = EINVAL;
        return -1;
    }

    /* Any unconsumed payload from a prior entry must be drained before
     * the next header is read; the contract is that callers either
     * read fully or skip explicitly, but defensively flush here too.
     */
    if (r->bytes_remaining > 0 || r->padding_remaining > 0) {
        if (oci_tar_skip_payload(r, err) < 0)
            return -1;
    }

    for (;;) {
        uint8_t block[TAR_BLOCK_SIZE];
        int rc = fill_block(r, block);
        if (rc < 0) {
            *err = "tar header read failed";
            errno = EIO;
            return -1;
        }
        if (rc == 0) {
            /* Stream ended cleanly mid-archive. Treat as EOF; the
             * archive may have omitted the final zero blocks, which
             * happens with hand-rolled tarballs.
             */
            return 0;
        }

        if (is_zero_block(block)) {
            if (r->saw_first_zero_block)
                return 0;
            r->saw_first_zero_block = true;
            continue;
        }
        r->saw_first_zero_block = false;

        if (!verify_chksum(block)) {
            *err = "tar header checksum mismatch";
            errno = EINVAL;
            return -1;
        }
        if (!is_ustar_magic(block)) {
            *err = "tar header missing ustar magic";
            errno = EINVAL;
            return -1;
        }

        uint8_t typeflag = block[OFF_TYPEFLAG];
        oci_tar_type_t type;
        int klass = classify_typeflag(typeflag, &type);
        if (klass < 0) {
            *err = "tar header carries unknown typeflag";
            errno = EINVAL;
            return -1;
        }

        uint64_t size = 0;
        if (parse_octal(block + OFF_SIZE, LEN_SIZE, &size) < 0) {
            *err = "tar header size field unparseable";
            errno = EINVAL;
            return -1;
        }

        if (klass == 1) {
            /* GNU long-name / long-link extension entry. The payload
             * carries the path or linkname for the NEXT real entry.
             */
            char **slot =
                typeflag == 'L' ? &r->pending_long_name : &r->pending_long_link;
            if (consume_long_record(r, size, slot, err) < 0)
                return -1;
            continue;
        }
        if (klass == 2) {
            if (consume_pax_record(r, size, typeflag == 'g', err) < 0)
                return -1;
            continue;
        }

        /* Real entry. Materialize path and linkname into reader-owned
         * buffers so the caller can read entry.path stably until the
         * next oci_tar_next call.
         */
        if (r->pending_long_name) {
            size_t want = strlen(r->pending_long_name) + 1;
            if (ensure_capacity(&r->path, &r->path_cap, want) < 0) {
                *err = "tar path buffer allocation failed";
                errno = ENOMEM;
                return -1;
            }
            memcpy(r->path, r->pending_long_name, want);
            free(r->pending_long_name);
            r->pending_long_name = NULL;
        } else {
            if (ensure_capacity(&r->path, &r->path_cap, TAR_PATH_MAX) < 0) {
                *err = "tar path buffer allocation failed";
                errno = ENOMEM;
                return -1;
            }
            if (build_path_from_header(block, r->path, r->path_cap) < 0) {
                *err = "tar header path overflow";
                errno = ENAMETOOLONG;
                return -1;
            }
        }
        if (r->pending_long_link) {
            size_t want = strlen(r->pending_long_link) + 1;
            if (ensure_capacity(&r->linkname, &r->linkname_cap, want) < 0) {
                *err = "tar linkname buffer allocation failed";
                errno = ENOMEM;
                return -1;
            }
            memcpy(r->linkname, r->pending_long_link, want);
            free(r->pending_long_link);
            r->pending_long_link = NULL;
        } else {
            if (ensure_capacity(&r->linkname, &r->linkname_cap,
                                LEN_LINKNAME + 1) < 0) {
                *err = "tar linkname buffer allocation failed";
                errno = ENOMEM;
                return -1;
            }
            if (copy_field_string(block + OFF_LINKNAME, LEN_LINKNAME,
                                  r->linkname, r->linkname_cap) < 0) {
                *err = "tar linkname overflow";
                errno = ENAMETOOLONG;
                return -1;
            }
        }

        /* Dirs may carry a trailing slash in name; normalize it away so
         * downstream matchers do not have to special-case both forms.
         */
        if (type == OCI_TAR_DIR)
            strip_trailing_slash(r->path);

        /* DIR entries should have size 0 in practice, but tolerate
         * archives that record an unused size. The payload contract
         * is "advertise size bytes; the reader consumes them".
         */
        out->path = r->path;
        out->linkname = (type == OCI_TAR_SYMLINK || type == OCI_TAR_HARDLINK)
                            ? r->linkname
                            : NULL;
        out->type = type;

        uint64_t mode = 0;
        uint64_t uid = 0;
        uint64_t gid = 0;
        uint64_t mtime = 0;
        if (parse_octal(block + OFF_MODE, LEN_MODE, &mode) < 0 ||
            parse_octal(block + OFF_UID, LEN_UID, &uid) < 0 ||
            parse_octal(block + OFF_GID, LEN_GID, &gid) < 0 ||
            parse_octal(block + OFF_MTIME, LEN_MTIME, &mtime) < 0) {
            *err = "tar header numeric field unparseable";
            errno = EINVAL;
            return -1;
        }
        out->mode = (uint32_t) (mode & 07777);
        out->uid = uid;
        out->gid = gid;
        out->mtime = mtime;
        out->size = type == OCI_TAR_REG ? size : 0;

        apply_whiteout_flags(out);

        /* Stage payload tracking. Even non-regular entries may have a
         * recorded size that the writer expects the reader to skip
         * (rare, but real). The reader honors whatever size field the
         * header advertises so the stream stays aligned.
         */
        r->bytes_remaining = size;
        r->padding_remaining =
            size > 0 ? (uint32_t) ((TAR_BLOCK_SIZE - (size % TAR_BLOCK_SIZE)) %
                                   TAR_BLOCK_SIZE)
                     : 0;

        return 1;
    }
}

int oci_tar_read_payload(oci_tar_reader_t *r,
                         void *buf,
                         size_t cap,
                         size_t *got,
                         const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (got)
        *got = 0;
    if (!r || !buf || !got) {
        *err = "tar read called with NULL argument";
        errno = EINVAL;
        return -1;
    }

    if (r->bytes_remaining == 0) {
        /* Drain any tail padding so the next oci_tar_next aligns. */
        if (r->padding_remaining > 0) {
            if (discard_bytes(r, r->padding_remaining) < 0) {
                *err = "tar padding read failed";
                errno = EIO;
                return -1;
            }
            r->padding_remaining = 0;
        }
        return 0;
    }

    size_t want = cap > r->bytes_remaining ? (size_t) r->bytes_remaining : cap;
    int rc = read_full(r, buf, want);
    if (rc <= 0) {
        *err = "tar payload truncated";
        errno = EIO;
        return -1;
    }
    r->bytes_remaining -= want;
    *got = want;
    return 0;
}

int oci_tar_skip_payload(oci_tar_reader_t *r, const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!r) {
        *err = "tar skip called with NULL reader";
        errno = EINVAL;
        return -1;
    }
    uint64_t drop = r->bytes_remaining + r->padding_remaining;
    r->bytes_remaining = 0;
    r->padding_remaining = 0;
    if (drop == 0)
        return 0;
    if (discard_bytes(r, drop) < 0) {
        *err = "tar skip read failed";
        errno = EIO;
        return -1;
    }
    return 0;
}
