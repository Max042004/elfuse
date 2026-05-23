/* OCI tar reader unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Builds tar streams in memory and feeds them
 * through oci_tar_reader_t via a callback that yields the bytes one
 * configurable chunk at a time, so the reader's short-read handling and
 * 512-byte block alignment are both exercised. The tests deliberately
 * avoid spawning external tar; the unit must accept the same byte
 * layout that real OCI registries serve regardless of which tool wrote
 * the layer.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oci/tar.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *fmt, ...)
{
    total++;
    char detail[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(detail, sizeof(detail), fmt, ap);
    va_end(ap);
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail);
}

/* --- in-memory tar builder ------------------------------------------ */

#define BLOCK 512

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} bb_t;

static void bb_init(bb_t *b)
{
    b->buf = NULL;
    b->len = 0;
    b->cap = 0;
}

static void bb_free(bb_t *b)
{
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

static void bb_grow(bb_t *b, size_t want)
{
    if (b->cap >= want)
        return;
    size_t nc = b->cap == 0 ? 1024 : b->cap;
    while (nc < want)
        nc *= 2;
    b->buf = realloc(b->buf, nc);
    if (!b->buf) {
        fprintf(stderr, "OOM in tar test builder\n");
        exit(2);
    }
    b->cap = nc;
}

static void bb_append(bb_t *b, const void *src, size_t n)
{
    bb_grow(b, b->len + n);
    memcpy(b->buf + b->len, src, n);
    b->len += n;
}

static void bb_zero(bb_t *b, size_t n)
{
    bb_grow(b, b->len + n);
    memset(b->buf + b->len, 0, n);
    b->len += n;
}

static void write_octal(uint8_t *field, size_t len, uint64_t value)
{
    /* tar octal fields end with NUL or space; convention is NUL-terminated
     * for the numeric portion plus padding zeros. The build helper writes
     * a leading-zero-padded octal then NUL terminator.
     */
    memset(field, '0', len);
    field[len - 1] = '\0';
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llo", (unsigned long long) value);
    size_t n = strlen(tmp);
    if (n >= len)
        n = len - 1;
    memcpy(field + (len - 1 - n), tmp, n);
}

static void write_string(uint8_t *field, size_t len, const char *s)
{
    memset(field, 0, len);
    if (!s)
        return;
    size_t n = strlen(s);
    if (n > len)
        n = len;
    memcpy(field, s, n);
}

static void compute_chksum(uint8_t *block)
{
    /* The chksum field contributes as 8 spaces while being computed. */
    memset(block + 148, ' ', 8);
    uint32_t sum = 0;
    for (size_t i = 0; i < BLOCK; i++)
        sum += block[i];
    write_octal(block + 148, 7, sum);
    block[148 + 6] = '\0';
    block[148 + 7] = ' ';
}

static void append_header(bb_t *b,
                          const char *name,
                          uint64_t size,
                          uint32_t mode,
                          char typeflag,
                          const char *linkname,
                          bool use_ustar_magic,
                          bool bad_chksum)
{
    uint8_t block[BLOCK];
    memset(block, 0, BLOCK);

    /* name (offset 0, len 100). For names longer than 100 chars, the
     * test helper deliberately uses GNU long-name records via
     * append_long_record(), not the ustar prefix field.
     */
    write_string(block, 100, name);

    write_octal(block + 100, 8, mode & 07777);
    write_octal(block + 108, 8, 0); /* uid */
    write_octal(block + 116, 8, 0); /* gid */
    write_octal(block + 124, 12, size);
    write_octal(block + 136, 12, 0); /* mtime */

    block[156] = (uint8_t) typeflag;

    if (linkname)
        write_string(block + 157, 100, linkname);

    if (use_ustar_magic) {
        memcpy(block + 257, "ustar", 6);
        memcpy(block + 263, "00", 2);
    }

    compute_chksum(block);
    if (bad_chksum)
        block[148] = (block[148] == '0') ? '1' : '0';

    bb_append(b, block, BLOCK);
}

static void append_payload(bb_t *b, const void *data, size_t n)
{
    bb_append(b, data, n);
    size_t pad = (BLOCK - (n % BLOCK)) % BLOCK;
    bb_zero(b, pad);
}

static void append_long_record(bb_t *b, char typeflag, const char *payload)
{
    /* GNU 'L' or 'K' long-name extension entry. Header carries
     * size = strlen(payload)+1 (the NUL is part of the record), name is
     * literally "././@LongLink".
     */
    size_t plen = strlen(payload) + 1;
    append_header(b, "././@LongLink", plen, 0644, typeflag, NULL, true, false);
    append_payload(b, payload, plen);
}

/* --- byte source callback ------------------------------------------- */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    size_t max_chunk; /* 0 = unbounded */
    bool fail_on_next;
} src_t;

static ssize_t src_read(void *ctx, void *buf, size_t cap)
{
    src_t *s = ctx;
    if (s->fail_on_next) {
        errno = EIO;
        return -1;
    }
    size_t left = s->len - s->pos;
    if (left == 0)
        return 0;
    size_t take = left < cap ? left : cap;
    if (s->max_chunk && take > s->max_chunk)
        take = s->max_chunk;
    memcpy(buf, s->buf + s->pos, take);
    s->pos += take;
    return (ssize_t) take;
}

/* --- helpers -------------------------------------------------------- */

static void drain_payload(oci_tar_reader_t *r,
                          char *out,
                          size_t out_cap,
                          size_t *got)
{
    *got = 0;
    char chunk[256];
    for (;;) {
        size_t n = 0;
        const char *err = NULL;
        if (oci_tar_read_payload(r, chunk, sizeof(chunk), &n, &err) < 0)
            return;
        if (n == 0)
            break;
        if (*got + n + 1 > out_cap)
            return;
        memcpy(out + *got, chunk, n);
        *got += n;
    }
    out[*got] = '\0';
}

/* --- test cases ----------------------------------------------------- */

static void test_empty_archive(void)
{
    /* Two consecutive zero blocks is the canonical EOF marker. */
    bb_t b;
    bb_init(&b);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 0)
        report_fail("empty archive: clean EOF", "expected 0, got %d (err=%s)",
                    rc, err);
    else
        report_pass("empty archive: clean EOF");
    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_regular_file(size_t chunk)
{
    bb_t b;
    bb_init(&b);
    const char *payload = "hello, world\n";
    size_t plen = strlen(payload);
    append_header(&b, "etc/hostname", plen, 0644, '0', NULL, true, false);
    append_payload(&b, payload, plen);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len, .max_chunk = chunk};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    char name[64];
    snprintf(name, sizeof(name), "regular file (chunk=%zu)", chunk ? chunk : 0);
    if (rc != 1) {
        report_fail(name, "expected 1, got %d (err=%s)", rc, err);
        goto out;
    }
    if (strcmp(e.path, "etc/hostname") != 0 || e.type != OCI_TAR_REG ||
        e.size != plen || e.mode != 0644 || e.is_whiteout ||
        e.is_opaque_whiteout) {
        report_fail(name, "header field mismatch (path=%s type=%d size=%llu)",
                    e.path, (int) e.type, (unsigned long long) e.size);
        goto out;
    }
    char got[64];
    size_t n = 0;
    drain_payload(r, got, sizeof(got), &n);
    if (n != plen || memcmp(got, payload, plen) != 0) {
        report_fail(name, "payload mismatch (n=%zu)", n);
        goto out;
    }
    rc = oci_tar_next(r, &e, &err);
    if (rc != 0) {
        report_fail(name, "expected EOF, got rc=%d err=%s", rc, err);
        goto out;
    }
    report_pass(name);
out:
    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_directory_and_symlink_and_hardlink(void)
{
    bb_t b;
    bb_init(&b);
    append_header(&b, "lib/", 0, 0755, '5', NULL, true, false);
    append_header(&b, "lib/foo", 0, 0777, '2', "./bar", true, false);
    append_header(&b, "etc/hostname2", 0, 0644, '1', "etc/hostname", true,
                  false);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;

    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || e.type != OCI_TAR_DIR || strcmp(e.path, "lib") != 0)
        report_fail("dir entry", "rc=%d type=%d path=%s err=%s", rc,
                    (int) e.type, e.path ? e.path : "(null)", err);
    else
        report_pass("dir entry (trailing slash stripped)");

    rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || e.type != OCI_TAR_SYMLINK ||
        strcmp(e.path, "lib/foo") != 0 || !e.linkname ||
        strcmp(e.linkname, "./bar") != 0)
        report_fail("symlink entry", "rc=%d type=%d path=%s link=%s err=%s", rc,
                    (int) e.type, e.path, e.linkname ? e.linkname : "(nil)",
                    err);
    else
        report_pass("symlink entry");

    rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || e.type != OCI_TAR_HARDLINK || !e.linkname ||
        strcmp(e.linkname, "etc/hostname") != 0)
        report_fail("hardlink entry", "rc=%d type=%d link=%s err=%s", rc,
                    (int) e.type, e.linkname ? e.linkname : "(nil)", err);
    else
        report_pass("hardlink entry");

    rc = oci_tar_next(r, &e, &err);
    if (rc != 0)
        report_fail("eof after 3 entries", "rc=%d err=%s", rc, err);
    else
        report_pass("eof after 3 entries");

    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_gnu_long_name(void)
{
    bb_t b;
    bb_init(&b);
    /* 250 chars: well beyond the 100-char in-header name slot. */
    char long_path[300];
    for (size_t i = 0; i < 250; i++)
        long_path[i] = (char) ('a' + (i % 26));
    long_path[250] = '\0';

    append_long_record(&b, 'L', long_path);
    append_header(&b, "placeholder", 0, 0644, '0', NULL, true, false);
    /* No payload (size=0). */
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1) {
        report_fail("gnu long name", "rc=%d err=%s", rc, err);
    } else if (strcmp(e.path, long_path) != 0) {
        report_fail("gnu long name", "path mismatch: got len=%zu",
                    strlen(e.path));
    } else if (e.type != OCI_TAR_REG) {
        report_fail("gnu long name", "type=%d", (int) e.type);
    } else {
        report_pass("gnu long name");
    }

    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_pax_extended_path(void)
{
    bb_t b;
    bb_init(&b);
    /* PAX 'x' extended header carries a per-file path override that
     * applies to the next non-extension entry. The record format is
     * "<len> key=value\n" where <len> covers the entire on-wire
     * record bytes. The reader must consume the record, latch
     * path / linkpath into the same pending buffers the GNU long-
     * name path uses, and surface the long name through entry.path.
     */
    const char *record = "21 path=etc/hostname\n";
    size_t rlen = 21;
    append_header(&b, "PaxHeaders/etc/hostname", (uint32_t) rlen, 0644, 'x',
                  NULL, true, false);
    append_payload(&b, record, rlen);
    /* Follow with the actual file entry. The ustar name is a stub the
     * PAX path record overrides.
     */
    append_header(&b, "stub", 0, 0644, '0', NULL, true, false);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1)
        report_fail("pax extended path", "expected rc=1, got %d (%s)", rc,
                    err ? err : "(null)");
    else if (e.type != OCI_TAR_REG)
        report_fail("pax extended path", "type=%d (want REG)", (int) e.type);
    else if (strcmp(e.path, "etc/hostname") != 0)
        report_fail("pax extended path", "path=\"%s\" (want etc/hostname)",
                    e.path ? e.path : "(null)");
    else
        report_pass("pax extended path latched onto next entry");

    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_pax_global_skipped(void)
{
    bb_t b;
    bb_init(&b);
    /* PAX 'g' global record sets defaults for all subsequent entries.
     * The unpack pipeline does not consume any global key today, so
     * the reader silently discards the payload bytes-correctly and
     * surfaces the next real entry with its own ustar fields.
     */
    const char *gdata = "23 comment=elfuse-test\n";
    size_t glen = 23;
    append_header(&b, "PaxGlobalHeader", (uint32_t) glen, 0644, 'g', NULL, true,
                  false);
    append_payload(&b, gdata, glen);
    append_header(&b, "etc/host.conf", 0, 0644, '0', NULL, true, false);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1)
        report_fail("pax global skipped", "expected rc=1, got %d (%s)", rc,
                    err ? err : "(null)");
    else if (strcmp(e.path, "etc/host.conf") != 0)
        report_fail("pax global skipped", "path=\"%s\" (want etc/host.conf)",
                    e.path ? e.path : "(null)");
    else
        report_pass("pax global record silently skipped");

    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_unsupported_typeflags(void)
{
    /* Char ('3'), block ('4'), and fifo ('6') all collapse to UNSUPPORTED
     * so the applier emits one refusal message; the reader does not
     * gate the dispatcher.
     */
    const char *types_label[] = {"char dev", "block dev", "fifo"};
    const char types[] = {'3', '4', '6'};
    for (size_t i = 0; i < 3; i++) {
        bb_t b;
        bb_init(&b);
        append_header(&b, "dev/foo", 0, 0644, types[i], NULL, true, false);
        bb_zero(&b, BLOCK * 2);
        src_t s = {.buf = b.buf, .len = b.len};
        oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
        oci_tar_entry_t e;
        const char *err = NULL;
        int rc = oci_tar_next(r, &e, &err);
        if (rc != 1 || e.type != OCI_TAR_UNSUPPORTED)
            report_fail(types_label[i], "rc=%d type=%d", rc, (int) e.type);
        else
            report_pass(types_label[i]);
        oci_tar_reader_free(r);
        bb_free(&b);
    }
}

static void test_unknown_typeflag_rejected(void)
{
    bb_t b;
    bb_init(&b);
    append_header(&b, "weird", 0, 0644, 'Z', NULL, true, false);
    bb_zero(&b, BLOCK * 2);
    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != -1)
        report_fail("unknown typeflag rejected", "rc=%d", rc);
    else
        report_pass("unknown typeflag rejected");
    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_chksum_mismatch(void)
{
    bb_t b;
    bb_init(&b);
    append_header(&b, "etc/hostname", 0, 0644, '0', NULL, true, true);
    bb_zero(&b, BLOCK * 2);
    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);
    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != -1)
        report_fail("chksum mismatch", "rc=%d err=%s", rc, err);
    else
        report_pass("chksum mismatch");
    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_whiteout_flags(void)
{
    bb_t b;
    bb_init(&b);
    append_header(&b, "etc/.wh.removed", 0, 0644, '0', NULL, true, false);
    append_header(&b, "subdir/.wh..wh..opq", 0, 0644, '0', NULL, true, false);
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || !e.is_whiteout || e.is_opaque_whiteout)
        report_fail("whiteout flag", "rc=%d wh=%d opq=%d", rc, e.is_whiteout,
                    e.is_opaque_whiteout);
    else
        report_pass("whiteout flag");
    rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || e.is_whiteout || !e.is_opaque_whiteout)
        report_fail("opaque whiteout flag", "rc=%d wh=%d opq=%d", rc,
                    e.is_whiteout, e.is_opaque_whiteout);
    else
        report_pass("opaque whiteout flag");
    oci_tar_reader_free(r);
    bb_free(&b);
}

static void test_skip_payload(void)
{
    /* The contract says callers may skip a payload and the reader will
     * still align the next header correctly even if read_payload was
     * never called.
     */
    bb_t b;
    bb_init(&b);
    const char *p1 = "first entry contents";
    const char *p2 = "second entry contents";
    append_header(&b, "a", strlen(p1), 0644, '0', NULL, true, false);
    append_payload(&b, p1, strlen(p1));
    append_header(&b, "b", strlen(p2), 0644, '0', NULL, true, false);
    append_payload(&b, p2, strlen(p2));
    bb_zero(&b, BLOCK * 2);

    src_t s = {.buf = b.buf, .len = b.len};
    oci_tar_reader_t *r = oci_tar_reader_new(src_read, &s);

    oci_tar_entry_t e;
    const char *err = NULL;
    int rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || strcmp(e.path, "a") != 0) {
        report_fail("skip first payload", "rc=%d path=%s", rc,
                    e.path ? e.path : "");
        goto out;
    }
    if (oci_tar_skip_payload(r, &err) < 0) {
        report_fail("skip first payload", "skip failed: %s", err);
        goto out;
    }
    rc = oci_tar_next(r, &e, &err);
    if (rc != 1 || strcmp(e.path, "b") != 0) {
        report_fail("second entry after skip", "rc=%d path=%s err=%s", rc,
                    e.path ? e.path : "", err);
        goto out;
    }
    /* Implicit drain via next call: do not skip, do not read. */
    rc = oci_tar_next(r, &e, &err);
    if (rc != 0) {
        report_fail("implicit drain on next", "rc=%d err=%s", rc, err);
        goto out;
    }
    report_pass("skip and implicit drain");
out:
    oci_tar_reader_free(r);
    bb_free(&b);
}

int main(void)
{
    printf("oci_tar reader\n");

    test_empty_archive();
    test_regular_file(0);   /* unbounded read */
    test_regular_file(1);   /* one byte at a time */
    test_regular_file(5);   /* sub-block chunks */
    test_regular_file(512); /* exact block */
    test_directory_and_symlink_and_hardlink();
    test_gnu_long_name();
    test_pax_extended_path();
    test_pax_global_skipped();
    test_unsupported_typeflags();
    test_unknown_typeflag_rejected();
    test_chksum_mismatch();
    test_whiteout_flags();
    test_skip_payload();

    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
