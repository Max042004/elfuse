/* OCI decompression dispatch unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Builds tmp-file payloads (raw, gzip, zstd)
 * and feeds them through oci_stream_t. The gzip fixture is generated
 * via zlib's deflate at test time so the test stays hermetic; the zstd
 * fixtures are embedded byte arrays produced once via the system zstd
 * CLI and committed verbatim, so the unit does not depend on libzstd's
 * encoder (which is intentionally NOT vendored — externals/zstd/ ships
 * decode-only).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <zlib.h>

#include "oci/decompress.h"
#include "oci/media-type.h"

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

/* "hello, world!\n" gzip-compressed via zlib at test time. */
static const char CANON[] = "hello, world!\n";
static const size_t CANON_LEN = sizeof(CANON) - 1;

/* zstd-compressed CANON with default frame parameters and no checksum,
 * produced once with `printf 'hello, world!\n' | zstd -c --no-check`.
 * The decompressed bytes must equal CANON exactly.
 */
static const uint8_t ZSTD_FIXTURE[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x71, 0x00, 0x00, 0x68, 0x65, 0x6c,
    0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a,
};

/* Same canonical payload but encoded with --long=28, requesting a
 * 256 MiB decoder window. The OCI_ZSTD_MAX_WINDOW_LOG = 27 cap must
 * reject this with EINVAL.
 */
static const uint8_t ZSTD_FIXTURE_28BIT[] = {
    0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x90, 0x71, 0x00, 0x00, 0x68, 0x65, 0x6c,
    0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a,
};

static int write_tmp(const void *data, size_t len, char *path_out)
{
    snprintf(path_out, 64, "/tmp/elfuse-decompress-XXXXXX");
    int fd = mkstemp(path_out);
    if (fd < 0) {
        perror("mkstemp");
        return -1;
    }
    if (write(fd, data, len) != (ssize_t) len) {
        perror("write");
        close(fd);
        return -1;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        perror("lseek");
        close(fd);
        return -1;
    }
    return fd;
}

static int build_gzip_fixture(const void *data,
                              size_t len,
                              uint8_t **out_buf,
                              size_t *out_len)
{
    z_stream zs = {0};
    /* windowBits 15 + 16 = gzip wrapper. */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    uLong bound = deflateBound(&zs, (uLong) len);
    uint8_t *buf = malloc(bound);
    if (!buf) {
        deflateEnd(&zs);
        return -1;
    }
    zs.next_in = (Bytef *) data;
    zs.avail_in = (uInt) len;
    zs.next_out = buf;
    zs.avail_out = (uInt) bound;
    int rc = deflate(&zs, Z_FINISH);
    if (rc != Z_STREAM_END) {
        free(buf);
        deflateEnd(&zs);
        return -1;
    }
    *out_buf = buf;
    *out_len = bound - zs.avail_out;
    deflateEnd(&zs);
    return 0;
}

static int read_all(oci_stream_t *s, uint8_t *out, size_t cap, size_t *got)
{
    *got = 0;
    while (*got < cap) {
        ssize_t n = oci_stream_read(s, out + *got, cap - *got);
        if (n < 0)
            return -1;
        if (n == 0)
            return 0;
        *got += (size_t) n;
    }
    /* Drain to EOF in case the caller's cap matched the payload exactly. */
    uint8_t scratch[64];
    ssize_t n = oci_stream_read(s, scratch, sizeof(scratch));
    if (n < 0)
        return -1;
    if (n > 0)
        return 1; /* more data than expected */
    return 0;
}

static void test_passthrough(void)
{
    char path[64];
    int fd = write_tmp(CANON, CANON_LEN, path);
    if (fd < 0) {
        report_fail("passthrough: tmp file", "errno=%d", errno);
        return;
    }
    const char *err = NULL;
    oci_stream_t *s = oci_decompress_open(fd, OCI_COMPRESSION_NONE, &err);
    if (!s) {
        report_fail("passthrough: open", "%s", err ? err : "(null)");
        close(fd);
        unlink(path);
        return;
    }
    uint8_t buf[64];
    size_t got = 0;
    int rc = read_all(s, buf, sizeof(buf), &got);
    if (rc != 0 || got != CANON_LEN || memcmp(buf, CANON, CANON_LEN) != 0)
        report_fail("passthrough", "rc=%d got=%zu", rc, got);
    else
        report_pass("passthrough");
    oci_stream_close(s);
    close(fd);
    unlink(path);
}

static void test_gzip_roundtrip(void)
{
    uint8_t *gz = NULL;
    size_t gzlen = 0;
    if (build_gzip_fixture(CANON, CANON_LEN, &gz, &gzlen) < 0) {
        report_fail("gzip roundtrip", "build_gzip_fixture failed");
        return;
    }
    char path[64];
    int fd = write_tmp(gz, gzlen, path);
    free(gz);
    if (fd < 0) {
        report_fail("gzip roundtrip: tmp file", "errno=%d", errno);
        return;
    }
    const char *err = NULL;
    oci_stream_t *s = oci_decompress_open(fd, OCI_COMPRESSION_GZIP, &err);
    if (!s) {
        report_fail("gzip roundtrip: open", "%s", err ? err : "(null)");
        close(fd);
        unlink(path);
        return;
    }
    uint8_t buf[64];
    size_t got = 0;
    int rc = read_all(s, buf, sizeof(buf), &got);
    if (rc != 0 || got != CANON_LEN || memcmp(buf, CANON, CANON_LEN) != 0)
        report_fail("gzip roundtrip", "rc=%d got=%zu", rc, got);
    else
        report_pass("gzip roundtrip");
    oci_stream_close(s);
    close(fd);
    unlink(path);
}

static void test_gzip_truncated(void)
{
    uint8_t *gz = NULL;
    size_t gzlen = 0;
    if (build_gzip_fixture(CANON, CANON_LEN, &gz, &gzlen) < 0 || gzlen < 4) {
        report_fail("gzip truncated", "build_gzip_fixture failed");
        free(gz);
        return;
    }
    /* Drop the trailing 4 bytes (gzip CRC32 + ISIZE) so inflate sees a
     * truncated frame. The decoder must surface an error rather than
     * silently returning short.
     */
    char path[64];
    int fd = write_tmp(gz, gzlen - 4, path);
    free(gz);
    if (fd < 0) {
        report_fail("gzip truncated: tmp file", "errno=%d", errno);
        return;
    }
    const char *err = NULL;
    oci_stream_t *s = oci_decompress_open(fd, OCI_COMPRESSION_GZIP, &err);
    if (!s) {
        report_fail("gzip truncated: open", "%s", err ? err : "(null)");
        close(fd);
        unlink(path);
        return;
    }
    uint8_t buf[64];
    ssize_t n;
    bool saw_error = false;
    while ((n = oci_stream_read(s, buf, sizeof(buf))) > 0)
        ;
    if (n < 0)
        saw_error = true;
    if (saw_error)
        report_pass("gzip truncated rejected");
    else
        report_fail("gzip truncated rejected", "stream completed cleanly");
    oci_stream_close(s);
    close(fd);
    unlink(path);
}

static void test_zstd_roundtrip(void)
{
    char path[64];
    int fd = write_tmp(ZSTD_FIXTURE, sizeof(ZSTD_FIXTURE), path);
    if (fd < 0) {
        report_fail("zstd roundtrip: tmp file", "errno=%d", errno);
        return;
    }
    const char *err = NULL;
    oci_stream_t *s = oci_decompress_open(fd, OCI_COMPRESSION_ZSTD, &err);
    if (!s) {
        report_fail("zstd roundtrip: open", "%s", err ? err : "(null)");
        close(fd);
        unlink(path);
        return;
    }
    uint8_t buf[64];
    size_t got = 0;
    int rc = read_all(s, buf, sizeof(buf), &got);
    if (rc != 0 || got != CANON_LEN || memcmp(buf, CANON, CANON_LEN) != 0)
        report_fail("zstd roundtrip", "rc=%d got=%zu", rc, got);
    else
        report_pass("zstd roundtrip");
    oci_stream_close(s);
    close(fd);
    unlink(path);
}

static void test_zstd_window_cap(void)
{
    char path[64];
    int fd = write_tmp(ZSTD_FIXTURE_28BIT, sizeof(ZSTD_FIXTURE_28BIT), path);
    if (fd < 0) {
        report_fail("zstd window cap: tmp file", "errno=%d", errno);
        return;
    }
    const char *err = NULL;
    oci_stream_t *s = oci_decompress_open(fd, OCI_COMPRESSION_ZSTD, &err);
    if (!s) {
        report_fail("zstd window cap: open", "%s", err ? err : "(null)");
        close(fd);
        unlink(path);
        return;
    }
    uint8_t buf[64];
    errno = 0;
    ssize_t n = oci_stream_read(s, buf, sizeof(buf));
    int saved_errno = errno;
    const char *last = oci_stream_last_error(s);
    if (n != -1 || saved_errno != EINVAL || !last || !strstr(last, "window")) {
        report_fail("zstd window cap rejected", "n=%zd errno=%d last=%s", n,
                    saved_errno, last ? last : "(null)");
    } else {
        report_pass("zstd window cap rejected with EINVAL");
    }
    oci_stream_close(s);
    close(fd);
    unlink(path);
}

int main(void)
{
    printf("oci_decompress dispatch\n");
    test_passthrough();
    test_gzip_roundtrip();
    test_gzip_truncated();
    test_zstd_roundtrip();
    test_zstd_window_cap();
    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
