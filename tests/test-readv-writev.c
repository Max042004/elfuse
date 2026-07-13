/*
 * Scatter-gather I/O tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests readv/writev scatter-gather I/O operations including pipe round-trips,
 * file I/O, and edge cases.
 *
 * Syscalls exercised: writev(66), readv(65), preadv(69), pwritev(70),
 *                     preadv2(286), pwritev2(287), pipe2(59), openat(56),
 *                     lseek(62), close(57), unlink(35)
 */

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include "test-harness.h"
#include "raw-syscall.h"

int passes = 0, fails = 0;

#ifndef RWF_APPEND
#define RWF_APPEND 0x00000010
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

/* Test 1: writev + readv via pipe */

static void test_pipe_roundtrip(void)
{
    TEST("writev->readv pipe roundtrip");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe");
        return;
    }

    struct iovec wv[3] = {
        {.iov_base = (void *) "hello", .iov_len = 5},
        {.iov_base = (void *) " ", .iov_len = 1},
        {.iov_base = (void *) "world", .iov_len = 5},
    };
    ssize_t nw = writev(pipefd[1], wv, 3);
    if (nw != 11) {
        FAIL("writev returned wrong count");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    char buf1[6] = {0}, buf2[5] = {0};
    struct iovec rv[2] = {
        {.iov_base = buf1, .iov_len = 6},
        {.iov_base = buf2, .iov_len = 5},
    };
    ssize_t nr = readv(pipefd[0], rv, 2);
    close(pipefd[0]);
    close(pipefd[1]);

    if (nr != 11) {
        FAIL("readv returned wrong count");
        return;
    }
    EXPECT_TRUE(!memcmp(buf1, "hello ", 6) && !memcmp(buf2, "world", 5),
                "data mismatch");
}

/* Test 2: writev to file + readv back */

static void test_file_roundtrip(void)
{
    TEST("writev->readv file roundtrip");

    const char *path = "/tmp/elfuse-test-writev.txt";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    int num = 42;
    char str[] = "test-data";
    struct iovec wv[2] = {
        {.iov_base = &num, .iov_len = sizeof(num)},
        {.iov_base = str, .iov_len = sizeof(str)},
    };
    ssize_t nw = writev(fd, wv, 2);
    if (nw != (ssize_t) (sizeof(num) + sizeof(str))) {
        FAIL("writev wrong count");
        close(fd);
        unlink(path);
        return;
    }

    lseek(fd, 0, SEEK_SET);

    int num2 = 0;
    char str2[sizeof(str)];
    memset(str2, 0, sizeof(str2));
    struct iovec rv[2] = {
        {.iov_base = &num2, .iov_len = sizeof(num2)},
        {.iov_base = str2, .iov_len = sizeof(str2)},
    };
    ssize_t nr = readv(fd, rv, 2);
    close(fd);
    unlink(path);

    if (nr != nw) {
        FAIL("readv wrong count");
        return;
    }
    EXPECT_TRUE(num2 == 42 && !strcmp(str2, "test-data"), "data mismatch");
}

static void test_lazy_source_full_write(void)
{
    TEST("lazy source buffers do not short-write");
    const size_t len = 3 * 4096;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int fd = open("/tmp/elfuse-test-lazy-write.bin", O_RDWR | O_CREAT | O_TRUNC,
                  0600);
    if (p == MAP_FAILED || fd < 0) {
        if (p != MAP_FAILED)
            munmap(p, len);
        if (fd >= 0)
            close(fd);
        unlink("/tmp/elfuse-test-lazy-write.bin");
        FAIL("setup");
        return;
    }
    unlink("/tmp/elfuse-test-lazy-write.bin");

    bool ok = pwrite(fd, p, 8192, 0) == 8192;
    ok = ok && lseek(fd, 0, SEEK_SET) == 0 && write(fd, p, 8192) == 8192;

    /* Alternate zero-alias and identity pages in one scalar source range. */
    p[4096] = 0x5A;
    ok = ok && pwrite(fd, p, len, 0) == (ssize_t) len;
    unsigned char check[3 * 4096];
    ok = ok && pread(fd, check, len, 0) == (ssize_t) len && check[0] == 0 &&
         check[4096] == 0x5A && check[8192] == 0;

    unsigned char *q = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (q == MAP_FAILED) {
        ok = false;
    } else {
        struct iovec iov[2] = {
            {.iov_base = q, .iov_len = 8192},
            {.iov_base = q + 8192, .iov_len = 4096},
        };
        ok = ok && lseek(fd, 0, SEEK_SET) == 0 &&
             writev(fd, iov, 2) == (ssize_t) len;
        munmap(q, len);
    }

    /* More than IOV_MAX alternating identity/zero runs uses the bounded
     * fragmented-source fallback, but remains one complete positional write. */
    const size_t fragmented_len = 5 * 1024 * 1024;
    unsigned char *fragmented =
        mmap(NULL, fragmented_len, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fragmented == MAP_FAILED) {
        ok = false;
    } else {
        for (size_t off = 0; off < fragmented_len; off += 8192)
            fragmented[off] = 1;
        ok = ok && pwrite(fd, fragmented, fragmented_len, 0) ==
                       (ssize_t) fragmented_len;
        munmap(fragmented, fragmented_len);
    }

    close(fd);
    munmap(p, len);
    EXPECT_TRUE(ok, "lazy pwrite/writev stopped at a GPA boundary");
}

/* Test 3: Single iovec (degenerate case) */

static void test_single_iovec(void)
{
    TEST("writev single iovec");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe");
        return;
    }

    char msg[] = "single";
    struct iovec v = {.iov_base = msg, .iov_len = 6};
    ssize_t nw = writev(pipefd[1], &v, 1);

    char buf[6] = {0};
    struct iovec rv = {.iov_base = buf, .iov_len = 6};
    ssize_t nr = readv(pipefd[0], &rv, 1);
    close(pipefd[0]);
    close(pipefd[1]);

    EXPECT_TRUE(nw == 6 && nr == 6 && !memcmp(buf, "single", 6),
                "single iovec mismatch");
}

/* Test 4: Zero-length iovec */

static void test_zero_length_iovec(void)
{
    TEST("writev with zero-length iovec");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe");
        return;
    }

    struct iovec wv[3] = {
        {.iov_base = (void *) "a", .iov_len = 1},
        {.iov_base = (void *) "", .iov_len = 0},
        {.iov_base = (void *) "b", .iov_len = 1},
    };
    ssize_t nw = writev(pipefd[1], wv, 3);

    char buf[2] = {0};
    ssize_t nr = read(pipefd[0], buf, 2);
    close(pipefd[0]);
    close(pipefd[1]);

    EXPECT_TRUE(nw == 2 && nr == 2 && buf[0] == 'a' && buf[1] == 'b',
                "zero-length iovec handling wrong");
}

/* Test 5: all-empty iovecs still validate descriptor access */

static void test_empty_iovec_access_checks(void)
{
    TEST("empty readv/writev access checks");

    struct iovec zv[2] = {{0}};
    int rfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int wfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (rfd < 0 || wfd < 0) {
        if (rfd >= 0)
            close(rfd);
        if (wfd >= 0)
            close(wfd);
        FAIL("open");
        return;
    }

    errno = 0;
    ssize_t wr = writev(rfd, zv, 2);
    int write_errno = errno;
    errno = 0;
    ssize_t rr = readv(wfd, zv, 2);
    int read_errno = errno;
    close(rfd);
    close(wfd);

    EXPECT_TRUE(
        wr == -1 && write_errno == EBADF && rr == -1 && read_errno == EBADF,
        "empty iovec access check skipped");
}

/* Test 6: Large writev (many iovecs) */

static void test_many_iovecs(void)
{
    TEST("writev 10 iovecs");

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        FAIL("pipe");
        return;
    }

    char data[10] = "0123456789";
    struct iovec wv[10];
    for (int i = 0; i < 10; i++)
        wv[i].iov_base = &data[i], wv[i].iov_len = 1;
    ssize_t nw = writev(pipefd[1], wv, 10);

    char buf[10] = {0};
    ssize_t nr = read(pipefd[0], buf, 10);
    close(pipefd[0]);
    close(pipefd[1]);

    EXPECT_TRUE(nw == 10 && nr == 10 && !memcmp(buf, "0123456789", 10),
                "10-iovec writev failed");
}

/* Test 7: pwritev2 RWF_APPEND semantics */

static void test_pwritev2_append(void)
{
    TEST("pwritev2 RWF_APPEND EOF");

    const char *path = "/tmp/elfuse-test-pwritev2-append.txt";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    if (write(fd, "base", 4) != 4 || lseek(fd, 1, SEEK_SET) != 1) {
        FAIL("setup");
        close(fd);
        unlink(path);
        return;
    }

    struct iovec wv[2] = {
        {.iov_base = (void *) "X", .iov_len = 1},
        {.iov_base = (void *) "Y", .iov_len = 1},
    };
    long ret = raw_syscall6(__NR_pwritev2, fd, (long) wv, 2, 0, 0, RWF_APPEND);
    if (ret < 0) {
        errno = (int) -ret;
        FAIL("pwritev2");
        close(fd);
        unlink(path);
        return;
    }
    if (ret != 2) {
        FAIL("pwritev2 count");
        close(fd);
        unlink(path);
        return;
    }
    if (lseek(fd, 0, SEEK_CUR) != 1) {
        FAIL("file offset changed");
        close(fd);
        unlink(path);
        return;
    }

    char buf[7] = {0};
    ssize_t nr = pread(fd, buf, 6, 0);
    close(fd);
    unlink(path);

    EXPECT_TRUE(nr == 6 && !memcmp(buf, "baseXY", 6), "append data mismatch");
}

/* Test 8: zero iovcnt returns 0 without moving the append file offset.
 * Linux reference (verified under qemu-system-aarch64): import_iovec()
 * yields an empty iterator, do_iter_write returns 0 before the offset is
 * touched, so pwritev2(RWF_APPEND) with iovcnt == 0 is a complete no-op.
 */

static void test_pwritev2_append_zero_iovcnt(void)
{
    TEST("pwritev2 RWF_APPEND zero iovcnt");

    const char *path = "/tmp/elfuse-test-pwritev2-append-zero.txt";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        FAIL("open");
        return;
    }

    if (write(fd, "base", 4) != 4 || lseek(fd, 1, SEEK_SET) != 1) {
        FAIL("setup");
        close(fd);
        unlink(path);
        return;
    }

    struct iovec wv = {.iov_base = (void *) "X", .iov_len = 1};
    long ret =
        raw_syscall6(__NR_pwritev2, fd, (long) &wv, 0, -1, 0, RWF_APPEND);
    off_t pos = lseek(fd, 0, SEEK_CUR);
    close(fd);
    unlink(path);

    EXPECT_TRUE(ret == 0 && pos == 1, "zero iovcnt not a no-op");
}

/* Test 8: zero-iovcnt validation ordering across all six vector entry
 * points. Linux reference (fs/read_write.c): a negative offset fails EINVAL
 * before the fd lookup (do_preadv/do_pwritev; -1 is a valid sentinel only
 * for preadv2/pwritev2), the positional variants fail non-seekable files
 * with ESPIPE (FMODE_PREAD/FMODE_PWRITE), wrong-direction and O_PATH fds
 * fail EBADF (FMODE_READ/FMODE_WRITE in do_iter_read/do_iter_write), and
 * RWF flags are never validated because do_iter_* return before
 * kiocb_set_rw_flags for an empty vector.
 */

enum vec_op {
    OP_READV,
    OP_WRITEV,
    OP_PREADV,
    OP_PWRITEV,
    OP_PREADV2,
    OP_PWRITEV2
};

static long vec_zero_syscall(int op, int fd, long off, long flags)
{
    switch (op) {
    case OP_READV:
        return raw_syscall3(__NR_readv, fd, 0, 0);
    case OP_WRITEV:
        return raw_syscall3(__NR_writev, fd, 0, 0);
    case OP_PREADV:
        return raw_syscall5(__NR_preadv, fd, 0, 0, off, 0);
    case OP_PWRITEV:
        return raw_syscall5(__NR_pwritev, fd, 0, 0, off, 0);
    case OP_PREADV2:
        return raw_syscall6(__NR_preadv2, fd, 0, 0, off, 0, flags);
    default:
        return raw_syscall6(__NR_pwritev2, fd, 0, 0, off, 0, flags);
    }
}

static void test_zero_iovcnt_validation(void)
{
    const char *path = "/tmp/elfuse-test-zero-iovcnt.txt";
    int rw = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    int ro = open(path, O_RDONLY);
    int wo = open(path, O_WRONLY);
    int opath = open(path, O_PATH);
    int stale = open(path, O_RDONLY);
    int pfd[2] = {-1, -1};
    if (rw < 0 || ro < 0 || wo < 0 || opath < 0 || stale < 0 ||
        pipe(pfd) != 0) {
        TEST("zero iovcnt setup");
        FAIL("open/pipe");
        goto out;
    }
    close(stale); /* keep the value: exercises the closed-fd path */

    const struct {
        const char *name;
        int op;
        int fd;
        long off;
        long flags;
        long expect;
    } cases[] = {
        /* Valid fd, matching direction: 0 regardless of variant */
        {"readv rdwr", OP_READV, rw, 0, 0, 0},
        {"writev rdwr", OP_WRITEV, rw, 0, 0, 0},
        {"preadv rdwr", OP_PREADV, rw, 0, 0, 0},
        {"pwritev rdwr", OP_PWRITEV, rw, 0, 0, 0},
        {"preadv2 rdwr", OP_PREADV2, rw, 0, 0, 0},
        {"pwritev2 rdwr", OP_PWRITEV2, rw, 0, 0, 0},
        {"readv rdonly", OP_READV, ro, 0, 0, 0},
        {"writev wronly", OP_WRITEV, wo, 0, 0, 0},
        /* Closed fd: EBADF */
        {"readv closed", OP_READV, stale, 0, 0, -EBADF},
        {"writev closed", OP_WRITEV, stale, 0, 0, -EBADF},
        {"preadv closed", OP_PREADV, stale, 0, 0, -EBADF},
        {"pwritev2 closed off=-1", OP_PWRITEV2, stale, -1, 0, -EBADF},
        /* O_PATH: EBADF (no FMODE_READ/FMODE_WRITE) */
        {"readv O_PATH", OP_READV, opath, 0, 0, -EBADF},
        {"writev O_PATH", OP_WRITEV, opath, 0, 0, -EBADF},
        /* Wrong access mode: EBADF */
        {"writev rdonly", OP_WRITEV, ro, 0, 0, -EBADF},
        {"pwritev rdonly", OP_PWRITEV, ro, 0, 0, -EBADF},
        {"pwritev2 rdonly", OP_PWRITEV2, ro, 0, 0, -EBADF},
        {"readv wronly", OP_READV, wo, 0, 0, -EBADF},
        {"preadv wronly", OP_PREADV, wo, 0, 0, -EBADF},
        {"preadv2 wronly", OP_PREADV2, wo, 0, 0, -EBADF},
        /* Pipes: direction from the fd, ESPIPE for positional variants */
        {"readv pipe rd-end", OP_READV, pfd[0], 0, 0, 0},
        {"writev pipe wr-end", OP_WRITEV, pfd[1], 0, 0, 0},
        {"writev pipe rd-end", OP_WRITEV, pfd[0], 0, 0, -EBADF},
        {"readv pipe wr-end", OP_READV, pfd[1], 0, 0, -EBADF},
        {"preadv pipe rd-end", OP_PREADV, pfd[0], 0, 0, -ESPIPE},
        {"pwritev pipe wr-end", OP_PWRITEV, pfd[1], 0, 0, -ESPIPE},
        {"preadv2 pipe off=-1", OP_PREADV2, pfd[0], -1, 0, 0},
        /* Negative offsets: EINVAL, even before the fd lookup */
        {"preadv rdwr off=-1", OP_PREADV, rw, -1, 0, -EINVAL},
        {"pwritev rdwr off=-1", OP_PWRITEV, rw, -1, 0, -EINVAL},
        {"preadv2 rdwr off=-2", OP_PREADV2, rw, -2, 0, -EINVAL},
        {"pwritev2 rdwr off=-2", OP_PWRITEV2, rw, -2, 0, -EINVAL},
        {"preadv closed off=-1", OP_PREADV, stale, -1, 0, -EINVAL},
        /* RWF flags are not validated for an empty vector */
        {"preadv2 rdwr RWF_APPEND", OP_PREADV2, rw, 0, RWF_APPEND, 0},
        {"pwritev2 rdwr bogus flag", OP_PWRITEV2, rw, 0, 1L << 27, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST(cases[i].name);
        long got = vec_zero_syscall(cases[i].op, cases[i].fd, cases[i].off,
                                    cases[i].flags);
        EXPECT_EQ(got, cases[i].expect, "wrong return");
    }

out:
    if (rw >= 0)
        close(rw);
    if (ro >= 0)
        close(ro);
    if (wo >= 0)
        close(wo);
    if (opath >= 0)
        close(opath);
    if (pfd[0] >= 0)
        close(pfd[0]);
    if (pfd[1] >= 0)
        close(pfd[1]);
    unlink(path);
}

/* Main */

int main(void)
{
    printf("test-readv-writev: scatter-gather I/O tests\n");

    test_pipe_roundtrip();
    test_file_roundtrip();
    test_lazy_source_full_write();
    test_single_iovec();
    test_zero_length_iovec();
    test_empty_iovec_access_checks();
    test_many_iovecs();
    test_pwritev2_append();
    test_pwritev2_append_zero_iovcnt();
    test_zero_iovcnt_validation();

    SUMMARY("test-readv-writev");
    return fails > 0 ? 1 : 0;
}
