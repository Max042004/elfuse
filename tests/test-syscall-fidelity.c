/*
 * Linux syscall fidelity tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers Linux syscalls whose semantics elfuse must emulate exactly: fchmodat2
 * (SYS 452) including AT_SYMLINK_NOFOLLOW, getcpu (SYS 168), openat2 (SYS 437)
 * with each RESOLVE_* flag variant (BENEATH, IN_ROOT, NO_SYMLINKS,
 * NO_MAGICLINKS, NO_XDEV), O_PATH descriptor enforcement for read/write/fstat,
 * madvise corner cases (MADV_COLD acceptance and MADV_DONTNEED across an
 * unmapped hole), and the low-address mmap hint preservation that ET_EXEC
 * layout depends on.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "test-harness.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

int passes = 0, fails = 0;

/* Some Linux fidelity tests probe semantics that depend on filesystem support
 * (e.g. changing a symlink's own mode via AT_SYMLINK_NOFOLLOW fails with
 * EOPNOTSUPP on most Linux filesystems). Counting those as skips keeps the
 * summary honest: the syscall path was reached and answered correctly, but the
 * kernel declined the specific request. Hard-failing on EOPNOTSUPP would turn
 * the regression into a false negative on perfectly conforming kernels.
 */
static int syscall_skips = 0;
#define SYSCALL_SKIP(reason)          \
    do {                              \
        printf("SKIP: %s\n", reason); \
        syscall_skips++;              \
    } while (0)

/* fchmodat2 (SYS 452). */

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

#ifndef SYS_getcpu
#define SYS_getcpu 168
#endif

static void test_fchmodat2_basic(void)
{
    TEST("fchmodat2 basic");
    char path[] = "/tmp/elfuse-test-fchmodat2-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        FAIL("mkstemp");
        return;
    }
    close(fd);
    /* fchmodat2(AT_FDCWD, path, 0644, 0) should work like fchmodat */
    long rc = syscall(SYS_fchmodat2, AT_FDCWD, path, 0644, 0);
    if (rc < 0) {
        FAIL("fchmodat2");
        unlink(path);
        return;
    }
    struct stat st;
    stat(path, &st);
    unlink(path);
    EXPECT_TRUE((st.st_mode & 0777) == 0644, "mode mismatch");
}

static void test_getcpu_basic(void)
{
    TEST("getcpu basic");
    unsigned cpu = 99, node = 99;
    long rc = syscall(SYS_getcpu, &cpu, &node, 0);
    if (rc < 0) {
        FAIL("getcpu");
        return;
    }
    EXPECT_TRUE(cpu == 0, "cpu should be 0");
    EXPECT_TRUE(node == 0, "node should be 0");
}

static void test_fchmodat2_symlink_nofollow(void)
{
    TEST("fchmodat2 AT_SYMLINK_NOFOLLOW");
    char target[] = "/tmp/elfuse-test-fchmodat2-target-XXXXXX";
    char linkpath[64];

    int fd = mkstemp(target);
    if (fd < 0) {
        FAIL("mkstemp target");
        return;
    }
    close(fd);
    /* Derive the symlink name from the unique target so we never call mktemp,
     * which is racy and triggers a linker warning on glibc.
     */
    snprintf(linkpath, sizeof(linkpath), "%s.lnk", target);

    if (symlink(target, linkpath) < 0) {
        FAIL("symlink");
        unlink(target);
        return;
    }

    /* AT_SYMLINK_NOFOLLOW must change the symlink's mode, not the target's.
     * Most Linux filesystems (including tmpfs, ext4, btrfs without the
     * symlink-mode opt-in) reject this with EOPNOTSUPP because the on-disk
     * inode for a symlink has no separately writable mode bit. Treat that
     * answer as an honest skip: the kernel reached fchmodat2_write and declined
     * the specific request. Any other negative return is a real failure that
     * the test should surface.
     */
    long rc =
        syscall(SYS_fchmodat2, AT_FDCWD, linkpath, 0700, AT_SYMLINK_NOFOLLOW);
    if (rc < 0) {
        if (errno == EOPNOTSUPP) {
            SYSCALL_SKIP(
                "fchmodat2 AT_SYMLINK_NOFOLLOW unsupported by host fs");
            goto out;
        }
        FAIL("fchmodat2 nofollow");
        goto out;
    }

    struct stat st_link, st_target;
    if (lstat(linkpath, &st_link) < 0) {
        FAIL("lstat link");
        goto out;
    }
    if (stat(target, &st_target) < 0) {
        FAIL("stat target");
        goto out;
    }

    EXPECT_TRUE((st_link.st_mode & 0777) == 0700, "link mode mismatch");
    EXPECT_TRUE((st_target.st_mode & 0777) == 0600, "target mode changed");

out:
    unlink(linkpath);
    unlink(target);
}

/* openat2 (SYS 437). */

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how {
    unsigned long long flags, mode, resolve;
};

#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

static void expect_openat2_errno(const char *name,
                                 int dirfd,
                                 const char *path,
                                 unsigned long long flags,
                                 unsigned long long mode,
                                 unsigned long long resolve,
                                 int expected_errno)
{
    TEST(name);
    struct open_how how = {.flags = flags, .mode = mode, .resolve = resolve};
    errno = 0;
    long fd = syscall(SYS_openat2, dirfd, path, &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("openat2 unexpectedly succeeded");
        return;
    }
    EXPECT_TRUE(errno == expected_errno, "wrong errno");
}

static void expect_fd_magiclink_rejected(const char *path_label,
                                         int dirfd,
                                         const char *path)
{
    static const struct {
        const char *resolve_name;
        unsigned long long resolve;
        int expected_errno;
    } cases[] = {
        {"NO_MAGICLINKS", RESOLVE_NO_MAGICLINKS, ELOOP},
        {"NO_SYMLINKS", RESOLVE_NO_SYMLINKS, ELOOP},
        {"NO_XDEV", RESOLVE_NO_XDEV, EXDEV},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char name[128];
        snprintf(name, sizeof(name), "openat2 %s rejects %s",
                 cases[i].resolve_name, path_label);
        expect_openat2_errno(name, dirfd, path, O_RDONLY, 0, cases[i].resolve,
                             cases[i].expected_errno);
    }
}

static void test_openat2_basic(void)
{
    TEST("openat2 basic open");
    struct open_how how = {.flags = O_RDONLY, .mode = 0, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        return;
    }
    close(fd);
    PASS();
}

static void test_openat2_rejects_nonzero_how_extension(void)
{
    TEST("openat2 rejects nonzero open_how extension");
    struct {
        struct open_how how;
        unsigned long long extra;
    } ext = {
        .how = {.flags = O_RDONLY, .mode = 0, .resolve = 0},
        .extra = 1,
    };
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &ext, sizeof(ext));
    if (fd >= 0) {
        close((int) fd);
        FAIL("accepted nonzero open_how extension");
        return;
    }
    EXPECT_TRUE(errno == E2BIG, "wrong errno");
}

static void test_openat2_rejects_oversized_how(void)
{
    TEST("openat2 rejects oversized open_how");
    struct open_how how = {.flags = O_RDONLY, .mode = 0, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, 4097);
    if (fd >= 0) {
        close((int) fd);
        FAIL("accepted oversized open_how");
        return;
    }
    EXPECT_TRUE(errno == E2BIG, "wrong errno");
}

static void test_openat2_rejects_unknown_flags(void)
{
    TEST("openat2 rejects unknown flags");
    struct open_how how = {.flags = 1ULL << 63, .mode = 0, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("accepted unknown flags");
        return;
    }
    EXPECT_TRUE(errno == EINVAL, "wrong errno");
}

static void test_openat2_rejects_mode_without_create(void)
{
    TEST("openat2 rejects mode without create");
    struct open_how how = {.flags = O_RDONLY, .mode = 0600, .resolve = 0};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/dev/null", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("accepted mode without create");
        return;
    }
    EXPECT_TRUE(errno == EINVAL, "wrong errno");
}

static void test_openat2_rejects_beneath_in_root(void)
{
    expect_openat2_errno("openat2 rejects BENEATH|IN_ROOT", AT_FDCWD,
                         "/dev/null", O_RDONLY, 0,
                         RESOLVE_BENEATH | RESOLVE_IN_ROOT, EINVAL);
}

static void test_openat2_rejects_directory_create(void)
{
    const char *path = "/tmp/elfuse-openat2-directory-create-probe";
    unlink(path);
    expect_openat2_errno("openat2 rejects O_DIRECTORY|O_CREAT", AT_FDCWD, path,
                         O_RDONLY | O_DIRECTORY | O_CREAT, 0600, 0, EINVAL);
    unlink(path);
}

static void test_openat2_rejects_tmpfile_readonly(void)
{
    expect_openat2_errno("openat2 rejects O_TMPFILE|O_RDONLY", AT_FDCWD, "/tmp",
                         O_TMPFILE | O_RDONLY, 0600, 0, EINVAL);
}

static void test_openat2_resolve_beneath(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects ..");
    /* Open a directory first */
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "../etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close(fd);
        FAIL("should have rejected .. traversal");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_beneath_allows_internal_dotdot(void)
{
    TEST("openat2 RESOLVE_BENEATH allows in-root ..");

    char dir_template[] = "/tmp/elfuse-openat2-beneath-XXXXXX";
    char subdir[PATH_MAX], target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(subdir, sizeof(subdir), "%s/subdir", dir_template);
    snprintf(target, sizeof(target), "%s/file", dir_template);
    if (mkdir(subdir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }

    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "subdir/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(subdir);
    rmdir(dir_template);
}

static void test_openat2_resolve_in_root_clamps_dotdot(void)
{
    TEST("openat2 RESOLVE_IN_ROOT clamps .. at root");

    char dir_template[] = "/tmp/elfuse-openat2-inroot-XXXXXX";
    char target[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target, sizeof(target), "%s/file", dir_template);
    filefd = open(target, O_CREAT | O_RDONLY, 0600);
    if (filefd < 0) {
        FAIL("open file");
        goto out;
    }
    close(filefd);
    filefd = -1;

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_IN_ROOT};
    long fd = syscall(SYS_openat2, dirfd, "/../file", &how, sizeof(how));
    if (fd < 0) {
        FAIL("openat2");
        goto out;
    }
    close((int) fd);
    PASS();

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(target);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_symlinks_intermediate(void)
{
    TEST("openat2 RESOLVE_NO_SYMLINKS rejects intermediate symlink");

    char dir_template[] = "/tmp/elfuse-openat2-XXXXXX";
    char target_dir[PATH_MAX], subfile[PATH_MAX];
    char link_path[PATH_MAX];
    int dirfd = -1, filefd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(target_dir, sizeof(target_dir), "%s/real", dir_template);
    snprintf(subfile, sizeof(subfile), "%s/subfile", target_dir);
    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);

    if (mkdir(target_dir, 0700) < 0) {
        FAIL("mkdir");
        goto out;
    }
    filefd = open(subfile, O_CREAT | O_RDWR, 0600);
    if (filefd < 0) {
        FAIL("open subfile");
        goto out;
    }
    close(filefd);
    filefd = -1;
    if (symlink("real", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_SYMLINKS};
    long fd = syscall(SYS_openat2, dirfd, "link/subfile", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        goto out;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    if (filefd >= 0)
        close(filefd);
    unlink(link_path);
    unlink(subfile);
    rmdir(target_dir);
    rmdir(dir_template);
}

static void test_openat2_resolve_beneath_rejects_symlink_escape(void)
{
    TEST("openat2 RESOLVE_BENEATH rejects symlink escape");

    char dir_template[] = "/tmp/elfuse-openat2-escape-XXXXXX";
    char link_path[PATH_MAX];
    int dirfd = -1;

    if (!mkdtemp(dir_template)) {
        FAIL("mkdtemp");
        return;
    }

    snprintf(link_path, sizeof(link_path), "%s/link", dir_template);
    if (symlink("/etc", link_path) < 0) {
        FAIL("symlink");
        goto out;
    }

    dirfd = open(dir_template, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open dir");
        goto out;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_BENEATH};
    long fd = syscall(SYS_openat2, dirfd, "link/passwd", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        goto out;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");

out:
    if (dirfd >= 0)
        close(dirfd);
    unlink(link_path);
    rmdir(dir_template);
}

static void test_openat2_resolve_no_magiclinks_proc_fd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects /proc/self/fd");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    long fd =
        syscall(SYS_openat2, AT_FDCWD, "/proc/self/fd/0", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

static void test_openat2_resolve_no_magiclinks_proc_cwd(void)
{
    TEST("openat2 RESOLVE_NO_MAGICLINKS rejects proc cwd magiclinks");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_MAGICLINKS};
    char cwd[256];

    if (!getcwd(cwd, sizeof(cwd))) {
        FAIL("getcwd");
        return;
    }
    if (chdir("/proc") < 0) {
        FAIL("chdir");
        return;
    }

    errno = 0;
    long fd = syscall(SYS_openat2, AT_FDCWD, "self/fd/0", &how, sizeof(how));
    int saved_errno = errno;
    if (chdir(cwd) < 0) {
        FAIL("restore cwd");
        return;
    }

    errno = saved_errno;
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ELOOP");
        return;
    }
    EXPECT_TRUE(errno == ELOOP, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_proc(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects crossing into /proc");
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd =
        syscall(SYS_openat2, dirfd, "/proc/self/status", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_allows_same_mount(void)
{
    TEST("openat2 RESOLVE_NO_XDEV allows same-mount path");
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    /* /tmp is a regular dir; another regular path stays in the same class. */
    long fd = syscall(SYS_openat2, dirfd, "/etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        PASS();
        return;
    }
    /* Acceptable if /etc/passwd doesn't exist on the host running the test, as
     * long as the error is not EXDEV.
     */
    EXPECT_TRUE(errno != EXDEV, "should not return EXDEV for same-class path");
}

static void test_openat2_resolve_no_xdev_absolute_ignores_dirfd_mount(void)
{
    TEST("openat2 RESOLVE_NO_XDEV absolute path ignores dirfd mount");
    int dirfd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /proc");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "/etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        PASS();
        return;
    }
    EXPECT_TRUE(errno != EXDEV, "absolute /etc should start from root mount");
}

static void test_openat2_resolve_no_xdev_rejects_relative_proc(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects relative crossing into /proc");
    int dirfd = open("/", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd =
        syscall(SYS_openat2, dirfd, "proc/self/status", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_relative_escape(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects relative escape from /proc");
    int dirfd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /proc");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "../etc/passwd", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_allows_regular_proc_name(void)
{
    TEST("openat2 RESOLVE_NO_XDEV allows regular dir named proc");
    char dir_template[] = "/tmp/elfuse-openat2-xdev-XXXXXX";
    char *dir = mkdtemp(dir_template);
    if (!dir) {
        FAIL("mkdtemp");
        return;
    }
    char proc_dir[PATH_MAX];
    char file_path[PATH_MAX];
    if (snprintf(proc_dir, sizeof(proc_dir), "%s/proc", dir) >=
            (int) sizeof(proc_dir) ||
        snprintf(file_path, sizeof(file_path), "%s/status", proc_dir) >=
            (int) sizeof(file_path)) {
        FAIL("path too long");
        rmdir(dir);
        return;
    }
    if (mkdir(proc_dir, 0700) < 0) {
        FAIL("mkdir proc");
        rmdir(dir);
        return;
    }
    int fd = open(file_path, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) {
        FAIL("create status");
        rmdir(proc_dir);
        rmdir(dir);
        return;
    }
    close(fd);

    int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open temp dir");
        unlink(file_path);
        rmdir(proc_dir);
        rmdir(dir);
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long opened = syscall(SYS_openat2, dirfd, "proc/status", &how, sizeof(how));
    close(dirfd);
    unlink(file_path);
    rmdir(proc_dir);
    rmdir(dir);
    if (opened >= 0) {
        close((int) opened);
        PASS();
        return;
    }
    EXPECT_TRUE(errno != EXDEV, "regular proc name is not a mount crossing");
}

static void test_openat2_resolve_no_xdev_rejects_dev(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects crossing into /dev");
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "/dev/null", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_dev_shm_from_dev(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects /dev to /dev/shm");
    int dirfd = open("/dev", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /dev");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "shm/missing", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_relative_tmp(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects relative crossing into /tmp");
    int dirfd = open("/", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /");
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "tmp/elfuse-no-xdev-missing", &how,
                      sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_transient_proc(void)
{
    /* A naive endpoint-only check would accept /proc/self/../../tmp/foo because
     * the lexical normalization collapses /proc/self/../.. to / and the final
     * classifier sees only /tmp/foo. Linux walks the path component by
     * component and catches the transient crossing into /proc. The component
     * walker must do the same.
     */
    TEST("openat2 RESOLVE_NO_XDEV catches transient /proc visit");
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd =
        syscall(SYS_openat2, AT_FDCWD,
                "/proc/self/../../tmp/elfuse-no-xdev-probe", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("walker accepted a path that traversed /proc");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_bare_proc(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects bare /proc");
    struct open_how how = {
        .flags = O_RDONLY | O_DIRECTORY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, AT_FDCWD, "/proc", &how, sizeof(how));
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV opening bare /proc");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_rejects_symlink_to_proc(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects symlink crossing into /proc");
    char dir_template[] = "/tmp/elfuse-openat2-xdev-link-XXXXXX";
    char *dir = mkdtemp(dir_template);
    if (!dir) {
        FAIL("mkdtemp");
        return;
    }

    char link_path[PATH_MAX];
    if (snprintf(link_path, sizeof(link_path), "%s/link", dir) >=
        (int) sizeof(link_path)) {
        FAIL("path too long");
        rmdir(dir);
        return;
    }
    if (symlink("/proc/self", link_path) < 0) {
        FAIL("symlink");
        rmdir(dir);
        return;
    }

    int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open temp dir");
        unlink(link_path);
        rmdir(dir);
        return;
    }
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, "link/status", &how, sizeof(how));
    close(dirfd);
    unlink(link_path);
    rmdir(dir);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_resolve_no_xdev_in_root_clamps_dotdot(void)
{
    /* IN_ROOT clamps ".." at the dirfd. The combined NO_XDEV precheck must use
     * the same floor, otherwise a path like /../../tmp from a /proc/1 dirfd
     * lexically pops above /proc and the walker would falsely report EXDEV even
     * though the actual resolution clamps and stays inside the proc class.
     */
    TEST("openat2 RESOLVE_IN_ROOT | NO_XDEV clamps .. at dirfd");
    int dirfd = open("/proc/self", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /proc/self");
        return;
    }
    struct open_how how = {.flags = O_RDONLY,
                           .mode = 0,
                           .resolve = RESOLVE_NO_XDEV | RESOLVE_IN_ROOT};
    long fd = syscall(SYS_openat2, dirfd, "/../../status", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        PASS();
        return;
    }
    EXPECT_TRUE(errno != EXDEV,
                "IN_ROOT clamp should keep the walk inside /proc/self");
}

static void test_openat2_resolve_no_xdev_rejects_proc_fd_magiclink(void)
{
    /* /proc/self/fd/N is a magic link whose target lives in whatever mount
     * holds the underlying fd. Following it out of procfs is a mount crossing
     * under Linux NO_XDEV. Without this guard the post-open check sees
     * proc_path stamped as /proc/self/fd/N and falsely agrees with the PROC
     * start class.
     */
    TEST("openat2 RESOLVE_NO_XDEV rejects /proc/self/fd magic link");
    int helper = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (helper < 0) {
        FAIL("open /tmp helper");
        return;
    }
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", helper);
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, AT_FDCWD, link_path, &how, sizeof(how));
    close(helper);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV for magic-link traversal");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_rejects_proc_pid_fd_magiclink(void)
{
    int helper = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (helper < 0) {
        TEST("openat2 prepares /proc/<pid>/fd helper");
        FAIL("open /tmp helper");
        return;
    }

    char path[128];
    if (snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long) getpid(),
                 helper) >= (int) sizeof(path)) {
        close(helper);
        TEST("openat2 prepares /proc/<pid>/fd helper");
        FAIL("path too long");
        return;
    }
    expect_fd_magiclink_rejected("absolute /proc/<pid>/fd", AT_FDCWD, path);

    int procfd = open("/proc", O_RDONLY | O_DIRECTORY);
    if (procfd < 0) {
        close(helper);
        TEST("openat2 prepares /proc/<pid>/fd helper");
        FAIL("open /proc");
        return;
    }
    if (snprintf(path, sizeof(path), "%ld/fd/%d", (long) getpid(), helper) >=
        (int) sizeof(path)) {
        close(procfd);
        close(helper);
        TEST("openat2 prepares /proc/<pid>/fd helper");
        FAIL("path too long");
        return;
    }
    expect_fd_magiclink_rejected("dirfd /proc <pid>/fd", procfd, path);
    close(procfd);
    close(helper);
}

static void test_openat2_resolve_no_xdev_rejects_dev_fd_magiclink(void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects /dev/fd magic link");
    int helper = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (helper < 0) {
        FAIL("open /tmp helper");
        return;
    }
    int dirfd = open("/dev", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        close(helper);
        FAIL("open /dev");
        return;
    }

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "fd/%d", helper);
    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, dirfd, link_path, &how, sizeof(how));
    close(dirfd);
    close(helper);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV for /dev/fd magic-link traversal");
        return;
    }
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

static void test_openat2_rejects_dev_fd_magiclink_variants(void)
{
    int helper = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (helper < 0) {
        TEST("openat2 prepares /dev/fd helper");
        FAIL("open /tmp helper");
        return;
    }

    char path[128];
    if (snprintf(path, sizeof(path), "/dev/fd/%d", helper) >=
        (int) sizeof(path)) {
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("path too long");
        return;
    }
    expect_fd_magiclink_rejected("absolute /dev/fd", AT_FDCWD, path);

    int rootfd = open("/", O_RDONLY | O_DIRECTORY);
    if (rootfd < 0) {
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("open /");
        return;
    }
    if (snprintf(path, sizeof(path), "dev/fd/%d", helper) >=
        (int) sizeof(path)) {
        close(rootfd);
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("path too long");
        return;
    }
    expect_fd_magiclink_rejected("dirfd / dev/fd", rootfd, path);
    close(rootfd);

    int cwdfd = open(".", O_RDONLY | O_DIRECTORY);
    if (cwdfd < 0) {
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("open cwd");
        return;
    }
    if (chdir("/") < 0) {
        close(cwdfd);
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("chdir /");
        return;
    }
    expect_fd_magiclink_rejected("cwd / dev/fd", AT_FDCWD, path);
    if (fchdir(cwdfd) < 0) {
        close(cwdfd);
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("restore cwd");
        return;
    }
    close(cwdfd);

    int devfd = open("/dev", O_RDONLY | O_DIRECTORY);
    if (devfd < 0) {
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("open /dev");
        return;
    }
    if (snprintf(path, sizeof(path), "shm/../fd/%d", helper) >=
        (int) sizeof(path)) {
        close(devfd);
        close(helper);
        TEST("openat2 prepares /dev/fd helper");
        FAIL("path too long");
        return;
    }
    expect_fd_magiclink_rejected("dirfd /dev shm/../fd", devfd, path);
    close(devfd);
    close(helper);
}

static void test_openat2_resolve_no_xdev_rejects_normalized_proc_fd_magiclink(
    void)
{
    TEST("openat2 RESOLVE_NO_XDEV rejects normalized proc fd magic links");
    int helper = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (helper < 0) {
        FAIL("open /tmp helper");
        return;
    }

    int dirfd = open("/proc/self", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        close(helper);
        FAIL("open /proc/self");
        return;
    }

    char dot_path[64];
    char dotdot_path[64];
    snprintf(dot_path, sizeof(dot_path), "./fd/%d", helper);
    snprintf(dotdot_path, sizeof(dotdot_path), "task/../fd/%d", helper);

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    const char *paths[] = {dot_path, dotdot_path};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        long fd = syscall(SYS_openat2, dirfd, paths[i], &how, sizeof(how));
        if (fd >= 0) {
            close((int) fd);
            close(dirfd);
            close(helper);
            FAIL("expected EXDEV for normalized magic-link traversal");
            return;
        }
        if (errno != EXDEV) {
            close(dirfd);
            close(helper);
            EXPECT_TRUE(errno == EXDEV, "wrong errno");
            return;
        }
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        close(dirfd);
        close(helper);
        FAIL("getcwd");
        return;
    }
    if (chdir("/proc/self") < 0) {
        close(dirfd);
        close(helper);
        FAIL("chdir /proc/self");
        return;
    }

    long fd = syscall(SYS_openat2, AT_FDCWD, dotdot_path, &how, sizeof(how));
    int saved_errno = errno;
    if (chdir(cwd) < 0) {
        close(dirfd);
        close(helper);
        FAIL("restore cwd");
        return;
    }

    close(dirfd);
    close(helper);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected EXDEV for cwd magic-link traversal");
        return;
    }
    errno = saved_errno;
    EXPECT_TRUE(errno == EXDEV, "wrong errno");
}

/* O_PATH enforcement. */

#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

static void test_opath_read_fails(void)
{
    TEST("O_PATH fd rejects read");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    char buf[1];
    ssize_t n = read(fd, buf, 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "read should return EBADF");
}

static void test_opath_write_fails(void)
{
    TEST("O_PATH fd rejects write");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    ssize_t n = write(fd, "x", 1);
    close(fd);
    EXPECT_TRUE(n < 0 && errno == EBADF, "write should return EBADF");
}

static void test_opath_fstat_works(void)
{
    TEST("O_PATH fd allows fstat");
    int fd = open("/dev/null", O_PATH);
    if (fd < 0) {
        FAIL("open O_PATH");
        return;
    }
    struct stat st;
    int rc = fstat(fd, &st);
    close(fd);
    EXPECT_TRUE(rc == 0, "fstat should work on O_PATH");
}

/* madvise parity. */

static void test_madvise_cold(void)
{
    TEST("madvise MADV_COLD accepted");
    void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    int rc = madvise(p, 4096, MADV_COLD);
    munmap(p, 4096);
    EXPECT_TRUE(rc == 0, "madvise MADV_COLD");
}

static void test_madvise_dontneed_unmapped(void)
{
    TEST("madvise DONTNEED on unmapped returns ENOMEM");
    /* Map a page, then unmap the second half to create a hole */
    void *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    munmap((char *) p + 4096, 4096);
    /* MADV_DONTNEED across the boundary should fail */
    int rc = madvise(p, 8192, MADV_DONTNEED);
    munmap(p, 4096);
    EXPECT_TRUE(rc < 0 && errno == ENOMEM, "expected ENOMEM for unmapped hole");
}

/* mmap low-hint preservation. */

static void test_mmap_low_hint_exact(void)
{
    TEST("mmap low hint preserves ET_EXEC-style address");
    size_t len = 0x21000;
    static const uintptr_t candidates[] = {
        0x00400000ULL, 0x00800000ULL, 0x01000000ULL,
        0x02000000ULL, 0x04000000ULL, 0x06000000ULL,
    };
    void *hint = MAP_FAILED;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        hint = mmap((void *) candidates[i], len, PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (hint != MAP_FAILED)
            break;
        if (errno != EEXIST && errno != EINVAL) {
            FAIL("probe mmap");
            return;
        }
    }
    if (hint == MAP_FAILED) {
        FAIL("no free low hint candidate");
        return;
    }
    munmap(hint, len);

    void *p = mmap(hint, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        FAIL("mmap");
        return;
    }
    EXPECT_TRUE((uintptr_t) p == (uintptr_t) hint,
                "low mmap hint should be honored when range is free");
    munmap(p, len);
}

/* A dirfd that is open but not a directory (and has no host-nameable path,
 * e.g. a pipe) must resolve a relative path with ENOTDIR, not EBADF: the fd
 * itself is valid, it just cannot anchor a lookup. Issue #133.
 */
static void test_openat2_resolve_no_xdev_non_directory_dirfd_rejects_enotdir(
    void)
{
    TEST("openat2 RESOLVE_NO_XDEV non-directory dirfd rejects ENOTDIR");
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        FAIL("pipe");
        return;
    }
    close(pipefd[1]);

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_NO_XDEV};
    long fd = syscall(SYS_openat2, pipefd[0], "relative", &how, sizeof(how));
    close(pipefd[0]);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ENOTDIR, openat2 unexpectedly succeeded");
        return;
    }
    EXPECT_TRUE(errno == ENOTDIR, "wrong errno");
}

/* openat2() has no AT_EMPTY_PATH equivalent, so an empty pathname must always
 * fail ENOENT -- even under RESOLVE_IN_ROOT, whose "." substitution for the
 * empty-path case could otherwise resolve to dirfd itself. Issue #133.
 */
static void test_openat2_empty_path_rejects_enoent(void)
{
    TEST("openat2 empty path rejects ENOENT under RESOLVE_IN_ROOT");
    int dirfd = open("/tmp", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) {
        FAIL("open /tmp");
        return;
    }

    struct open_how how = {
        .flags = O_RDONLY, .mode = 0, .resolve = RESOLVE_IN_ROOT};
    long fd = syscall(SYS_openat2, dirfd, "", &how, sizeof(how));
    close(dirfd);
    if (fd >= 0) {
        close((int) fd);
        FAIL("expected ENOENT, openat2 unexpectedly succeeded");
        return;
    }
    EXPECT_TRUE(errno == ENOENT, "wrong errno");
}

int main(void)
{
    printf("Linux syscall fidelity tests:\n");

    /* fchmodat2 / getcpu */
    test_fchmodat2_basic();
    test_fchmodat2_symlink_nofollow();
    test_getcpu_basic();

    /* openat2 RESOLVE_* */
    test_openat2_basic();
    test_openat2_rejects_nonzero_how_extension();
    test_openat2_rejects_oversized_how();
    test_openat2_rejects_unknown_flags();
    test_openat2_rejects_mode_without_create();
    test_openat2_rejects_beneath_in_root();
    test_openat2_rejects_directory_create();
    test_openat2_rejects_tmpfile_readonly();
    test_openat2_resolve_beneath();
    test_openat2_resolve_beneath_allows_internal_dotdot();
    test_openat2_resolve_in_root_clamps_dotdot();
    test_openat2_resolve_no_symlinks_intermediate();
    test_openat2_resolve_beneath_rejects_symlink_escape();
    test_openat2_resolve_no_magiclinks_proc_fd();
    test_openat2_resolve_no_magiclinks_proc_cwd();
    test_openat2_resolve_no_xdev_rejects_proc();
    test_openat2_resolve_no_xdev_rejects_dev();
    test_openat2_resolve_no_xdev_allows_same_mount();
    test_openat2_resolve_no_xdev_absolute_ignores_dirfd_mount();
    test_openat2_resolve_no_xdev_rejects_relative_proc();
    test_openat2_resolve_no_xdev_rejects_relative_escape();
    test_openat2_resolve_no_xdev_allows_regular_proc_name();
    test_openat2_resolve_no_xdev_rejects_dev_shm_from_dev();
    test_openat2_resolve_no_xdev_rejects_relative_tmp();
    test_openat2_resolve_no_xdev_rejects_transient_proc();
    test_openat2_resolve_no_xdev_rejects_bare_proc();
    test_openat2_resolve_no_xdev_rejects_symlink_to_proc();
    test_openat2_resolve_no_xdev_in_root_clamps_dotdot();
    test_openat2_resolve_no_xdev_rejects_proc_fd_magiclink();
    test_openat2_rejects_proc_pid_fd_magiclink();
    test_openat2_resolve_no_xdev_rejects_dev_fd_magiclink();
    test_openat2_rejects_dev_fd_magiclink_variants();
    test_openat2_resolve_no_xdev_rejects_normalized_proc_fd_magiclink();
    test_openat2_resolve_no_xdev_non_directory_dirfd_rejects_enotdir();
    test_openat2_empty_path_rejects_enoent();

    /* O_PATH */
    test_opath_read_fails();
    test_opath_write_fails();
    test_opath_fstat_works();

    /* madvise */
    test_madvise_cold();
    test_madvise_dontneed_unmapped();

    /* mmap low-hint */
    test_mmap_low_hint_exact();

    printf("\ntest-syscall-fidelity: %d passed, %d failed, %d skipped%s\n",
           passes, fails, syscall_skips, fails == 0 ? " - PASS" : " - FAIL");
    return fails ? 1 : 0;
}
