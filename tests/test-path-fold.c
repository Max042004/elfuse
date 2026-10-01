/*
 * test-path-fold.c -- one object, one answer, however the path is spelled.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Linux steps over "//" runs and "." components in the path walk every path
 * syscall shares, so "//sys/bus", "/./sys/bus", "/sys/./bus" and "/sys//bus"
 * are "/sys/bus" to all of them. elfuse serves part of the namespace from
 * intercepts that match literal prefixes, and a name that reaches one unfolded
 * is answered by whoever its spelling happens to match: one entry point serves
 * it and the next reports ENOENT.
 *
 * Each name below is asked at every entry point under its canonical spelling,
 * and then again under six respellings. The canonical answer is the expected
 * one, so nothing here is recorded: a name this kernel or this build does not
 * have answers ENOENT under every spelling, and that agrees too.
 *
 * The last component is different: a "." or a slash that ends a name is not
 * noise but a requirement that the name resolve to a directory, and rmdir
 * refuses the "." outright. Each name is asked under both endings too, and held
 * to what Linux makes of them: a directory answers as itself, anything else
 * answers ENOTDIR. The second half asserts the creation side against the errno
 * Linux gives, with a symlink target beside it, which is stored as written
 * because it is not walked.
 *
 * Plain Linux path semantics throughout, so the reference kernel adjudicates it
 * and the test is registered in tests/test-matrix.sh.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static int checked;

/* An answer, rendered: what kind of object and, where the entry point has more
 * to say than that, what it said. Two spellings agree when the strings do.
 */
#define ANSWER_MAX 96

static void render_errno(char *out, int err)
{
    snprintf(out, ANSWER_MAX, "E%d", err);
}

static void render_stat(char *out, const struct stat *st)
{
    snprintf(out, ANSWER_MAX, "mode=%o rdev=%u:%u", (unsigned) st->st_mode,
             major(st->st_rdev), minor(st->st_rdev));
}

typedef void (*entry_fn)(const char *path, char *out);

static void do_stat(const char *path, char *out)
{
    struct stat st;
    if (stat(path, &st) < 0)
        render_errno(out, errno);
    else
        render_stat(out, &st);
}

static void do_lstat(const char *path, char *out)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        render_errno(out, errno);
    else
        render_stat(out, &st);
}

static void do_fstatat(const char *path, char *out)
{
    struct stat st;
    if (fstatat(AT_FDCWD, path, &st, AT_SYMLINK_NOFOLLOW) < 0)
        render_errno(out, errno);
    else
        render_stat(out, &st);
}

static void do_access(const char *path, char *out)
{
    if (access(path, F_OK) < 0)
        render_errno(out, errno);
    else
        snprintf(out, ANSWER_MAX, "ok");
}

/* O_NONBLOCK and O_NOCTTY so a device node neither parks the test nor becomes
 * its terminal. The descriptor's own identity is part of the answer: a name
 * served by one spelling and passed to the host by another opens either way and
 * only the fstat tells them apart.
 */
static void do_open(const char *path, char *out)
{
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) {
        render_errno(out, errno);
        return;
    }
    struct stat st;
    if (fstat(fd, &st) < 0)
        render_errno(out, errno);
    else
        render_stat(out, &st);
    close(fd);
}

static void do_statfs(const char *path, char *out)
{
    struct statfs sf;
    if (statfs(path, &sf) < 0)
        render_errno(out, errno);
    else
        snprintf(out, ANSWER_MAX, "type=%lx", (unsigned long) sf.f_type);
}

static void do_readlink(const char *path, char *out)
{
    char buf[ANSWER_MAX - 8];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0) {
        render_errno(out, errno);
        return;
    }
    buf[n] = '\0';
    snprintf(out, ANSWER_MAX, "-> %s", buf);
}

/* The number of entries, which is what a listing served by the wrong owner gets
 * wrong.
 */
static void do_getdents(const char *path, char *out)
{
    DIR *d = opendir(path);
    if (!d) {
        render_errno(out, errno);
        return;
    }
    int n = 0;
    while (readdir(d))
        n++;
    closedir(d);
    snprintf(out, ANSWER_MAX, "%d entries", n);
}

/* chdir and what getcwd then reports, in a child so the cwd of the test does
 * not move. getcwd names the directory, never the spelling that reached it.
 */
static void do_chdir(const char *path, char *out)
{
    int fds[2];
    if (pipe(fds) < 0) {
        render_errno(out, errno);
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        render_errno(out, errno);
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        char msg[ANSWER_MAX];
        close(fds[0]);
        if (chdir(path) < 0) {
            render_errno(msg, errno);
        } else {
            char cwd[ANSWER_MAX - 8];
            if (!getcwd(cwd, sizeof(cwd)))
                render_errno(msg, errno);
            else
                snprintf(msg, sizeof(msg), "cwd %s", cwd);
        }
        if (write(fds[1], msg, strlen(msg) + 1) < 0)
            _exit(1);
        _exit(0);
    }
    close(fds[1]);
    ssize_t n = read(fds[0], out, ANSWER_MAX - 1);
    close(fds[0]);
    out[n > 0 ? n : 0] = '\0';
    int status;
    waitpid(pid, &status, 0);
}

static const struct {
    const char *name;
    entry_fn fn;
} entries[] = {
    {"stat", do_stat},         {"lstat", do_lstat},
    {"fstatat", do_fstatat},   {"access", do_access},
    {"open", do_open},         {"statfs", do_statfs},
    {"readlink", do_readlink}, {"getdents", do_getdents},
    {"chdir", do_chdir},
};

#define N_ENTRIES (sizeof(entries) / sizeof(entries[0]))

/* Six respellings of an absolute name with at least two components. The last
 * two interleave a "." and a "//": stepping over the "." in "/.//x" uncovers a
 * "//" a finished first pass no longer sees, and "/././/x" is the same a turn
 * deeper.
 */
#define N_SPELLINGS 6


static int respell(const char *canon, int which, char *out, size_t outsz)
{
    const char *second = strchr(canon + 1, '/');
    if (!second)
        return -1;
    int head = (int) (second - canon);
    int n;
    switch (which) {
    case 0:
        n = snprintf(out, outsz, "/%s", canon);
        break;
    case 1:
        n = snprintf(out, outsz, "/.%s", canon);
        break;
    case 2:
        n = snprintf(out, outsz, "%.*s/.%s", head, canon, second);
        break;
    case 3:
        n = snprintf(out, outsz, "%.*s/%s", head, canon, second);
        break;
    case 4:
        n = snprintf(out, outsz, "/./%s", canon);
        break;
    default:
        n = snprintf(out, outsz, "/././%s", canon);
        break;
    }
    return n > 0 && (size_t) n < outsz ? 0 : -1;
}

/* What the canonical spelling says a respelling should answer. For the six
 * respellings that is the canonical answer itself. For "<canon>/." and
 * "<canon>/" it is the directory @canon resolves to, or ENOTDIR when it is not
 * one; a final symlink is followed to get there, so lstat and readlink answer
 * for the directory, not the link.
 */
static void expect(size_t e, const char *canon, bool trailing, char *want)
{
    const char *name = entries[e].name;
    struct stat st, lst;

    if (!trailing || stat(canon, &st) < 0) {
        entries[e].fn(canon, want);
        return;
    }
    bool is_link = lstat(canon, &lst) == 0 && S_ISLNK(lst.st_mode);
    if (!S_ISDIR(st.st_mode))
        render_errno(want, ENOTDIR);
    else if (is_link && (!strcmp(name, "lstat") || !strcmp(name, "fstatat")))
        do_stat(canon, want);
    else if (is_link && !strcmp(name, "readlink"))
        render_errno(want, EINVAL);
    else
        entries[e].fn(canon, want);
}

/* Ask @path, with the canonical answer taken on both sides of it. Some of these
 * directories list live state: /dev/fd lists the caller's descriptors and
 * /dev/shm what every process of the user has made, either of which can change
 * between two adjacent calls for reasons that have nothing to do with a
 * spelling. A canonical answer that moved during the sample is no answer to
 * hold the respelling to, so the sample is taken again; a respelling that
 * differs from a canonical answer that held still fails.
 */
#define SAMPLE_TRIES 8

static void check_one(size_t e,
                      const char *canon,
                      const char *path,
                      bool trailing)
{
    char want[ANSWER_MAX], got[ANSWER_MAX], after[ANSWER_MAX];

    checked++;
    for (int t = 0; t < SAMPLE_TRIES; t++) {
        expect(e, canon, trailing, want);
        entries[e].fn(path, got);
        expect(e, canon, trailing, after);
        if (strcmp(want, after) != 0)
            continue;
        if (strcmp(want, got) != 0) {
            printf("FAIL %s %s: %s, want %s as %s answers\n", entries[e].name,
                   path, got, want, canon);
            failures++;
        }
        return;
    }
    printf("FAIL %s %s: %s never answered the same twice in %d samples\n",
           entries[e].name, path, canon, SAMPLE_TRIES);
    failures++;
}

static void check_name(const char *canon)
{
    static const char *const endings[] = {"/.", "/"};
    char path[PATH_MAX];

    for (size_t e = 0; e < N_ENTRIES; e++) {
        for (int s = 0; s < N_SPELLINGS; s++)
            if (respell(canon, s, path, sizeof(path)) == 0)
                check_one(e, canon, path, false);
        for (size_t s = 0; s < 2; s++)
            if (snprintf(path, sizeof(path), "%s%s", canon, endings[s]) <
                (int) sizeof(path))
                check_one(e, canon, path, true);
    }
}

/* First entry of @dir that is not "." or "..", as "<dir>/<entry>". */
static int first_entry(const char *dir, char *out, size_t outsz)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    struct dirent *de;
    int rc = -1;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        int n = snprintf(out, outsz, "%s/%s", dir, de->d_name);
        if (n > 0 && (size_t) n < outsz)
            rc = 0;
        break;
    }
    closedir(d);
    return rc;
}

static void expect_errno(const char *what, int rc, int want)
{
    int got = rc < 0 ? errno : 0;
    checked++;
    if (got != want) {
        printf("FAIL %s: errno %d, want %d\n", what, got, want);
        failures++;
    }
}

/* The creation side. A "." that ends the name keeps the meaning Linux gives it
 * there, and a link target is not walked at all.
 */
static void check_last_component(void)
{
    char dir[] = "/tmp/test-path-fold-XXXXXX";
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        failures++;
        return;
    }

    char file[PATH_MAX], sub[PATH_MAX], path[PATH_MAX];
    snprintf(file, sizeof(file), "%s/f", dir);
    snprintf(sub, sizeof(sub), "%s/d", dir);
    int fd = open(file, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0 || mkdir(sub, 0700) < 0) {
        perror("setup");
        failures++;
        return;
    }
    close(fd);

    snprintf(path, sizeof(path), "%s//./d/.", dir);
    expect_errno("rmdir of a directory spelled d/.", rmdir(path), EINVAL);

    snprintf(path, sizeof(path), "%s/.//d/", dir);
    expect_errno("rmdir of a directory spelled d/", rmdir(path), 0);

    /* A link's target is data, not a path being walked: it is stored as written
     * and read back the same, noise included.
     */
    static const char target[] = "/tmp//no/./such/.";
    char link[PATH_MAX], back[sizeof(target) + 8];
    snprintf(link, sizeof(link), "%s//./l", dir);
    expect_errno("symlink with a noisy target", symlink(target, link), 0);
    ssize_t n = readlink(link, back, sizeof(back) - 1);
    back[n > 0 ? n : 0] = '\0';
    checked++;
    if (strcmp(back, target) != 0) {
        printf("FAIL readlink: target reads back \"%s\", want \"%s\"\n", back,
               target);
        failures++;
    }
    expect_errno("unlink of the link", unlink(link), 0);

    snprintf(path, sizeof(path), "%s/./f", dir);
    expect_errno("unlink through an interior .", unlink(path), 0);
    expect_errno("rmdir of the scratch directory", rmdir(dir), 0);
}

int main(void)
{
    /* One name from each owner the namespace has: procfs, the host's own /dev,
     * the devpts and shm directories, sysfs and its CPU subtree, the synthetic
     * USB trees, the synthesized /etc files, and a directory nothing
     * intercepts. The USB names are absent on a machine with no device and no
     * fixture, which agrees under every spelling like any other absence.
     */
    static const char *const names[] = {
        "/proc/self/status",
        "/proc/self/exe",
        "/proc/sys/kernel",
        "/dev/null",
        "/dev/urandom",
        "/dev/pts",
        "/dev/shm",
        "/dev/fd",
        "/dev/stdout",
        "/sys/devices",
        "/sys/devices/system/cpu/online",
        "/sys/bus/usb/devices",
        "/dev/bus/usb",
        "/etc/passwd",
        "/etc/mtab",
        "/tmp/no-such-name-here",
    };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        check_name(names[i]);

    /* A device directory and the node inside it, discovered: their numbers are
     * the host's, and the node is two components below the literal the layer
     * that serves it matches.
     */
    char busdir[PATH_MAX], node[PATH_MAX], sysdev[PATH_MAX];
    if (first_entry("/dev/bus/usb", busdir, sizeof(busdir)) == 0) {
        check_name(busdir);
        if (first_entry(busdir, node, sizeof(node)) == 0)
            check_name(node);
    }
    if (first_entry("/sys/bus/usb/devices", sysdev, sizeof(sysdev)) == 0)
        check_name(sysdev);

    check_last_component();

    if (!failures)
        printf("PASS: %d answers agree with the canonical spelling\n", checked);
    printf("%d failed\n", failures);
    return failures ? 1 : 0;
}
