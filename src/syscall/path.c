/*
 * Shared guest/host path handling
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include "utils.h"

#include "syscall/abi.h"
#include "syscall/fuse.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/sidecar.h"

#ifndef MAXSYMLINKS
#define MAXSYMLINKS 40
#endif

#define PROC_PATH_COMPONENTS_MAX (LINUX_PATH_MAX / 2)

/* True when path equals prefix exactly, or extends it with '/'. Avoids the
 * surprise where "/sys/devices/system/cpufoo" would match a bare strncmp on
 * "/sys/devices/system/cpu" and pull an unrelated path through the intercept
 * layer.
 */
static bool path_prefix_match(const char *path, const char *prefix, size_t plen)
{
    if (strncmp(path, prefix, plen) != 0)
        return false;
    return path[plen] == '\0' || path[plen] == '/';
}

#define SYSFS_CPU_PREFIX "/sys/devices/system/cpu"

bool path_might_use_open_intercept(const char *path)
{
    if (!path || path[0] != '/')
        return false;

    if (!strncmp(path, "/proc", 5))
        return true;
    if (!strncmp(path, "/dev", 4))
        return true;
    if (fuse_path_matches_mount(path))
        return true;
    if (path_prefix_match(path, SYSFS_CPU_PREFIX, sizeof(SYSFS_CPU_PREFIX) - 1))
        return true;
    if (!strcmp(path, "/etc/mtab") || !strcmp(path, "/etc/passwd") ||
        !strcmp(path, "/etc/group"))
        return true;
    if (!strcmp(path, "/var/run/utmp") || !strcmp(path, "/run/utmp"))
        return true;

    return false;
}

bool path_might_use_stat_intercept(const char *path)
{
    if (!path || path[0] != '/')
        return false;

    if (!strncmp(path, "/proc", 5))
        return true;
    if (!strncmp(path, "/dev/shm", 8))
        return true;
    if (!strcmp(path, "/dev/fuse"))
        return true;
    /* glibc ptsname(3) stats /dev/pts/N after TIOCGPTN to confirm the slave
     * exists and is a char device; without this the stat falls through to the
     * host where /dev/pts is absent and ptsname returns ENOENT.
     */
    if (!strncmp(path, "/dev/pts/", 9) || !strcmp(path, "/dev/pts") ||
        !strcmp(path, "/dev/pts/"))
        return true;
    if (fuse_path_matches_mount(path))
        return true;
    if (path_prefix_match(path, SYSFS_CPU_PREFIX, sizeof(SYSFS_CPU_PREFIX) - 1))
        return true;

    return false;
}

int path_check_intercept_access(const struct stat *st, int mode, int flags)
{
    if ((mode & ~(F_OK | R_OK | W_OK | X_OK)) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (mode == F_OK)
        return 0;

    mode_t granted = 0;
    uint32_t uid =
        (flags & LINUX_AT_EACCESS) ? proc_get_euid() : proc_get_uid();
    uint32_t gid =
        (flags & LINUX_AT_EACCESS) ? proc_get_egid() : proc_get_gid();

    if (uid == 0) {
        /* CAP_DAC_OVERRIDE: root reads and writes any file regardless of mode
         * bits. Execute still requires at least one x-bit set so non-executable
         * files cannot be run as root. Matches Linux generic_permission() in
         * fs/namei.c.
         */
        granted |= R_OK | W_OK;
        if (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
            granted |= X_OK;
    } else {
        mode_t bits;
        if (uid == st->st_uid)
            bits = (st->st_mode >> 6) & 7;
        else if (gid == st->st_gid)
            bits = (st->st_mode >> 3) & 7;
        else
            bits = st->st_mode & 7;

        if (bits & 4)
            granted |= R_OK;
        if (bits & 2)
            granted |= W_OK;
        if (bits & 1)
            granted |= X_OK;
    }

    if ((mode & granted) == mode)
        return 0;

    errno = EACCES;
    return -1;
}

int path_translate_at(guest_fd_t dirfd,
                      const char *path,
                      unsigned int flags,
                      path_translation_t *tx)
{
    if (!tx) {
        errno = EINVAL;
        return -1;
    }

    /* Only the fields read on the no-rewrite fast path need explicit defaults;
     * proc_path / guest_buf / host_buf are read-after-written by their
     * respective resolvers. memset of all three 4 KiB buffers would add ~12 KiB
     * of zeroing per call, which became visible at ~30 calls per dynamic-linker
     * startup after the sidecar caches dropped the rest of the openat overhead.
     */
    tx->guest_path = path;
    tx->intercept_path = path;
    tx->host_path = path;
    tx->proc_resolved = 0;
    tx->fuse_path = false;

    if (!path)
        return 0;

    tx->proc_resolved =
        resolve_proc_at_path(dirfd, path, tx->proc_path, sizeof(tx->proc_path));
    if (tx->proc_resolved < 0)
        return -1;
    if (tx->proc_resolved > 0) {
        tx->guest_path = tx->proc_path;
        tx->intercept_path = tx->proc_path;
    } else {
        int fuse_rc = fuse_resolve_at_path(dirfd, path, tx->guest_buf,
                                           sizeof(tx->guest_buf));
        if (fuse_rc < 0)
            return -1;
        if (fuse_rc > 0) {
            tx->guest_path = tx->guest_buf;
            tx->intercept_path = tx->guest_buf;
            tx->fuse_path = true;
        }
    }

    errno = 0;
    if ((flags & PATH_TR_CREATE) && sidecar_active() &&
        sidecar_path_targets_reserved_name(tx->guest_path)) {
        errno = ENOENT;
        return -1;
    }

    if (flags & PATH_TR_CREATE) {
        tx->host_path = path_resolve_sysroot_create_path(
            tx->guest_path, tx->host_buf, sizeof(tx->host_buf),
            (flags & PATH_TR_CREATE_PARENTS) != 0);
    } else if (flags & PATH_TR_NOFOLLOW) {
        tx->host_path = path_resolve_sysroot_nofollow_path(
            tx->guest_path, tx->host_buf, sizeof(tx->host_buf));
    } else {
        tx->host_path = path_resolve_sysroot_path(tx->guest_path, tx->host_buf,
                                                  sizeof(tx->host_buf));
    }

    /* Sidecar only runs after sysroot resolution succeeds. If the resolver
     * rejected the path (e.g. nofollow containment violation), sidecar must not
     * be allowed to walk an alternate index and resurrect the rejected target.
     */
    if (tx->host_path && !(flags & PATH_TR_CREATE)) {
        int sidecar_rc = sidecar_translate_lookup_at(
            dirfd, tx->guest_path, tx->host_buf, sizeof(tx->host_buf));
        if (sidecar_rc < 0)
            return -1;
        if (sidecar_rc > 0)
            tx->host_path = tx->host_buf;
    }

    if (!tx->host_path) {
        /* Resolvers set errno on every failure path; only synthesize one if a
         * future caller forgets, so the error class survives instead of being
         * flattened to ENAMETOOLONG.
         */
        if (errno == 0)
            errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

int path_translate_dirent_name(guest_fd_t dirfd,
                               const char *host_name,
                               char *guest_name,
                               size_t guest_name_sz)
{
    if (!host_name || !guest_name || guest_name_sz == 0) {
        errno = EINVAL;
        return -1;
    }

    guest_name[0] = '\0';
    int sidecar_rc = sidecar_translate_dirent_name(dirfd, host_name, guest_name,
                                                   guest_name_sz);
    if (sidecar_rc < 0)
        return sidecar_rc;
    if (sidecar_rc > 0)
        return sidecar_rc;
    if (guest_name[0] != '\0')
        return 0;

    size_t len = strlen(host_name);
    if (len + 1 > guest_name_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(guest_name, host_name, len + 1);
    return 0;
}

static bool path_next_component(const char **pathp,
                                const char **comp,
                                size_t *len)
{
    const char *p = *pathp;

    while (*p == '/')
        p++;
    if (*p == '\0') {
        *pathp = p;
        return false;
    }

    *comp = p;
    while (*p != '\0' && *p != '/')
        p++;
    *len = (size_t) (p - *comp);
    *pathp = p;
    return true;
}

static bool path_component_is_dot(const char *comp, size_t len)
{
    return len == 1 && comp[0] == '.';
}

const char *path_resolve_sysroot_path(const char *path, char *buf, size_t bufsz)
{
    return proc_resolve_sysroot_path(path, buf, bufsz);
}

const char *path_resolve_sysroot_nofollow_path(const char *path,
                                               char *buf,
                                               size_t bufsz)
{
    return proc_resolve_sysroot_nofollow_path(path, buf, bufsz);
}

const char *path_resolve_sysroot_create_path(const char *path,
                                             char *buf,
                                             size_t bufsz,
                                             bool create_parents)
{
    return proc_resolve_sysroot_create_path(path, buf, bufsz, create_parents);
}

int sys_path_has_symlink(guest_fd_t dirfd, const char *path)
{
    if (!path || path[0] == '\0')
        return 0;

    host_fd_t base_fd;
    bool owned_base_fd = false;
    const char *scan = path;
    char sysroot_buf[LINUX_PATH_MAX];

    if (path[0] == '/') {
        const char *host_path = path_resolve_sysroot_nofollow_path(
            path, sysroot_buf, sizeof(sysroot_buf));
        if (!host_path) {
            errno = ENAMETOOLONG;
            return -1;
        }
        base_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (base_fd < 0)
            return -1;
        owned_base_fd = true;
        scan = host_path;
    } else {
        host_fd_ref_t dir_ref;
        if (host_dirfd_ref_open(dirfd, &dir_ref) < 0) {
            errno = EBADF;
            return -1;
        }
        if (dir_ref.fd == AT_FDCWD) {
            base_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (base_fd < 0)
                return -1;
            owned_base_fd = true;
        } else {
            base_fd = dir_ref.fd;
            owned_base_fd = dir_ref.owned;
        }
    }

    host_fd_t current_fd = base_fd;
    bool owned_current_fd = owned_base_fd;
    const char *comp;
    size_t len;
    int rc = 0;
    int walk_count = 0;

    while (path_next_component(&scan, &comp, &len)) {
        if (++walk_count > MAXSYMLINKS) {
            errno = ELOOP;
            rc = -1;
            goto out;
        }
        if (path_component_is_dot(comp, len))
            continue;

        char name[NAME_MAX + 1];
        if (len > NAME_MAX) {
            errno = ENAMETOOLONG;
            rc = -1;
            goto out;
        }
        memcpy(name, comp, len);
        name[len] = '\0';

        struct stat st;
        if (fstatat(current_fd, name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            rc = -1;
            goto out;
        }
        if (S_ISLNK(st.st_mode)) {
            errno = ELOOP;
            rc = -1;
            goto out;
        }

        const char *rest = scan;
        while (*rest == '/')
            rest++;
        if (*rest == '\0')
            break;
        if (!S_ISDIR(st.st_mode)) {
            errno = ENOTDIR;
            rc = -1;
            goto out;
        }

        host_fd_t next_fd =
            openat(current_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (next_fd < 0) {
            rc = -1;
            goto out;
        }
        if (owned_current_fd)
            close(current_fd);
        current_fd = next_fd;
        owned_current_fd = true;
    }

out:
    if (owned_current_fd && current_fd >= 0)
        close(current_fd);
    return rc;
}

static int proc_push_component(char *out,
                               size_t outsz,
                               size_t marks[],
                               size_t *depth,
                               const char *comp,
                               size_t len)
{
    size_t cur = strlen(out);
    size_t write_pos = cur;

    if (cur == 1 && out[0] == '/') {
        if (cur + len >= outsz)
            return -1;
        marks[*depth] = cur;
        memcpy(out + cur, comp, len);
        out[cur + len] = '\0';
        (*depth)++;
        return 0;
    }

    if (cur + 1 + len >= outsz)
        return -1;

    marks[*depth] = write_pos;
    out[write_pos] = '/';
    memcpy(out + write_pos + 1, comp, len);
    out[write_pos + 1 + len] = '\0';
    (*depth)++;
    return 0;
}

static int proc_apply_components(const char *path,
                                 char *out,
                                 size_t outsz,
                                 size_t marks[],
                                 size_t marks_cap,
                                 size_t *depth)
{
    const char *seg = path;
    while (*seg) {
        while (*seg == '/')
            seg++;
        if (*seg == '\0')
            break;

        const char *end = seg;
        while (*end != '\0' && *end != '/')
            end++;

        size_t len = (size_t) (end - seg);
        if (len == 1 && seg[0] == '.') {
            seg = end;
            continue;
        }
        if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (*depth > 0) {
                *depth -= 1;
                out[marks[*depth]] = '\0';
            }
            seg = end;
            continue;
        }
        if (*depth >= marks_cap) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (proc_push_component(out, outsz, marks, depth, seg, len) < 0)
            return -1;
        seg = end;
    }
    return 0;
}

static int proc_seed_absolute_path(const char *path,
                                   char *out,
                                   size_t outsz,
                                   size_t marks[],
                                   size_t marks_cap,
                                   size_t *depth)
{
    *depth = 0;
    str_copy_trunc(out, "/", outsz);
    return proc_apply_components(path, out, outsz, marks, marks_cap, depth);
}

int resolve_proc_dirfd_path(guest_fd_t dirfd,
                            const char *path,
                            char *out,
                            size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD || !path || path[0] == '/')
        return 0;

    fd_entry_t snap;
    if (!fd_snapshot(dirfd, &snap) || snap.type != FD_DIR ||
        snap.proc_path[0] == '\0')
        return 0;

    size_t marks[PROC_PATH_COMPONENTS_MAX];
    size_t depth;
    if (proc_seed_absolute_path(snap.proc_path, out, outsz, marks,
                                ARRAY_SIZE(marks), &depth) < 0 ||
        proc_apply_components(path, out, outsz, marks, ARRAY_SIZE(marks),
                              &depth) < 0) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 1;
}

static int resolve_proc_cwd_path(const char *path, char *out, size_t outsz)
{
    if (!path || path[0] == '\0' || path[0] == '/')
        return 0;

    proc_cwd_view_t view;
    if (proc_acquire_cwd_view(&view) < 0)
        return 0;

    int rc = 0;
    if (!strncmp(view.path, "/proc", 5)) {
        size_t marks[PROC_PATH_COMPONENTS_MAX];
        size_t depth;
        if (proc_seed_absolute_path(view.path, out, outsz, marks,
                                    ARRAY_SIZE(marks), &depth) < 0 ||
            proc_apply_components(path, out, outsz, marks, ARRAY_SIZE(marks),
                                  &depth) < 0) {
            errno = ENAMETOOLONG;
            rc = -1;
        } else {
            rc = 1;
        }
    }

    proc_release_cwd_view(&view);
    return rc;
}

int resolve_proc_at_path(guest_fd_t dirfd,
                         const char *path,
                         char *out,
                         size_t outsz)
{
    if (!path || path[0] == '\0' || path[0] == '/')
        return 0;

    int rc = resolve_proc_dirfd_path(dirfd, path, out, outsz);
    if (rc != 0 || dirfd != LINUX_AT_FDCWD)
        return rc;

    return resolve_proc_cwd_path(path, out, outsz);
}

int path_openat2_stays_beneath(const char *path, bool clamp_at_root)
{
    int depth = 0;
    const char *p = path;

    while (*p) {
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        const char *start = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - start);

        if (len == 1 && start[0] == '.')
            continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth == 0) {
                if (!clamp_at_root)
                    return 0;
            } else {
                depth--;
            }
            continue;
        }
        depth++;
    }

    return 1;
}

int path_openat2_normalize_in_root(const char *path, char *out, size_t outsz)
{
    size_t depth = 0;
    size_t marks[LINUX_PATH_MAX / 2];
    size_t out_len = 0;
    const char *p = path;

    if (outsz == 0)
        return -1;
    out[0] = '\0';

    while (*p) {
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        const char *start = p;
        while (*p && *p != '/')
            p++;
        size_t len = (size_t) (p - start);

        if (len == 1 && start[0] == '.')
            continue;
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth > 0) {
                out_len = marks[depth - 1];
                out[out_len] = '\0';
                depth--;
            }
            continue;
        }

        if (depth >= (LINUX_PATH_MAX / 2))
            return -1;

        marks[depth] = out_len;
        if (out_len != 0) {
            if (out_len + 1 >= outsz)
                return -1;
            out[out_len++] = '/';
        }
        if (out_len + len >= outsz)
            return -1;
        memcpy(out + out_len, start, len);
        out_len += len;
        out[out_len] = '\0';
        depth++;
    }

    if (out_len == 0) {
        if (outsz < 2)
            return -1;
        out[0] = '.';
        out[1] = '\0';
    }

    return 0;
}

static int path_openat2_dirfd_host_path(guest_fd_t dirfd,
                                        char *out,
                                        size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD) {
        /* getcwd into a provably non-NULL local buffer, then copy. Writing
         * straight into the caller pointer trips a false-positive leak in
         * static analyzers that model getcwd(NULL, ...) as allocating.
         */
        char cwd[LINUX_PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd)))
            return -1;
        size_t n = strlen(cwd) + 1;
        if (n > outsz) {
            errno = ERANGE;
            return -1;
        }
        memcpy(out, cwd, n);
        return 0;
    }

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0) {
        errno = EBADF;
        return -1;
    }
    int rc = fcntl(dir_ref.fd, F_GETPATH, out);
    host_fd_ref_close(&dir_ref);
    return rc < 0 ? -1 : 0;
}

int path_openat2_resolved_within_root(guest_fd_t dirfd,
                                      const char *path,
                                      uint64_t oflags,
                                      bool in_root)
{
    char root_path[LINUX_PATH_MAX], joined[LINUX_PATH_MAX];
    char real_root[LINUX_PATH_MAX], real_path[LINUX_PATH_MAX];
    const char *rel = path;
    char normalized[LINUX_PATH_MAX];

    if (path_openat2_dirfd_host_path(dirfd, root_path, sizeof(root_path)) < 0)
        return -1;
    if (!realpath(root_path, real_root))
        return -1;

    if (in_root) {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0) {
            errno = ENAMETOOLONG;
            return -1;
        }
        rel = normalized;
    } else if (path[0] == '/') {
        errno = EXDEV;
        return -1;
    }

    if (*rel == '\0')
        rel = ".";

    if (snprintf(joined, sizeof(joined), "%s/%s", real_root, rel) >=
        (int) sizeof(joined)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    bool follow_final = true;
    if (oflags & LINUX_O_NOFOLLOW)
        follow_final = false;
    if (oflags & LINUX_O_CREAT)
        follow_final = false;

    if (follow_final) {
        if (!realpath(joined, real_path))
            return -1;
    } else {
        char parent[LINUX_PATH_MAX];
        char *slash;

        str_copy_trunc(parent, joined, sizeof(parent));
        slash = strrchr(parent, '/');
        if (!slash)
            return -1;
        if (slash == parent) {
            parent[1] = '\0';
        } else {
            *slash = '\0';
        }
        if (!realpath(parent, real_path))
            return -1;

        size_t parent_len = strlen(real_path);
        const char *tail = (slash == parent) ? joined + 1 : slash + 1;
        if (snprintf(real_path + parent_len, sizeof(real_path) - parent_len,
                     "/%s", tail) >= (int) (sizeof(real_path) - parent_len)) {
            errno = ENAMETOOLONG;
            return -1;
        }
    }

    size_t root_len = strlen(real_root);
    if (strncmp(real_path, real_root, root_len) != 0 ||
        (real_path[root_len] != '\0' && real_path[root_len] != '/')) {
        errno = EXDEV;
        return -1;
    }

    return 0;
}

/* Mount-class taxonomy used by RESOLVE_NO_XDEV. Distinct return values mean
 * distinct logical filesystems from the guest's perspective. FUSE mounts encode
 * mount_id into the high bits so two distinct FUSE mounts compare unequal.
 */
#define PATH_MOUNT_ROOT 0
#define PATH_MOUNT_PROC 1
#define PATH_MOUNT_DEV 2
#define PATH_MOUNT_SYS 3
#define PATH_MOUNT_TMP 4
#define PATH_MOUNT_DEV_SHM 5
/* fuse_next_mount_id is a monotonic int starting at 100 (see fuse.c). The base
 * is sized well clear of any realistic mount_id so the four non-FUSE classes
 * never collide with the FUSE class numbers even after hundreds of millions of
 * mount cycles. mount_id values that ever do approach this bound would
 * represent a runtime that long outlived elfuse's intended lifetime.
 */
#define PATH_MOUNT_FUSE_BASE 0x10000000

static int classify_guest_path_mount(const char *guest_path)
{
    if (!guest_path || guest_path[0] != '/')
        return -1;

    int fuse_id = fuse_path_mount_id(guest_path);
    if (fuse_id >= 0)
        return PATH_MOUNT_FUSE_BASE + fuse_id;

    if (path_prefix_match(guest_path, "/proc", 5))
        return PATH_MOUNT_PROC;
    if (path_prefix_match(guest_path, "/tmp", 4))
        return PATH_MOUNT_TMP;
    if (path_prefix_match(guest_path, "/dev/shm", 8))
        return PATH_MOUNT_DEV_SHM;
    if (path_prefix_match(guest_path, "/dev", 4))
        return PATH_MOUNT_DEV;
    if (path_prefix_match(guest_path, "/sys", 4))
        return PATH_MOUNT_SYS;

    return PATH_MOUNT_ROOT;
}

static int host_path_to_guest_path(const char *host_path,
                                   char *out,
                                   size_t outsz)
{
    char sysroot[LINUX_PATH_MAX];
    const char *guest_path = host_path;

    if (proc_sysroot_snapshot(sysroot, sizeof(sysroot))) {
        size_t sysroot_len = strlen(sysroot);
        if (!strncmp(host_path, sysroot, sysroot_len) &&
            (host_path[sysroot_len] == '\0' || host_path[sysroot_len] == '/')) {
            guest_path = host_path + sysroot_len;
            if (*guest_path == '\0')
                guest_path = "/";
        }
    }

    size_t len = str_copy_trunc(out, guest_path, outsz);
    if (len >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int dirfd_guest_base_path(guest_fd_t dirfd, char *out, size_t outsz)
{
    if (dirfd == LINUX_AT_FDCWD) {
        proc_cwd_view_t view;
        if (proc_acquire_cwd_view(&view) < 0) {
            errno = EBADF;
            return -1;
        }
        size_t len = str_copy_trunc(out, view.path, outsz);
        proc_release_cwd_view(&view);
        if (len >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    fd_entry_t snap;
    if (!fd_snapshot(dirfd, &snap)) {
        errno = EBADF;
        return -1;
    }
    if (snap.proc_path[0] != '\0') {
        size_t len = str_copy_trunc(out, snap.proc_path, outsz);
        if (len >= outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        return 0;
    }

    if (snap.type == FD_FUSE_DIR) {
        int rc = fuse_resolve_at_path(dirfd, ".", out, outsz);
        if (rc < 0)
            return -1;
        if (rc > 0)
            return 0;
    }

    char host_path[LINUX_PATH_MAX];
    if (path_openat2_dirfd_host_path(dirfd, host_path, sizeof(host_path)) == 0)
        return host_path_to_guest_path(host_path, out, outsz);

    /* fd_snapshot already proved dirfd is open, so a valid-but-wrong-type fd
     * (pipe, socket, epoll, ...) belongs here, not in the "bad fd" case: Linux
     * resolves a relative path against such a dirfd with ENOTDIR, reserving
     * EBADF for a closed or out-of-range descriptor.
     */
    if (snap.type != FD_DIR) {
        errno = ENOTDIR;
        return -1;
    }

    /* Some host-backed directory handles cannot be named back through
     * F_GETPATH. Keep a root-class fallback for those rare cases so regular
     * relative paths can still proceed.
     */
    out[0] = '/';
    out[1] = '\0';
    return 0;
}

static bool normalized_proc_self_fd_anchor(const char *path)
{
    if (!strncmp(path, "proc/self/fd/", 13))
        return true;
    if (strncmp(path, "proc/", 5))
        return false;

    char *endp;
    const char *pid_start = path + sizeof("proc/") - 1;
    errno = 0;
    long long pid = strtoll(pid_start, &endp, 10);
    if (endp == pid_start || errno == ERANGE ||
        pid != (long long) proc_get_pid())
        return false;
    return strncmp(endp, "/fd/", 4) == 0;
}

bool path_openat2_is_fd_magiclink_anchor(guest_fd_t dirfd, const char *path)
{
    if (!path)
        return false;

    char normalized[LINUX_PATH_MAX];

    if (path[0] == '/') {
        if (path_openat2_normalize_in_root(path, normalized,
                                           sizeof(normalized)) < 0)
            return false;
    } else {
        char base[LINUX_PATH_MAX];
        char joined[LINUX_PATH_MAX];
        if (dirfd_guest_base_path(dirfd, base, sizeof(base)) < 0)
            return false;
        if (snprintf(joined, sizeof(joined), "%s/%s", base, path) >=
            (int) sizeof(joined))
            return false;
        if (path_openat2_normalize_in_root(joined, normalized,
                                           sizeof(normalized)) < 0)
            return false;
    }

    return strncmp(normalized, "dev/fd/", 7) == 0 ||
           normalized_proc_self_fd_anchor(normalized);
}

/* Pop one trailing component from an absolute path, refusing to drop below the
 * supplied floor length. floor_len is strlen of the walk root (1 == "/" for the
 * bare-absolute case, dirfd-base length for IN_ROOT resolution). At the floor
 * the path is left unchanged, matching Linux's ".." at "/" semantics and
 * RESOLVE_IN_ROOT's clamp-at-dirfd rule.
 */
static void guest_path_pop(char *current, size_t floor_len)
{
    size_t len = strlen(current);
    if (len <= floor_len)
        return;
    char *slash = strrchr(current, '/');
    if (!slash || slash == current) {
        current[0] = '/';
        current[1] = '\0';
        return;
    }
    if ((size_t) (slash - current) < floor_len)
        return;
    *slash = '\0';
}

static int guest_path_append(char *current,
                             size_t currentsz,
                             const char *comp,
                             size_t len)
{
    size_t cur_len = strlen(current);
    bool need_slash = (cur_len == 0 || current[cur_len - 1] != '/');
    size_t want = cur_len + (need_slash ? 1 : 0) + len + 1;
    if (want > currentsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (need_slash)
        current[cur_len++] = '/';
    memcpy(current + cur_len, comp, len);
    current[cur_len + len] = '\0';
    return 0;
}

static int open_guest_walk_root_fd(guest_fd_t dirfd,
                                   bool absolute,
                                   host_fd_t *out)
{
    if (absolute) {
        char sysroot[LINUX_PATH_MAX];
        const char *root = "/";
        if (proc_sysroot_snapshot(sysroot, sizeof(sysroot)))
            root = sysroot;
        *out = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        return *out < 0 ? -1 : 0;
    }

    host_fd_ref_t dir_ref;
    if (host_dirfd_ref_open(dirfd, &dir_ref) < 0) {
        errno = EBADF;
        return -1;
    }

    if (dir_ref.fd == AT_FDCWD)
        *out = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    else
        *out = dup(dir_ref.fd);
    host_fd_ref_close(&dir_ref);
    return *out < 0 ? -1 : 0;
}

static int replace_walk_fd(host_fd_t *current_fd, host_fd_t next_fd)
{
    if (next_fd < 0)
        return -1;
    if (*current_fd >= 0)
        close(*current_fd);
    *current_fd = next_fd;
    return 0;
}

static int reset_walk_fd(host_fd_t *current_fd, host_fd_t root_fd)
{
    host_fd_t next_fd = dup(root_fd);
    if (next_fd < 0)
        return -1;
    return replace_walk_fd(current_fd, next_fd);
}

int path_openat2_crosses_mount(guest_fd_t dirfd,
                               const char *path,
                               bool in_root,
                               int *out_start_class)
{
    if (out_start_class)
        *out_start_class = -1;
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    char current[LINUX_PATH_MAX];
    const char *walk = path;
    char pending[LINUX_PATH_MAX];
    host_fd_t current_fd = -1;
    host_fd_t root_fd = -1;
    host_fd_t absolute_root_fd = -1;
    bool host_walk = true;
    int symlink_count = 0;
    int rc = -1;

    /* The walk has to track every intermediate prefix because lexical
     * collapsing of ".." would erase a transient mount crossing (e.g.
     * "/proc/self/../../tmp" passes through /proc before the upward components
     * apply, and Linux NO_XDEV detects that). The start frame matches how the
     * kernel anchors resolution: absolute paths begin at "/" regardless of
     * dirfd; relative paths and RESOLVE_IN_ROOT begin at the dirfd's tracked
     * guest path.
     */
    if (path[0] == '/' && !in_root) {
        current[0] = '/';
        current[1] = '\0';
    } else if (dirfd_guest_base_path(dirfd, current, sizeof(current)) < 0) {
        goto out;
    }

    /* IN_ROOT clamps ".." at dirfd; outside IN_ROOT the walker can traverse up
     * to "/" so a transition like /proc/1 -> /proc -> / surfaces as the
     * expected cross. The floor matches whichever rule applies so the precheck
     * never out-rejects the actual resolution that follows in
     * path_openat2_normalize_in_root.
     */
    size_t floor_len = in_root ? strlen(current) : 1;

    int start_class = classify_guest_path_mount(current);
    if (start_class < 0) {
        errno = EINVAL;
        goto out;
    }
    if (out_start_class)
        *out_start_class = start_class;

    if (open_guest_walk_root_fd(dirfd, path[0] == '/' && !in_root,
                                &current_fd) < 0) {
        if (path[0] == '/' || errno != EBADF)
            goto out;
        host_walk = false;
        errno = 0;
    }
    if (host_walk) {
        root_fd = dup(current_fd);
        if (root_fd < 0)
            goto out;
        if (open_guest_walk_root_fd(LINUX_AT_FDCWD, true, &absolute_root_fd) <
            0)
            goto out;
    }

    while (*walk) {
        while (*walk == '/')
            walk++;
        if (!*walk)
            break;

        const char *comp = walk;
        while (*walk && *walk != '/')
            walk++;
        size_t len = (size_t) (walk - comp);

        if (len == 1 && comp[0] == '.')
            continue;

        if (len == 2 && comp[0] == '.' && comp[1] == '.') {
            size_t before_len = strlen(current);
            guest_path_pop(current, floor_len);
            if (host_walk && strlen(current) < before_len) {
                host_fd_t parent_fd = openat(
                    current_fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (replace_walk_fd(&current_fd, parent_fd) < 0)
                    goto out;
            }
        } else {
            char name[NAME_MAX + 1];
            char parent[LINUX_PATH_MAX];
            if (len > NAME_MAX) {
                errno = ENAMETOOLONG;
                goto out;
            }
            memcpy(name, comp, len);
            name[len] = '\0';
            if (str_copy_trunc(parent, current, sizeof(parent)) >=
                sizeof(parent)) {
                errno = ENAMETOOLONG;
                goto out;
            }

            struct stat st;
            if (host_walk &&
                fstatat(current_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
                if (S_ISLNK(st.st_mode)) {
                    if (guest_path_append(current, sizeof(current), comp, len) <
                        0)
                        goto out;

                    int cls = classify_guest_path_mount(current);
                    if (cls < 0) {
                        errno = EINVAL;
                        goto out;
                    }
                    if (cls != start_class) {
                        rc = 1;
                        goto out;
                    }
                    str_copy_trunc(current, parent, sizeof(current));

                    char target[LINUX_PATH_MAX];
                    ssize_t target_len = readlinkat(current_fd, name, target,
                                                    sizeof(target) - 1);
                    if (target_len < 0)
                        goto out;
                    if (++symlink_count > MAXSYMLINKS) {
                        errno = ELOOP;
                        goto out;
                    }
                    target[target_len] = '\0';

                    char rest_buf[LINUX_PATH_MAX];
                    const char *rest = walk;
                    while (*rest == '/')
                        rest++;
                    if (str_copy_trunc(rest_buf, rest, sizeof(rest_buf)) >=
                        sizeof(rest_buf)) {
                        errno = ENAMETOOLONG;
                        goto out;
                    }
                    if (snprintf(pending, sizeof(pending), "%s%s%s", target,
                                 rest_buf[0] ? "/" : "",
                                 rest_buf) >= (int) sizeof(pending)) {
                        errno = ENAMETOOLONG;
                        goto out;
                    }
                    walk = pending;

                    if (target[0] == '/') {
                        host_fd_t reset_fd =
                            in_root ? root_fd : absolute_root_fd;
                        if (reset_walk_fd(&current_fd, reset_fd) < 0)
                            goto out;
                        if (in_root) {
                            if (dirfd_guest_base_path(dirfd, current,
                                                      sizeof(current)) < 0)
                                goto out;
                        } else {
                            current[0] = '/';
                            current[1] = '\0';
                        }
                    }
                    continue;
                }
            } else if (host_walk && errno != ENOENT) {
                goto out;
            }

            if (guest_path_append(current, sizeof(current), comp, len) < 0)
                goto out;
        }

        int cls = classify_guest_path_mount(current);
        if (cls < 0) {
            errno = EINVAL;
            goto out;
        }
        if (cls != start_class) {
            rc = 1;
            goto out;
        }

        const char *rest = walk;
        while (*rest == '/')
            rest++;
        if (host_walk && *rest != '\0' &&
            !(len == 2 && comp[0] == '.' && comp[1] == '.')) {
            char name[NAME_MAX + 1];
            if (len > NAME_MAX) {
                errno = ENAMETOOLONG;
                goto out;
            }
            memcpy(name, comp, len);
            name[len] = '\0';
            host_fd_t next_fd =
                openat(current_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (replace_walk_fd(&current_fd, next_fd) < 0)
                goto out;
        }
    }

    rc = 0;

out:
    if (current_fd >= 0)
        close(current_fd);
    if (root_fd >= 0)
        close(root_fd);
    if (absolute_root_fd >= 0)
        close(absolute_root_fd);
    return rc;
}

int path_openat2_check_fd_xdev(int guest_fd, int start_class)
{
    if (start_class < 0) {
        errno = EINVAL;
        return -1;
    }

    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap)) {
        errno = EBADF;
        return -1;
    }

    /* Synthetic /dev fds (FD_URANDOM) and FUSE fds have no resolvable host
     * path, but their semantic class is fixed by the fd type; classify those
     * without F_GETPATH so a NO_XDEV resolution that intended to land outside
     * /dev or outside the originating FUSE mount catches them.
     *
     * The post-check is only meaningful for resolutions that started in the
     * root class. For PROC/DEV/SYS/TMP/DEV_SHM/FUSE the precheck's walker
     * already classified the dirfd against the right intercept, and any
     * successful open went through the intercept layer (procfs emulation backs
     * FD_REGULAR with a /tmp/elfuse-proc-XXXXXX temp file whose F_GETPATH would
     * mis-classify as /tmp). Trust the precheck in those cases and only
     * re-derive the class when the resolution started at root: that is
     * precisely the window where a symlink can escape into an intercept class
     * without the walker seeing it (sidecar shadows hide the link node from
     * fstatat).
     *
     * The /proc/self/fd/N magic-link case (where snap.proc_path stamps the
     * resulting fd with a PROC label even though the real mount of the dup
     * target may be elsewhere) is closed at the precheck by rejecting magic
     * links under NO_XDEV, so this post-check does not have to second-guess
     * proc_path here.
     */
    if (start_class != PATH_MOUNT_ROOT)
        return 0;

    char guest_path[LINUX_PATH_MAX];
    int end_class;
    if (snap.proc_path[0] != '\0') {
        end_class = classify_guest_path_mount(snap.proc_path);
    } else if (snap.type == FD_URANDOM) {
        end_class = PATH_MOUNT_DEV;
    } else if (snap.type == FD_FUSE_DIR || snap.type == FD_FUSE_FILE ||
               snap.type == FD_FUSE_DEV) {
        int mnt_id;
        if (fuse_fd_mnt_id(guest_fd, &mnt_id) < 0)
            return -1;
        end_class = PATH_MOUNT_FUSE_BASE + mnt_id;
    } else if (snap.host_fd >= 0) {
        char host_path[LINUX_PATH_MAX];
        if (fcntl(snap.host_fd, F_GETPATH, host_path) < 0)
            return -1;
        if (host_path_to_guest_path(host_path, guest_path, sizeof(guest_path)) <
            0)
            return -1;
        end_class = classify_guest_path_mount(guest_path);
    } else {
        errno = EBADF;
        return -1;
    }
    if (end_class < 0) {
        errno = EINVAL;
        return -1;
    }

    return (end_class != start_class) ? 1 : 0;
}
