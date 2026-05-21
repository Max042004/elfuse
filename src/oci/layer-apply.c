/* OCI layer applier implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/layer-apply.h"

#define LA_PATH_MAX 4096
#define LA_CHUNK 65536

/* strchrnul is gated behind macOS 15.4 deployment target; emulate it
 * inline so the applier builds against older SDKs without an
 * availability check.
 */
static const char *la_strchrnul(const char *s, int c)
{
    const char *p = strchr(s, c);
    return p ? p : s + strlen(s);
}

static int set_err(const char **err, const char *msg, int err_no)
{
    if (err)
        *err = msg;
    errno = err_no;
    return -1;
}

static const char *basename_of(const char *p)
{
    const char *slash = strrchr(p, '/');
    return slash ? slash + 1 : p;
}

/* Normalize the parent prefix of guest_path into parent_out (without
 * trailing slash). parent_out may be the same buffer as guest_path's
 * substring source, but for safety the caller passes a fresh buffer.
 */
static void parent_of(const char *guest_path, char *parent_out, size_t cap)
{
    const char *slash = strrchr(guest_path, '/');
    if (!slash) {
        parent_out[0] = '\0';
        return;
    }
    size_t n = (size_t) (slash - guest_path);
    if (n >= cap)
        n = cap - 1;
    memcpy(parent_out, guest_path, n);
    parent_out[n] = '\0';
}

int oci_path_join_safe(const char *root_dir,
                       const char *guest_path,
                       char *out,
                       size_t cap,
                       const char **err)
{
    if (!root_dir || !guest_path || !out || cap == 0)
        return set_err(err, "path join: NULL argument", EINVAL);
    if (guest_path[0] == '/')
        return set_err(err, "path join: absolute guest path", EINVAL);
    if (guest_path[0] == '\0' || strcmp(guest_path, ".") == 0)
        return set_err(err, "path join: empty path", EINVAL);

    /* Walk segments and reject `..` outright. Mirrors the no-follow
     * basename rule from src/syscall/path.h::path_translate_at.
     */
    const char *p = guest_path;
    while (*p) {
        const char *next = la_strchrnul(p, '/');
        size_t seglen = (size_t) (next - p);
        if (seglen == 2 && p[0] == '.' && p[1] == '.')
            return set_err(err, "path join: segment is ..", EINVAL);
        p = *next ? next + 1 : next;
    }

    size_t rl = strlen(root_dir);
    size_t gl = strlen(guest_path);
    if (rl + 1 + gl + 1 > cap)
        return set_err(err, "path join: assembled length overflow",
                       ENAMETOOLONG);
    memcpy(out, root_dir, rl);
    out[rl] = '/';
    memcpy(out + rl + 1, guest_path, gl + 1);
    return 0;
}

int oci_symlink_target_check(const char *link_dir, const char *target)
{
    if (!target)
        return set_err(NULL, NULL, EINVAL);

    /* Compose the conceptual destination relative to the unpack root.
     * Absolute targets treat '/' as the unpack root (the symlink is
     * unpacked into the layer sysroot, so absolute means root-relative);
     * relative targets start from link_dir.
     */
    char buf[LA_PATH_MAX];
    if (target[0] == '/') {
        if (strlcpy(buf, target + 1, sizeof(buf)) >= sizeof(buf))
            return set_err(NULL, NULL, ENAMETOOLONG);
    } else {
        if (link_dir && link_dir[0]) {
            if ((size_t) snprintf(buf, sizeof(buf), "%s/%s", link_dir,
                                  target) >= sizeof(buf))
                return set_err(NULL, NULL, ENAMETOOLONG);
        } else {
            if (strlcpy(buf, target, sizeof(buf)) >= sizeof(buf))
                return set_err(NULL, NULL, ENAMETOOLONG);
        }
    }

    /* Track depth as we walk segments. `..` decrements; `.` and empty
     * stay. Any drop below zero means a follower would step above the
     * unpack root, which is rejected.
     */
    int depth = 0;
    char *save = NULL;
    char *seg = strtok_r(buf, "/", &save);
    while (seg) {
        if (strcmp(seg, "..") == 0) {
            if (--depth < 0)
                return set_err(NULL, NULL, ELOOP);
        } else if (strcmp(seg, ".") != 0 && seg[0] != '\0') {
            depth++;
        }
        seg = strtok_r(NULL, "/", &save);
    }
    return 0;
}

/* Recursive rm-rf rooted at path. Used by whiteout and opaque dir. */
static int rm_recursive(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        return unlink(path);
    }
    DIR *d = opendir(path);
    if (!d)
        return -1;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[LA_PATH_MAX];
        if ((size_t) snprintf(child, sizeof(child), "%s/%s", path,
                              de->d_name) >= sizeof(child)) {
            rc = -1;
            errno = ENAMETOOLONG;
            break;
        }
        if (rm_recursive(child) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0)
        rc = rmdir(path);
    return rc;
}

/* mkdir -p for the directory containing 'host_path'. Mode 0755 for
 * implicit parents; the entry's own mode is applied later when the
 * tar provides it.
 */
static int mkdir_parents(const char *host_path, const char **err)
{
    char buf[LA_PATH_MAX];
    if (strlcpy(buf, host_path, sizeof(buf)) >= sizeof(buf))
        return set_err(err, "mkdir parents: path overflow", ENAMETOOLONG);
    char *slash = strrchr(buf, '/');
    if (!slash || slash == buf)
        return 0;
    *slash = '\0';
    /* Walk components and mkdir each. */
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
            return set_err(err, "mkdir parents: mkdir failed", errno);
        *p = '/';
    }
    if (mkdir(buf, 0755) < 0 && errno != EEXIST)
        return set_err(err, "mkdir parents: mkdir failed", errno);
    return 0;
}

static int copy_payload_to_fd(oci_tar_reader_t *r,
                              int fd,
                              uint64_t want,
                              const char **err)
{
    uint8_t buf[LA_CHUNK];
    while (want > 0) {
        size_t got = 0;
        size_t take = want > sizeof(buf) ? sizeof(buf) : (size_t) want;
        const char *terr = NULL;
        if (oci_tar_read_payload(r, buf, take, &got, &terr) < 0)
            return set_err(err, terr ? terr : "tar payload read failed", EIO);
        if (got == 0)
            return set_err(err, "tar payload truncated", EIO);
        const uint8_t *p = buf;
        size_t remaining = got;
        while (remaining > 0) {
            ssize_t n = write(fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return set_err(err, "layer apply: file write failed", errno);
            }
            p += n;
            remaining -= (size_t) n;
        }
        want -= got;
    }
    return 0;
}

static int apply_regular(oci_tar_reader_t *r,
                         const oci_tar_entry_t *e,
                         const char *host_path,
                         oci_layer_apply_stats_t *stats,
                         const char **err)
{
    if (mkdir_parents(host_path, err) < 0)
        return -1;
    /* Remove any existing entry first so we never accidentally write
     * through a symlink left by a lower layer.
     */
    if (unlink(host_path) < 0 && errno != ENOENT) {
        if (errno == EISDIR && rm_recursive(host_path) < 0)
            return set_err(err, "layer apply: cannot remove existing dir",
                           errno);
        else if (errno != EISDIR)
            return set_err(err, "layer apply: cannot remove existing entry",
                           errno);
    }
    int fd = open(host_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0)
        return set_err(err, "layer apply: open file failed", errno);
    if (copy_payload_to_fd(r, fd, e->size, err) < 0) {
        close(fd);
        unlink(host_path);
        return -1;
    }
    /* fchmod to the requested mode bits (low 12). The host inode may
     * silently drop bits the running user cannot set, but the sidecar
     * carries the authoritative value regardless.
     */
    if (fchmod(fd, (mode_t) (e->mode & 07777)) < 0 && errno != EPERM)
        return set_err(err, "layer apply: fchmod failed", errno);
    close(fd);
    if (stats)
        stats->files++;
    return 0;
}

static int apply_dir(const oci_tar_entry_t *e,
                     const char *host_path,
                     oci_layer_apply_stats_t *stats,
                     const char **err)
{
    if (mkdir_parents(host_path, err) < 0)
        return -1;
    if (mkdir(host_path, 0755) < 0 && errno != EEXIST)
        return set_err(err, "layer apply: mkdir failed", errno);
    /* Apply mode bits; reuse fchmod via opening the dir so trailing
     * symlinks are not followed (open with O_NOFOLLOW + O_DIRECTORY).
     */
    int fd = open(host_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        (void) fchmod(fd, (mode_t) (e->mode & 07777));
        close(fd);
    }
    if (stats)
        stats->dirs++;
    return 0;
}

static int apply_symlink(const oci_tar_entry_t *e,
                         const char *host_path,
                         const char *guest_path,
                         oci_layer_apply_stats_t *stats,
                         const char **err)
{
    if (!e->linkname || !e->linkname[0])
        return set_err(err, "layer apply: empty symlink target", EINVAL);

    char parent[LA_PATH_MAX];
    parent_of(guest_path, parent, sizeof(parent));
    if (oci_symlink_target_check(parent, e->linkname) < 0)
        return set_err(err, "layer apply: symlink target escapes root", ELOOP);

    if (mkdir_parents(host_path, err) < 0)
        return -1;
    if (unlink(host_path) < 0 && errno != ENOENT) {
        if (errno == EISDIR && rm_recursive(host_path) < 0)
            return set_err(err, "layer apply: cannot remove existing dir",
                           errno);
        else if (errno != EISDIR)
            return set_err(err, "layer apply: cannot remove existing entry",
                           errno);
    }
    if (symlink(e->linkname, host_path) < 0)
        return set_err(err, "layer apply: symlink failed", errno);
    if (stats)
        stats->symlinks++;
    return 0;
}

static int apply_hardlink(const oci_tar_entry_t *e,
                          const char *root_dir,
                          const char *host_path,
                          oci_layer_apply_stats_t *stats,
                          const char **err)
{
    if (!e->linkname || !e->linkname[0])
        return set_err(err, "layer apply: empty hardlink target", EINVAL);

    char target_host[LA_PATH_MAX];
    /* The hardlink target is an intra-archive guest path. Validate it
     * the same way as a regular entry's path.
     */
    if (oci_path_join_safe(root_dir, e->linkname, target_host,
                           sizeof(target_host), err) < 0)
        return -1;
    /* The target must exist already; OCI mandates entries in apply
     * order, and a hardlink that names a missing file is a malformed
     * archive (or a forward reference, which we explicitly reject).
     */
    struct stat st;
    if (lstat(target_host, &st) < 0)
        return set_err(err, "layer apply: hardlink target missing", ENOLINK);

    if (mkdir_parents(host_path, err) < 0)
        return -1;
    if (unlink(host_path) < 0 && errno != ENOENT)
        return set_err(err, "layer apply: cannot remove existing entry", errno);
    if (link(target_host, host_path) < 0)
        return set_err(err, "layer apply: link failed", errno);
    if (stats)
        stats->hardlinks++;
    return 0;
}

static int apply_whiteout(const oci_tar_entry_t *e,
                          const char *root_dir,
                          oci_meta_table_t *meta,
                          oci_layer_apply_stats_t *stats,
                          const char **err)
{
    /* Path is "...dir/.wh.<name>"; the entry being whited out is
     * "...dir/<name>".
     */
    const char *base = basename_of(e->path);
    if (strncmp(base, ".wh.", 4) != 0 || base[4] == '\0')
        return set_err(err, "layer apply: malformed whiteout entry", EINVAL);

    size_t parent_len = (size_t) (base - e->path);
    char target[LA_PATH_MAX];
    if (parent_len + strlen(base + 4) + 1 > sizeof(target))
        return set_err(err, "layer apply: whiteout path overflow",
                       ENAMETOOLONG);
    memcpy(target, e->path, parent_len);
    strcpy(target + parent_len, base + 4);

    char host_path[LA_PATH_MAX];
    if (oci_path_join_safe(root_dir, target, host_path, sizeof(host_path),
                           err) < 0)
        return -1;
    if (rm_recursive(host_path) < 0 && errno != ENOENT)
        return set_err(err, "layer apply: whiteout removal failed", errno);
    if (meta)
        oci_meta_remove(meta, target);
    if (stats)
        stats->whiteouts++;
    return 0;
}

static int apply_opaque_whiteout(const oci_tar_entry_t *e,
                                 const char *root_dir,
                                 oci_meta_table_t *meta,
                                 oci_layer_apply_stats_t *stats,
                                 const char **err)
{
    /* Path is "...dir/.wh..wh..opq"; clear all CHILDREN of "...dir/"
     * but leave the directory itself.
     */
    const char *base = basename_of(e->path);
    if (strcmp(base, ".wh..wh..opq") != 0)
        return set_err(err, "layer apply: malformed opaque marker", EINVAL);
    size_t parent_len = (size_t) (base - e->path);
    char dir[LA_PATH_MAX];
    if (parent_len == 0) {
        /* Opaque at layer root: clear top-level lower-layer entries. */
        dir[0] = '\0';
    } else {
        /* Drop the trailing slash before the marker. */
        size_t copy = parent_len - 1;
        if (copy + 1 > sizeof(dir))
            return set_err(err, "layer apply: opaque path overflow",
                           ENAMETOOLONG);
        memcpy(dir, e->path, copy);
        dir[copy] = '\0';
    }

    char host_dir[LA_PATH_MAX];
    if (dir[0] == '\0') {
        if ((size_t) snprintf(host_dir, sizeof(host_dir), "%s", root_dir) >=
            sizeof(host_dir))
            return set_err(err, "layer apply: opaque host path overflow",
                           ENAMETOOLONG);
    } else {
        if (oci_path_join_safe(root_dir, dir, host_dir, sizeof(host_dir), err) <
            0)
            return -1;
    }

    DIR *d = opendir(host_dir);
    if (!d) {
        if (errno == ENOENT) {
            if (stats)
                stats->opaques++;
            return 0;
        }
        return set_err(err, "layer apply: opaque opendir failed", errno);
    }
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (strncmp(de->d_name, ".wh.", 4) == 0)
            continue; /* let the marker entry itself stay for the iter */
        char child_host[LA_PATH_MAX];
        if ((size_t) snprintf(child_host, sizeof(child_host), "%s/%s", host_dir,
                              de->d_name) >= sizeof(child_host)) {
            rc = -1;
            errno = ENAMETOOLONG;
            break;
        }
        if (rm_recursive(child_host) < 0) {
            rc = -1;
            break;
        }
        if (meta) {
            char child_guest[LA_PATH_MAX];
            if (dir[0])
                snprintf(child_guest, sizeof(child_guest), "%s/%s", dir,
                         de->d_name);
            else
                snprintf(child_guest, sizeof(child_guest), "%s", de->d_name);
            oci_meta_remove(meta, child_guest);
        }
    }
    closedir(d);
    if (rc < 0)
        return set_err(err, "layer apply: opaque clear failed", errno);
    if (stats)
        stats->opaques++;
    return 0;
}

/* Whiteout-handling discipline shared by oci_layer_apply (overlay) and
 * oci_layer_apply_raw_tar (Plan 3 C3.3 raw per-layer cache populate).
 * Overlay mode interprets .wh.<name> and .wh..wh..opq tar entries as
 * delete / clear directives against root_dir; raw mode leaves them as
 * regular 0-byte files at their tar path so the assembler can replay
 * the whiteout intent against the running work_dir later.
 */
typedef enum {
    APPLY_MODE_OVERLAY,
    APPLY_MODE_RAW_TAR,
} apply_mode_t;

static int layer_apply_impl(oci_tar_reader_t *r,
                            const char *root_dir,
                            apply_mode_t mode,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!r || !root_dir)
        return set_err(err, "layer apply: NULL argument", EINVAL);

    for (;;) {
        oci_tar_entry_t e;
        const char *terr = NULL;
        int rc = oci_tar_next(r, &e, &terr);
        if (rc < 0)
            return set_err(err, terr ? terr : "tar next failed",
                           errno ? errno : EIO);
        if (rc == 0)
            return 0;

        /* Strip a leading slash if present; OCI layer paths are
         * relative, but some encoders ship them with a leading slash.
         */
        const char *gp = e.path;
        while (gp[0] == '/')
            gp++;

        if (mode == APPLY_MODE_OVERLAY) {
            if (e.is_opaque_whiteout) {
                oci_tar_entry_t e2 = e;
                e2.path = (char *) gp;
                if (apply_opaque_whiteout(&e2, root_dir, meta, stats, err) < 0)
                    return -1;
                continue;
            }
            if (e.is_whiteout) {
                oci_tar_entry_t e2 = e;
                e2.path = (char *) gp;
                if (apply_whiteout(&e2, root_dir, meta, stats, err) < 0)
                    return -1;
                continue;
            }
        }
        /* Raw-tar mode falls through: .wh.<name> and .wh..wh..opq are
         * typeflag '0' regular tar entries with zero payload, and the
         * regular-file dispatch below writes them on disk as 0-byte
         * files at their tar path. The assembler consumes the markers
         * later.
         */

        if (e.type == OCI_TAR_UNSUPPORTED)
            return set_err(err, "layer apply: unsupported entry type", ENOTSUP);

        char host_path[LA_PATH_MAX];
        if (oci_path_join_safe(root_dir, gp, host_path, sizeof(host_path),
                               err) < 0)
            return -1;

        oci_tar_entry_t e2 = e;
        e2.path = (char *) gp;
        switch (e.type) {
        case OCI_TAR_REG:
            if (apply_regular(r, &e2, host_path, stats, err) < 0)
                return -1;
            break;
        case OCI_TAR_DIR:
            if (apply_dir(&e2, host_path, stats, err) < 0)
                return -1;
            break;
        case OCI_TAR_SYMLINK:
            if (apply_symlink(&e2, host_path, gp, stats, err) < 0)
                return -1;
            break;
        case OCI_TAR_HARDLINK:
            if (apply_hardlink(&e2, root_dir, host_path, stats, err) < 0)
                return -1;
            break;
        case OCI_TAR_UNSUPPORTED:
            /* Already handled above; here for switch completeness. */
            return set_err(err, "layer apply: unsupported entry type", ENOTSUP);
        }

        if (meta && e.type != OCI_TAR_HARDLINK)
            (void) oci_meta_record(meta, gp, e.uid, e.gid, e.mode);
    }
}

int oci_layer_apply(oci_tar_reader_t *r,
                    const char *root_dir,
                    oci_layer_apply_stats_t *stats,
                    oci_meta_table_t *meta,
                    const char **err)
{
    return layer_apply_impl(r, root_dir, APPLY_MODE_OVERLAY, stats, meta, err);
}

int oci_layer_apply_raw_tar(oci_tar_reader_t *r,
                            const char *root_dir,
                            oci_layer_apply_stats_t *stats,
                            oci_meta_table_t *meta,
                            const char **err)
{
    return layer_apply_impl(r, root_dir, APPLY_MODE_RAW_TAR, stats, meta, err);
}
