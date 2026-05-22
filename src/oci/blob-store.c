/* Content-addressable blob store for OCI image data
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The commit path uses link(2) rather than rename(2) so that a second writer
 * racing on the same digest cannot silently overwrite a blob that another
 * process already finalized. link returning EEXIST is treated as a dedup
 * hit; both clients then unlink their staging file and report success. This
 * matches the content-addressable invariant: identical bytes map to one
 * inode, regardless of how many concurrent writers raced to produce them.
 */

#include "blob-store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "digest.h"

/* Largest path the store will materialize. Comfortably above PATH_MAX so
 * snprintf truncation never silently corrupts a path; callers that pass an
 * out_size smaller than this can still recover via the returned length.
 */
#define STORE_PATH_MAX 4096

struct oci_blob_store {
    char *root;
};

struct oci_blob_writer {
    oci_blob_store_t *store;
    oci_digest_algo_t algo;
    char expected_hex[OCI_DIGEST_HEX_MAX + 1];
    char tmp_path[STORE_PATH_MAX];
    int fd;
    oci_digester_t *digester;
    bool failed;
};

static int mkdir_one(const char *path)
{
    if (mkdir(path, 0755) == 0)
        return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
            return 0;
        errno = ENOTDIR;
        return -1;
    }
    return -1;
}

/* Create every directory along path. Walks component by component so that a
 * missing intermediate directory does not abort the whole open. path must
 * fit in STORE_PATH_MAX; the caller is responsible for upstream length
 * checks (only internal call sites build these paths from store->root plus
 * fixed suffixes, all of which stay well under the limit).
 */
static int mkdir_p(const char *path)
{
    char buf[STORE_PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(buf, path, len + 1);

    for (size_t i = 1; i < len; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir_one(buf) < 0)
            return -1;
        buf[i] = '/';
    }
    return mkdir_one(buf);
}

static int join2(char *out, size_t out_size, const char *a, const char *b)
{
    int n = snprintf(out, out_size, "%s/%s", a, b);
    if (n < 0 || (size_t) n >= out_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return n;
}

static int ensure_layout(const char *root)
{
    char path[STORE_PATH_MAX];
    if (mkdir_p(root) < 0)
        return -1;
    if (join2(path, sizeof(path), root, "blobs") < 0 || mkdir_one(path) < 0)
        return -1;
    if (join2(path, sizeof(path), root, "tmp") < 0 || mkdir_one(path) < 0)
        return -1;

    static const char *const algos[] = {"sha256", "sha512"};
    for (size_t i = 0; i < sizeof(algos) / sizeof(algos[0]); i++) {
        int n = snprintf(path, sizeof(path), "%s/blobs/%s", root, algos[i]);
        if (n < 0 || (size_t) n >= sizeof(path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (mkdir_one(path) < 0)
            return -1;
    }
    return 0;
}

oci_blob_store_t *oci_blob_store_open(const char *root)
{
    if (!root || !*root) {
        errno = EINVAL;
        return NULL;
    }
    if (ensure_layout(root) < 0)
        return NULL;

    oci_blob_store_t *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->root = strdup(root);
    if (!s->root) {
        free(s);
        return NULL;
    }
    return s;
}

void oci_blob_store_close(oci_blob_store_t *s)
{
    if (!s)
        return;
    free(s->root);
    free(s);
}

int oci_blob_store_path(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex,
                        char *out,
                        size_t out_size)
{
    if (!s || !out || out_size == 0) {
        if (out && out_size)
            out[0] = '\0';
        return -1;
    }
    const char *name = oci_digest_algo_name(algo);
    if (!name || !oci_digest_hex_valid(algo, hex)) {
        out[0] = '\0';
        return -1;
    }
    int n = snprintf(out, out_size, "%s/blobs/%s/%s", s->root, name, hex);
    if (n < 0) {
        out[0] = '\0';
        return -1;
    }
    return n;
}

bool oci_blob_store_has(const oci_blob_store_t *s,
                        oci_digest_algo_t algo,
                        const char *hex)
{
    char path[STORE_PATH_MAX];
    int n = oci_blob_store_path(s, algo, hex, path, sizeof(path));
    if (n < 0 || (size_t) n >= sizeof(path))
        return false;
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Monotonic counter used to disambiguate concurrent staging files within the
 * same process. mkstemp itself supplies the global uniqueness via the random
 * XXXXXX suffix; the counter is here only so that read-modify failures of
 * the rand pool cannot defeat in-process uniqueness.
 */
static unsigned long writer_seq(void)
{
    static unsigned long n = 0;
    return __sync_add_and_fetch(&n, 1);
}

/* Shared writer construction. tmp_template_suffix is the part after
 * "<root>/tmp/" -- the caller composes a pid/seq form (anonymous) or a
 * digest-prefix form (named) and this helper opens mkstemp + chmod + the
 * digester, identical between the two public entry points.
 */
static oci_blob_writer_t *writer_begin_with_template(oci_blob_store_t *s,
                                                     oci_digest_algo_t algo,
                                                     const char *expected_hex,
                                                     const char *tmp_template_suffix)
{
    if (!s || !oci_digest_hex_valid(algo, expected_hex)) {
        errno = EINVAL;
        return NULL;
    }

    oci_blob_writer_t *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;
    w->store = s;
    w->algo = algo;
    memcpy(w->expected_hex, expected_hex, oci_digest_hex_len(algo) + 1);
    w->fd = -1;

    int n = snprintf(w->tmp_path, sizeof(w->tmp_path), "%s/tmp/%s",
                     s->root, tmp_template_suffix);
    if (n < 0 || (size_t) n >= sizeof(w->tmp_path)) {
        free(w);
        errno = ENAMETOOLONG;
        return NULL;
    }

    int fd = mkstemp(w->tmp_path);
    if (fd < 0) {
        int saved = errno;
        free(w);
        errno = saved;
        return NULL;
    }
    (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (fchmod(fd, 0644) < 0) {
        int saved = errno;
        (void) close(fd);
        (void) unlink(w->tmp_path);
        free(w);
        errno = saved;
        return NULL;
    }
    w->fd = fd;

    w->digester = oci_digester_new(algo);
    if (!w->digester) {
        int saved = errno ? errno : ENOMEM;
        (void) close(w->fd);
        (void) unlink(w->tmp_path);
        free(w);
        errno = saved;
        return NULL;
    }
    return w;
}

oci_blob_writer_t *oci_blob_writer_begin(oci_blob_store_t *s,
                                         oci_digest_algo_t algo,
                                         const char *expected_hex)
{
    char tmpl[128];
    int n = snprintf(tmpl, sizeof(tmpl), "blob-%ld-%lu-XXXXXX",
                     (long) getpid(), writer_seq());
    if (n < 0 || (size_t) n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return writer_begin_with_template(s, algo, expected_hex, tmpl);
}

#define OCI_BLOB_NAMED_HEX_PREFIX 16

oci_blob_writer_t *oci_blob_writer_begin_named(oci_blob_store_t *s,
                                               oci_digest_algo_t algo,
                                               const char *expected_hex)
{
    if (!expected_hex) {
        errno = EINVAL;
        return NULL;
    }
    char prefix[OCI_BLOB_NAMED_HEX_PREFIX + 1];
    size_t hl = strlen(expected_hex);
    size_t use = hl < OCI_BLOB_NAMED_HEX_PREFIX ? hl : OCI_BLOB_NAMED_HEX_PREFIX;
    memcpy(prefix, expected_hex, use);
    prefix[use] = '\0';
    char tmpl[64];
    int n = snprintf(tmpl, sizeof(tmpl), "blob-%s-XXXXXX", prefix);
    if (n < 0 || (size_t) n >= sizeof(tmpl)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return writer_begin_with_template(s, algo, expected_hex, tmpl);
}

/* Build the per-store tmp/ path into out. Returns true on success, false on
 * overflow. The caller is responsible for sizing out (STORE_PATH_MAX fits).
 */
static bool tmp_dir_path(const oci_blob_store_t *s, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/tmp", s->root);
    return n > 0 && (size_t) n < cap;
}

/* Pull the leading hex16 digest prefix used for tmp filenames. expected_hex
 * is validated by the caller (oci_digest_hex_valid).
 */
static void named_prefix_for(const char *expected_hex, char *out)
{
    size_t hl = strlen(expected_hex);
    size_t use = hl < OCI_BLOB_NAMED_HEX_PREFIX ? hl : OCI_BLOB_NAMED_HEX_PREFIX;
    memcpy(out, expected_hex, use);
    out[use] = '\0';
}

/* Open an existing partial as a writer. Re-hashes the bytes already on disk
 * and positions the fd at end-of-file. Returns the writer on success or
 * NULL on any I/O failure; the caller decides whether to fall back to a
 * fresh writer. The partial file at path is NOT unlinked on failure --
 * caller policy.
 */
static oci_blob_writer_t *open_partial_as_writer(oci_blob_store_t *s,
                                                 oci_digest_algo_t algo,
                                                 const char *expected_hex,
                                                 const char *path,
                                                 int64_t partial_size)
{
    oci_blob_writer_t *w = calloc(1, sizeof(*w));
    if (!w)
        return NULL;
    w->store = s;
    w->algo = algo;
    memcpy(w->expected_hex, expected_hex, oci_digest_hex_len(algo) + 1);
    size_t plen = strlen(path);
    if (plen + 1 > sizeof(w->tmp_path)) {
        free(w);
        errno = ENAMETOOLONG;
        return NULL;
    }
    memcpy(w->tmp_path, path, plen + 1);
    w->fd = open(path, O_RDWR);
    if (w->fd < 0) {
        free(w);
        return NULL;
    }
    (void) fcntl(w->fd, F_SETFD, FD_CLOEXEC);
    w->digester = oci_digester_new(algo);
    if (!w->digester) {
        int saved = errno ? errno : ENOMEM;
        (void) close(w->fd);
        free(w);
        errno = saved;
        return NULL;
    }
    if (lseek(w->fd, 0, SEEK_SET) < 0)
        goto fail_io;
    int64_t consumed = 0;
    char buf[64 * 1024];
    while (consumed < partial_size) {
        ssize_t got = read(w->fd, buf, sizeof(buf));
        if (got == 0)
            break;
        if (got < 0) {
            if (errno == EINTR)
                continue;
            goto fail_io;
        }
        oci_digester_update(w->digester, buf, (size_t) got);
        consumed += got;
    }
    if (consumed != partial_size)
        goto fail_io;
    if (lseek(w->fd, 0, SEEK_END) < 0)
        goto fail_io;
    return w;

fail_io: {
    int saved = errno ? errno : EIO;
    oci_digester_free(w->digester);
    (void) close(w->fd);
    free(w);
    errno = saved;
    return NULL;
}
}

oci_blob_writer_t *oci_blob_writer_resume_named(oci_blob_store_t *s,
                                                oci_digest_algo_t algo,
                                                const char *expected_hex,
                                                int64_t expected_size,
                                                int64_t *out_resume_offset)
{
    if (out_resume_offset)
        *out_resume_offset = 0;
    if (!s || !oci_digest_hex_valid(algo, expected_hex)) {
        errno = EINVAL;
        return NULL;
    }

    char tmp_dir[STORE_PATH_MAX];
    if (!tmp_dir_path(s, tmp_dir, sizeof(tmp_dir)))
        return oci_blob_writer_begin_named(s, algo, expected_hex);

    char prefix[OCI_BLOB_NAMED_HEX_PREFIX + 1];
    named_prefix_for(expected_hex, prefix);
    char glob[8 + OCI_BLOB_NAMED_HEX_PREFIX];
    int gn = snprintf(glob, sizeof(glob), "blob-%s-", prefix);
    if (gn <= 0 || (size_t) gn >= sizeof(glob))
        return oci_blob_writer_begin_named(s, algo, expected_hex);
    size_t glen = (size_t) gn;

    DIR *d = opendir(tmp_dir);
    if (!d)
        return oci_blob_writer_begin_named(s, algo, expected_hex);

    char best_path[STORE_PATH_MAX] = {0};
    int64_t best_size = -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, glob, glen) != 0)
            continue;
        char cand[STORE_PATH_MAX];
        int cn = snprintf(cand, sizeof(cand), "%s/%s", tmp_dir, de->d_name);
        if (cn <= 0 || (size_t) cn >= sizeof(cand))
            continue;
        struct stat st;
        if (stat(cand, &st) < 0 || !S_ISREG(st.st_mode))
            continue;
        int64_t sz = (int64_t) st.st_size;
        /* Keep the largest partial; unlink everything else. A partial that is
         * already at or past the declared size is corrupt or stale -- the
         * caller cannot send a useful Range from it -- so drop it here and
         * fall through to the fresh-writer path on no surviving partial.
         */
        if (sz <= 0 || sz >= expected_size) {
            (void) unlink(cand);
            continue;
        }
        if (sz > best_size) {
            if (best_path[0])
                (void) unlink(best_path);
            memcpy(best_path, cand, (size_t) cn + 1);
            best_size = sz;
        } else {
            (void) unlink(cand);
        }
    }
    closedir(d);

    if (best_size <= 0 || !best_path[0])
        return oci_blob_writer_begin_named(s, algo, expected_hex);

    oci_blob_writer_t *w = open_partial_as_writer(s, algo, expected_hex,
                                                  best_path, best_size);
    if (!w) {
        (void) unlink(best_path);
        return oci_blob_writer_begin_named(s, algo, expected_hex);
    }
    if (out_resume_offset)
        *out_resume_offset = best_size;
    return w;
}

void oci_blob_store_sweep_partials(oci_blob_store_t *s, long ttl_secs)
{
    if (!s)
        return;
    char tmp_dir[STORE_PATH_MAX];
    if (!tmp_dir_path(s, tmp_dir, sizeof(tmp_dir)))
        return;
    DIR *d = opendir(tmp_dir);
    if (!d)
        return;
    time_t now = time(NULL);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "blob-", 5) != 0)
            continue;
        char path[STORE_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", tmp_dir, de->d_name);
        if (n <= 0 || (size_t) n >= sizeof(path))
            continue;
        struct stat st;
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode))
            continue;
        if ((long) (now - st.st_mtime) >= ttl_secs)
            (void) unlink(path);
    }
    closedir(d);
}

bool oci_blob_writer_write(oci_blob_writer_t *w, const void *buf, size_t len)
{
    if (!w || w->failed || (!buf && len)) {
        if (w)
            w->failed = true;
        errno = EINVAL;
        return false;
    }
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(w->fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            w->failed = true;
            return false;
        }
        if (n == 0) {
            w->failed = true;
            errno = EIO;
            return false;
        }
        oci_digester_update(w->digester, p, (size_t) n);
        p += n;
        len -= (size_t) n;
    }
    return true;
}

/* Discard staging file, free fd and digester. Errno is preserved across the
 * cleanup so the caller can return its own diagnostic.
 */
static void writer_cleanup_fail(oci_blob_writer_t *w)
{
    int saved = errno;
    if (w->fd >= 0)
        (void) close(w->fd);
    (void) unlink(w->tmp_path);
    oci_digester_free(w->digester);
    free(w);
    errno = saved;
}

int oci_blob_writer_commit(oci_blob_writer_t *w)
{
    if (!w) {
        errno = EINVAL;
        return -1;
    }
    if (w->failed) {
        writer_cleanup_fail(w);
        errno = EIO;
        return -1;
    }

    char got_hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digester_finish_hex(w->digester, got_hex) == 0) {
        writer_cleanup_fail(w);
        errno = EIO;
        return -1;
    }
    oci_digester_free(w->digester);
    w->digester = NULL;

    if (strcmp(got_hex, w->expected_hex) != 0) {
        if (w->fd >= 0)
            (void) close(w->fd);
        (void) unlink(w->tmp_path);
        free(w);
        errno = EINVAL;
        return -1;
    }

    if (fsync(w->fd) < 0) {
        int saved = errno;
        (void) close(w->fd);
        (void) unlink(w->tmp_path);
        free(w);
        errno = saved;
        return -1;
    }
    if (close(w->fd) < 0) {
        int saved = errno;
        w->fd = -1;
        (void) unlink(w->tmp_path);
        free(w);
        errno = saved;
        return -1;
    }
    w->fd = -1;

    char final_path[STORE_PATH_MAX];
    int n = oci_blob_store_path(w->store, w->algo, w->expected_hex, final_path,
                                sizeof(final_path));
    if (n < 0 || (size_t) n >= sizeof(final_path)) {
        (void) unlink(w->tmp_path);
        free(w);
        errno = ENAMETOOLONG;
        return -1;
    }

    if (link(w->tmp_path, final_path) < 0) {
        if (errno != EEXIST) {
            int saved = errno;
            (void) unlink(w->tmp_path);
            free(w);
            errno = saved;
            return -1;
        }
        /* Dedup hit: another writer beat this one. Content is identical
         * because the digest matched, so dropping the staging file is the
         * correct action.
         */
    }
    (void) unlink(w->tmp_path);
    free(w);
    return 0;
}

void oci_blob_writer_abort(oci_blob_writer_t *w)
{
    if (!w)
        return;
    if (w->fd >= 0)
        (void) close(w->fd);
    (void) unlink(w->tmp_path);
    oci_digester_free(w->digester);
    free(w);
}

int oci_blob_store_put_bytes(oci_blob_store_t *s,
                             oci_digest_algo_t algo,
                             const char *expected_hex,
                             const void *buf,
                             size_t len)
{
    oci_blob_writer_t *w = oci_blob_writer_begin(s, algo, expected_hex);
    if (!w)
        return -1;
    if (!oci_blob_writer_write(w, buf, len)) {
        int saved = errno;
        oci_blob_writer_abort(w);
        errno = saved;
        return -1;
    }
    return oci_blob_writer_commit(w);
}
