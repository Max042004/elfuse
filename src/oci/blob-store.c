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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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

oci_blob_writer_t *oci_blob_writer_begin(oci_blob_store_t *s,
                                         oci_digest_algo_t algo,
                                         const char *expected_hex)
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

    int n = snprintf(w->tmp_path, sizeof(w->tmp_path),
                     "%s/tmp/blob-%ld-%lu-XXXXXX",
                     s->root, (long) getpid(), writer_seq());
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
