/* Local OCI image store: blobs + tag-to-digest pinning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The pin write path uses rename(2) rather than link(2) because tag pins are
 * mutable: pulling alpine:3.20 today may resolve to a different digest than
 * yesterday, and overwriting the pin is the correct semantic. The blob store
 * underneath this layer keeps its link(2) discipline because content-addressed
 * blobs are immutable.
 *
 * The store root also carries an OCI image-layout 1.0.0 marker
 * (<root>/oci-layout) so that external tools that consume the image-layout
 * spec -- skopeo, umoci, crane -- can recognize the directory without any
 * elfuse-specific knowledge. Writing the marker is idempotent: it is only
 * created when missing, and existing markers are never rewritten so a third
 * party that bumped the imageLayoutVersion is not stomped.
 */

#include "store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "digest.h"

/* Largest path the store materializes. Comfortably above PATH_MAX so snprintf
 * truncation surfaces as ENAMETOOLONG instead of a silent corruption.
 */
#define STORE_PATH_MAX 4096

struct oci_store {
    char *root;
    oci_blob_store_t *blobs;
};

/* OCI image-layout 1.0.0 marker payload. The spec wants a JSON object with
 * exactly one field: imageLayoutVersion = "1.0.0". The trailing newline is
 * conventional and matches what umoci / skopeo write.
 */
static const char OCI_LAYOUT_BODY[] = "{\"imageLayoutVersion\":\"1.0.0\"}\n";

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

/* Create every directory along path. Walks component by component so a missing
 * intermediate directory does not abort the open. Same shape as the helper in
 * blob-store.c; kept independent here to avoid leaking blob-store internals.
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

/* Idempotently write <root>/oci-layout. Returns 0 on success or when the
 * marker already exists, -1 on any unexpected IO failure. The write uses a
 * pid + counter-suffixed tmp file plus rename so a concurrent opener never
 * observes a partial JSON document. link(2) is preferred over rename(2) for
 * the publish step so that two racing openers cannot replace an external
 * tool's bumped marker with our own; EEXIST is the happy path.
 */
static unsigned long layout_seq(void)
{
    static unsigned long n = 0;
    return __sync_add_and_fetch(&n, 1);
}

static int ensure_oci_layout_marker(const char *root)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/oci-layout", root);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct stat st;
    if (stat(path, &st) == 0) {
        if (!S_ISREG(st.st_mode)) {
            errno = ENOTDIR;
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT)
        return -1;

    char tmp[STORE_PATH_MAX];
    n = snprintf(tmp, sizeof(tmp), "%s.tmp-%d-%lu", path, (int) getpid(),
                 layout_seq());
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    size_t body_len = sizeof(OCI_LAYOUT_BODY) - 1;
    if (write(fd, OCI_LAYOUT_BODY, body_len) != (ssize_t) body_len) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        return -1;
    }
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        return -1;
    }
    if (close(fd) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        return -1;
    }
    if (link(tmp, path) < 0) {
        int saved = errno;
        unlink(tmp);
        if (saved == EEXIST)
            return 0;
        errno = saved;
        return -1;
    }
    unlink(tmp);
    return 0;
}

oci_store_t *oci_store_open(const char *root)
{
    if (!root || !*root) {
        errno = EINVAL;
        return NULL;
    }
    oci_blob_store_t *blobs = oci_blob_store_open(root);
    if (!blobs)
        return NULL;

    char refs[STORE_PATH_MAX];
    int n = snprintf(refs, sizeof(refs), "%s/refs", root);
    if (n < 0 || (size_t) n >= sizeof(refs)) {
        oci_blob_store_close(blobs);
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (mkdir_one(refs) < 0) {
        oci_blob_store_close(blobs);
        return NULL;
    }
    if (ensure_oci_layout_marker(root) < 0) {
        int saved = errno;
        oci_blob_store_close(blobs);
        errno = saved;
        return NULL;
    }

    oci_store_t *s = calloc(1, sizeof(*s));
    if (!s) {
        oci_blob_store_close(blobs);
        errno = ENOMEM;
        return NULL;
    }
    s->root = strdup(root);
    if (!s->root) {
        free(s);
        oci_blob_store_close(blobs);
        errno = ENOMEM;
        return NULL;
    }
    s->blobs = blobs;
    return s;
}

void oci_store_close(oci_store_t *s)
{
    if (!s)
        return;
    oci_blob_store_close(s->blobs);
    free(s->root);
    free(s);
}

const char *oci_store_root(const oci_store_t *s)
{
    return s ? s->root : NULL;
}

oci_blob_store_t *oci_store_blobs(oci_store_t *s)
{
    return s ? s->blobs : NULL;
}

char *oci_store_default_root(void)
{
    const char *xdg = getenv("XDG_DATA_HOME");
    if (xdg && *xdg) {
        size_t n = strlen(xdg) + sizeof("/elfuse/store");
        char *r = malloc(n);
        if (!r) {
            errno = ENOMEM;
            return NULL;
        }
        snprintf(r, n, "%s/elfuse/store", xdg);
        return r;
    }
    const char *home = getenv("HOME");
    if (!home || !*home) {
        errno = ENOENT;
        return NULL;
    }
    static const char SUFFIX[] = "/Library/Application Support/elfuse/store";
    size_t n = strlen(home) + sizeof(SUFFIX);
    char *r = malloc(n);
    if (!r) {
        errno = ENOMEM;
        return NULL;
    }
    snprintf(r, n, "%s%s", home, SUFFIX);
    return r;
}

static int build_ref_dir(const oci_store_t *s, const oci_ref_t *ref,
                         char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/refs/%s/%s", s->root, ref->registry,
                     ref->repository);
    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int build_ref_path(const oci_store_t *s, const oci_ref_t *ref,
                          char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/refs/%s/%s/%s", s->root, ref->registry,
                     ref->repository, ref->tag);
    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static unsigned long pin_seq(void)
{
    static unsigned long n = 0;
    return __sync_add_and_fetch(&n, 1);
}

int oci_store_put_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      const char *digest_str,
                      const char **err_msg)
{
    if (!s || !ref || !digest_str || !ref->registry || !ref->repository) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    if (!ref->tag) {
        if (err_msg)
            *err_msg = "ref has no tag; digest-only refs are self-pinning";
        errno = EINVAL;
        return -1;
    }

    /* Validate digest shape so a corrupt caller cannot poison the pin file
     * with arbitrary bytes that later defeat oci_store_get_ref.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        if (err_msg)
            *err_msg = "digest must be lowercase <algo>:<hex>";
        errno = EINVAL;
        return -1;
    }

    char dir[STORE_PATH_MAX];
    if (build_ref_dir(s, ref, dir, sizeof(dir)) < 0) {
        if (err_msg)
            *err_msg = "pin directory path exceeds STORE_PATH_MAX";
        return -1;
    }
    if (mkdir_p(dir) < 0) {
        if (err_msg)
            *err_msg = "failed to create pin directory";
        return -1;
    }
    char path[STORE_PATH_MAX];
    if (build_ref_path(s, ref, path, sizeof(path)) < 0) {
        if (err_msg)
            *err_msg = "pin file path exceeds STORE_PATH_MAX";
        return -1;
    }

    char tmp[STORE_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp-%d-%lu", path, (int) getpid(),
                     pin_seq());
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        if (err_msg)
            *err_msg = "pin tmp path exceeds STORE_PATH_MAX";
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        if (err_msg)
            *err_msg = "failed to create pin tmp file";
        return -1;
    }
    size_t dlen = strlen(digest_str);
    const char nl = '\n';
    if (write(fd, digest_str, dlen) != (ssize_t) dlen ||
        write(fd, &nl, 1) != 1) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "failed to write pin tmp file";
        return -1;
    }
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "fsync on pin tmp file failed";
        return -1;
    }
    if (close(fd) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "close on pin tmp file failed";
        return -1;
    }
    if (rename(tmp, path) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "rename of pin tmp file failed";
        return -1;
    }
    return 0;
}

int oci_store_get_ref(oci_store_t *s,
                      const oci_ref_t *ref,
                      char **out_digest,
                      const char **err_msg)
{
    if (!s || !ref || !out_digest || !ref->registry || !ref->repository) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    *out_digest = NULL;
    if (!ref->tag) {
        if (err_msg)
            *err_msg = "ref has no tag";
        errno = EINVAL;
        return -1;
    }

    char path[STORE_PATH_MAX];
    if (build_ref_path(s, ref, path, sizeof(path)) < 0) {
        if (err_msg)
            *err_msg = "pin file path exceeds STORE_PATH_MAX";
        return -1;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (err_msg)
            *err_msg = errno == ENOENT ? "ref not pinned in local store"
                                       : "failed to open pin file";
        return -1;
    }
    char buf[OCI_DIGEST_HEX_MAX + 16];
    if (!fgets(buf, sizeof(buf), fp)) {
        int saved = ferror(fp) ? errno : EINVAL;
        fclose(fp);
        errno = saved;
        if (err_msg)
            *err_msg = "pin file is empty or unreadable";
        return -1;
    }
    fclose(fp);

    size_t blen = strlen(buf);
    while (blen > 0 && (buf[blen - 1] == '\n' || buf[blen - 1] == '\r'))
        buf[--blen] = '\0';

    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(buf, &algo, hex)) {
        if (err_msg)
            *err_msg = "pin file does not contain a valid digest";
        errno = EINVAL;
        return -1;
    }
    char *copy = strdup(buf);
    if (!copy) {
        if (err_msg)
            *err_msg = "out of memory";
        errno = ENOMEM;
        return -1;
    }
    *out_digest = copy;
    return 0;
}
