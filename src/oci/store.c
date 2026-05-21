/* Local OCI image store: blobs + tag-to-digest pinning
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pin discipline:
 *
 *   - index.json is the only pin store. A pin is one descriptor in
 *     manifests[] keyed by org.opencontainers.image.ref.name.
 *   - Writers serialize via flock(<root>/index.json.lock, LOCK_EX) and
 *     publish via tmp + rename. The lock file is independent of index.json
 *     itself so that rename(2) replacing the inode does not invalidate the
 *     advisory lock identity for concurrent writers.
 *   - Readers parse the file lock-free: rename is atomic on a POSIX
 *     filesystem and cJSON consumes the document in one shot.
 *   - Re-pinning the same canonical name replaces the existing manifests[]
 *     entry in place; pull-by-tag with a moved tag updates rather than
 *     accumulating duplicates.
 *
 * Blob store layout:
 *
 *   - The blob layer below this module keeps its link(2) discipline because
 *     content-addressed blobs are immutable; tag pins use rename(2) because
 *     pulling alpine:3.20 today may resolve to a different digest tomorrow
 *     and overwriting the pin is the correct semantic.
 *
 * Image-layout marker:
 *
 *   - <root>/oci-layout advertises the directory as a standards-compliant
 *     OCI image-layout so skopeo, umoci, and crane can consume the store
 *     directly. Writing the marker is idempotent: it is only created when
 *     missing and existing markers are never rewritten so a third party
 *     that bumped the imageLayoutVersion is not stomped.
 *
 * Pre-C2.2 stores wrote pin files under refs/<registry>/<repository>/<tag>
 * instead of index.json. C2.2 stops writing that tree; C2.3 will migrate
 * older stores on open. This module does not remove a pre-existing refs/
 * directory so a downgrade still finds the legacy data.
 */

#include "store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../externals/cjson/cJSON.h"
#include "digest.h"

/* Largest path the store materializes. Comfortably above PATH_MAX so snprintf
 * truncation surfaces as ENAMETOOLONG instead of a silent corruption.
 */
#define STORE_PATH_MAX 4096

/* Conservative ceiling for a single manifest body. Real OCI manifests run
 * a few KiB; index.json itself is bounded by O(pin count * descriptor size)
 * and stays well under this. Anything larger is treated as a corrupted or
 * hostile blob and rejected at parse time.
 */
#define MAX_MANIFEST_BYTES (4 * 1024 * 1024)

/* OCI annotation key under which pin names live in manifests[] descriptors. */
static const char ANNOT_REF_NAME[] = "org.opencontainers.image.ref.name";

/* OCI media types used when filling the manifests[] descriptor. The actual
 * mediaType is read from the manifest blob when present; these constants
 * are the fallbacks used when the blob omits the JSON field (an older
 * Docker manifest, for instance).
 */
static const char MT_OCI_IMAGE_INDEX[] =
    "application/vnd.oci.image.index.v1+json";
static const char MT_OCI_IMAGE_MANIFEST[] =
    "application/vnd.oci.image.manifest.v1+json";

struct oci_store {
    char *root;
    oci_blob_store_t *blobs;
};

/* OCI image-layout 1.0.0 marker payload. The spec wants a JSON object with
 * exactly one field: imageLayoutVersion = "1.0.0". The trailing newline is
 * conventional and matches what umoci / skopeo write.
 */
static const char OCI_LAYOUT_BODY[] = "{\"imageLayoutVersion\":\"1.0.0\"}\n";

/* Idempotently write <root>/oci-layout. Returns 0 on success or when the
 * marker already exists, -1 on any unexpected IO failure. The write uses a
 * pid + counter-suffixed tmp file plus link(2) so a concurrent opener never
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

/* Resolve the on-disk path of a manifest blob keyed by "<algo>:<hex>". The
 * digest string has already been validated by oci_digest_parse, so the hex
 * length is bounded and snprintf cannot truncate within STORE_PATH_MAX.
 */
static int blob_path_for_digest(const oci_store_t *s,
                                const char *digest_str,
                                char *out, size_t cap)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        errno = EINVAL;
        return -1;
    }
    int n = oci_blob_store_path(s->blobs, algo, hex, out, cap);
    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* stat the manifest blob and return its size. The caller has already
 * validated the digest shape; ENOENT here means the caller forgot to
 * persist the blob before pinning it, which is a programmer error in the
 * pull / fixture path rather than user input.
 */
static int blob_size(const oci_store_t *s,
                     const char *digest_str,
                     int64_t *out_size)
{
    char path[STORE_PATH_MAX];
    if (blob_path_for_digest(s, digest_str, path, sizeof(path)) < 0)
        return -1;
    struct stat st;
    if (stat(path, &st) < 0)
        return -1;
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        return -1;
    }
    *out_size = (int64_t) st.st_size;
    return 0;
}

/* Best-effort read of the manifest blob's mediaType. Returns a heap-allocated
 * string on success. When the blob omits the JSON mediaType field (older
 * Docker manifests), sniff the shape: a top-level manifests array means an
 * image-index, a layers array means an image-manifest. Falls back to the
 * OCI image-manifest media type when the JSON is unrecognized so the
 * descriptor stays schema-valid. Returns NULL on IO or parse failure with
 * errno preserved.
 */
static char *infer_manifest_media_type(const oci_store_t *s,
                                       const char *digest_str)
{
    char path[STORE_PATH_MAX];
    if (blob_path_for_digest(s, digest_str, path, sizeof(path)) < 0)
        return NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return NULL;
    }
    if (st.st_size <= 0 || st.st_size > (off_t) MAX_MANIFEST_BYTES) {
        close(fd);
        errno = EINVAL;
        return NULL;
    }
    size_t len = (size_t) st.st_size;
    char *body = malloc(len + 1);
    if (!body) {
        close(fd);
        errno = ENOMEM;
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, body + off, len - off);
        if (got < 0) {
            int saved = errno;
            free(body);
            close(fd);
            errno = saved;
            return NULL;
        }
        if (got == 0)
            break;
        off += (size_t) got;
    }
    close(fd);
    body[off] = '\0';

    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) {
        errno = EINVAL;
        return NULL;
    }

    const char *mt = NULL;
    const cJSON *mt_field = cJSON_GetObjectItemCaseSensitive(root, "mediaType");
    if (cJSON_IsString(mt_field) && mt_field->valuestring)
        mt = mt_field->valuestring;

    char *dup = NULL;
    if (mt) {
        dup = strdup(mt);
    } else if (cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(root,
                                                              "manifests"))) {
        dup = strdup(MT_OCI_IMAGE_INDEX);
    } else {
        dup = strdup(MT_OCI_IMAGE_MANIFEST);
    }
    cJSON_Delete(root);
    if (!dup) {
        errno = ENOMEM;
        return NULL;
    }
    return dup;
}

/* Read <root>/index.json as a parsed cJSON tree. Returns NULL with errno=ENOENT
 * when the file is missing (the empty-store happy path), NULL with another
 * errno on IO failure, or NULL with errno=EINVAL on a parse error. The caller
 * owns the returned tree and must cJSON_Delete it.
 */
static cJSON *read_index_json(const char *root, const char **err_msg)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/index.json", root);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        if (err_msg)
            *err_msg = "index.json path exceeds STORE_PATH_MAX";
        return NULL;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        if (err_msg && errno != ENOENT)
            *err_msg = "failed to open index.json";
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        if (err_msg)
            *err_msg = "fstat on index.json failed";
        return NULL;
    }
    if (st.st_size < 0 || st.st_size > (off_t) MAX_MANIFEST_BYTES) {
        close(fd);
        errno = EINVAL;
        if (err_msg)
            *err_msg = "index.json is empty or implausibly large";
        return NULL;
    }
    size_t len = (size_t) st.st_size;
    char *body = malloc(len + 1);
    if (!body) {
        close(fd);
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "out of memory reading index.json";
        return NULL;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, body + off, len - off);
        if (got < 0) {
            int saved = errno;
            free(body);
            close(fd);
            errno = saved;
            if (err_msg)
                *err_msg = "read on index.json failed";
            return NULL;
        }
        if (got == 0)
            break;
        off += (size_t) got;
    }
    close(fd);
    body[off] = '\0';

    cJSON *root_json = cJSON_Parse(body);
    free(body);
    if (!root_json) {
        errno = EINVAL;
        if (err_msg)
            *err_msg = "index.json is not valid JSON";
        return NULL;
    }
    return root_json;
}

/* Build an empty OCI image-index skeleton. Returns NULL on alloc failure. */
static cJSON *new_empty_index(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return NULL;
    if (!cJSON_AddNumberToObject(root, "schemaVersion", 2) ||
        !cJSON_AddStringToObject(root, "mediaType", MT_OCI_IMAGE_INDEX)) {
        cJSON_Delete(root);
        return NULL;
    }
    cJSON *manifests = cJSON_CreateArray();
    if (!manifests) {
        cJSON_Delete(root);
        return NULL;
    }
    if (!cJSON_AddItemToObject(root, "manifests", manifests)) {
        cJSON_Delete(manifests);
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

/* Walk the manifests[] array, return the index of the descriptor whose
 * annotations.<ANNOT_REF_NAME> equals name, or -1 if not found.
 */
static int find_manifest_index(const cJSON *manifests, const char *name)
{
    if (!cJSON_IsArray(manifests))
        return -1;
    int n = cJSON_GetArraySize(manifests);
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        if (!cJSON_IsObject(entry))
            continue;
        const cJSON *annots =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        if (!cJSON_IsObject(annots))
            continue;
        const cJSON *got =
            cJSON_GetObjectItemCaseSensitive(annots, ANNOT_REF_NAME);
        if (cJSON_IsString(got) && got->valuestring &&
            strcmp(got->valuestring, name) == 0)
            return i;
    }
    return -1;
}

/* Build a manifests[] descriptor object for (name, media_type, digest, size).
 * Returns a newly-allocated cJSON node owned by the caller. NULL on alloc.
 */
static cJSON *build_descriptor(const char *name, const char *media_type,
                               const char *digest_str, int64_t size)
{
    cJSON *desc = cJSON_CreateObject();
    if (!desc)
        return NULL;
    if (!cJSON_AddStringToObject(desc, "mediaType", media_type) ||
        !cJSON_AddStringToObject(desc, "digest", digest_str) ||
        !cJSON_AddNumberToObject(desc, "size", (double) size))
        goto fail;
    cJSON *annots = cJSON_CreateObject();
    if (!annots)
        goto fail;
    if (!cJSON_AddItemToObject(desc, "annotations", annots)) {
        cJSON_Delete(annots);
        goto fail;
    }
    if (!cJSON_AddStringToObject(annots, ANNOT_REF_NAME, name))
        goto fail;
    return desc;

fail:
    cJSON_Delete(desc);
    return NULL;
}

static unsigned long pin_seq(void)
{
    static unsigned long n = 0;
    return __sync_add_and_fetch(&n, 1);
}

/* Serialize root_json to <root>/index.json via tmp + rename. The publish is
 * atomic with respect to readers: an open() either sees the previous inode
 * or the new one, never a half-written file. fsync the tmp file before
 * rename so a crash after rename leaves a durable document.
 */
static int write_index_json(const char *root, const cJSON *root_json,
                            const char **err_msg)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/index.json", root);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        if (err_msg)
            *err_msg = "index.json path exceeds STORE_PATH_MAX";
        return -1;
    }
    char tmp[STORE_PATH_MAX];
    n = snprintf(tmp, sizeof(tmp), "%s.tmp-%d-%lu", path, (int) getpid(),
                 pin_seq());
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        if (err_msg)
            *err_msg = "index.json tmp path exceeds STORE_PATH_MAX";
        return -1;
    }

    char *body = cJSON_PrintUnformatted(root_json);
    if (!body) {
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "failed to serialize index.json";
        return -1;
    }
    size_t body_len = strlen(body);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        int saved = errno;
        free(body);
        errno = saved;
        if (err_msg)
            *err_msg = "failed to create index.json tmp file";
        return -1;
    }

    /* Append a trailing newline so external tools that line-print the file
     * (jq, cat) render cleanly. cJSON_PrintUnformatted does not include it.
     */
    const char nl = '\n';
    if (write(fd, body, body_len) != (ssize_t) body_len ||
        write(fd, &nl, 1) != 1) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        free(body);
        errno = saved;
        if (err_msg)
            *err_msg = "failed to write index.json tmp file";
        return -1;
    }
    free(body);
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "fsync on index.json tmp file failed";
        return -1;
    }
    if (close(fd) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "close on index.json tmp file failed";
        return -1;
    }
    if (rename(tmp, path) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        if (err_msg)
            *err_msg = "rename of index.json tmp file failed";
        return -1;
    }
    return 0;
}

/* Acquire LOCK_EX on <root>/index.json.lock. The lock file is created when
 * missing; failures to create it (full disk, permission) surface immediately
 * so a writer never proceeds without coordination. Returns the lock fd on
 * success; the caller must close() it to release the lock (POSIX advisory
 * lock semantics tie lifetime to the fd).
 */
static int acquire_index_lock(const char *root, const char **err_msg)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/index.json.lock", root);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        if (err_msg)
            *err_msg = "index.json.lock path exceeds STORE_PATH_MAX";
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) {
        if (err_msg)
            *err_msg = "failed to open index.json.lock";
        return -1;
    }
    if (flock(fd, LOCK_EX) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        if (err_msg)
            *err_msg = "flock on index.json.lock failed";
        return -1;
    }
    return fd;
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

    /* Validate digest shape so a corrupt caller cannot poison the pin
     * descriptor with arbitrary bytes that later defeat oci_store_get_ref.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        if (err_msg)
            *err_msg = "digest must be lowercase <algo>:<hex>";
        errno = EINVAL;
        return -1;
    }

    int64_t size = 0;
    if (blob_size(s, digest_str, &size) < 0) {
        if (err_msg)
            *err_msg = "manifest blob is not present in the local store";
        return -1;
    }
    char *media_type = infer_manifest_media_type(s, digest_str);
    if (!media_type) {
        if (err_msg)
            *err_msg = "failed to determine manifest mediaType from blob";
        return -1;
    }

    char *name = oci_ref_canonical_name(ref);
    if (!name) {
        int saved = errno;
        free(media_type);
        errno = saved;
        if (err_msg)
            *err_msg = "failed to render canonical ref name";
        return -1;
    }

    int rc = -1;
    int lock_fd = acquire_index_lock(s->root, err_msg);
    if (lock_fd < 0)
        goto out_no_lock;

    const char *read_err = NULL;
    cJSON *root_json = read_index_json(s->root, &read_err);
    if (!root_json) {
        if (errno != ENOENT) {
            if (err_msg)
                *err_msg = read_err ? read_err : "failed to read index.json";
            goto out;
        }
        root_json = new_empty_index();
        if (!root_json) {
            errno = ENOMEM;
            if (err_msg)
                *err_msg = "out of memory building empty index.json";
            goto out;
        }
    }

    cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(root_json, "manifests");
    if (!cJSON_IsArray(manifests)) {
        /* Corrupt or hand-edited index: rebuild the array so writes still
         * make progress. The old contents are discarded.
         */
        cJSON_DeleteItemFromObject(root_json, "manifests");
        manifests = cJSON_CreateArray();
        if (!manifests || !cJSON_AddItemToObject(root_json, "manifests",
                                                  manifests)) {
            cJSON_Delete(manifests);
            errno = ENOMEM;
            if (err_msg)
                *err_msg = "out of memory rebuilding manifests array";
            goto out;
        }
    }

    cJSON *desc = build_descriptor(name, media_type, digest_str, size);
    if (!desc) {
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "out of memory building pin descriptor";
        goto out;
    }

    int existing = find_manifest_index(manifests, name);
    if (existing >= 0) {
        /* Replace in place so concurrent re-pulls of the same tag do not
         * accumulate duplicate descriptors.
         */
        if (!cJSON_ReplaceItemInArray(manifests, existing, desc)) {
            cJSON_Delete(desc);
            errno = EIO;
            if (err_msg)
                *err_msg = "failed to replace existing pin descriptor";
            goto out;
        }
    } else if (!cJSON_AddItemToArray(manifests, desc)) {
        cJSON_Delete(desc);
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "failed to append pin descriptor";
        goto out;
    }

    if (write_index_json(s->root, root_json, err_msg) < 0)
        goto out;

    rc = 0;

out:
    cJSON_Delete(root_json);
    /* close releases the flock per POSIX advisory-lock semantics. */
    close(lock_fd);
out_no_lock:
    free(name);
    free(media_type);
    return rc;
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

    char *name = oci_ref_canonical_name(ref);
    if (!name) {
        if (err_msg)
            *err_msg = "failed to render canonical ref name";
        return -1;
    }

    const char *read_err = NULL;
    cJSON *root_json = read_index_json(s->root, &read_err);
    if (!root_json) {
        free(name);
        if (errno == ENOENT && err_msg)
            *err_msg = "ref not pinned in local store";
        else if (err_msg)
            *err_msg = read_err ? read_err : "failed to read index.json";
        return -1;
    }

    cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(root_json, "manifests");
    int idx = find_manifest_index(manifests, name);
    free(name);
    if (idx < 0) {
        cJSON_Delete(root_json);
        errno = ENOENT;
        if (err_msg)
            *err_msg = "ref not pinned in local store";
        return -1;
    }

    const cJSON *entry = cJSON_GetArrayItem(manifests, idx);
    const cJSON *digest_field =
        cJSON_GetObjectItemCaseSensitive(entry, "digest");
    if (!cJSON_IsString(digest_field) || !digest_field->valuestring) {
        cJSON_Delete(root_json);
        errno = EINVAL;
        if (err_msg)
            *err_msg = "pin descriptor is missing digest field";
        return -1;
    }

    /* Re-validate the digest shape so a hand-edited index.json cannot smuggle
     * a malformed digest back to a caller that trusts the store output.
     */
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_field->valuestring, &algo, hex)) {
        cJSON_Delete(root_json);
        errno = EINVAL;
        if (err_msg)
            *err_msg = "pin descriptor digest has invalid shape";
        return -1;
    }

    char *copy = strdup(digest_field->valuestring);
    cJSON_Delete(root_json);
    if (!copy) {
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "out of memory";
        return -1;
    }
    *out_digest = copy;
    return 0;
}

int oci_store_list_refs(oci_store_t *s,
                        oci_pin_list_t *out,
                        const char **err_msg)
{
    if (!s || !out) {
        if (err_msg)
            *err_msg = "invalid arguments";
        errno = EINVAL;
        return -1;
    }
    out->items = NULL;
    out->count = 0;

    const char *read_err = NULL;
    cJSON *root_json = read_index_json(s->root, &read_err);
    if (!root_json) {
        if (errno == ENOENT)
            return 0;
        if (err_msg)
            *err_msg = read_err ? read_err : "failed to read index.json";
        return -1;
    }

    cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(root_json, "manifests");
    if (!cJSON_IsArray(manifests)) {
        cJSON_Delete(root_json);
        return 0;
    }
    int n = cJSON_GetArraySize(manifests);
    if (n <= 0) {
        cJSON_Delete(root_json);
        return 0;
    }

    oci_pin_entry_t *items = calloc((size_t) n, sizeof(*items));
    if (!items) {
        cJSON_Delete(root_json);
        errno = ENOMEM;
        if (err_msg)
            *err_msg = "out of memory allocating pin list";
        return -1;
    }
    size_t filled = 0;
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        if (!cJSON_IsObject(entry))
            continue;
        const cJSON *annots =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        const cJSON *name_field =
            cJSON_IsObject(annots)
                ? cJSON_GetObjectItemCaseSensitive(annots, ANNOT_REF_NAME)
                : NULL;
        const cJSON *digest_field =
            cJSON_GetObjectItemCaseSensitive(entry, "digest");
        if (!cJSON_IsString(name_field) || !name_field->valuestring ||
            !cJSON_IsString(digest_field) || !digest_field->valuestring) {
            /* Skip schema-incomplete entries: a third-party tool may have
             * inserted a manifest without the ref-name annotation, in which
             * case it is not a pin from elfuse's perspective.
             */
            continue;
        }
        char *name_copy = strdup(name_field->valuestring);
        char *digest_copy = strdup(digest_field->valuestring);
        if (!name_copy || !digest_copy) {
            free(name_copy);
            free(digest_copy);
            for (size_t k = 0; k < filled; k++) {
                free(items[k].name);
                free(items[k].digest);
            }
            free(items);
            cJSON_Delete(root_json);
            errno = ENOMEM;
            if (err_msg)
                *err_msg = "out of memory copying pin entry";
            return -1;
        }
        items[filled].name = name_copy;
        items[filled].digest = digest_copy;
        filled++;
    }
    cJSON_Delete(root_json);

    if (filled == 0) {
        free(items);
        return 0;
    }

    out->items = items;
    out->count = filled;
    return 0;
}

void oci_pin_list_free(oci_pin_list_t *list)
{
    if (!list)
        return;
    if (list->items) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->items[i].name);
            free(list->items[i].digest);
        }
        free(list->items);
    }
    list->items = NULL;
    list->count = 0;
}
