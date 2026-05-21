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
 * instead of index.json. C2.3 migrates older stores on open by recursively
 * scanning refs/ and rebuilding index.json under the same flock that
 * oci_store_put_ref takes, so a concurrent first-open and first-put cannot
 * double-write. refs/ is left in place for one release so a downgrade still
 * finds the legacy data. Migration is suppressed when ELFUSE_OCI_NO_MIGRATE
 * is set in the environment; in that mode an older store appears empty to
 * oci_store_get_ref / oci_store_list_refs until the env var is cleared on a
 * subsequent open.
 */

#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../../externals/cjson/cJSON.h"
#include "digest-set.h"
#include "digest.h"
#include "manifest.h"
#include "origin-meta.h"
#include "volume.h"

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

/* Environment variable that disables C2.3 auto-migration of pre-index.json
 * stores. When set to any non-empty value, oci_store_open leaves refs/ and
 * the absent index.json alone so a downgrade test or recovery workflow can
 * inspect the legacy layout without the daemon helpfully rewriting it.
 */
static const char NO_MIGRATE_ENV[] = "ELFUSE_OCI_NO_MIGRATE";

/* Walks <root>/refs/ recursively, rebuilds <root>/index.json with one
 * descriptor per discovered pin file, and writes it via tmp + rename. The
 * caller must already hold an LOCK_EX on <root>/index.json.lock. Returns 0
 * on success (including the no-pins-found case), -1 with errno preserved on
 * an unrecoverable IO error. Individual pins whose manifest blob is missing
 * from blobs/ are skipped with a stderr warning so a single dangling pin
 * does not block migration for the rest of the store.
 */
static int migrate_legacy_refs(struct oci_store *s);

/* Plan 3 C3.3b: probe <root>/layers/.schema and migrate v1 stores to v2.
 *
 * Behaviour matrix at oci_store_open time:
 *
 *   - marker present + schemaVersion == 2: no-op.
 *   - marker present + other schemaVersion or unparseable JSON: fail with
 *     errno=EINVAL so a forward-incompatible store does not get silently
 *     repopulated under the wrong shape.
 *   - marker absent + ELFUSE_OCI_NO_MIGRATE set: no-op (inspection mode;
 *     analogous to the C2.3 refs/ -> index.json gate).
 *   - marker absent + <root>/layers/sha256/ empty: write v2 marker.
 *   - marker absent + <root>/layers/sha256/ populated: wipe every direct
 *     child entry under layers/sha256/ (C3.2 cumulative-by-diff_id entries
 *     are not v2-compatible; reachability is recomputable from manifests
 *     at unpack time) and then write the v2 marker.
 *
 * The wipe + write runs under flock(<root>/index.json.lock, LOCK_EX) and
 * re-stats the marker under hold so a concurrent opener does not double
 * migrate. The wipe is scoped to <root>/layers/sha256/ children only;
 * blobs/, images/, tmp/, refs/, index.json, and layers/.staging/ are
 * never touched.
 */
static int ensure_layer_schema_marker(const char *root);

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

/* Ensure <root>/layers/sha256/ and <root>/layers/.staging/ exist on open. The
 * Plan 3 C3.2 per-layer snapshot cache depends on both directories: the first
 * holds committed cache entries and the second is the in-flight staging area
 * for clonefile(2) snapshots. The blob store already created <root> itself
 * (oci_blob_store_open mkdirs the root tree), so this helper only adds the
 * layers/ subtree. mkdir EEXIST is benign so reopens are idempotent.
 */
static int ensure_layer_dirs(const char *root)
{
    static const char *const subdirs[] = {
        "layers",
        "layers/sha256",
        "layers/.staging",
    };
    for (size_t i = 0; i < sizeof(subdirs) / sizeof(subdirs[0]); i++) {
        char path[STORE_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", root, subdirs[i]);
        if (n < 0 || (size_t) n >= sizeof(path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (mkdir(path, 0755) < 0 && errno != EEXIST)
            return -1;
    }
    return 0;
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
    if (ensure_layer_dirs(root) < 0) {
        int saved = errno;
        oci_blob_store_close(blobs);
        errno = saved;
        return NULL;
    }
    if (ensure_layer_schema_marker(root) < 0) {
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

    /* C2.3 auto-migration: detect a pre-index.json store (refs/ tree without
     * an index.json) and rebuild index.json under the same flock that
     * oci_store_put_ref takes. Suppressed by ELFUSE_OCI_NO_MIGRATE so a
     * downgrade test or recovery workflow can inspect the legacy layout
     * without it being silently rewritten.
     */
    const char *no_migrate = getenv(NO_MIGRATE_ENV);
    if (!no_migrate || !*no_migrate) {
        if (migrate_legacy_refs(s) < 0) {
            int saved = errno;
            oci_store_close(s);
            errno = saved;
            return NULL;
        }
    }
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

/* Slurp the manifest-class blob at digest_str into a heap buffer. The
 * caller frees *out_body. Mirrors the size and bounds checks of
 * infer_manifest_media_type so a corrupt or hostile blob does not
 * trigger a multi-GB malloc here. Returns 0 on success or -1 with
 * errno preserved on failure.
 */
static int load_manifest_blob(const oci_store_t *s, const char *digest_str,
                              char **out_body, size_t *out_len)
{
    char path[STORE_PATH_MAX];
    if (blob_path_for_digest(s, digest_str, path, sizeof(path)) < 0)
        return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (st.st_size <= 0 || st.st_size > (off_t) MAX_MANIFEST_BYTES) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    size_t len = (size_t) st.st_size;
    char *body = malloc(len + 1);
    if (!body) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, body + off, len - off);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            int saved = errno;
            free(body);
            close(fd);
            errno = saved;
            return -1;
        }
        if (got == 0)
            break;
        off += (size_t) got;
    }
    close(fd);
    if (off != len) {
        free(body);
        errno = EIO;
        return -1;
    }
    body[len] = '\0';
    *out_body = body;
    *out_len = len;
    return 0;
}

/* True when blobs/<algo>/<hex> for digest_str exists on disk. Errors
 * other than ENOENT (permission, ENAMETOOLONG) propagate as "missing"
 * because the caller's failure path treats either as fatal for the
 * keep-set walk; the distinction is academic.
 */
static bool manifest_blob_exists(const oci_store_t *s, const char *digest_str)
{
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex))
        return false;
    return oci_blob_store_has(s->blobs, algo, hex);
}

/* Recursive expander: ensure digest_str is in out and, if its blob is
 * a manifest or image-index, also add every descriptor it references.
 * Recursion terminates because oci_digest_set_add is a no-op for any
 * digest already in the set, so a cycle (theoretical: an image-index
 * pointing at itself) is bounded.
 *
 * Returns 0 on success, -1 on fatal failure (missing or unparseable
 * blob) with errno set and *err populated.
 */
static int expand_manifest_digest(oci_store_t *s,
                                  const char *digest_str,
                                  oci_digest_set_t *out,
                                  const char **err)
{
    if (oci_digest_set_contains(out, digest_str))
        return 0;
    if (oci_digest_set_add(out, digest_str) < 0) {
        if (err)
            *err = "collect_roots: digest_set_add failed";
        return -1;
    }

    char *body = NULL;
    size_t body_len = 0;
    if (load_manifest_blob(s, digest_str, &body, &body_len) < 0) {
        if (err)
            *err = "collect_roots: referenced manifest blob is missing or "
                   "unreadable";
        return -1;
    }

    oci_manifest_t manifest = {0};
    const char *perr = NULL;
    if (oci_manifest_parse(body, body_len, &manifest, &perr) == 0) {
        int rc = 0;
        if (oci_digest_set_add(out, manifest.config.digest_str) < 0) {
            if (err)
                *err = "collect_roots: digest_set_add for config failed";
            rc = -1;
            goto manifest_done;
        }
        for (size_t i = 0; i < manifest.nlayers; i++) {
            if (oci_digest_set_add(out,
                                   manifest.layers[i].digest_str) < 0) {
                if (err)
                    *err = "collect_roots: digest_set_add for layer failed";
                rc = -1;
                goto manifest_done;
            }
        }
    manifest_done:
        oci_manifest_free(&manifest);
        free(body);
        return rc;
    }
    memset(&manifest, 0, sizeof(manifest));

    /* Not an image-manifest. Try image-index: a multi-arch index
     * references one sub-manifest descriptor per platform.
     */
    oci_index_t index = {0};
    const char *ierr = NULL;
    if (oci_index_parse(body, body_len, &index, &ierr) < 0) {
        free(body);
        if (err)
            *err = "collect_roots: blob is neither image-manifest nor "
                   "image-index";
        errno = EINVAL;
        return -1;
    }
    free(body);

    for (size_t i = 0; i < index.nentries; i++) {
        const char *sub = index.entries[i].desc.digest_str;
        /* Record the sub-manifest descriptor digest even when the
         * blob is not on disk: a multi-arch index legitimately
         * references blobs for other platforms that pull never
         * fetched, and a sweep must not delete the platforms that
         * did materialise. When the blob is present recurse so its
         * config + layers join the keep set; when absent the index
         * descriptor alone is enough because there is no blob to
         * delete.
         */
        if (manifest_blob_exists(s, sub)) {
            if (expand_manifest_digest(s, sub, out, err) < 0) {
                oci_index_free(&index);
                return -1;
            }
        } else if (oci_digest_set_add(out, sub) < 0) {
            if (err)
                *err = "collect_roots: digest_set_add for sub-manifest failed";
            oci_index_free(&index);
            return -1;
        }
    }
    oci_index_free(&index);
    return 0;
}

int oci_store_collect_roots(oci_store_t *s,
                            oci_digest_set_t *out,
                            const char *volume_root,
                            const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!s || !out) {
        if (err)
            *err = "collect_roots: NULL argument";
        errno = EINVAL;
        return -1;
    }
    oci_digest_set_init(out);

    /* Source 1: pins in index.json. list_refs handles the empty case
     * (no index.json yet) without surfacing an error, so a fresh
     * store contributes zero entries from this source.
     */
    oci_pin_list_t pins = {0};
    const char *list_err = NULL;
    if (oci_store_list_refs(s, &pins, &list_err) < 0) {
        if (err)
            *err = list_err ? list_err
                            : "collect_roots: oci_store_list_refs failed";
        return -1;
    }
    for (size_t i = 0; i < pins.count; i++) {
        if (expand_manifest_digest(s, pins.items[i].digest, out, err) < 0) {
            oci_pin_list_free(&pins);
            oci_digest_set_free(out);
            return -1;
        }
    }
    oci_pin_list_free(&pins);

    /* Source 2: unpacked image trees under <volume_root>/images/.
     * A NULL volume_root skips this source entirely (callers that
     * only need the pin contribution). A missing images/ directory
     * is treated as zero contribution by oci_volume_list_unpacked.
     */
    if (volume_root) {
        oci_volume_list_t trees = {0};
        const char *vlerr = NULL;
        if (oci_volume_list_unpacked(volume_root, &trees, &vlerr) < 0) {
            if (err)
                *err = vlerr ? vlerr
                             : "collect_roots: volume_list_unpacked failed";
            oci_digest_set_free(out);
            return -1;
        }
        for (size_t i = 0; i < trees.count; i++) {
            oci_origin_t origin = {0};
            const char *oerr = NULL;
            if (oci_origin_read(trees.items[i], &origin, &oerr) < 0) {
                if (err)
                    *err = oerr
                               ? oerr
                               : "collect_roots: origin sidecar read failed";
                oci_volume_list_free(&trees);
                oci_digest_set_free(out);
                return -1;
            }
            if (expand_manifest_digest(s, origin.manifest_digest, out, err) <
                0) {
                oci_origin_free(&origin);
                oci_volume_list_free(&trees);
                oci_digest_set_free(out);
                return -1;
            }
            oci_origin_free(&origin);
        }
        oci_volume_list_free(&trees);
    }
    return 0;
}

/* Read a legacy pin file at path. The format is a single line of
 * "<algo>:<hex>" optionally followed by \n or \r\n. Trims trailing whitespace
 * and validates digest shape. Returns a heap-allocated digest string on
 * success, NULL on IO or schema failure with errno preserved.
 */
static char *read_legacy_pin_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    char buf[OCI_DIGEST_HEX_MAX + 32];
    ssize_t got = read(fd, buf, sizeof(buf) - 1);
    int saved_errno = errno;
    close(fd);
    if (got < 0) {
        errno = saved_errno;
        return NULL;
    }
    if (got == 0) {
        errno = EINVAL;
        return NULL;
    }
    buf[got] = '\0';
    /* Trim trailing newline / carriage return so a Windows-edited pin file
     * does not feed a stray byte into the digest validator.
     */
    while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r' ||
                       buf[got - 1] == ' ' || buf[got - 1] == '\t')) {
        buf[--got] = '\0';
    }
    if (got == 0) {
        errno = EINVAL;
        return NULL;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(buf, &algo, hex)) {
        errno = EINVAL;
        return NULL;
    }
    char *copy = strdup(buf);
    if (!copy) {
        errno = ENOMEM;
        return NULL;
    }
    return copy;
}

/* Synthesize a pin descriptor for one legacy refs/ leaf and insert it into
 * manifests[]. (name, digest_str) describe the pin; the manifest blob must
 * exist on disk so mediaType + size can be derived. Returns 0 on success,
 * +1 if the pin should be skipped (missing blob or other recoverable hole),
 * -1 with errno preserved on an unrecoverable failure.
 */
static int migrate_append_descriptor(const oci_store_t *s, cJSON *manifests,
                                     const char *name, const char *digest_str)
{
    int64_t size = 0;
    if (blob_size(s, digest_str, &size) < 0) {
        if (errno == ENOENT) {
            fprintf(stderr,
                    "elfuse oci: migration skipping pin %s: manifest blob "
                    "%s missing from blobs/\n", name, digest_str);
            return 1;
        }
        return -1;
    }
    char *media_type = infer_manifest_media_type(s, digest_str);
    if (!media_type)
        return -1;
    cJSON *desc = build_descriptor(name, media_type, digest_str, size);
    free(media_type);
    if (!desc) {
        errno = ENOMEM;
        return -1;
    }
    /* Pre-existing index entry with the same name should not happen during
     * a fresh migration, but defend against a partially-migrated store
     * inheriting from an earlier crash: a later refs/ leaf with the same
     * canonical name simply replaces the earlier one. */
    int existing = find_manifest_index(manifests, name);
    if (existing >= 0) {
        if (!cJSON_ReplaceItemInArray(manifests, existing, desc)) {
            cJSON_Delete(desc);
            errno = EIO;
            return -1;
        }
    } else if (!cJSON_AddItemToArray(manifests, desc)) {
        cJSON_Delete(desc);
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

/* Recursive walk of refs/. depth counts directory levels below refs/:
 *   depth 0 = registry, depth 1.. = repository components, leaf file = tag.
 * head and head_len accumulate the relative path so the leaf callback can
 * split it into registry/repo/tag. *migrated and *skipped track totals for
 * the final log line. Returns 0 on success, -1 on unrecoverable failure.
 */
static int scan_refs_dir(const oci_store_t *s, cJSON *manifests,
                         const char *dir_abs,
                         const char *rel_head, size_t rel_head_len,
                         size_t depth, size_t *migrated, size_t *skipped)
{
    DIR *dp = opendir(dir_abs);
    if (!dp)
        return -1;

    int rc = 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        const char *name = de->d_name;
        if (name[0] == '.' &&
            (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
            continue;
        /* Hidden files (e.g. .DS_Store) are ignored: legacy pins always used
         * an unprefixed registry / tag name so a dotfile cannot represent a
         * pin and we skip it without surfacing as a migration warning. */
        if (name[0] == '.')
            continue;

        size_t name_len = strlen(name);
        char child_abs[STORE_PATH_MAX];
        int n = snprintf(child_abs, sizeof(child_abs), "%s/%s", dir_abs, name);
        if (n < 0 || (size_t) n >= sizeof(child_abs)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        char child_rel[STORE_PATH_MAX];
        int rn = rel_head_len == 0
                     ? snprintf(child_rel, sizeof(child_rel), "%s", name)
                     : snprintf(child_rel, sizeof(child_rel), "%s/%s",
                                rel_head, name);
        if (rn < 0 || (size_t) rn >= sizeof(child_rel)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }

        struct stat st;
        if (lstat(child_abs, &st) < 0) {
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            if (scan_refs_dir(s, manifests, child_abs, child_rel,
                              (size_t) rn, depth + 1, migrated, skipped) < 0) {
                rc = -1;
                break;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode))
            continue;

        /* Leaf file. Need at least one repository component plus the tag, so
         * total depth must be >= 2 (registry / repo / tag). A leaf that lands
         * directly under refs/<registry>/ has no repository component and is
         * not a well-formed legacy pin; skip it with a warning so the store
         * is not silently lossy.
         */
        if (depth < 2) {
            fprintf(stderr,
                    "elfuse oci: migration skipping refs/%s: not deep enough "
                    "for <registry>/<repo>/<tag>\n", child_rel);
            (*skipped)++;
            continue;
        }
        (void) name_len;

        /* Split child_rel = "<registry>/<repo-component>(/<repo-component>)*"
         * "/<tag>". First '/' separates registry; last '/' separates tag.
         */
        const char *first_slash = strchr(child_rel, '/');
        const char *last_slash = strrchr(child_rel, '/');
        if (!first_slash || !last_slash || first_slash == last_slash) {
            fprintf(stderr,
                    "elfuse oci: migration skipping refs/%s: malformed path\n",
                    child_rel);
            (*skipped)++;
            continue;
        }
        size_t reg_len = (size_t) (first_slash - child_rel);
        size_t repo_len = (size_t) (last_slash - first_slash - 1);
        const char *repo_start = first_slash + 1;
        const char *tag_start = last_slash + 1;
        size_t tag_len = strlen(tag_start);
        if (reg_len == 0 || repo_len == 0 || tag_len == 0) {
            fprintf(stderr,
                    "elfuse oci: migration skipping refs/%s: empty path "
                    "component\n", child_rel);
            (*skipped)++;
            continue;
        }

        char *digest_str = read_legacy_pin_file(child_abs);
        if (!digest_str) {
            fprintf(stderr,
                    "elfuse oci: migration skipping refs/%s: pin file "
                    "unreadable or malformed\n", child_rel);
            (*skipped)++;
            continue;
        }

        /* Build canonical "<registry>/<repository>:<tag>" inline (cannot
         * borrow oci_ref_canonical_name without round-tripping through the
         * parser, which would reject repository components that the legacy
         * code path happened to accept). */
        size_t total = reg_len + 1 + repo_len + 1 + tag_len + 1;
        char *canon = malloc(total);
        if (!canon) {
            free(digest_str);
            errno = ENOMEM;
            rc = -1;
            break;
        }
        char *wp = canon;
        memcpy(wp, child_rel, reg_len);
        wp += reg_len;
        *wp++ = '/';
        memcpy(wp, repo_start, repo_len);
        wp += repo_len;
        *wp++ = ':';
        memcpy(wp, tag_start, tag_len);
        wp += tag_len;
        *wp = '\0';

        int ar = migrate_append_descriptor(s, manifests, canon, digest_str);
        free(canon);
        free(digest_str);
        if (ar < 0) {
            rc = -1;
            break;
        }
        if (ar > 0) {
            (*skipped)++;
            continue;
        }
        (*migrated)++;
    }
    closedir(dp);
    return rc;
}

static int migrate_legacy_refs(struct oci_store *s)
{
    char refs_path[STORE_PATH_MAX];
    int n = snprintf(refs_path, sizeof(refs_path), "%s/refs", s->root);
    if (n < 0 || (size_t) n >= sizeof(refs_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct stat st;
    if (lstat(refs_path, &st) < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;

    char index_path[STORE_PATH_MAX];
    n = snprintf(index_path, sizeof(index_path), "%s/index.json", s->root);
    if (n < 0 || (size_t) n >= sizeof(index_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (lstat(index_path, &st) == 0)
        return 0;
    if (errno != ENOENT)
        return -1;

    /* Race window: between the unlocked check and acquire_index_lock a
     * concurrent put_ref / open may have written index.json. Re-check under
     * the lock and bail out if so, otherwise two migrations would race and
     * the later write would partially overwrite a put_ref's descriptor.
     */
    const char *lock_err = NULL;
    int lock_fd = acquire_index_lock(s->root, &lock_err);
    if (lock_fd < 0)
        return -1;

    if (lstat(index_path, &st) == 0) {
        close(lock_fd);
        return 0;
    }
    if (errno != ENOENT) {
        int saved = errno;
        close(lock_fd);
        errno = saved;
        return -1;
    }

    cJSON *root_json = new_empty_index();
    if (!root_json) {
        close(lock_fd);
        errno = ENOMEM;
        return -1;
    }
    cJSON *manifests = cJSON_GetObjectItemCaseSensitive(root_json, "manifests");

    size_t migrated = 0, skipped = 0;
    int rc = scan_refs_dir(s, manifests, refs_path, "", 0, 0,
                           &migrated, &skipped);
    if (rc < 0) {
        int saved = errno;
        cJSON_Delete(root_json);
        close(lock_fd);
        errno = saved;
        return -1;
    }

    /* Write even when migrated == 0 so a future open does not re-probe a
     * refs/ tree that turned out to be empty or all-skipped. An empty
     * index.json is the documented C2.2 happy-path shape (manifests: []).
     */
    const char *write_err = NULL;
    if (write_index_json(s->root, root_json, &write_err) < 0) {
        int saved = errno;
        cJSON_Delete(root_json);
        close(lock_fd);
        errno = saved;
        return -1;
    }
    cJSON_Delete(root_json);
    close(lock_fd);

    if (skipped > 0) {
        fprintf(stderr,
                "elfuse oci: migrated %zu pin(s) from refs/ to index.json "
                "(refs/ kept for downgrade fallback; %zu pin(s) skipped)\n",
                migrated, skipped);
    } else {
        fprintf(stderr,
                "elfuse oci: migrated %zu pin(s) from refs/ to index.json "
                "(refs/ kept for downgrade fallback)\n", migrated);
    }
    return 0;
}

/* Algorithm set this build expects to find under blobs/. Other algorithm
 * subdirectories (a future operator hand-created sha384/, for instance)
 * are left untouched: sweep only inspects directories it recognises.
 */
static const oci_digest_algo_t PRUNE_ALGOS[] = {
    OCI_DIGEST_SHA256,
    OCI_DIGEST_SHA512,
};

/* One dangling-blob entry produced by the classify phase and consumed
 * by the apply phase. path is heap-owned. verdict starts at PRUNE and
 * may be flipped to SKIP by the older-than veto or the keep-bytes
 * budget. size is the on-disk byte count (st_size at classify time);
 * mtime is st_mtime, used as the sort key for the LRU budget and the
 * comparison source for the older-than cutoff.
 */
typedef enum {
    PRUNE_VERDICT_PRUNE = 0,
    PRUNE_VERDICT_SKIP = 1,
} prune_verdict_t;

typedef struct {
    char *path;
    uint64_t size;
    time_t mtime;
    prune_verdict_t verdict;
} prune_candidate_t;

typedef struct {
    prune_candidate_t *items;
    size_t count;
    size_t cap;
} prune_candidate_list_t;

/* Append one dangling-blob entry. Doubles cap from 32 so the realloc
 * cost amortizes across a typical store's tens-to-hundreds of blobs.
 * On alloc failure returns -1 with errno=ENOMEM; the caller is
 * responsible for cleaning up entries staged so far via
 * prune_candidate_list_free.
 */
static int prune_candidate_list_append(prune_candidate_list_t *list,
                                       char *path, uint64_t size, time_t mtime)
{
    if (list->count == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 32;
        prune_candidate_t *grown =
            realloc(list->items, new_cap * sizeof(*grown));
        if (!grown) {
            errno = ENOMEM;
            return -1;
        }
        list->items = grown;
        list->cap = new_cap;
    }
    list->items[list->count].path = path;
    list->items[list->count].size = size;
    list->items[list->count].mtime = mtime;
    list->items[list->count].verdict = PRUNE_VERDICT_PRUNE;
    list->count++;
    return 0;
}

static void prune_candidate_list_free(prune_candidate_list_t *list)
{
    if (!list)
        return;
    for (size_t i = 0; i < list->count; i++)
        free(list->items[i].path);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

/* qsort comparator over an indirection array of candidate pointers
 * (prune_candidate_t **). Sort key is ascending mtime with the path
 * as tie-breaker so order stays deterministic on stores that
 * materialize blobs in quick succession (the test suite needs
 * stable LRU picks against a fixture).
 */
static int prune_candidate_ptr_cmp_mtime_asc(const void *a, const void *b)
{
    const prune_candidate_t *pa = *(const prune_candidate_t * const *) a;
    const prune_candidate_t *pb = *(const prune_candidate_t * const *) b;
    if (pa->mtime < pb->mtime)
        return -1;
    if (pa->mtime > pb->mtime)
        return 1;
    return strcmp(pa->path, pb->path);
}

/* Classify one blobs/<algo>/ directory. For every regular file whose
 * name is a valid lowercase hex digest of the right length, build the
 * canonical "<algo>:<hex>" digest, look it up in the keep set, and
 * either bump kept_blobs (reachable) or append a candidate (dangling).
 * lstat ENOENT mid-walk is treated as a concurrent prune and skipped
 * silently. Subdirectories, dotfiles, and otherwise-shaped entries
 * pass through untouched so the OCI image-layout spec's regular-blob
 * convention is preserved without trampling foreign state.
 *
 * Returns 0 on success and -1 on unrecoverable IO failure with errno
 * preserved.
 */
static int classify_algo_dir(oci_store_t *s,
                             oci_digest_algo_t algo,
                             const oci_digest_set_t *keep,
                             oci_store_prune_options_t *stats,
                             prune_candidate_list_t *list,
                             const char **err)
{
    const char *algo_name = oci_digest_algo_name(algo);
    if (!algo_name) {
        if (err)
            *err = "prune: unknown digest algorithm";
        errno = EINVAL;
        return -1;
    }

    char dir_path[STORE_PATH_MAX];
    int n = snprintf(dir_path, sizeof(dir_path), "%s/blobs/%s", s->root,
                     algo_name);
    if (n < 0 || (size_t) n >= sizeof(dir_path)) {
        if (err)
            *err = "prune: blobs/<algo> path exceeds STORE_PATH_MAX";
        errno = ENAMETOOLONG;
        return -1;
    }

    DIR *dp = opendir(dir_path);
    if (!dp) {
        if (errno == ENOENT)
            return 0;
        if (err)
            *err = "prune: opendir on blobs/<algo> failed";
        return -1;
    }

    int rc = 0;
    struct dirent *de;
    size_t hex_len = oci_digest_hex_len(algo);
    while ((de = readdir(dp)) != NULL) {
        const char *name = de->d_name;
        if (name[0] == '.' &&
            (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
            continue;
        if (name[0] == '.')
            continue;
        /* Reject anything that is not the expected hex shape before
         * paying for an lstat. This both filters subdirectories
         * (whose names rarely happen to be 64 hex chars) and shields
         * the digest_set lookup from non-blob filenames.
         */
        if (strlen(name) != hex_len)
            continue;
        if (!oci_digest_hex_valid(algo, name))
            continue;

        char blob_path[STORE_PATH_MAX];
        int bn = snprintf(blob_path, sizeof(blob_path), "%s/%s", dir_path,
                          name);
        if (bn < 0 || (size_t) bn >= sizeof(blob_path)) {
            if (err)
                *err = "prune: blob path exceeds STORE_PATH_MAX";
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }

        struct stat st;
        if (lstat(blob_path, &st) < 0) {
            if (errno == ENOENT)
                continue;
            if (err)
                *err = "prune: lstat on blob failed";
            rc = -1;
            break;
        }
        if (!S_ISREG(st.st_mode))
            continue;

        char digest[OCI_DIGEST_HEX_MAX + 16];
        int dn = snprintf(digest, sizeof(digest), "%s:%s", algo_name, name);
        if (dn < 0 || (size_t) dn >= sizeof(digest)) {
            if (err)
                *err = "prune: digest string buffer too small";
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }

        if (oci_digest_set_contains(keep, digest)) {
            stats->kept_blobs++;
            continue;
        }

        char *path_copy = strdup(blob_path);
        if (!path_copy) {
            if (err)
                *err = "prune: strdup blob path failed";
            errno = ENOMEM;
            rc = -1;
            break;
        }
        if (prune_candidate_list_append(list, path_copy, (uint64_t) st.st_size,
                                        st.st_mtime) < 0) {
            free(path_copy);
            if (err)
                *err = "prune: candidate list grow failed";
            rc = -1;
            break;
        }
    }
    closedir(dp);
    return rc;
}

/* Apply the C1.4 filter passes to the candidate list. Both passes
 * mutate verdict only; nothing is unlinked here. The caller invokes
 * apply_verdicts afterwards to count + (when commit) unlink.
 *
 * older-than veto (B1) inspects each candidate independently: when
 * older_than_sec is non-zero and (now - mtime) is less than the
 * cutoff, verdict flips to SKIP. now is provided by the caller so a
 * single time(NULL) snapshot drives the whole filter pass (avoids
 * the boundary case where a candidate flips between PRUNE and SKIP
 * across two sequential time(NULL) reads).
 *
 * keep-bytes budget (B2) operates over the candidates still in PRUNE
 * state after B1. Their pointers are gathered, sorted by mtime
 * ascending, and walked newest-first. The newest candidates whose
 * cumulative size fits keep_bytes flip to SKIP; the first candidate
 * that does not fit terminates the walk so any older candidate stays
 * in PRUNE even if its own size would have fit alone. This matches
 * LRU semantics: oldest evicted first, regardless of size.
 */
static int apply_filters(oci_store_prune_options_t *opts,
                         prune_candidate_list_t *list,
                         time_t now, const char **err)
{
    if (opts->older_than_sec > 0) {
        time_t cutoff = (time_t) opts->older_than_sec;
        for (size_t i = 0; i < list->count; i++) {
            if (list->items[i].verdict != PRUNE_VERDICT_PRUNE)
                continue;
            time_t age = now - list->items[i].mtime;
            if (age < cutoff)
                list->items[i].verdict = PRUNE_VERDICT_SKIP;
        }
    }

    if (opts->keep_bytes > 0 && list->count > 0) {
        prune_candidate_t **active =
            (prune_candidate_t **) malloc(list->count * sizeof(*active));
        if (!active) {
            if (err)
                *err = "prune: out of memory ranking candidates";
            errno = ENOMEM;
            return -1;
        }
        size_t na = 0;
        for (size_t i = 0; i < list->count; i++) {
            if (list->items[i].verdict == PRUNE_VERDICT_PRUNE)
                active[na++] = &list->items[i];
        }
        if (na > 0) {
            /* Sort the active subset through an indirection array so
             * the candidate-list iteration order in apply_verdicts
             * stays in insertion order (the test suite is easier to
             * reason about when path verdicts read in the same order
             * the classify phase produced them).
             */
            qsort((void *) active, na, sizeof(*active),
                  prune_candidate_ptr_cmp_mtime_asc);
            uint64_t running = 0;
            for (ssize_t i = (ssize_t) na - 1; i >= 0; i--) {
                /* Use unsigned arithmetic with an overflow guard so a
                 * pathological size never wraps the accumulator.
                 */
                uint64_t next = running + active[i]->size;
                if (next < running) {
                    /* Overflow: cannot fit any more blobs under the
                     * budget, so stop reclassifying.
                     */
                    break;
                }
                if (next <= opts->keep_bytes) {
                    active[i]->verdict = PRUNE_VERDICT_SKIP;
                    running = next;
                } else {
                    break;
                }
            }
        }
        free((void *) active);
    }
    return 0;
}

/* Materialise filter verdicts onto disk and stats. Every candidate
 * contributes to exactly one output bucket: SKIP -> skipped_*, PRUNE
 * -> pruned_* (and unlink when commit). The unlink failure policy
 * mirrors C1.3: ENOENT is treated as a concurrent prune and counted
 * silently; any other unlink errno is fatal so the caller's stats
 * never report bytes we did not actually reclaim.
 */
static int apply_verdicts(prune_candidate_list_t *list, bool commit,
                          oci_store_prune_options_t *stats, const char **err)
{
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].verdict == PRUNE_VERDICT_SKIP) {
            stats->skipped_blobs++;
            stats->skipped_bytes += list->items[i].size;
            continue;
        }
        stats->pruned_blobs++;
        stats->pruned_bytes += list->items[i].size;
        if (!commit)
            continue;
        if (unlink(list->items[i].path) < 0) {
            if (errno == ENOENT)
                continue;
            if (err)
                *err = "prune: unlink on dangling blob failed";
            return -1;
        }
    }
    return 0;
}

int oci_store_prune(oci_store_t *s,
                    oci_store_prune_options_t *opts,
                    const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!s || !opts) {
        if (err)
            *err = "prune: NULL argument";
        errno = EINVAL;
        return -1;
    }

    opts->kept_blobs = 0;
    opts->pruned_blobs = 0;
    opts->pruned_bytes = 0;
    opts->skipped_blobs = 0;
    opts->skipped_bytes = 0;

    /* Serialize against oci_store_put_ref so a pull cannot publish a
     * new pin between collect_roots and sweep. Mark and sweep both run
     * under the lock.
     */
    int lock_fd = acquire_index_lock(s->root, err);
    if (lock_fd < 0)
        return -1;

    oci_digest_set_t keep = {0};
    if (oci_store_collect_roots(s, &keep, opts->volume_root, err) < 0) {
        int saved = errno;
        close(lock_fd);
        errno = saved;
        return -1;
    }

    prune_candidate_list_t candidates = {0};
    int rc = 0;
    for (size_t i = 0; i < sizeof(PRUNE_ALGOS) / sizeof(PRUNE_ALGOS[0]); i++) {
        if (classify_algo_dir(s, PRUNE_ALGOS[i], &keep, opts, &candidates,
                              err) < 0) {
            rc = -1;
            goto done;
        }
    }

    /* Filters short-circuit when no candidates exist or when neither
     * input flag is set; in either case verdicts stay PRUNE and the
     * apply pass behaves exactly like the C1.3 sweep.
     */
    if (apply_filters(opts, &candidates, time(NULL), err) < 0) {
        rc = -1;
        goto done;
    }
    if (apply_verdicts(&candidates, opts->commit, opts, err) < 0) {
        rc = -1;
        goto done;
    }

done:;
    int saved = errno;
    prune_candidate_list_free(&candidates);
    oci_digest_set_free(&keep);
    close(lock_fd);
    errno = saved;
    return rc;
}

/* --- Plan 3 C3.2: layer cache helpers ---------------------------------- */

/* Parse a "<algo>:<hex>" diff_id into its components and the lowercase
 * algorithm name used as the cache subdir. Validation matches the digest
 * library; oci_digest_parse already rejects unknown algos and bad hex.
 */
static int parse_diff_id_for_cache(const char *diff_id,
                                   oci_digest_algo_t *out_algo,
                                   char *out_hex,
                                   const char **out_algo_name)
{
    if (!diff_id || !*diff_id) {
        errno = EINVAL;
        return -1;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(diff_id, &algo, hex)) {
        errno = EINVAL;
        return -1;
    }
    const char *name = oci_digest_algo_name(algo);
    if (!name) {
        errno = EINVAL;
        return -1;
    }
    *out_algo = algo;
    memcpy(out_hex, hex, strlen(hex) + 1);
    *out_algo_name = name;
    return 0;
}

int oci_store_layer_has(oci_store_t *s, const char *diff_id)
{
    if (!s) {
        errno = EINVAL;
        return -1;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    const char *algo_name = NULL;
    if (parse_diff_id_for_cache(diff_id, &algo, hex, &algo_name) < 0)
        return -1;

    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/layers/%s/%s", s->root, algo_name,
                     hex);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    struct stat st;
    if (stat(path, &st) < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 1;
}

int oci_store_layer_resolve(oci_store_t *s,
                            const char *diff_id,
                            char *out, size_t cap)
{
    if (!s || !out || cap == 0) {
        errno = EINVAL;
        return -1;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    const char *algo_name = NULL;
    if (parse_diff_id_for_cache(diff_id, &algo, hex, &algo_name) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/layers/%s/%s/", s->root, algo_name, hex);
    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Produce 12 lowercase hex chars from 6 random bytes. Mirrors the local
 * rand_hex helpers in src/oci/unpack.c and src/oci/clone-rootfs.c; kept
 * static here so store.c stays self-contained.
 */
static int layer_stage_rand_suffix(char out[13])
{
    uint8_t raw[6];
    if (getentropy(raw, sizeof(raw)) < 0)
        return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2] = hex[raw[i] >> 4];
        out[i * 2 + 1] = hex[raw[i] & 0xf];
    }
    out[12] = '\0';
    return 0;
}

int oci_store_layer_stage_path(oci_store_t *s,
                               const char *diff_id,
                               char *out, size_t cap)
{
    if (!s || !out || cap == 0) {
        errno = EINVAL;
        return -1;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    const char *algo_name = NULL;
    if (parse_diff_id_for_cache(diff_id, &algo, hex, &algo_name) < 0)
        return -1;
    char rand_suffix[13];
    if (layer_stage_rand_suffix(rand_suffix) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/layers/.staging/%s-%s-%s", s->root, algo_name,
                     hex, rand_suffix);
    if (n < 0 || (size_t) n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Recursively rm a path (file, symlink, or directory). Mirrors the discipline
 * in src/oci/clone-rootfs.c so the layer stage abort path does not shell out.
 * Returns 0 on success or when path was already absent; -1 with errno set on
 * any unexpected IO error. Designed for staging cleanup, not as a general-
 * purpose rm.
 */
static int layer_stage_rm(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISDIR(st.st_mode))
        return unlink(path);
    DIR *d = opendir(path);
    if (!d)
        return -1;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[STORE_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (layer_stage_rm(child) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0 && rmdir(path) < 0)
        rc = -1;
    return rc;
}

int oci_store_layer_commit(oci_store_t *s,
                           const char *stage_path,
                           const char *diff_id,
                           const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!s || !stage_path || !*stage_path) {
        *err = "layer_commit: NULL argument";
        errno = EINVAL;
        return -1;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    const char *algo_name = NULL;
    if (parse_diff_id_for_cache(diff_id, &algo, hex, &algo_name) < 0) {
        *err = "layer_commit: invalid diff_id";
        return -1;
    }
    char dest[STORE_PATH_MAX];
    int n = snprintf(dest, sizeof(dest), "%s/layers/%s/%s", s->root, algo_name,
                     hex);
    if (n < 0 || (size_t) n >= sizeof(dest)) {
        *err = "layer_commit: dest path exceeds STORE_PATH_MAX";
        errno = ENAMETOOLONG;
        return -1;
    }
    if (rename(stage_path, dest) == 0)
        return 0;
    int saved = errno;
    if (saved == EEXIST || saved == ENOTEMPTY) {
        /* Concurrent writer landed the same entry first; drop the loser's
         * staging tree and treat this as a benign success. The cache content
         * is content-addressed so the winning entry is byte-equivalent.
         */
        (void) layer_stage_rm(stage_path);
        errno = 0;
        return 0;
    }
    *err = "layer_commit: rename to layers/<algo>/<hex>/ failed";
    errno = saved;
    return -1;
}

/* --- Plan 3 C3.3b: layer cache schema marker --------------------------- */

/* Relative path of the schema marker beneath the store root. */
static const char LAYER_SCHEMA_REL_PATH[] = "layers/.schema";

/* Schema version this build writes and accepts. v1 was the implicit
 * C3.2 cumulative-by-diff_id layout (no marker). v2 will be the C3.3
 * raw per-layer payload plus ChainID stack cache. C3.3b lands the
 * marker + migration; C3.3c will rewrite the unpack assembly to
 * populate and consume the v2 cache.
 */
#define LAYER_SCHEMA_VERSION_CURRENT 2

/* Body written on first migration to v2. The description field is
 * informational; readers only key on schemaVersion. Trailing newline
 * matches the oci-layout marker convention. */
static const char LAYER_SCHEMA_V2_BODY[] =
    "{\"schemaVersion\":2,"
    "\"description\":\"raw per-layer payload + ChainID stack cache\"}\n";

/* Upper bound on the marker file size. The expected body is ~80 bytes;
 * anything larger is treated as a malformed marker rather than parsed.
 */
#define LAYER_SCHEMA_MAX_BYTES 4096

/* Counter used for the marker's tmp file suffix; kept distinct from the
 * oci-layout counter so the two helpers do not contend on the same
 * monotonic source.
 */
static unsigned long layer_schema_seq(void)
{
    static unsigned long n = 0;
    return __sync_add_and_fetch(&n, 1);
}

/* Read <root>/layers/.schema and extract the schemaVersion field. On
 * success returns 0 and writes the parsed integer to *out_version. On
 * failure returns -1 with errno set (ENOENT when the marker is absent;
 * EINVAL for unparseable JSON, missing schemaVersion field, wrong type,
 * non-regular file, or size out of range; other errno values propagated
 * from open / read / fstat). When non-NULL, *out_reason is populated on
 * the -1 paths with a static description for the caller to surface via
 * stderr.
 */
static int read_layer_schema_version(const char *root, int *out_version,
                                     const char **out_reason)
{
    if (out_reason)
        *out_reason = NULL;
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, LAYER_SCHEMA_REL_PATH);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        if (out_reason)
            *out_reason = "layers/.schema path exceeds STORE_PATH_MAX";
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            if (out_reason)
                *out_reason = "layers/.schema absent";
            return -1;
        }
        if (out_reason)
            *out_reason = "open layers/.schema failed";
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved = errno;
        close(fd);
        if (out_reason)
            *out_reason = "fstat layers/.schema failed";
        errno = saved;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        if (out_reason)
            *out_reason = "layers/.schema is not a regular file";
        errno = EINVAL;
        return -1;
    }
    if (st.st_size <= 0 || st.st_size > LAYER_SCHEMA_MAX_BYTES) {
        close(fd);
        if (out_reason)
            *out_reason = "layers/.schema size out of range";
        errno = EINVAL;
        return -1;
    }
    char buf[LAYER_SCHEMA_MAX_BYTES + 1];
    ssize_t got = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (got != (ssize_t) st.st_size) {
        if (out_reason)
            *out_reason = "read layers/.schema failed";
        errno = EIO;
        return -1;
    }
    buf[got] = '\0';
    cJSON *json = cJSON_Parse(buf);
    if (!json) {
        if (out_reason)
            *out_reason = "layers/.schema JSON parse failed";
        errno = EINVAL;
        return -1;
    }
    cJSON *v = cJSON_GetObjectItemCaseSensitive(json, "schemaVersion");
    if (!cJSON_IsNumber(v)) {
        cJSON_Delete(json);
        if (out_reason)
            *out_reason = "layers/.schema schemaVersion missing or not a number";
        errno = EINVAL;
        return -1;
    }
    int version = v->valueint;
    cJSON_Delete(json);
    *out_version = version;
    return 0;
}

/* Recursively remove every direct child of <root>/layers/sha256/, leaving
 * the layers/sha256/ directory itself in place. Each child is dispatched
 * through layer_stage_rm so symlinks, regular files, and nested
 * directories are all handled identically. On the first IO failure the
 * call returns -1 with errno preserved; *out_removed reflects the entry
 * count successfully removed before the error. layer_stage_rm is
 * ENOENT-tolerant so a partial wipe resumes cleanly on a later open.
 */
static int wipe_layers_sha256(const char *root, size_t *out_removed)
{
    *out_removed = 0;
    char dir_path[STORE_PATH_MAX];
    int n = snprintf(dir_path, sizeof(dir_path), "%s/layers/sha256", root);
    if (n < 0 || (size_t) n >= sizeof(dir_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    DIR *d = opendir(dir_path);
    if (!d) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    int rc = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[STORE_PATH_MAX];
        int cn = snprintf(child, sizeof(child), "%s/%s", dir_path, de->d_name);
        if (cn < 0 || (size_t) cn >= sizeof(child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (layer_stage_rm(child) < 0) {
            rc = -1;
            break;
        }
        (*out_removed)++;
    }
    closedir(d);
    return rc;
}

/* Write <root>/layers/.schema atomically. The body is materialized into a
 * pid + counter-suffixed tmp file, fsynced, and renamed into place. The
 * caller must hold flock(<root>/index.json.lock, LOCK_EX) so two openers
 * cannot race the rename. Returns 0 on success, -1 with errno preserved
 * on any IO failure (the tmp file is removed before returning).
 */
static int write_layer_schema_v2(const char *root)
{
    char path[STORE_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, LAYER_SCHEMA_REL_PATH);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char tmp[STORE_PATH_MAX];
    n = snprintf(tmp, sizeof(tmp), "%s.tmp-%d-%lu", path, (int) getpid(),
                 layer_schema_seq());
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0)
        return -1;
    size_t body_len = sizeof(LAYER_SCHEMA_V2_BODY) - 1;
    if (write(fd, LAYER_SCHEMA_V2_BODY, body_len) != (ssize_t) body_len) {
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
    if (rename(tmp, path) < 0) {
        int saved = errno;
        unlink(tmp);
        errno = saved;
        return -1;
    }
    return 0;
}

static int ensure_layer_schema_marker(const char *root)
{
    /* First probe is lock-free so the marker-present fast path does not
     * pay the flock cost on every open. */
    int version = 0;
    const char *reason = NULL;
    int rc = read_layer_schema_version(root, &version, &reason);
    if (rc == 0) {
        if (version == LAYER_SCHEMA_VERSION_CURRENT)
            return 0;
        fprintf(stderr,
                "elfuse oci: unsupported layers schema version %d at %s; "
                "this build understands up to %d\n",
                version, root, LAYER_SCHEMA_VERSION_CURRENT);
        errno = EINVAL;
        return -1;
    }
    if (errno != ENOENT) {
        int saved = errno;
        fprintf(stderr, "elfuse oci: layers/.schema unreadable at %s: %s\n",
                root, reason ? reason : "unknown error");
        errno = saved;
        return -1;
    }

    /* Marker absent. ELFUSE_OCI_NO_MIGRATE leaves the store untouched so
     * a downgrade test or recovery workflow can inspect any pre-existing
     * v1 entries without the daemon helpfully rewriting state. */
    const char *no_migrate = getenv(NO_MIGRATE_ENV);
    if (no_migrate && *no_migrate)
        return 0;

    const char *lock_err = NULL;
    int lock_fd = acquire_index_lock(root, &lock_err);
    if (lock_fd < 0) {
        int saved = errno;
        fprintf(stderr, "elfuse oci: %s\n",
                lock_err ? lock_err : "failed to acquire index.json.lock");
        errno = saved;
        return -1;
    }

    /* Re-stat under hold: a racing opener may already have migrated. */
    rc = read_layer_schema_version(root, &version, &reason);
    if (rc == 0) {
        close(lock_fd);
        if (version == LAYER_SCHEMA_VERSION_CURRENT)
            return 0;
        fprintf(stderr,
                "elfuse oci: unsupported layers schema version %d at %s; "
                "this build understands up to %d\n",
                version, root, LAYER_SCHEMA_VERSION_CURRENT);
        errno = EINVAL;
        return -1;
    }
    if (errno != ENOENT) {
        int saved = errno;
        close(lock_fd);
        fprintf(stderr, "elfuse oci: layers/.schema unreadable at %s: %s\n",
                root, reason ? reason : "unknown error");
        errno = saved;
        return -1;
    }

    /* Marker still absent under hold: wipe pre-existing v1 entries and
     * publish the v2 marker. */
    size_t removed = 0;
    if (wipe_layers_sha256(root, &removed) < 0) {
        int saved = errno;
        close(lock_fd);
        fprintf(stderr,
                "elfuse oci: failed to migrate layer cache schema at %s: "
                "wipe partial (%zu entr%s removed before error)\n",
                root, removed, removed == 1 ? "y" : "ies");
        errno = saved;
        return -1;
    }
    if (removed > 0) {
        fprintf(stderr,
                "elfuse oci: layer cache schema v1 detected; cleared %zu "
                "entr%s from %s/layers/sha256 to migrate to v2 "
                "(raw + ChainID stack)\n",
                removed, removed == 1 ? "y" : "ies", root);
    }

    if (write_layer_schema_v2(root) < 0) {
        int saved = errno;
        close(lock_fd);
        fprintf(stderr,
                "elfuse oci: failed to write layers/.schema at %s\n", root);
        errno = saved;
        return -1;
    }
    close(lock_fd);
    return 0;
}
