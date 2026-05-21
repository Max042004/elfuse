/* OCI layer unpack orchestrator implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/decompress.h"
#include "oci/digest.h"
#include "oci/layer-apply.h"
#include "oci/layer-meta.h"
#include "oci/manifest.h"
#include "oci/media-type.h"
#include "oci/origin-meta.h"
#include "oci/ref.h"
#include "oci/store.h"
#include "oci/tar.h"
#include "oci/unpack.h"
#include "oci/volume.h"

#define UN_PATH_MAX 4096
#define UN_BLOB_BUF 65536

typedef struct {
    oci_stream_t *s;
} unpack_stream_ctx_t;

static ssize_t unpack_stream_read_cb(void *ctx, void *buf, size_t cap)
{
    unpack_stream_ctx_t *c = ctx;
    return oci_stream_read(c->s, buf, cap);
}

static int set_err(const char **err, const char *msg, int err_no)
{
    if (err)
        *err = msg;
    errno = err_no;
    return -1;
}

static int mkdir_p(const char *path)
{
    char buf[UN_PATH_MAX];
    size_t n = strlen(path);
    if (n >= sizeof(buf))
        return -1;
    memcpy(buf, path, n + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, 0755) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rand_hex(char *out, size_t n_hex)
{
    size_t need = n_hex / 2;
    uint8_t buf[16];
    if (need > sizeof(buf))
        return -1;
    if (getentropy(buf, need) < 0)
        return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < need; i++) {
        out[i * 2] = hex[buf[i] >> 4];
        out[i * 2 + 1] = hex[buf[i] & 0xf];
    }
    out[n_hex] = '\0';
    return 0;
}

static int read_blob(oci_blob_store_t *bs,
                     oci_digest_algo_t algo,
                     const char *hex,
                     uint8_t **out_buf,
                     size_t *out_len,
                     const char **err)
{
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, algo, hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: blob path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: blob open failed", errno);
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return set_err(err, "unpack: blob fstat failed", errno);
    }
    if (st.st_size < 0 || st.st_size > (off_t) (256 * 1024 * 1024)) {
        close(fd);
        return set_err(err, "unpack: blob size out of bounds", EINVAL);
    }
    uint8_t *buf = malloc((size_t) st.st_size + 1);
    if (!buf) {
        close(fd);
        return set_err(err, "unpack: blob buffer alloc failed", ENOMEM);
    }
    ssize_t got = read(fd, buf, (size_t) st.st_size);
    close(fd);
    if (got != st.st_size) {
        free(buf);
        return set_err(err, "unpack: blob short read", EIO);
    }
    buf[got] = '\0';
    *out_buf = buf;
    *out_len = (size_t) got;
    return 0;
}

/* Open the on-disk blob path and confirm its sha256 hash matches the
 * descriptor's expected digest. Phase 1 already verified at write time,
 * but unpack re-verifies in case a host-side tool modified the blob.
 */
static int reverify_layer_digest(oci_blob_store_t *bs,
                                 const oci_descriptor_t *desc,
                                 const char **err)
{
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, desc->algo, desc->hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: layer path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: layer open failed", errno);

    oci_digester_t *d = oci_digester_new(desc->algo);
    if (!d) {
        close(fd);
        return set_err(err, "unpack: digester alloc failed", ENOMEM);
    }
    uint8_t buf[UN_BLOB_BUF];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            oci_digester_free(d);
            close(fd);
            return set_err(err, "unpack: layer read failed", errno);
        }
        if (n == 0)
            break;
        oci_digester_update(d, buf, (size_t) n);
    }
    close(fd);
    char got_hex[OCI_DIGEST_HEX_MAX + 1];
    oci_digester_finish_hex(d, got_hex);
    oci_digester_free(d);
    if (strcmp(got_hex, desc->hex) != 0)
        return set_err(err, "unpack: layer blob digest mismatch", EINVAL);
    return 0;
}

/* Recursively rm a path so clonefile(2) can recreate it. Matches the
 * discipline used in src/oci/clone-rootfs.c: lstat + recurse, no shell-out.
 * Returns 0 on success or when path was already absent; -1 with errno set
 * on any unexpected IO error. The caller is responsible for ensuring path
 * is safe to remove (e.g. a freshly mkdir'd stage_dir, not a user dir).
 */
static int rm_recursive(const char *path)
{
    struct stat st;
    if (lstat(path, &st) < 0)
        return errno == ENOENT ? 0 : -1;
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
        char child[UN_PATH_MAX];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        if (rm_recursive(child) < 0) {
            rc = -1;
            break;
        }
    }
    closedir(d);
    if (rc == 0 && rmdir(path) < 0)
        rc = -1;
    return rc;
}

/* Restore stage_dir from a cumulative cache snapshot. Performs rm -rf
 * stage_dir followed by clonefile(cache_dir, stage_dir, CLONE_NOFOLLOW)
 * which atomically recreates stage_dir with the snapshot contents. If a
 * meta table is supplied, the cached .elfuse-meta.json (if present) is
 * read back and merged into it so subsequent extracts in the same image
 * accumulate on top of the cumulative meta the snapshot persisted.
 * A missing sidecar inside the cache (older snapshot, or a layer that
 * never recorded meta) is benign: nothing to merge, return 0.
 */
static int restore_layer_cache(const char *stage_dir,
                               const char *cache_dir,
                               oci_meta_table_t *meta,
                               const char **err)
{
    if (rm_recursive(stage_dir) < 0)
        return set_err(err, "unpack: cache restore rm stage_dir failed", errno);
    if (clonefile(cache_dir, stage_dir, CLONE_NOFOLLOW) < 0) {
        if (errno == EXDEV)
            return set_err(err,
                           "unpack: cache restore EXDEV (store and stage "
                           "must share an APFS volume)",
                           EXDEV);
        return set_err(err, "unpack: cache restore clonefile failed", errno);
    }
    if (!meta)
        return 0;
    oci_meta_table_t *cached = NULL;
    const char *merr = NULL;
    if (oci_meta_read(stage_dir, &cached, &merr) < 0) {
        if (errno == ENOENT) {
            errno = 0;
            return 0;
        }
        return set_err(err, merr ? merr : "unpack: cache meta read failed",
                       errno);
    }
    int rc = oci_meta_merge(meta, cached);
    int saved = errno;
    oci_meta_table_free(cached);
    if (rc < 0) {
        errno = saved;
        return set_err(err, "unpack: cache meta merge failed", saved);
    }
    return 0;
}

/* Snapshot stage_dir into the layer cache for diff_id. First flushes the
 * caller-supplied meta table (if any) into stage_dir so the snapshot
 * contains the cumulative .elfuse-meta.json that a subsequent cache hit
 * can merge back. Then clonefile(stage_dir, layers/.staging/...) +
 * oci_store_layer_commit publishes the snapshot atomically. A rename race
 * with another writer is handled inside oci_store_layer_commit (loser's
 * staging tree is removed and 0 is returned).
 */
static int snapshot_layer_cache(const char *stage_dir,
                                oci_store_t *cache_store,
                                const char *diff_id,
                                oci_meta_table_t *meta,
                                const char **err)
{
    if (meta) {
        const char *merr = NULL;
        if (oci_meta_write(meta, stage_dir, &merr) < 0)
            return set_err(err,
                           merr ? merr : "unpack: cache meta write failed",
                           errno);
    }
    char stage_path[UN_PATH_MAX];
    if (oci_store_layer_stage_path(cache_store, diff_id, stage_path,
                                   sizeof(stage_path)) < 0)
        return set_err(err, "unpack: layer stage_path resolve failed", errno);
    if (clonefile(stage_dir, stage_path, CLONE_NOFOLLOW) < 0) {
        if (errno == EXDEV)
            return set_err(err,
                           "unpack: cache snapshot EXDEV (store and stage "
                           "must share an APFS volume)",
                           EXDEV);
        return set_err(err, "unpack: cache snapshot clonefile failed", errno);
    }
    const char *cerr = NULL;
    if (oci_store_layer_commit(cache_store, stage_path, diff_id, &cerr) < 0) {
        int saved = errno;
        (void) rm_recursive(stage_path);
        errno = saved;
        return set_err(err, cerr ? cerr : "unpack: layer commit failed", saved);
    }
    return 0;
}

int oci_unpack_layer(oci_blob_store_t *bs,
                     const oci_descriptor_t *desc,
                     const char *stage_dir,
                     const oci_unpack_layer_options_t *opts,
                     oci_layer_apply_stats_t *stats,
                     oci_meta_table_t *meta,
                     const char *log_label,
                     const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!bs || !desc || !stage_dir)
        return set_err(err, "unpack_layer: NULL argument", EINVAL);

    if (oci_media_type_is_foreign(desc->media_type))
        return set_err(err, "unpack: layer is foreign / nondistributable",
                       ENOTSUP);

    bool cache_enabled = opts && opts->cache_store && opts->diff_id;

    /* Cache-hit fast path: the cached snapshot already encodes both the
     * filesystem state and the cumulative meta sidecar through this layer,
     * so the helper short-circuits the entire reverify + decompress +
     * apply chain. Reverify is intentionally skipped here: the cache entry
     * was populated by a prior successful unpack that already validated
     * the compressed blob.
     */
    if (cache_enabled) {
        int hit = oci_store_layer_has(opts->cache_store, opts->diff_id);
        if (hit < 0)
            return set_err(err, "unpack: cache lookup failed", errno);
        if (hit == 1) {
            char cache_dir[UN_PATH_MAX];
            if (oci_store_layer_resolve(opts->cache_store, opts->diff_id,
                                        cache_dir, sizeof(cache_dir)) < 0)
                return set_err(err,
                               "unpack: cache path resolve failed", errno);
            /* Strip the trailing '/' clonefile would reject as a duplicate. */
            size_t cdl = strlen(cache_dir);
            if (cdl > 0 && cache_dir[cdl - 1] == '/')
                cache_dir[cdl - 1] = '\0';
            if (restore_layer_cache(stage_dir, cache_dir, meta, err) < 0)
                return -1;
            if (log_label)
                fprintf(stderr, "  %s: %s (cached)\n", log_label,
                        desc->digest_str);
            return 0;
        }
    }

    if (reverify_layer_digest(bs, desc, err) < 0)
        return -1;
    char path[UN_PATH_MAX];
    if (oci_blob_store_path(bs, desc->algo, desc->hex, path, sizeof(path)) < 0)
        return set_err(err, "unpack: layer path resolve failed", errno);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return set_err(err, "unpack: layer open failed", errno);

    oci_compression_t alg = oci_media_type_compression(desc->media_type);
    oci_stream_t *stream = oci_decompress_open(fd, alg, err);
    if (!stream) {
        close(fd);
        return -1;
    }

    unpack_stream_ctx_t tctx = {.s = stream};
    oci_tar_reader_t *r = oci_tar_reader_new(unpack_stream_read_cb, &tctx);
    if (!r) {
        oci_stream_close(stream);
        close(fd);
        return set_err(err, "unpack: tar reader alloc failed", ENOMEM);
    }

    if (log_label)
        fprintf(stderr, "  %s: %s\n", log_label, desc->digest_str);

    oci_layer_apply_stats_t local_stats = {0};
    int rc = oci_layer_apply(r, stage_dir, &local_stats, meta, err);

    oci_tar_reader_free(r);
    oci_stream_close(stream);
    close(fd);

    if (rc < 0)
        return -1;
    if (stats) {
        stats->files += local_stats.files;
        stats->dirs += local_stats.dirs;
        stats->symlinks += local_stats.symlinks;
        stats->hardlinks += local_stats.hardlinks;
        stats->whiteouts += local_stats.whiteouts;
        stats->opaques += local_stats.opaques;
    }
    if (log_label)
        fprintf(stderr,
                "    +files=%zu dirs=%zu symlinks=%zu hardlinks=%zu "
                "whiteouts=%zu opaques=%zu\n",
                local_stats.files, local_stats.dirs, local_stats.symlinks,
                local_stats.hardlinks, local_stats.whiteouts,
                local_stats.opaques);

    /* Cache-miss snapshot: persist the cumulative state for future hits.
     * Errors propagate so a misconfigured store (EXDEV across filesystems,
     * out-of-space, etc) does not silently degrade the cache.
     */
    if (cache_enabled &&
        snapshot_layer_cache(stage_dir, opts->cache_store, opts->diff_id, meta,
                             err) < 0)
        return -1;

    return 0;
}

/* Resolve the manifest digest for ref: prefer ref->digest_str when
 * present, else read the pin file via oci_store_get_ref.
 */
static int resolve_manifest_digest(oci_store_t *store,
                                   const oci_ref_t *ref,
                                   char *out_str,
                                   size_t out_cap,
                                   const char **err)
{
    if (ref->digest && ref->digest[0]) {
        if (strlen(ref->digest) + 1 > out_cap)
            return set_err(err, "unpack: digest string overflow", ENAMETOOLONG);
        memcpy(out_str, ref->digest, strlen(ref->digest) + 1);
        return 0;
    }
    char *pin = NULL;
    const char *perr = NULL;
    if (oci_store_get_ref(store, ref, &pin, &perr) < 0) {
        if (errno == ENOENT)
            return set_err(
                err, "unpack: tag pin missing; run 'elfuse oci pull' first",
                ENOENT);
        return set_err(err, perr ? perr : "unpack: tag pin read failed",
                       errno ? errno : EIO);
    }
    if (strlen(pin) + 1 > out_cap) {
        free(pin);
        return set_err(err, "unpack: pin string overflow", ENAMETOOLONG);
    }
    memcpy(out_str, pin, strlen(pin) + 1);
    free(pin);
    return 0;
}

int oci_unpack(oci_store_t *store,
               const oci_ref_t *ref,
               const oci_unpack_options_t *opts,
               char **out_image_dir,
               const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!store || !ref || !out_image_dir)
        return set_err(err, "unpack: NULL argument", EINVAL);
    *out_image_dir = NULL;

    bool quiet = opts && opts->quiet;
    bool force = opts && opts->force_relayer;

    /* Resolve / provision the sysroot volume. */
    char *volume_root = NULL;
    if (oci_volume_ensure(opts ? opts->volume_root : NULL, &volume_root, err) <
        0)
        return -1;

    /* Ensure images/ and images/.staging/ exist. */
    char *images_dir = NULL;
    char *staging_dir = NULL;
    if (oci_volume_subdir(volume_root, "images", &images_dir, err) < 0)
        goto fail_volume;
    if (oci_volume_subdir(volume_root, "images/.staging", &staging_dir, err) <
        0)
        goto fail_images;

    /* Resolve the manifest digest. */
    char manifest_digest[OCI_DIGEST_HEX_MAX + 16];
    if (resolve_manifest_digest(store, ref, manifest_digest,
                                sizeof(manifest_digest), err) < 0)
        goto fail_staging;

    oci_digest_algo_t algo;
    char manifest_hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(manifest_digest, &algo, manifest_hex))
        return set_err(err, "unpack: manifest digest parse failed", EINVAL);

    /* Read the manifest blob. If it is an image-index, pick linux/arm64
     * and re-read the sub-manifest.
     */
    oci_blob_store_t *bs = oci_store_blobs(store);
    if (!bs) {
        set_err(err, "unpack: blob store unavailable", EIO);
        goto fail_staging;
    }
    uint8_t *body = NULL;
    size_t body_len = 0;
    if (read_blob(bs, algo, manifest_hex, &body, &body_len, err) < 0)
        goto fail_staging;

    oci_manifest_t manifest = {0};
    oci_index_t index = {0};
    const char *perr = NULL;
    char *image_hex = NULL;
    /* Try manifest first; if it fails, try index. */
    if (oci_manifest_parse((const char *) body, body_len, &manifest, &perr) <
        0) {
        memset(&manifest, 0, sizeof(manifest));
        if (oci_index_parse((const char *) body, body_len, &index, &perr) < 0) {
            set_err(err, perr ? perr : "unpack: manifest parse failed", EINVAL);
            free(body);
            goto fail_staging;
        }
        free(body);
        const oci_index_entry_t *pick = oci_index_pick_linux_arm64(&index);
        if (!pick) {
            oci_index_free(&index);
            set_err(err, "unpack: no linux/arm64 entry in image index", ENOENT);
            goto fail_staging;
        }
        char sub_digest[OCI_DIGEST_HEX_MAX + 16];
        if (strlen(pick->desc.digest_str) >= sizeof(sub_digest)) {
            oci_index_free(&index);
            set_err(err, "unpack: sub-manifest digest overflow", ENAMETOOLONG);
            goto fail_staging;
        }
        memcpy(sub_digest, pick->desc.digest_str,
               strlen(pick->desc.digest_str) + 1);
        oci_digest_algo_t sub_algo;
        char sub_hex[OCI_DIGEST_HEX_MAX + 1];
        if (!oci_digest_parse(sub_digest, &sub_algo, sub_hex)) {
            oci_index_free(&index);
            set_err(err, "unpack: sub-manifest digest parse failed", EINVAL);
            goto fail_staging;
        }
        oci_index_free(&index);
        if (read_blob(bs, sub_algo, sub_hex, &body, &body_len, err) < 0)
            goto fail_staging;
        if (oci_manifest_parse((const char *) body, body_len, &manifest,
                               &perr) < 0) {
            set_err(err, perr ? perr : "unpack: sub-manifest parse failed",
                    EINVAL);
            free(body);
            goto fail_staging;
        }
        image_hex = strdup(sub_hex);
    } else {
        image_hex = strdup(manifest_hex);
    }
    free(body);

    if (!image_hex) {
        oci_manifest_free(&manifest);
        set_err(err, "unpack: image hex strdup failed", ENOMEM);
        goto fail_staging;
    }

    /* Final target: <volume>/images/sha256-<hex>/. The directory has
     * '-' instead of ':' to keep the path filesystem-friendly.
     */
    char final_dir[UN_PATH_MAX];
    if ((size_t) snprintf(final_dir, sizeof(final_dir), "%s/sha256-%s",
                          images_dir, image_hex) >= sizeof(final_dir)) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: final dir overflow", ENAMETOOLONG);
        goto fail_staging;
    }

    struct stat st;
    if (lstat(final_dir, &st) == 0 && !force) {
        /* Idempotent rerun: image sysroot already exists. */
        free(image_hex);
        oci_manifest_free(&manifest);
        size_t want = strlen(final_dir) + 2;
        char *dup = malloc(want);
        if (!dup) {
            set_err(err, "unpack: strdup final path failed", ENOMEM);
            goto fail_staging;
        }
        snprintf(dup, want, "%s/", final_dir);
        *out_image_dir = dup;
        free(staging_dir);
        free(images_dir);
        free(volume_root);
        return 0;
    }
    if (force) {
        /* Remove any prior commit so the staging rename does not race. */
        char rm[UN_PATH_MAX];
        snprintf(rm, sizeof(rm), "rm -rf '%s'", final_dir);
        (void) system(rm);
    }

    /* Stage under <volume>/images/.staging/<random>/ */
    char stage_id[13];
    if (rand_hex(stage_id, 12) < 0) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: getentropy failed", errno);
        goto fail_staging;
    }
    char stage_dir[UN_PATH_MAX];
    if ((size_t) snprintf(stage_dir, sizeof(stage_dir), "%s/%s", staging_dir,
                          stage_id) >= sizeof(stage_dir)) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: stage dir overflow", ENAMETOOLONG);
        goto fail_staging;
    }
    if (mkdir_p(stage_dir) < 0) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: mkdir stage failed", errno);
        goto fail_staging;
    }

    if (!quiet)
        fprintf(stderr, "elfuse oci unpack: applying %zu layer(s)\n",
                manifest.nlayers);

    /* Read + parse the image-config blob up-front so per-layer diff_ids
     * are available to the cache hook in oci_unpack_layer. The Plan 1
     * origin sidecar still consumes the same struct later in this
     * function, so the read happens exactly once.
     */
    oci_image_config_t cfg = {0};
    {
        uint8_t *cfg_body = NULL;
        size_t cfg_len = 0;
        if (read_blob(bs, manifest.config.algo, manifest.config.hex, &cfg_body,
                      &cfg_len, err) < 0) {
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
        const char *cparse_err = NULL;
        if (oci_image_config_parse((const char *) cfg_body, cfg_len, &cfg,
                                   &cparse_err) < 0) {
            set_err(err,
                    cparse_err ? cparse_err
                               : "unpack: image config parse failed",
                    EINVAL);
            free(cfg_body);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
        free(cfg_body);
    }

    /* Validate that diff_ids[] length matches manifest.layers[] length. A
     * mismatch is a malformed image (the OCI image-spec mandates one
     * diff_id per layer in order); fail-fast so the cache never associates
     * a diff_id with the wrong layer payload.
     */
    size_t diff_ids_count = 0;
    if (cfg.rootfs_diff_ids)
        while (cfg.rootfs_diff_ids[diff_ids_count])
            diff_ids_count++;
    if (diff_ids_count != manifest.nlayers) {
        set_err(err,
                "unpack: image config rootfs.diff_ids count mismatch", EINVAL);
        oci_image_config_free(&cfg);
        free(image_hex);
        oci_manifest_free(&manifest);
        goto fail_stage_dir;
    }

    oci_meta_table_t *meta = oci_meta_table_new();
    if (!meta) {
        oci_image_config_free(&cfg);
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: meta table alloc failed", ENOMEM);
        goto fail_stage_dir;
    }

    for (size_t i = 0; i < manifest.nlayers; i++) {
        char label[32];
        const char *log_label = NULL;
        if (!quiet) {
            snprintf(label, sizeof(label), "layer %zu", i + 1);
            log_label = label;
        }
        oci_unpack_layer_options_t lopts = {
            .cache_store = store,
            .diff_id = cfg.rootfs_diff_ids[i],
        };
        if (oci_unpack_layer(bs, &manifest.layers[i], stage_dir, &lopts, NULL,
                             meta, log_label, err) < 0) {
            oci_meta_table_free(meta);
            oci_image_config_free(&cfg);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
    }

    /* Persist the cumulative meta sidecar after the loop. Cache miss paths
     * inside oci_unpack_layer already flushed an intermediate sidecar for
     * snapshot purposes; this final write makes the on-disk state agree
     * with the in-memory table regardless of which path each layer took.
     */
    if (oci_meta_write(meta, stage_dir, err) < 0) {
        oci_meta_table_free(meta);
        oci_image_config_free(&cfg);
        free(image_hex);
        oci_manifest_free(&manifest);
        goto fail_stage_dir;
    }
    oci_meta_table_free(meta);

    /* Origin sidecar: records manifest_digest + config_digest + diff_ids
     * the Plan 1 keep-set walker reads. A failure here aborts the commit
     * because a missing origin file would let prune silently delete layer
     * blobs still backing this unpacked tree.
     */
    {
        char manifest_full[OCI_DIGEST_HEX_MAX + 16];
        if ((size_t) snprintf(manifest_full, sizeof(manifest_full), "sha256:%s",
                              image_hex) >= sizeof(manifest_full)) {
            oci_image_config_free(&cfg);
            set_err(err, "unpack: manifest digest overflow", ENAMETOOLONG);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }

        const char *origin_err = NULL;
        if (oci_origin_write(stage_dir, manifest_full,
                             manifest.config.digest_str, cfg.rootfs_diff_ids,
                             &origin_err) < 0) {
            set_err(err,
                    origin_err ? origin_err : "unpack: origin write failed",
                    errno ? errno : EIO);
            oci_image_config_free(&cfg);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
    }
    oci_image_config_free(&cfg);

    oci_manifest_free(&manifest);

    /* Atomic commit. */
    if (rename(stage_dir, final_dir) < 0) {
        set_err(err, "unpack: stage rename failed", errno);
        free(image_hex);
        goto fail_stage_dir;
    }
    free(image_hex);

    size_t want = strlen(final_dir) + 2;
    char *dup = malloc(want);
    if (!dup) {
        set_err(err, "unpack: strdup final path failed", ENOMEM);
        goto fail_staging;
    }
    snprintf(dup, want, "%s/", final_dir);
    *out_image_dir = dup;

    free(staging_dir);
    free(images_dir);
    free(volume_root);
    return 0;

fail_stage_dir: {
    char rm[UN_PATH_MAX];
    snprintf(rm, sizeof(rm), "rm -rf '%s'", stage_dir);
    (void) system(rm);
}
fail_staging:
    free(staging_dir);
fail_images:
    free(images_dir);
fail_volume:
    free(volume_root);
    return -1;
}
