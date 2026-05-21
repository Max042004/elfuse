/* OCI layer unpack orchestrator implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
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

static int apply_one_layer(oci_blob_store_t *bs,
                           const oci_descriptor_t *desc,
                           const char *root_dir,
                           oci_meta_table_t *meta,
                           bool quiet,
                           size_t idx,
                           const char **err)
{
    if (oci_media_type_is_foreign(desc->media_type))
        return set_err(err, "unpack: layer is foreign / nondistributable",
                       ENOTSUP);
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

    if (!quiet)
        fprintf(stderr, "  layer %zu: %s\n", idx + 1, desc->digest_str);

    oci_layer_apply_stats_t stats = {0};
    int rc = oci_layer_apply(r, root_dir, &stats, meta, err);

    oci_tar_reader_free(r);
    oci_stream_close(stream);
    close(fd);

    if (rc < 0)
        return -1;
    if (!quiet)
        fprintf(stderr,
                "    +files=%zu dirs=%zu symlinks=%zu hardlinks=%zu "
                "whiteouts=%zu opaques=%zu\n",
                stats.files, stats.dirs, stats.symlinks, stats.hardlinks,
                stats.whiteouts, stats.opaques);
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

    oci_meta_table_t *meta = oci_meta_table_new();
    if (!meta) {
        free(image_hex);
        oci_manifest_free(&manifest);
        set_err(err, "unpack: meta table alloc failed", ENOMEM);
        goto fail_stage_dir;
    }

    for (size_t i = 0; i < manifest.nlayers; i++) {
        if (apply_one_layer(bs, &manifest.layers[i], stage_dir, meta, quiet, i,
                            err) < 0) {
            oci_meta_table_free(meta);
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
    }

    /* Write the sidecar metadata before committing the stage. */
    if (oci_meta_write(meta, stage_dir, err) < 0) {
        oci_meta_table_free(meta);
        free(image_hex);
        oci_manifest_free(&manifest);
        goto fail_stage_dir;
    }
    oci_meta_table_free(meta);

    /* Read + parse the image-config blob so the origin sidecar can
     * record the diff_ids the Plan 1 root-set walker needs. A missing
     * origin file would let prune silently delete layer blobs still
     * backing this unpacked tree, so any failure here aborts the
     * commit.
     */
    {
        uint8_t *cfg_body = NULL;
        size_t cfg_len = 0;
        if (read_blob(bs, manifest.config.algo, manifest.config.hex, &cfg_body,
                      &cfg_len, err) < 0) {
            free(image_hex);
            oci_manifest_free(&manifest);
            goto fail_stage_dir;
        }
        oci_image_config_t cfg = {0};
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
        oci_image_config_free(&cfg);
    }

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
