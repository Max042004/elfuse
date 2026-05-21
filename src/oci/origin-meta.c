/* OCI unpacked-tree provenance sidecar implementation
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../externals/cjson/cJSON.h"
#include "oci/origin-meta.h"

#define OCI_ORIGIN_FILE ".elfuse-origin.json"

static int set_err(const char **err, const char *msg, int err_no)
{
    if (err)
        *err = msg;
    errno = err_no;
    return -1;
}

static char *build_path(const char *root_dir, const char *name, int tmp)
{
    size_t want = strlen(root_dir) + 1 + strlen(name) + (tmp ? 4 : 0) + 1;
    char *p = malloc(want);
    if (!p)
        return NULL;
    snprintf(p, want, "%s/%s%s", root_dir, name, tmp ? ".tmp" : "");
    return p;
}

int oci_origin_write(const char *root_dir,
                     const char *manifest_digest,
                     const char *config_digest,
                     char *const *diff_ids,
                     const char **err)
{
    static const char *dummy_err;
    if (!err)
        err = &dummy_err;
    *err = NULL;
    if (!root_dir || !manifest_digest || !config_digest)
        return set_err(err, "origin write: NULL argument", EINVAL);
    if (!root_dir[0] || !manifest_digest[0] || !config_digest[0])
        return set_err(err, "origin write: empty argument", EINVAL);

    cJSON *root = cJSON_CreateObject();
    if (!root)
        return set_err(err, "origin write: cJSON_CreateObject failed", ENOMEM);
    if (!cJSON_AddStringToObject(root, "manifest_digest", manifest_digest)) {
        cJSON_Delete(root);
        return set_err(err, "origin write: manifest_digest add failed", ENOMEM);
    }
    if (!cJSON_AddStringToObject(root, "config_digest", config_digest)) {
        cJSON_Delete(root);
        return set_err(err, "origin write: config_digest add failed", ENOMEM);
    }
    cJSON *arr = cJSON_AddArrayToObject(root, "layer_diffids");
    if (!arr) {
        cJSON_Delete(root);
        return set_err(err, "origin write: layer_diffids add failed", ENOMEM);
    }
    if (diff_ids) {
        for (char *const *p = diff_ids; *p; p++) {
            cJSON *s = cJSON_CreateString(*p);
            if (!s) {
                cJSON_Delete(root);
                return set_err(err, "origin write: diff_id string failed",
                               ENOMEM);
            }
            cJSON_AddItemToArray(arr, s);
        }
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json)
        return set_err(err, "origin write: cJSON_Print failed", ENOMEM);
    size_t jlen = strlen(json);

    char *tmp_path = build_path(root_dir, OCI_ORIGIN_FILE, 1);
    char *final_path = build_path(root_dir, OCI_ORIGIN_FILE, 0);
    if (!tmp_path || !final_path) {
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: path allocation failed", ENOMEM);
    }

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        int saved = errno;
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: open tmp failed", saved);
    }
    if (write(fd, json, jlen) != (ssize_t) jlen) {
        int saved = errno ? errno : EIO;
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: write failed", saved);
    }
    if (fsync(fd) < 0) {
        int saved = errno;
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: fsync failed", saved);
    }
    close(fd);
    if (rename(tmp_path, final_path) < 0) {
        int saved = errno;
        unlink(tmp_path);
        free(tmp_path);
        free(final_path);
        free(json);
        return set_err(err, "origin write: rename failed", saved);
    }

    free(tmp_path);
    free(final_path);
    free(json);
    return 0;
}
