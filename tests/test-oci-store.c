/* Local OCI image store unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the pin / unpin / open / list invariants of src/oci/store.c against
 * an mkdtemp scratch root. Pin writes go through index.json (OCI image-index
 * v1.0.0 schema), so each test first persists a small manifest-shaped blob
 * under blobs/sha256/ and then pins by its digest. Coverage:
 *
 *   - open layout creation (oci-layout marker + blobs/sha256)
 *   - put + get round trip, with pin descriptor materialized in index.json
 *   - get miss surfaces ENOENT
 *   - digest-only refs are rejected (their digest is the pin)
 *   - malformed digest input is rejected
 *   - deep repository slashes are accepted (annotation key carries them)
 *   - overwrite-same-ref replaces the descriptor in place, no duplicates
 *   - blob + pin share the same store root
 *   - schema validity of the emitted index.json (top-level fields and
 *     descriptor shape)
 *   - enumeration API returns every pin
 *   - concurrent writers are serialized by flock and both pins survive
 *   - layout marker is fresh / backfilled / preserved
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../externals/cjson/cJSON.h"
#include "oci/blob-store.h"
#include "oci/digest.h"
#include "oci/ref.h"
#include "oci/store.h"

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int total = 0;
static int passed = 0;

static void report_pass(const char *name)
{
    total++;
    passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *detail)
{
    total++;
    printf("  " RED "FAIL" RESET " %s: %s\n", name, detail ? detail : "");
}

static int remove_entry(const char *path, const struct stat *st, int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

static void wipe_dir(const char *root)
{
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static char *make_scratch_root(void)
{
    char tmpl[] = "/tmp/elfuse-test-oci-store-XXXXXX";
    char *p = mkdtemp(tmpl);
    if (!p)
        return NULL;
    return strdup(p);
}

static bool parse_ref(const char *s, oci_ref_t *out)
{
    const char *err = NULL;
    if (oci_ref_parse(s, out, &err) < 0) {
        fprintf(stderr, "ref parse failed for %s: %s\n", s, err ? err : "?");
        return false;
    }
    return true;
}

/* Stage a manifest-shaped JSON blob under <store>/blobs/sha256/<hex>. The
 * body is hashed by the blob store; the caller receives the resulting
 * "<algo>:<hex>" digest in out_digest. The default body is an OCI image
 * manifest skeleton so infer_manifest_media_type picks the manifest media
 * type; pass NULL/0 to use the default.
 */
static bool stage_manifest_blob(oci_blob_store_t *blobs,
                                const char *body_opt, size_t body_len_opt,
                                char *out_digest, size_t cap)
{
    static const char DEFAULT_BODY[] =
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[]}";

    const char *body = body_opt ? body_opt : DEFAULT_BODY;
    size_t body_len = body_opt ? body_len_opt : sizeof(DEFAULT_BODY) - 1;

    oci_digester_t *d = oci_digester_new(OCI_DIGEST_SHA256);
    if (!d)
        return false;
    oci_digester_update(d, body, body_len);
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (oci_digester_finish_hex(d, hex) == 0) {
        oci_digester_free(d);
        return false;
    }
    oci_digester_free(d);
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, hex, body,
                                 body_len) < 0)
        return false;
    int n = snprintf(out_digest, cap, "sha256:%s", hex);
    if (n < 0 || (size_t) n >= cap)
        return false;
    return true;
}

static bool read_whole(const char *path, char *buf, size_t cap, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    ssize_t got = read(fd, buf, cap - 1);
    close(fd);
    if (got < 0)
        return false;
    buf[got] = '\0';
    if (out_len)
        *out_len = (size_t) got;
    return true;
}

/* Slurp <root>/index.json and cJSON_Parse it. Returns NULL on missing or
 * unparseable. The caller cJSON_Delete()s.
 */
static cJSON *load_index_json(const char *root)
{
    char path[2048];
    snprintf(path, sizeof(path), "%s/index.json", root);
    char buf[8192];
    size_t got = 0;
    if (!read_whole(path, buf, sizeof(buf), &got))
        return NULL;
    return cJSON_Parse(buf);
}

static void test_open_creates_layout(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-open", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("open_creates_layout", "oci_store_open returned NULL");
        return;
    }
    struct stat st;
    char path[2048];
    snprintf(path, sizeof(path), "%s/blobs/sha256", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail("open_creates_layout", "blobs/sha256 missing");
        oci_store_close(s);
        return;
    }
    snprintf(path, sizeof(path), "%s/oci-layout", root);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("open_creates_layout", "oci-layout missing");
        oci_store_close(s);
        return;
    }
    /* index.json is materialized only on first put; a fresh store should
     * have none on disk so external tools observe an empty image layout
     * rather than a phantom pin set.
     */
    snprintf(path, sizeof(path), "%s/index.json", root);
    if (stat(path, &st) == 0) {
        report_fail("open_creates_layout",
                    "index.json materialized before any pin");
        oci_store_close(s);
        return;
    }
    if (!oci_store_blobs(s)) {
        report_fail("open_creates_layout", "blobs handle is NULL");
        oci_store_close(s);
        return;
    }
    if (strcmp(oci_store_root(s), root) != 0) {
        report_fail("open_creates_layout", "root string mismatch");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("open_creates_layout");
}

static void test_put_get_round_trip(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-roundtrip", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("put_get_round_trip", "open failed");
        return;
    }
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, digest_str,
                             sizeof(digest_str))) {
        report_fail("put_get_round_trip", "could not stage manifest blob");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("put_get_round_trip", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, digest_str) != 0) {
        report_fail("put_get_round_trip", "digest mismatch");
        free(got);
        goto cleanup;
    }
    free(got);

    /* The index.json must exist and contain the canonical pin name. */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("put_get_round_trip", "index.json missing or unparseable");
        goto cleanup;
    }
    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 1) {
        report_fail("put_get_round_trip", "manifests array shape unexpected");
        cJSON_Delete(idx);
        goto cleanup;
    }
    const cJSON *entry = cJSON_GetArrayItem(manifests, 0);
    const cJSON *annots =
        cJSON_GetObjectItemCaseSensitive(entry, "annotations");
    const cJSON *name =
        cJSON_GetObjectItemCaseSensitive(annots,
                                         "org.opencontainers.image.ref.name");
    if (!cJSON_IsString(name) ||
        strcmp(name->valuestring, "docker.io/library/alpine:3.20") != 0) {
        report_fail("put_get_round_trip", "ref.name annotation mismatch");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("put_get_round_trip");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_get_miss_enoent(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-miss", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("get_miss_enoent", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("ghcr.io/owner/img:tag", &ref)) {
        report_fail("get_miss_enoent", "ref parse failed");
        oci_store_close(s);
        return;
    }
    char *got = NULL;
    errno = 0;
    const char *err = NULL;
    int rc = oci_store_get_ref(s, &ref, &got, &err);
    if (rc == 0 || errno != ENOENT) {
        report_fail("get_miss_enoent", "expected -1 with ENOENT");
        free(got);
    } else if (got != NULL) {
        report_fail("get_miss_enoent", "out_digest must be NULL on miss");
    } else {
        report_pass("get_miss_enoent");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_digest_only_ref_rejected(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-digest-only", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("digest_only_ref_rejected", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(
            "alpine@sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            &ref, &err) < 0) {
        report_fail("digest_only_ref_rejected", err ? err : "ref parse failed");
        oci_store_close(s);
        return;
    }
    if (ref.tag != NULL) {
        report_fail("digest_only_ref_rejected",
                    "digest-only ref unexpectedly carries a tag");
        oci_ref_free(&ref);
        oci_store_close(s);
        return;
    }
    err = NULL;
    errno = 0;
    int rc = oci_store_put_ref(
        s, &ref,
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &err);
    if (rc == 0 || errno != EINVAL) {
        report_fail("digest_only_ref_rejected", "expected EINVAL on put");
    } else {
        report_pass("digest_only_ref_rejected");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_malformed_digest_rejected(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-bad-digest", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("malformed_digest_rejected", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("malformed_digest_rejected", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    errno = 0;
    int rc = oci_store_put_ref(s, &ref, "not-a-digest", &err);
    if (rc == 0 || errno != EINVAL) {
        report_fail("malformed_digest_rejected", "expected EINVAL on put");
    } else {
        report_pass("malformed_digest_rejected");
    }
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_deep_repository(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-deep", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("deep_repository", "open failed");
        return;
    }
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, digest_str,
                             sizeof(digest_str))) {
        report_fail("deep_repository", "could not stage manifest blob");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("ghcr.io/owner/group/sub/img:v1.0", &ref)) {
        report_fail("deep_repository", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("deep_repository", err ? err : "put failed");
        goto cleanup;
    }
    /* The annotation carries the full canonical name verbatim; no path
     * directory tree is created on disk.
     */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("deep_repository", "index.json missing");
        goto cleanup;
    }
    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    const cJSON *entry = cJSON_GetArrayItem(manifests, 0);
    const cJSON *annots =
        cJSON_GetObjectItemCaseSensitive(entry, "annotations");
    const cJSON *name =
        cJSON_GetObjectItemCaseSensitive(annots,
                                         "org.opencontainers.image.ref.name");
    if (!cJSON_IsString(name) ||
        strcmp(name->valuestring,
               "ghcr.io/owner/group/sub/img:v1.0") != 0) {
        report_fail("deep_repository", "deep ref name annotation mismatch");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("deep_repository");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_overwrite_pin(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-overwrite", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("overwrite_pin", "open failed");
        return;
    }
    /* First pin: default manifest body. */
    char first_digest[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), NULL, 0, first_digest,
                             sizeof(first_digest))) {
        report_fail("overwrite_pin", "could not stage first blob");
        oci_store_close(s);
        return;
    }
    /* Second pin: same shape but different bytes so the digest differs. */
    static const char SECOND_BODY[] =
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"variant\":\"second\"}";
    char second_digest[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), SECOND_BODY,
                             sizeof(SECOND_BODY) - 1, second_digest,
                             sizeof(second_digest))) {
        report_fail("overwrite_pin", "could not stage second blob");
        oci_store_close(s);
        return;
    }
    if (strcmp(first_digest, second_digest) == 0) {
        report_fail("overwrite_pin",
                    "test setup error: both bodies hashed identically");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("overwrite_pin", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, first_digest, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "first put failed");
        goto cleanup;
    }
    if (oci_store_put_ref(s, &ref, second_digest, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "second put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, second_digest) != 0) {
        report_fail("overwrite_pin", "pin was not overwritten");
        free(got);
        goto cleanup;
    }
    free(got);

    /* The manifests array must still have exactly one entry for this pin. */
    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("overwrite_pin", "index.json missing");
        goto cleanup;
    }
    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 1) {
        report_fail("overwrite_pin", "duplicate descriptor after overwrite");
        cJSON_Delete(idx);
        goto cleanup;
    }
    cJSON_Delete(idx);
    report_pass("overwrite_pin");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

static void test_pin_blob_share_root(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-share", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("pin_blob_share_root", "open failed");
        return;
    }
    oci_blob_store_t *blobs = oci_store_blobs(s);
    char digest_str[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(blobs, NULL, 0, digest_str, sizeof(digest_str))) {
        report_fail("pin_blob_share_root", "stage manifest blob failed");
        oci_store_close(s);
        return;
    }
    oci_digest_algo_t algo;
    char hex[OCI_DIGEST_HEX_MAX + 1];
    if (!oci_digest_parse(digest_str, &algo, hex)) {
        report_fail("pin_blob_share_root", "digest parse failed");
        oci_store_close(s);
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("pin_blob_share_root", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
        report_fail("pin_blob_share_root", err ? err : "put_ref failed");
        goto cleanup;
    }
    if (!oci_blob_store_has(blobs, algo, hex)) {
        report_fail("pin_blob_share_root", "blob disappeared after pin");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0 ||
        strcmp(got, digest_str) != 0) {
        report_fail("pin_blob_share_root", "pin disappeared after blob");
        free(got);
        goto cleanup;
    }
    free(got);
    report_pass("pin_blob_share_root");

cleanup:
    oci_ref_free(&ref);
    oci_store_close(s);
}

/* Pull three distinct tags into the same store; verify index.json schema is
 * OCI image-index v1.0.0 shaped and contains all three pins.
 */
static void test_three_pins_schema(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-three-pins", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("three_pins_schema", "open failed");
        return;
    }
    const char *tags[] = {"alpine:3.18", "alpine:3.19", "alpine:3.20"};
    /* Stage a distinct manifest body per tag so each pin has a unique digest
     * and index.json must carry three independent entries.
     */
    for (int i = 0; i < 3; i++) {
        char body[512];
        int n = snprintf(body, sizeof(body),
            "{\"schemaVersion\":2,"
            "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
            "\"config\":{"
            "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
            "\"digest\":\"sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
            "\"size\":3},"
            "\"layers\":[],\"tag\":\"%s\"}",
            tags[i]);
        char digest_str[OCI_DIGEST_HEX_MAX + 16];
        if (!stage_manifest_blob(oci_store_blobs(s), body, (size_t) n,
                                 digest_str, sizeof(digest_str))) {
            report_fail("three_pins_schema", "stage failed");
            oci_store_close(s);
            return;
        }
        oci_ref_t ref = {0};
        if (!parse_ref(tags[i], &ref)) {
            report_fail("three_pins_schema", "ref parse failed");
            oci_store_close(s);
            return;
        }
        const char *err = NULL;
        if (oci_store_put_ref(s, &ref, digest_str, &err) < 0) {
            report_fail("three_pins_schema", err ? err : "put failed");
            oci_ref_free(&ref);
            oci_store_close(s);
            return;
        }
        oci_ref_free(&ref);
    }

    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("three_pins_schema", "index.json missing");
        oci_store_close(s);
        return;
    }
    const cJSON *sv = cJSON_GetObjectItemCaseSensitive(idx, "schemaVersion");
    const cJSON *mt = cJSON_GetObjectItemCaseSensitive(idx, "mediaType");
    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsNumber(sv) || sv->valueint != 2) {
        report_fail("three_pins_schema", "schemaVersion != 2");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    if (!cJSON_IsString(mt) ||
        strcmp(mt->valuestring, "application/vnd.oci.image.index.v1+json")
            != 0) {
        report_fail("three_pins_schema", "top-level mediaType mismatch");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 3) {
        report_fail("three_pins_schema", "manifests array size != 3");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    /* Every descriptor must carry mediaType + digest + size + the ref.name
     * annotation. Validate one field at a time so a failure points at the
     * exact missing piece.
     */
    for (int i = 0; i < 3; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        const cJSON *dmt = cJSON_GetObjectItemCaseSensitive(entry, "mediaType");
        const cJSON *dig = cJSON_GetObjectItemCaseSensitive(entry, "digest");
        const cJSON *sz = cJSON_GetObjectItemCaseSensitive(entry, "size");
        const cJSON *an =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        const cJSON *nm =
            cJSON_IsObject(an)
                ? cJSON_GetObjectItemCaseSensitive(
                      an, "org.opencontainers.image.ref.name")
                : NULL;
        if (!cJSON_IsString(dmt) || !cJSON_IsString(dig) ||
            !cJSON_IsNumber(sz) || sz->valuedouble <= 0 ||
            !cJSON_IsString(nm)) {
            char buf[160];
            snprintf(buf, sizeof(buf), "entry %d missing required field", i);
            report_fail("three_pins_schema", buf);
            cJSON_Delete(idx);
            oci_store_close(s);
            return;
        }
    }
    cJSON_Delete(idx);
    report_pass("three_pins_schema");
    oci_store_close(s);
}

/* Drive oci_store_list_refs over the same three-pin store as above and
 * verify every name + digest is reported back.
 */
static void test_list_refs(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-list", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("list_refs", "open failed");
        return;
    }

    /* Empty store reports zero entries, not an error. */
    oci_pin_list_t empty = {0};
    const char *err = NULL;
    if (oci_store_list_refs(s, &empty, &err) < 0 || empty.count != 0 ||
        empty.items != NULL) {
        report_fail("list_refs", "empty store did not report zero pins");
        oci_pin_list_free(&empty);
        oci_store_close(s);
        return;
    }

    const char *tags[] = {"alpine:3.18", "alpine:3.19", "alpine:3.20"};
    char digests[3][OCI_DIGEST_HEX_MAX + 16];
    for (int i = 0; i < 3; i++) {
        char body[512];
        int n = snprintf(body, sizeof(body),
            "{\"schemaVersion\":2,"
            "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
            "\"config\":{"
            "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
            "\"digest\":\"sha256:"
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
            "\"size\":3},"
            "\"layers\":[],\"tag\":\"%s\"}",
            tags[i]);
        if (!stage_manifest_blob(oci_store_blobs(s), body, (size_t) n,
                                 digests[i], sizeof(digests[i]))) {
            report_fail("list_refs", "stage failed");
            oci_store_close(s);
            return;
        }
        oci_ref_t ref = {0};
        if (!parse_ref(tags[i], &ref) ||
            oci_store_put_ref(s, &ref, digests[i], NULL) < 0) {
            report_fail("list_refs", "put failed");
            oci_ref_free(&ref);
            oci_store_close(s);
            return;
        }
        oci_ref_free(&ref);
    }

    oci_pin_list_t list = {0};
    err = NULL;
    if (oci_store_list_refs(s, &list, &err) < 0) {
        report_fail("list_refs", err ? err : "list failed");
        oci_store_close(s);
        return;
    }
    if (list.count != 3) {
        report_fail("list_refs", "count != 3");
        oci_pin_list_free(&list);
        oci_store_close(s);
        return;
    }

    /* For each expected pin, find a list entry with matching name +
     * digest. Linear lookup is fine at three entries.
     */
    for (int i = 0; i < 3; i++) {
        char want_name[128];
        snprintf(want_name, sizeof(want_name), "docker.io/library/%s",
                 tags[i]);
        bool found = false;
        for (size_t k = 0; k < list.count; k++) {
            if (strcmp(list.items[k].name, want_name) == 0 &&
                strcmp(list.items[k].digest, digests[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            char buf[160];
            snprintf(buf, sizeof(buf), "missing pin %s in list output",
                     want_name);
            report_fail("list_refs", buf);
            oci_pin_list_free(&list);
            oci_store_close(s);
            return;
        }
    }
    oci_pin_list_free(&list);
    report_pass("list_refs");
    oci_store_close(s);
}

/* Concurrent writer test: two threads each pin a distinct tag against the
 * same store. flock must serialize the read-modify-write of index.json so
 * both descriptors land in the final document.
 */
typedef struct {
    oci_store_t *store;
    const char *ref_str;
    const char *digest_str;
    int rc;
    const char *err;
} concurrent_writer_arg_t;

static void *concurrent_writer(void *opaque)
{
    concurrent_writer_arg_t *a = (concurrent_writer_arg_t *) opaque;
    oci_ref_t ref = {0};
    if (!parse_ref(a->ref_str, &ref)) {
        a->rc = -1;
        a->err = "ref parse failed";
        return NULL;
    }
    a->rc = oci_store_put_ref(a->store, &ref, a->digest_str, &a->err);
    oci_ref_free(&ref);
    return NULL;
}

static void test_concurrent_writers(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-concurrent", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("concurrent_writers", "open failed");
        return;
    }
    /* Two distinct manifest blobs / digests, one per tag. */
    char body_a[512];
    int na = snprintf(body_a, sizeof(body_a),
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"writer\":\"a\"}");
    char digest_a[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), body_a, (size_t) na, digest_a,
                             sizeof(digest_a))) {
        report_fail("concurrent_writers", "stage A failed");
        oci_store_close(s);
        return;
    }
    char body_b[512];
    int nb = snprintf(body_b, sizeof(body_b),
        "{\"schemaVersion\":2,"
        "\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\","
        "\"config\":{"
        "\"mediaType\":\"application/vnd.oci.image.config.v1+json\","
        "\"digest\":\"sha256:"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\","
        "\"size\":3},"
        "\"layers\":[],\"writer\":\"b\"}");
    char digest_b[OCI_DIGEST_HEX_MAX + 16];
    if (!stage_manifest_blob(oci_store_blobs(s), body_b, (size_t) nb, digest_b,
                             sizeof(digest_b))) {
        report_fail("concurrent_writers", "stage B failed");
        oci_store_close(s);
        return;
    }

    concurrent_writer_arg_t arg_a = {.store = s,
                                     .ref_str = "alpine:writer-a",
                                     .digest_str = digest_a};
    concurrent_writer_arg_t arg_b = {.store = s,
                                     .ref_str = "alpine:writer-b",
                                     .digest_str = digest_b};

    /* Launch both threads concurrently. flock guarantees the read-modify-
     * write of index.json is serialized; both pins must end up in the final
     * document regardless of which thread won the race.
     */
    pthread_t ta, tb;
    pthread_create(&ta, NULL, concurrent_writer, &arg_a);
    pthread_create(&tb, NULL, concurrent_writer, &arg_b);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    if (arg_a.rc != 0 || arg_b.rc != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "writer rc a=%d b=%d (a=%s b=%s)",
                 arg_a.rc, arg_b.rc, arg_a.err ? arg_a.err : "(none)",
                 arg_b.err ? arg_b.err : "(none)");
        report_fail("concurrent_writers", buf);
        oci_store_close(s);
        return;
    }

    cJSON *idx = load_index_json(root);
    if (!idx) {
        report_fail("concurrent_writers", "index.json missing");
        oci_store_close(s);
        return;
    }
    const cJSON *manifests =
        cJSON_GetObjectItemCaseSensitive(idx, "manifests");
    if (!cJSON_IsArray(manifests) || cJSON_GetArraySize(manifests) != 2) {
        report_fail("concurrent_writers",
                    "expected 2 manifests after concurrent put");
        cJSON_Delete(idx);
        oci_store_close(s);
        return;
    }
    bool saw_a = false, saw_b = false;
    int n = cJSON_GetArraySize(manifests);
    for (int i = 0; i < n; i++) {
        const cJSON *entry = cJSON_GetArrayItem(manifests, i);
        const cJSON *annots =
            cJSON_GetObjectItemCaseSensitive(entry, "annotations");
        const cJSON *name =
            cJSON_GetObjectItemCaseSensitive(
                annots, "org.opencontainers.image.ref.name");
        if (!cJSON_IsString(name))
            continue;
        if (strcmp(name->valuestring, "docker.io/library/alpine:writer-a")
            == 0)
            saw_a = true;
        else if (strcmp(name->valuestring,
                        "docker.io/library/alpine:writer-b") == 0)
            saw_b = true;
    }
    cJSON_Delete(idx);
    if (!saw_a || !saw_b) {
        report_fail("concurrent_writers", "one of the two writers lost");
        oci_store_close(s);
        return;
    }
    report_pass("concurrent_writers");
    oci_store_close(s);
}

/* OCI image-layout 1.0.0 marker payload that oci_store_open writes when the
 * store root is missing the marker. Kept in sync with src/oci/store.c.
 */
static const char EXPECTED_LAYOUT[] = "{\"imageLayoutVersion\":\"1.0.0\"}\n";

static void test_layout_marker_fresh(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-fresh", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_fresh", "open failed");
        return;
    }
    char path[2048];
    snprintf(path, sizeof(path), "%s/oci-layout", root);
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("layout_marker_fresh", "oci-layout file missing");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(path, buf, sizeof(buf), &got)) {
        report_fail("layout_marker_fresh", "could not read marker");
        oci_store_close(s);
        return;
    }
    if (got != sizeof(EXPECTED_LAYOUT) - 1 ||
        memcmp(buf, EXPECTED_LAYOUT, got) != 0) {
        report_fail("layout_marker_fresh", "marker payload mismatch");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_fresh");
}

static void test_layout_marker_added_on_existing(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-backfill", scratch);
    /* Simulate a pre-marker store: open + close once to materialize the
     * directory layout, then unlink the marker so the next open must
     * backfill it from scratch. blobs/sha256/ stays in place, matching a
     * Phase-1 store that predates the marker.
     */
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_backfill", "initial open failed");
        return;
    }
    oci_store_close(s);
    char marker[2048];
    snprintf(marker, sizeof(marker), "%s/oci-layout", root);
    if (unlink(marker) != 0) {
        report_fail("layout_marker_backfill", "could not unlink seed marker");
        return;
    }
    struct stat st;
    if (stat(marker, &st) == 0) {
        report_fail("layout_marker_backfill", "marker survived unlink");
        return;
    }
    s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_backfill", "reopen failed");
        return;
    }
    if (stat(marker, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("layout_marker_backfill", "marker not restored on reopen");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(marker, buf, sizeof(buf), &got) ||
        got != sizeof(EXPECTED_LAYOUT) - 1 ||
        memcmp(buf, EXPECTED_LAYOUT, got) != 0) {
        report_fail("layout_marker_backfill", "restored marker payload bad");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_backfill");
}

static void test_layout_marker_preserved(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-layout-preserve", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_preserve", "initial open failed");
        return;
    }
    oci_store_close(s);

    char marker[2048];
    snprintf(marker, sizeof(marker), "%s/oci-layout", root);
    /* Overwrite the marker with a future imageLayoutVersion stand-in so a
     * silent rewrite would clobber it. The store must leave the bytes
     * untouched on subsequent open: idempotent contract.
     */
    static const char OVERRIDE[] = "{\"imageLayoutVersion\":\"9.9.9\"}\n";
    int fd = open(marker, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        report_fail("layout_marker_preserve", "could not reopen marker");
        return;
    }
    if (write(fd, OVERRIDE, sizeof(OVERRIDE) - 1) !=
        (ssize_t) (sizeof(OVERRIDE) - 1)) {
        close(fd);
        report_fail("layout_marker_preserve", "could not seed override");
        return;
    }
    close(fd);

    struct stat before;
    if (stat(marker, &before) != 0) {
        report_fail("layout_marker_preserve", "marker missing after override");
        return;
    }

    s = oci_store_open(root);
    if (!s) {
        report_fail("layout_marker_preserve", "reopen failed");
        return;
    }

    struct stat after;
    if (stat(marker, &after) != 0) {
        report_fail("layout_marker_preserve", "marker missing after reopen");
        oci_store_close(s);
        return;
    }
    if (before.st_ino != after.st_ino) {
        report_fail("layout_marker_preserve", "marker inode changed");
        oci_store_close(s);
        return;
    }
    char buf[256];
    size_t got = 0;
    if (!read_whole(marker, buf, sizeof(buf), &got) ||
        got != sizeof(OVERRIDE) - 1 || memcmp(buf, OVERRIDE, got) != 0) {
        report_fail("layout_marker_preserve", "marker bytes changed");
        oci_store_close(s);
        return;
    }
    oci_store_close(s);
    report_pass("layout_marker_preserve");
}

static void test_default_root_from_env(void)
{
    /* Save and clear environment so the default-root computation is fully
     * deterministic within the test. */
    char *saved_xdg = NULL;
    const char *cur_xdg = getenv("XDG_DATA_HOME");
    if (cur_xdg)
        saved_xdg = strdup(cur_xdg);
    char *saved_home = NULL;
    const char *cur_home = getenv("HOME");
    if (cur_home)
        saved_home = strdup(cur_home);

    /* XDG path takes precedence. */
    setenv("XDG_DATA_HOME", "/tmp/elfuse-xdg-test", 1);
    setenv("HOME", "/tmp/elfuse-home-test", 1);
    char *r1 = oci_store_default_root();
    if (!r1 || strcmp(r1, "/tmp/elfuse-xdg-test/elfuse/store") != 0) {
        report_fail("default_root_from_env",
                    "XDG_DATA_HOME path not respected");
        free(r1);
        goto restore;
    }
    free(r1);

    /* Fall back to HOME when XDG is unset. */
    unsetenv("XDG_DATA_HOME");
    char *r2 = oci_store_default_root();
    if (!r2 ||
        strcmp(r2,
               "/tmp/elfuse-home-test/Library/Application Support/elfuse/store")
            != 0) {
        report_fail("default_root_from_env",
                    "HOME fallback path not respected");
        free(r2);
        goto restore;
    }
    free(r2);

    /* Neither set: errno=ENOENT. */
    unsetenv("HOME");
    errno = 0;
    char *r3 = oci_store_default_root();
    if (r3 || errno != ENOENT) {
        report_fail("default_root_from_env",
                    "expected NULL with ENOENT when no env present");
        free(r3);
        goto restore;
    }
    report_pass("default_root_from_env");

restore:
    if (saved_xdg)
        setenv("XDG_DATA_HOME", saved_xdg, 1);
    else
        unsetenv("XDG_DATA_HOME");
    if (saved_home)
        setenv("HOME", saved_home, 1);
    else
        unsetenv("HOME");
    free(saved_xdg);
    free(saved_home);
}

int main(void)
{
    printf("OCI store unit tests\n");
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "could not create scratch dir: %s\n", strerror(errno));
        return 1;
    }

    test_open_creates_layout(scratch);
    test_put_get_round_trip(scratch);
    test_get_miss_enoent(scratch);
    test_digest_only_ref_rejected(scratch);
    test_malformed_digest_rejected(scratch);
    test_deep_repository(scratch);
    test_overwrite_pin(scratch);
    test_pin_blob_share_root(scratch);
    test_three_pins_schema(scratch);
    test_list_refs(scratch);
    test_concurrent_writers(scratch);
    test_layout_marker_fresh(scratch);
    test_layout_marker_added_on_existing(scratch);
    test_layout_marker_preserved(scratch);
    test_default_root_from_env();

    wipe_dir(scratch);
    free(scratch);

    printf("\n%s/%d store tests passed\n", passed == total ? GREEN : RED,
           total);
    printf("%d/%d\n" RESET, passed, total);
    return passed == total ? 0 : 1;
}
