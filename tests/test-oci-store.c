/* Local OCI image store unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the pin / unpin / open invariants of src/oci/store.c against an
 * mkdtemp scratch root: open layout creation, put + get round trip, miss
 * surfaces ENOENT, digest-only refs are rejected (their digest is the pin),
 * malformed digest input is rejected, deep repository slashes get mkdir -p,
 * and the underlying blob store handle survives the wrapping store.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* The pin digest used across cases. SHA-256 of "abc"; the same value verified
 * by test-oci-digest and test-oci-blob-store so the suites cross-reference.
 */
static const char DIGEST_ABC[] =
    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static bool parse_ref(const char *s, oci_ref_t *out)
{
    const char *err = NULL;
    if (oci_ref_parse(s, out, &err) < 0) {
        fprintf(stderr, "ref parse failed for %s: %s\n", s, err ? err : "?");
        return false;
    }
    return true;
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
    snprintf(path, sizeof(path), "%s/refs", root);
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        report_fail("open_creates_layout", "refs/ missing");
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
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("put_get_round_trip", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, DIGEST_ABC, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("put_get_round_trip", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, DIGEST_ABC) != 0) {
        report_fail("put_get_round_trip", "digest mismatch");
        free(got);
        goto cleanup;
    }
    free(got);

    /* Pin file lives at <root>/refs/docker.io/library/alpine/3.20 */
    struct stat st;
    char path[2048];
    snprintf(path, sizeof(path), "%s/refs/docker.io/library/alpine/3.20", root);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("put_get_round_trip", "pin file not at expected path");
        goto cleanup;
    }
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
    int rc = oci_store_put_ref(s, &ref, DIGEST_ABC, &err);
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

static void test_deep_repository_mkdir(const char *scratch)
{
    char root[1024];
    snprintf(root, sizeof(root), "%s/case-deep", scratch);
    oci_store_t *s = oci_store_open(root);
    if (!s) {
        report_fail("deep_repository_mkdir", "open failed");
        return;
    }
    oci_ref_t ref = {0};
    if (!parse_ref("ghcr.io/owner/group/sub/img:v1.0", &ref)) {
        report_fail("deep_repository_mkdir", "ref parse failed");
        oci_store_close(s);
        return;
    }
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, DIGEST_ABC, &err) < 0) {
        report_fail("deep_repository_mkdir", err ? err : "put failed");
        goto cleanup;
    }
    struct stat st;
    char path[2048];
    snprintf(path, sizeof(path),
             "%s/refs/ghcr.io/owner/group/sub/img/v1.0", root);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        report_fail("deep_repository_mkdir", "deep pin not at expected path");
        goto cleanup;
    }
    report_pass("deep_repository_mkdir");

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
    oci_ref_t ref = {0};
    if (!parse_ref("alpine:3.20", &ref)) {
        report_fail("overwrite_pin", "ref parse failed");
        oci_store_close(s);
        return;
    }
    static const char SECOND[] =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852"
        "b855";
    const char *err = NULL;
    if (oci_store_put_ref(s, &ref, DIGEST_ABC, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "first put failed");
        goto cleanup;
    }
    if (oci_store_put_ref(s, &ref, SECOND, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "second put failed");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0) {
        report_fail("overwrite_pin", err ? err : "get failed");
        goto cleanup;
    }
    if (!got || strcmp(got, SECOND) != 0) {
        report_fail("overwrite_pin", "pin was not overwritten");
        free(got);
        goto cleanup;
    }
    free(got);
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
    static const char ABC[] = "abc";
    static const char ABC_HEX[] =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    if (oci_blob_store_put_bytes(blobs, OCI_DIGEST_SHA256, ABC_HEX, ABC,
                                 sizeof(ABC) - 1) < 0) {
        report_fail("pin_blob_share_root", "blob put failed");
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
    if (oci_store_put_ref(s, &ref, DIGEST_ABC, &err) < 0) {
        report_fail("pin_blob_share_root", err ? err : "put_ref failed");
        goto cleanup;
    }
    if (!oci_blob_store_has(blobs, OCI_DIGEST_SHA256, ABC_HEX)) {
        report_fail("pin_blob_share_root", "blob disappeared after pin");
        goto cleanup;
    }
    char *got = NULL;
    if (oci_store_get_ref(s, &ref, &got, &err) < 0 ||
        strcmp(got, DIGEST_ABC) != 0) {
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
    test_deep_repository_mkdir(scratch);
    test_overwrite_pin(scratch);
    test_pin_blob_share_root(scratch);
    test_default_root_from_env();

    wipe_dir(scratch);
    free(scratch);

    printf("\n%s/%d store tests passed\n", passed == total ? GREEN : RED,
           total);
    printf("%d/%d\n" RESET, passed, total);
    return passed == total ? 0 : 1;
}
