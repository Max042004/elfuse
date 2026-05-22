/* OCI content-addressable blob store unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Native macOS test program. Drives every documented store invariant from
 * the open path (layout creation), through one-shot and streaming commits,
 * digest mismatch rejection, dedup, abort, and store-survives-restart, all
 * inside an mkdtemp scratch directory that is wiped on exit.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "oci/blob-store.h"
#include "oci/digest.h"

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

/* Pre-computed SHA-256 of the byte string "abc". Same as the one verified by
 * test-oci-digest, so the two suites cross-reference each other.
 */
static const char SHA256_ABC[] =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

static int remove_entry(const char *path,
                        const struct stat *st,
                        int typeflag,
                        struct FTW *ftwbuf)
{
    (void) st;
    (void) typeflag;
    (void) ftwbuf;
    return remove(path);
}

static void wipe_dir(const char *root)
{
    /* FTW_DEPTH guarantees children are processed before parents so rmdir
     * does not race against still-populated directories.
     */
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static bool dir_is_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool empty = true;
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        empty = false;
        break;
    }
    closedir(dir);
    return empty;
}

static bool path_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool path_is_file(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static char *make_scratch_root(void)
{
    char *tmpl = strdup("/tmp/elfuse-oci-blob-XXXXXX");
    if (!tmpl)
        return NULL;
    if (!mkdtemp(tmpl)) {
        free(tmpl);
        return NULL;
    }
    return tmpl;
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    /* Layout creation: open on a fresh dir must produce blobs/sha256,
     * blobs/sha512, and tmp under root.
     */
    char store_root[512];
    snprintf(store_root, sizeof(store_root), "%s/store", scratch);

    printf("oci_blob_store layout\n");
    oci_blob_store_t *s = oci_blob_store_open(store_root);
    if (!s) {
        report_fail("open creates layout",
                    strerror(errno));
        goto cleanup;
    }
    {
        char p[512];
        snprintf(p, sizeof(p), "%s/blobs/sha256", store_root);
        bool ok_sha256 = path_is_dir(p);
        snprintf(p, sizeof(p), "%s/blobs/sha512", store_root);
        bool ok_sha512 = path_is_dir(p);
        snprintf(p, sizeof(p), "%s/tmp", store_root);
        bool ok_tmp = path_is_dir(p);
        if (ok_sha256 && ok_sha512 && ok_tmp)
            report_pass("open creates blobs/sha256, blobs/sha512, tmp");
        else
            report_fail("open creates blobs/sha256, blobs/sha512, tmp", NULL);
    }

    /* Reopening an already-populated root is idempotent. */
    {
        oci_blob_store_t *again = oci_blob_store_open(store_root);
        if (again) {
            report_pass("open is idempotent on existing layout");
            oci_blob_store_close(again);
        } else {
            report_fail("open is idempotent on existing layout",
                        strerror(errno));
        }
    }

    /* Bad inputs. */
    {
        errno = 0;
        oci_blob_store_t *bad = oci_blob_store_open(NULL);
        if (!bad && errno == EINVAL)
            report_pass("open rejects NULL root");
        else
            report_fail("open rejects NULL root",
                        bad ? "returned handle" : strerror(errno));
        oci_blob_store_close(bad);
    }
    {
        errno = 0;
        oci_blob_store_t *bad = oci_blob_store_open("");
        if (!bad && errno == EINVAL)
            report_pass("open rejects empty root");
        else
            report_fail("open rejects empty root",
                        bad ? "returned handle" : strerror(errno));
        oci_blob_store_close(bad);
    }

    /* Path resolution: shape matches the OCI image-layout convention. */
    printf("oci_blob_store_path\n");
    {
        char out[512];
        int n = oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, out,
                                    sizeof(out));
        char want[512];
        snprintf(want, sizeof(want), "%s/blobs/sha256/%s", store_root,
                 SHA256_ABC);
        if (n > 0 && (size_t) n == strlen(want) && strcmp(out, want) == 0)
            report_pass("path builds blobs/<algo>/<hex>");
        else
            report_fail("path builds blobs/<algo>/<hex>", out);
    }
    {
        char out[512];
        int n = oci_blob_store_path(s, OCI_DIGEST_SHA256, "not-hex", out,
                                    sizeof(out));
        if (n == -1)
            report_pass("path rejects malformed hex");
        else
            report_fail("path rejects malformed hex", out);
    }

    /* One-shot put followed by has() round trip. */
    printf("oci_blob_store_put_bytes\n");
    {
        if (oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, SHA256_ABC, "abc",
                                     3) != 0) {
            report_fail("put_bytes commits a known-good blob", strerror(errno));
        } else {
            char path[512];
            oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, path,
                                sizeof(path));
            if (path_is_file(path) &&
                oci_blob_store_has(s, OCI_DIGEST_SHA256, SHA256_ABC))
                report_pass("put_bytes commits a known-good blob");
            else
                report_fail("put_bytes commits a known-good blob",
                            "blob not visible after commit");
        }
        char tmp_dir[512];
        snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);
        if (dir_is_empty(tmp_dir))
            report_pass("commit leaves tmp/ empty");
        else
            report_fail("commit leaves tmp/ empty", NULL);
    }

    /* Dedup: repeat the same commit and confirm exit success without
     * touching the final inode. The fact that we observe the same path with
     * the same content is enough; the writer's link(2) path takes the EEXIST
     * branch internally.
     */
    {
        struct stat before, after;
        char path[512];
        oci_blob_store_path(s, OCI_DIGEST_SHA256, SHA256_ABC, path,
                            sizeof(path));
        if (stat(path, &before) != 0) {
            report_fail("dedup commit is idempotent", "no first blob");
        } else if (oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, SHA256_ABC,
                                            "abc", 3) != 0) {
            report_fail("dedup commit is idempotent", strerror(errno));
        } else if (stat(path, &after) != 0) {
            report_fail("dedup commit is idempotent", "blob disappeared");
        } else if (before.st_ino != after.st_ino) {
            report_fail("dedup commit is idempotent",
                        "inode changed (should stay the same)");
        } else {
            report_pass("dedup commit is idempotent");
        }
    }

    /* Digest mismatch: caller declares a hex that does not match the bytes.
     * Commit must fail with EINVAL and leave no visible blob, no tmp leftover.
     */
    {
        static const char WRONG[] =
            "0000000000000000000000000000000000000000000000000000000000000000";
        errno = 0;
        int rc = oci_blob_store_put_bytes(s, OCI_DIGEST_SHA256, WRONG, "abc",
                                          3);
        char tmp_dir[512];
        snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);
        if (rc == -1 && errno == EINVAL &&
            !oci_blob_store_has(s, OCI_DIGEST_SHA256, WRONG) &&
            dir_is_empty(tmp_dir))
            report_pass("digest mismatch rejected, tmp/ stays empty");
        else
            report_fail("digest mismatch rejected, tmp/ stays empty",
                        strerror(errno));
    }

    /* Streaming writer: write the same bytes in multiple chunks and confirm
     * the commit hash still matches.
     */
    printf("oci_blob_writer streaming\n");
    {
        /* SHA-256("hello world") = b94d27b9... */
        const char *payload = "hello world";
        char expected[OCI_DIGEST_HEX_MAX + 1];
        oci_digest_bytes(OCI_DIGEST_SHA256, payload, strlen(payload), expected);

        oci_blob_writer_t *w =
            oci_blob_writer_begin(s, OCI_DIGEST_SHA256, expected);
        if (!w) {
            report_fail("streaming writer commits chunked payload",
                        strerror(errno));
        } else if (!oci_blob_writer_write(w, "hello ", 6) ||
                   !oci_blob_writer_write(w, "world", 5)) {
            report_fail("streaming writer commits chunked payload",
                        strerror(errno));
            oci_blob_writer_abort(w);
        } else if (oci_blob_writer_commit(w) != 0) {
            report_fail("streaming writer commits chunked payload",
                        strerror(errno));
        } else if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, expected)) {
            report_fail("streaming writer commits chunked payload",
                        "not visible after commit");
        } else {
            report_pass("streaming writer commits chunked payload");
        }
    }

    /* Abort path: write some data, abort, confirm no committed blob and no
     * tmp leftover.
     */
    {
        static const char EXPECTED[] =
            "deadbeef00000000000000000000000000000000000000000000000000000000";
        oci_blob_writer_t *w =
            oci_blob_writer_begin(s, OCI_DIGEST_SHA256, EXPECTED);
        if (!w) {
            report_fail("abort leaves no leftover", strerror(errno));
        } else {
            (void) oci_blob_writer_write(w, "partial", 7);
            oci_blob_writer_abort(w);
            char tmp_dir[512];
            snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);
            if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, EXPECTED) &&
                dir_is_empty(tmp_dir))
                report_pass("abort leaves no leftover");
            else
                report_fail("abort leaves no leftover", NULL);
        }
    }

    /* Restart: close the store handle, reopen the same root, confirm the
     * committed blob is still visible. This is the "store survives restart"
     * acceptance criterion from issue #31.
     */
    printf("oci_blob_store restart\n");
    oci_blob_store_close(s);
    s = oci_blob_store_open(store_root);
    if (!s) {
        report_fail("reopen sees previously-committed blob", strerror(errno));
        goto cleanup;
    }
    if (oci_blob_store_has(s, OCI_DIGEST_SHA256, SHA256_ABC))
        report_pass("reopen sees previously-committed blob");
    else
        report_fail("reopen sees previously-committed blob",
                    "has() returned false");

    /* has() must distinguish present vs absent. */
    {
        static const char ABSENT[] =
            "feedface00000000000000000000000000000000000000000000000000000000";
        if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, ABSENT))
            report_pass("has() returns false for unknown digest");
        else
            report_fail("has() returns false for unknown digest", NULL);
    }

    /* Resume + sweep: the curl_multi pull path relies on these two store
     * APIs to survive an interrupted blob fetch. Drive both directly
     * without the fetcher in the loop so a regression in the store gets
     * caught by this suite instead of the higher-level test-oci-fetch.
     */
    printf("oci_blob_writer_resume_named\n");
    {
        /* Plant a partial that holds the first three bytes of "abcdef" under
         * the SHA-256-of-"abcdef" digest. resume_named must locate it,
         * re-hash the prefix into its digester, position the fd at end, and
         * report the resume offset. A subsequent write of the remaining
         * bytes plus commit must produce a final blob whose hex matches the
         * full-content digest.
         */
        static const char FULL[] = "abcdef";
        static const size_t FULL_LEN = 6;
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (oci_digest_bytes(OCI_DIGEST_SHA256, FULL, FULL_LEN, hex) == 0) {
            report_fail("resume happy path", "digest precompute failed");
            goto resume_done;
        }
        char prefix[17];
        memcpy(prefix, hex, 16);
        prefix[16] = '\0';
        char partial[768];
        snprintf(partial, sizeof(partial), "%s/tmp/blob-%s-aaaaaa",
                 store_root, prefix);
        int fd = open(partial, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            report_fail("resume happy path", strerror(errno));
            goto resume_done;
        }
        if (write(fd, FULL, 3) != 3) {
            close(fd);
            report_fail("resume happy path", "short write seeding partial");
            goto resume_done;
        }
        close(fd);

        int64_t off = -1;
        oci_blob_writer_t *w = oci_blob_writer_resume_named(
            s, OCI_DIGEST_SHA256, hex, (int64_t) FULL_LEN, &off);
        if (!w || off != 3) {
            if (w)
                oci_blob_writer_abort(w);
            report_fail("resume happy path", "writer null or offset != 3");
            goto resume_done;
        }
        if (!oci_blob_writer_write(w, FULL + 3, FULL_LEN - 3)) {
            oci_blob_writer_abort(w);
            report_fail("resume happy path", "write tail failed");
            goto resume_done;
        }
        if (oci_blob_writer_commit(w) < 0) {
            report_fail("resume happy path", strerror(errno));
            goto resume_done;
        }
        if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, hex)) {
            report_fail("resume happy path", "commit missing");
            goto resume_done;
        }
        report_pass("resume reopens partial, re-hashes, commits");
    }
resume_done:

    {
        /* No partial -> resume_named must transparently fall back to a
         * fresh writer with offset zero. The committed blob is identical
         * to the begin_named code path.
         */
        static const char BODY[] = "zzzz";
        char hex[OCI_DIGEST_HEX_MAX + 1];
        if (oci_digest_bytes(OCI_DIGEST_SHA256, BODY, 4, hex) == 0) {
            report_fail("resume falls back to fresh writer",
                        "digest precompute failed");
            goto fresh_done;
        }
        int64_t off = -1;
        oci_blob_writer_t *w = oci_blob_writer_resume_named(
            s, OCI_DIGEST_SHA256, hex, 4, &off);
        if (!w || off != 0) {
            if (w)
                oci_blob_writer_abort(w);
            report_fail("resume falls back to fresh writer",
                        "writer null or offset != 0");
            goto fresh_done;
        }
        if (!oci_blob_writer_write(w, BODY, 4) ||
            oci_blob_writer_commit(w) < 0) {
            report_fail("resume falls back to fresh writer",
                        "write/commit failed");
            goto fresh_done;
        }
        if (!oci_blob_store_has(s, OCI_DIGEST_SHA256, hex))
            report_fail("resume falls back to fresh writer", "commit missing");
        else
            report_pass("resume falls back to fresh writer");
    }
fresh_done:

    printf("oci_blob_store_sweep_partials\n");
    {
        /* Drop two partials in tmp/. Backdate the first by eight days so
         * sweep with a seven-day TTL unlinks it; leave the second fresh
         * so it survives. The directory entry count after the sweep is
         * the load-bearing assertion: nothing else writes to tmp/ during
         * this case.
         */
        char tmp_dir[768];
        snprintf(tmp_dir, sizeof(tmp_dir), "%s/tmp", store_root);

        char stale[1024];
        char fresh[1024];
        snprintf(stale, sizeof(stale), "%s/blob-deadbeef00000000-stale",
                 tmp_dir);
        snprintf(fresh, sizeof(fresh), "%s/blob-deadbeef00000000-fresh",
                 tmp_dir);
        int fd_a = open(stale, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int fd_b = open(fresh, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_a < 0 || fd_b < 0) {
            if (fd_a >= 0) close(fd_a);
            if (fd_b >= 0) close(fd_b);
            report_fail("sweep TTL", "fixture open failed");
            goto sweep_done;
        }
        (void) write(fd_a, "x", 1);
        (void) write(fd_b, "x", 1);
        close(fd_a);
        close(fd_b);

        struct timeval tv[2];
        tv[0].tv_sec = time(NULL) - 8L * 86400;
        tv[0].tv_usec = 0;
        tv[1] = tv[0];
        if (utimes(stale, tv) < 0) {
            report_fail("sweep TTL", "utimes failed");
            goto sweep_done;
        }

        oci_blob_store_sweep_partials(s, 7L * 86400);

        struct stat st;
        bool stale_gone = stat(stale, &st) < 0 && errno == ENOENT;
        bool fresh_present = stat(fresh, &st) == 0 && S_ISREG(st.st_mode);
        if (!stale_gone)
            report_fail("sweep TTL", "stale partial survived");
        else if (!fresh_present)
            report_fail("sweep TTL", "fresh partial swept");
        else
            report_pass("sweep TTL unlinks aged partials only");

        (void) unlink(fresh);
    }
sweep_done:

cleanup:
    oci_blob_store_close(s);
    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
