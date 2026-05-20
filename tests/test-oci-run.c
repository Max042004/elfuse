/* elfuse oci run unit tests
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two slices of coverage:
 *
 * 1. oci_cli_run argument parser: -h prints usage, missing IMAGE
 *    surfaces rc=2, unknown options surface rc=2, -e without a value
 *    surfaces rc=2. These exercise the option-walk shape without
 *    touching the store or the volume.
 *
 * 2. oci_run programmatic path: with a case-insensitive --volume
 *    override (/tmp on a default APFS macOS install), oci_run must
 *    fail fast inside oci_unpack -> oci_volume_ensure before reaching
 *    the launch backend. The test confirms the failure is reported
 *    via *err and that the launch override (registered through
 *    oci_run_set_launch_for_testing) was NOT invoked.
 *
 * The full-pipeline test that actually runs through unpack +
 * clone-rootfs + launch capture lives in tests/test-oci-compat.sh
 * (Phase 3 commit 6) where a fixture builder synthesizes a real
 * sparsebundle volume on demand. Mirroring it here would require
 * either an OCI_VOLUME_TEST=1 hdiutil flow inside C (heavy) or a
 * second test-only hook that bypasses oci_volume_ensure (invasive);
 * the compat shell harness covers the same ground without either.
 */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "oci/ref.h"
#include "oci/run.h"
#include "oci/store.h"

/* Linker stub. oci_run falls back to elfuse_launch when no test hook
 * is installed; every test below installs a hook before calling
 * oci_run, but the linker still needs to resolve the elfuse_launch
 * symbol. Providing a stub here keeps the test binary's link island
 * tight (no core/launch.o, no HVF / VM / syscall transitive chain
 * dragged into a unit test). If the stub ever actually runs, the
 * test was buggy.
 */
int elfuse_launch(const launch_args_t *args)
{
    (void) args;
    fprintf(stderr,
            "test bug: real elfuse_launch reached; the test forgot to"
            " install a hook via oci_run_set_launch_for_testing\n");
    abort();
}

#define GREEN "\033[0;32m"
#define RED "\033[0;31m"
#define RESET "\033[0m"

static int g_total = 0;
static int g_passed = 0;

static void report_pass(const char *name)
{
    g_total++;
    g_passed++;
    printf("  " GREEN "OK" RESET "   %s\n", name);
}

static void report_fail(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void report_fail(const char *name, const char *fmt, ...)
{
    g_total++;
    printf("  " RED "FAIL" RESET " %s", name);
    if (fmt && *fmt) {
        printf(": ");
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
}

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
    (void) nftw(root, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

static char *make_scratch_root(void)
{
    char tmpl[] = "/tmp/elfuse-test-oci-run-XXXXXX";
    if (!mkdtemp(tmpl))
        return NULL;
    return strdup(tmpl);
}

/* Capture state for the test-only launch hook. The hook fires when the
 * orchestration reaches launch dispatch; tests assert g_launched == 0
 * to prove the upstream error short-circuited.
 */
static int g_launched = 0;

static int never_called_launch(const launch_args_t *args)
{
    (void) args;
    g_launched++;
    return 0;
}

static bool contains(const char *haystack, const char *needle)
{
    return haystack && needle && strstr(haystack, needle) != NULL;
}

/* Capture stdout from a command invocation. Returns heap-allocated
 * buffer (caller frees) plus rc. argv is passed to oci_cli_run which
 * walks from argv[1] (so argv[0] = "run" matches the cli.c dispatch).
 *
 * open_memstream cannot back a dup2 redirect (its FILE* has no real
 * fd), so the capture uses a real tmpfile and reads it back after the
 * call. The tmpfile is unlinked immediately after open so it
 * disappears regardless of test outcome.
 */
typedef struct {
    int rc;
    char *out;
    size_t out_len;
} cli_result_t;

static cli_result_t capture_oci_cli_run(int argc, char **argv)
{
    cli_result_t r = {0};
    char tmpl[] = "/tmp/elfuse-test-oci-run-stdout-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        r.rc = -1;
        return r;
    }
    unlink(tmpl);

    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    dup2(fd, STDOUT_FILENO);

    r.rc = oci_cli_run(argc, argv);

    fflush(stdout);
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    off_t end = lseek(fd, 0, SEEK_CUR);
    if (end < 0)
        end = 0;
    lseek(fd, 0, SEEK_SET);
    char *buf = malloc((size_t) end + 1);
    if (buf) {
        ssize_t n = read(fd, buf, (size_t) end);
        if (n < 0)
            n = 0;
        buf[n] = '\0';
        r.out = buf;
        r.out_len = (size_t) n;
    }
    close(fd);
    return r;
}

/* ── CLI parser cases ─────────────────────────────────────────────── */

static void case_cli_usage(void)
{
    const char *name = "cli: -h prints usage and returns 0";
    char *argv[] = {"run", "-h", NULL};
    cli_result_t r = capture_oci_cli_run(2, argv);
    if (r.rc != 0) {
        report_fail(name, "rc=%d (want 0)", r.rc);
    } else if (!contains(r.out, "usage: elfuse oci run") ||
               !contains(r.out, "--entrypoint")) {
        report_fail(name, "usage text missing");
    } else {
        report_pass(name);
    }
    free(r.out);
}

static void case_cli_missing_image(void)
{
    const char *name = "cli: missing IMAGE returns rc=2";
    char *argv[] = {"run", "--keep", NULL};
    /* Redirect stderr so the user-visible error does not pollute the
     * test driver report. */
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
    int rc = oci_cli_run(2, argv);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (rc != 2)
        report_fail(name, "rc=%d (want 2)", rc);
    else
        report_pass(name);
}

static void case_cli_unknown_option(void)
{
    const char *name = "cli: unknown option returns rc=2";
    char *argv[] = {"run", "--nope", "alpine", NULL};
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
    int rc = oci_cli_run(3, argv);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (rc != 2)
        report_fail(name, "rc=%d (want 2)", rc);
    else
        report_pass(name);
}

static void case_cli_missing_env_value(void)
{
    const char *name = "cli: -e without value returns rc=2";
    char *argv[] = {"run", "-e", NULL};
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
    int rc = oci_cli_run(2, argv);
    if (saved_stderr >= 0) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (rc != 2)
        report_fail(name, "rc=%d (want 2)", rc);
    else
        report_pass(name);
}

/* ── oci_run programmatic: early failure on bad volume ───────────── */

static void case_run_case_insensitive_volume(const char *scratch)
{
    const char *name =
        "run: --volume=/tmp (case-insensitive) fails fast; launch not"
        " invoked";

    char store_root[1024];
    snprintf(store_root, sizeof(store_root), "%s/store", scratch);

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        report_fail(name, "store open failed: %s", strerror(errno));
        return;
    }

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    if (oci_ref_parse("alpine:3", &ref, &parse_err) < 0) {
        report_fail(name, "ref parse: %s", parse_err ? parse_err : "?");
        oci_store_close(store);
        return;
    }

    oci_run_options_t opts = {0};
    opts.volume_dir = "/tmp"; /* not case-sensitive on default macOS APFS */

    g_launched = 0;
    oci_run_set_launch_for_testing(never_called_launch);
    const char *run_err = NULL;
    errno = 0;
    int rc = oci_run(store, &ref, &opts, NULL, &run_err);
    oci_run_set_launch_for_testing(NULL);

    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (g_launched != 0) {
        report_fail(name,
                    "launch override fired (%d times); orchestrator"
                    " should have short-circuited",
                    g_launched);
    } else if (!run_err) {
        report_fail(name, "no err message populated");
    } else {
        report_pass(name);
    }

    oci_ref_free(&ref);
    oci_store_close(store);
}

/* ── oci_run programmatic: no pin ─────────────────────────────────── */

static void case_run_no_pin(const char *scratch)
{
    const char *name =
        "run: ref with no local pin reports ENOENT-class failure";

    char store_root[1024];
    snprintf(store_root, sizeof(store_root), "%s/store-no-pin", scratch);

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        report_fail(name, "store open failed: %s", strerror(errno));
        return;
    }

    oci_ref_t ref = {0};
    const char *parse_err = NULL;
    if (oci_ref_parse("never-pulled:tag", &ref, &parse_err) < 0) {
        report_fail(name, "ref parse: %s", parse_err ? parse_err : "?");
        oci_store_close(store);
        return;
    }

    oci_run_options_t opts = {0};
    opts.volume_dir = "/tmp"; /* still bad volume, so unpack short-circuits */

    g_launched = 0;
    oci_run_set_launch_for_testing(never_called_launch);
    const char *run_err = NULL;
    int rc = oci_run(store, &ref, &opts, NULL, &run_err);
    oci_run_set_launch_for_testing(NULL);

    if (rc != -1) {
        report_fail(name, "rc=%d (want -1)", rc);
    } else if (g_launched != 0) {
        report_fail(name, "launch override fired despite pre-launch error");
    } else if (!run_err) {
        report_fail(name, "no err message populated");
    } else {
        report_pass(name);
    }

    oci_ref_free(&ref);
    oci_store_close(store);
}

int main(void)
{
    char *scratch = make_scratch_root();
    if (!scratch) {
        fprintf(stderr, "scratch mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }
    printf("OCI run unit tests (scratch=%s)\n", scratch);

    case_cli_usage();
    case_cli_missing_image();
    case_cli_unknown_option();
    case_cli_missing_env_value();
    case_run_case_insensitive_volume(scratch);
    case_run_no_pin(scratch);

    wipe_dir(scratch);
    free(scratch);

    printf("\nResults: %d/%d passed\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
