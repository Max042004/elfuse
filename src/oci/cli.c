/* `elfuse oci` subcommand dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Slice 5a turns pull into a real subcommand: argument parsing for --store,
 * -u USER[:PASS], --insecure-ca PEM, --insecure, -q, plus the actual oci_pull
 * invocation against a freshly opened store and fetcher. Slice 5b extends
 * inspect with --store and --all-platforms and an offline manifest tree
 * renderer (src/oci/inspect.c). prune and list still return rc=2 "not
 * implemented yet".
 */

#include "cli.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fetch.h"
#include "inspect.h"
#include "pull.h"
#include "ref.h"
#include "store.h"

static int print_usage(FILE *out)
{
    fputs(
        "usage: elfuse oci <subcommand> [args]\n"
        "\n"
        "Subcommands:\n"
        "  pull    [OPTIONS] <ref>  Download an image into the local store\n"
        "  inspect [OPTIONS] <ref>  Show the canonical reference and parsed fields\n"
        "  prune                    Remove unreferenced blobs from the local store\n"
        "  list                     List images in the local store\n"
        "\n"
        "Pull options:\n"
        "  --store DIR           Override the local store root\n"
        "                        (default: ~/Library/Application Support/elfuse/store)\n"
        "  -u, --user USER[:PASS]  HTTP Basic auth for private registries\n"
        "  --insecure-ca PEM     Trust PEM as the registry CA bundle\n"
        "  --insecure            Skip TLS verify (loopback registries only)\n"
        "  -q, --quiet           Suppress per-blob progress output\n"
        "\n"
        "Inspect options:\n"
        "  --store DIR           Override the local store root\n"
        "  --all-platforms       List every platform entry of an image index\n"
        "                        instead of drilling into linux/arm64\n"
        "\n"
        "Refs follow the docker/containerd grammar:\n"
        "  alpine, alpine:3.20, user/repo, ghcr.io/owner/img:tag,\n"
        "  repo@sha256:<hex>, repo:tag@sha256:<hex>\n",
        out);
    return out == stderr ? 2 : 0;
}

/* Argument parser state for `oci inspect`. Mirrors pull_args_t in shape so a
 * future cleanup could share the flag-loop, but the option set is disjoint
 * enough that today the two parsers live side by side.
 */
typedef struct {
    const char *store_root;
    bool show_all_platforms;
    const char *ref_str;
} inspect_args_t;

static int parse_inspect_args(int argc, char **argv, inspect_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "--all-platforms")) {
            out->show_all_platforms = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else {
            fprintf(stderr, "error: unknown inspect option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: inspect needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after inspect reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int cmd_inspect(int argc, char **argv)
{
    inspect_args_t args = {0};
    int prc = parse_inspect_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args.ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: %s\n", err ? err : "invalid reference");
        return 1;
    }
    char *canonical = oci_ref_canonical(&ref);
    if (!canonical) {
        fputs("error: out of memory rendering canonical reference\n", stderr);
        oci_ref_free(&ref);
        return 1;
    }
    printf("canonical:  %s\n", canonical);
    printf("registry:   %s\n", ref.registry);
    printf("repository: %s\n", ref.repository);
    printf("tag:        %s\n", ref.tag ? ref.tag : "(none)");
    printf("digest:     %s\n", ref.digest ? ref.digest : "(none)");
    free(canonical);

    /* Resolve store root: --store override or platform default. */
    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            oci_ref_free(&ref);
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }

    oci_inspect_options_t opts = {
        .out = stdout,
        .show_all_platforms = args.show_all_platforms,
    };
    err = NULL;
    int rc = oci_inspect(store, &ref, &opts, &err);
    if (rc < 0 && err)
        fprintf(stderr, "error: %s\n", err);

    oci_store_close(store);
    oci_ref_free(&ref);
    free(default_root);
    return rc < 0 ? 1 : 0;
}

/* Argument parser state for `oci pull`. Defaults are populated by the caller,
 * then patched by parse_pull_args.
 */
typedef struct {
    const char *store_root;  /* heap-owned by main, not by parse */
    const char *user;
    const char *password;
    const char *ca_file;
    bool allow_insecure;
    bool quiet;
    const char *ref_str;
    char *user_pass_buf;     /* heap; freed by caller */
} pull_args_t;

/* Split USER[:PASS] in-place. Returns 0 on success or -1 with errno=ENOMEM. */
static int split_userpass(const char *spec, pull_args_t *out)
{
    free(out->user_pass_buf);
    out->user_pass_buf = strdup(spec);
    if (!out->user_pass_buf) {
        errno = ENOMEM;
        return -1;
    }
    char *colon = strchr(out->user_pass_buf, ':');
    if (colon) {
        *colon = '\0';
        out->user = out->user_pass_buf;
        out->password = colon + 1;
    } else {
        out->user = out->user_pass_buf;
        out->password = "";
    }
    return 0;
}

/* argv layout coming in: ["pull", "--flag", "...", "<ref>"]. argv[0] is the
 * subcommand name; argv[argc-1] is the ref. Anything in between is options.
 * Returns 0 on success, -1 on bad arguments (after printing an error).
 */
static int parse_pull_args(int argc, char **argv, pull_args_t *out)
{
    int i = 1;
    while (i < argc) {
        const char *a = argv[i];
        if (a[0] != '-')
            break;
        if (!strcmp(a, "--")) {
            i++;
            break;
        }
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            return 1;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            out->quiet = true;
        } else if (!strcmp(a, "--insecure")) {
            out->allow_insecure = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "-u") || !strcmp(a, "--user")) {
            if (++i >= argc) {
                fputs("error: -u needs USER[:PASS]\n", stderr);
                return -1;
            }
            if (split_userpass(argv[i], out) < 0) {
                fputs("error: out of memory parsing credentials\n", stderr);
                return -1;
            }
        } else if (!strcmp(a, "--insecure-ca")) {
            if (++i >= argc) {
                fputs("error: --insecure-ca needs a PEM path\n", stderr);
                return -1;
            }
            out->ca_file = argv[i];
        } else {
            fprintf(stderr, "error: unknown pull option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: pull needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after pull reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int cmd_pull(int argc, char **argv)
{
    pull_args_t args = {0};
    int prc = parse_pull_args(argc, argv, &args);
    if (prc == 1) {
        free(args.user_pass_buf);
        return print_usage(stdout);
    }
    if (prc < 0) {
        free(args.user_pass_buf);
        return 2;
    }

    /* Default store root: either --store override or the platform default. */
    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            free(args.user_pass_buf);
            return 1;
        }
        store_root = default_root;
    }

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args.ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: invalid reference: %s\n",
                err ? err : "(unknown)");
        free(default_root);
        free(args.user_pass_buf);
        return 1;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        free(args.user_pass_buf);
        return 1;
    }

    oci_fetcher_options_t fopts = {
        .username = args.user,
        .password = args.password,
        .ca_file = args.ca_file,
        .allow_insecure = args.allow_insecure,
    };
    oci_fetcher_t *fetcher = oci_fetcher_new(&fopts);
    if (!fetcher) {
        fprintf(stderr, "error: could not create fetcher: %s\n",
                strerror(errno));
        oci_store_close(store);
        oci_ref_free(&ref);
        free(default_root);
        free(args.user_pass_buf);
        return 1;
    }

    if (!args.quiet) {
        char *canon = oci_ref_canonical(&ref);
        fprintf(stderr, "elfuse oci pull %s\n  store: %s\n",
                canon ? canon : args.ref_str, store_root);
        free(canon);
    }

    oci_pull_options_t popts = {.quiet = args.quiet};
    err = NULL;
    int rc = oci_pull(fetcher, store, &ref, &popts, &err);
    if (rc < 0) {
        fprintf(stderr, "error: pull failed: %s\n",
                err ? err : strerror(errno));
    } else if (!args.quiet) {
        fputs("done.\n", stderr);
    }

    oci_fetcher_free(fetcher);
    oci_store_close(store);
    oci_ref_free(&ref);
    free(default_root);
    free(args.user_pass_buf);
    return rc < 0 ? 1 : 0;
}

static int cmd_not_implemented(const char *name)
{
    fprintf(stderr,
            "error: 'oci %s' is not implemented yet (see issue #31 Phase 1)\n",
            name);
    return 2;
}

int oci_cli_main(int argc, char **argv)
{
    if (argc < 2)
        return print_usage(stderr);

    const char *sub = argv[1];
    if (!strcmp(sub, "-h") || !strcmp(sub, "--help") || !strcmp(sub, "help"))
        return print_usage(stdout);
    if (!strcmp(sub, "inspect"))
        return cmd_inspect(argc - 1, argv + 1);
    if (!strcmp(sub, "pull"))
        return cmd_pull(argc - 1, argv + 1);
    if (!strcmp(sub, "prune"))
        return cmd_not_implemented("prune");
    if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
        return cmd_not_implemented("list");

    fprintf(stderr, "error: unknown oci subcommand: %s\n", sub);
    return print_usage(stderr);
}
