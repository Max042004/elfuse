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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clone-rootfs.h"
#include "fetch.h"
#include "inspect.h"
#include "pull.h"
#include "ref.h"
#include "run.h"
#include "store.h"
#include "unpack.h"
#include "volume.h"

static int print_usage(FILE *out)
{
    fputs(
        "usage: elfuse oci <subcommand> [args]\n"
        "\n"
        "Subcommands:\n"
        "  pull    [OPTIONS] <ref>  Download an image into the local store\n"
        "  inspect [OPTIONS] <ref>  Show the canonical reference and parsed "
        "fields\n"
        "  unpack  [OPTIONS] <ref>  Apply layers into a case-sensitive "
        "sysroot\n"
        "  clone   [OPTIONS] <ref>  Create a per-run rootfs via APFS "
        "clonefile\n"
        "  run     [OPTIONS] <ref> [ARG...]\n"
        "                           Launch a guest binary from a pulled image\n"
        "  prune                    Remove unreferenced blobs from the local "
        "store\n"
        "  list                     List images in the local store\n"
        "\n"
        "Pull options:\n"
        "  --store DIR           Override the local store root\n"
        "                        (default: ~/Library/Application "
        "Support/elfuse/store)\n"
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
        "Unpack options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume mount point\n"
        "                        (default: auto-provisioned sparsebundle "
        "under\n"
        "                         ~/Library/Application "
        "Support/elfuse/sysroots/)\n"
        "  --force               Re-extract even if the image sysroot exists\n"
        "  -q, --quiet           Suppress per-layer progress output\n"
        "\n"
        "Clone options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Override the sysroot APFS volume mount point\n"
        "  --name NAME           Human-friendly suffix for the per-run rootfs\n"
        "  --keep                Do not register the run dir for cleanup "
        "(no-op)\n"
        "\n"
        "Prune options:\n"
        "  --store DIR           Override the local store root\n"
        "  --volume DIR          Treat unpacked sysroots under DIR/images/ as "
        "roots\n"
        "  --commit              Actually unlink dangling blobs "
        "(default: dry-run)\n"
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
    const char *store_root; /* heap-owned by main, not by parse */
    const char *user;
    const char *password;
    const char *ca_file;
    bool allow_insecure;
    bool quiet;
    const char *ref_str;
    char *user_pass_buf; /* heap; freed by caller */
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

typedef struct {
    const char *store_root;
    const char *volume_root;
    const char *ref_str;
    const char *name; /* clone only */
    bool quiet;
    bool force_relayer;
    bool keep_on_exit; /* clone only */
} unpack_args_t;

static int parse_unpack_args(int argc,
                             char **argv,
                             unpack_args_t *out,
                             bool clone_mode)
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
        } else if (!strcmp(a, "--force")) {
            if (clone_mode) {
                fputs("error: --force is not valid for oci clone\n", stderr);
                return -1;
            }
            out->force_relayer = true;
        } else if (!strcmp(a, "--keep")) {
            if (!clone_mode) {
                fputs("error: --keep is only valid for oci clone\n", stderr);
                return -1;
            }
            out->keep_on_exit = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else if (clone_mode && !strcmp(a, "--name")) {
            if (++i >= argc) {
                fputs("error: --name needs an argument\n", stderr);
                return -1;
            }
            out->name = argv[i];
        } else {
            fprintf(stderr, "error: unknown option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i >= argc) {
        fputs("error: subcommand needs a reference argument\n", stderr);
        return -1;
    }
    if (i != argc - 1) {
        fputs("error: extra arguments after reference\n", stderr);
        return -1;
    }
    out->ref_str = argv[i];
    return 0;
}

static int do_unpack(const unpack_args_t *args,
                     char **out_image_dir,
                     oci_store_t **out_store_keep)
{
    char *default_root = NULL;
    const char *store_root = args->store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root (HOME?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_ref_t ref = {0};
    const char *err = NULL;
    if (oci_ref_parse(args->ref_str, &ref, &err) < 0) {
        fprintf(stderr, "error: invalid reference: %s\n",
                err ? err : "(unknown)");
        free(default_root);
        return 1;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }

    oci_unpack_options_t uopts = {
        .volume_root = args->volume_root,
        .quiet = args->quiet,
        .force_relayer = args->force_relayer,
    };
    err = NULL;
    int rc = oci_unpack(store, &ref, &uopts, out_image_dir, &err);
    if (rc < 0) {
        fprintf(stderr, "error: unpack failed: %s\n",
                err ? err : strerror(errno));
        oci_store_close(store);
        oci_ref_free(&ref);
        free(default_root);
        return 1;
    }
    oci_ref_free(&ref);
    free(default_root);
    if (out_store_keep)
        *out_store_keep = store;
    else
        oci_store_close(store);
    return 0;
}

static int cmd_unpack(int argc, char **argv)
{
    unpack_args_t args = {0};
    int prc = parse_unpack_args(argc, argv, &args, false);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;
    char *image_dir = NULL;
    int rc = do_unpack(&args, &image_dir, NULL);
    if (rc != 0) {
        free(image_dir);
        return rc;
    }
    /* stdout: just the absolute path so $(elfuse oci unpack ref) composes. */
    printf("%s\n", image_dir);
    free(image_dir);
    return 0;
}

static int cmd_clone(int argc, char **argv)
{
    unpack_args_t args = {0};
    int prc = parse_unpack_args(argc, argv, &args, true);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *image_dir = NULL;
    oci_store_t *store = NULL;
    int rc = do_unpack(&args, &image_dir, &store);
    if (rc != 0) {
        free(image_dir);
        return rc;
    }
    oci_store_close(store);

    /* Resolve the volume root the same way unpack did so clone-rootfs
     * lands in the same sparsebundle.
     */
    char *volume_root = NULL;
    const char *err = NULL;
    if (oci_volume_ensure(args.volume_root, &volume_root, &err) < 0) {
        fprintf(stderr, "error: volume_ensure failed: %s\n",
                err ? err : strerror(errno));
        free(image_dir);
        return 1;
    }

    /* image_dir has a trailing slash; strip it for the clone source. */
    size_t il = strlen(image_dir);
    if (il > 1 && image_dir[il - 1] == '/')
        image_dir[il - 1] = '\0';

    char *run_dir = NULL;
    err = NULL;
    if (oci_clone_rootfs(image_dir, volume_root, &run_dir, &err) < 0) {
        fprintf(stderr, "error: clone failed: %s\n",
                err ? err : strerror(errno));
        free(image_dir);
        free(volume_root);
        return 1;
    }
    /* --keep is forward-looking; Phase 2 does not auto-clean either way. */
    (void) args.keep_on_exit;
    printf("%s\n", run_dir);
    free(run_dir);
    free(image_dir);
    free(volume_root);
    return 0;
}

static int cmd_not_implemented(const char *name)
{
    fprintf(stderr,
            "error: 'oci %s' is not implemented yet (see issue #31 Phase 1)\n",
            name);
    return 2;
}

/* Argument parser state for `oci prune`. The flag set is intentionally
 * minimal: dry-run is the default (so the operator can review what would
 * be reclaimed before committing) and --commit is the only switch that
 * actually unlinks. --volume mirrors the same flag in unpack/clone so
 * the same volume root the user uses for unpacked sysroots also feeds
 * the keep-set walk; without --volume only pins contribute.
 */
typedef struct {
    const char *store_root;
    const char *volume_root;
    bool commit;
} prune_args_t;

static int parse_prune_args(int argc, char **argv, prune_args_t *out)
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
        } else if (!strcmp(a, "--commit")) {
            out->commit = true;
        } else if (!strcmp(a, "--store")) {
            if (++i >= argc) {
                fputs("error: --store needs an argument\n", stderr);
                return -1;
            }
            out->store_root = argv[i];
        } else if (!strcmp(a, "--volume")) {
            if (++i >= argc) {
                fputs("error: --volume needs an argument\n", stderr);
                return -1;
            }
            out->volume_root = argv[i];
        } else {
            fprintf(stderr, "error: unknown prune option: %s\n", a);
            return -1;
        }
        i++;
    }
    if (i != argc) {
        fputs("error: prune takes no positional arguments\n", stderr);
        return -1;
    }
    return 0;
}

static int cmd_prune(int argc, char **argv)
{
    prune_args_t args = {0};
    int prc = parse_prune_args(argc, argv, &args);
    if (prc == 1)
        return print_usage(stdout);
    if (prc < 0)
        return 2;

    char *default_root = NULL;
    const char *store_root = args.store_root;
    if (!store_root) {
        default_root = oci_store_default_root();
        if (!default_root) {
            fprintf(stderr,
                    "error: could not determine default store root "
                    "(HOME not set?)\n");
            return 1;
        }
        store_root = default_root;
    }

    oci_store_t *store = oci_store_open(store_root);
    if (!store) {
        fprintf(stderr, "error: could not open store at %s: %s\n", store_root,
                strerror(errno));
        free(default_root);
        return 1;
    }

    oci_store_prune_options_t opts = {
        .commit = args.commit,
        .volume_root = args.volume_root,
    };
    const char *err = NULL;
    int rc = oci_store_prune(store, &opts, &err);
    if (rc < 0) {
        fprintf(stderr, "error: prune failed: %s\n",
                err ? err : strerror(errno));
        oci_store_close(store);
        free(default_root);
        return 1;
    }

    if (args.commit) {
        printf("reclaimed: %zu blobs (%llu bytes)\n", opts.pruned_blobs,
               (unsigned long long) opts.pruned_bytes);
        printf("kept:      %zu blobs\n", opts.kept_blobs);
    } else {
        printf("reclaimable: %zu blobs (%llu bytes)\n", opts.pruned_blobs,
               (unsigned long long) opts.pruned_bytes);
        printf("kept:        %zu blobs\n", opts.kept_blobs);
        printf("(dry-run; pass --commit to delete)\n");
    }

    oci_store_close(store);
    free(default_root);
    return 0;
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
    if (!strcmp(sub, "unpack"))
        return cmd_unpack(argc - 1, argv + 1);
    if (!strcmp(sub, "clone"))
        return cmd_clone(argc - 1, argv + 1);
    if (!strcmp(sub, "run"))
        return oci_cli_run(argc - 1, argv + 1);
    if (!strcmp(sub, "prune"))
        return cmd_prune(argc - 1, argv + 1);
    if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
        return cmd_not_implemented("list");

    fprintf(stderr, "error: unknown oci subcommand: %s\n", sub);
    return print_usage(stderr);
}
