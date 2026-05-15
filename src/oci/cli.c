/* `elfuse oci` subcommand dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 only wires the inspect path through the reference parser. pull,
 * prune, and list intentionally exit 2 with an explanatory message so early
 * users get a stable surface to script against without touching code that
 * does not yet exist.
 */

#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ref.h"

static int print_usage(FILE *out)
{
    fputs(
        "usage: elfuse oci <subcommand> [args]\n"
        "\n"
        "Subcommands:\n"
        "  pull <ref>      Download an image into the local store\n"
        "  inspect <ref>   Show the canonical reference and parsed fields\n"
        "  prune           Remove unreferenced blobs from the local store\n"
        "  list            List images in the local store\n"
        "\n"
        "Refs follow the docker/containerd grammar:\n"
        "  alpine, alpine:3.20, user/repo, ghcr.io/owner/img:tag,\n"
        "  repo@sha256:<hex>, repo:tag@sha256:<hex>\n",
        out);
    return out == stderr ? 2 : 0;
}

static int cmd_inspect(int argc, char **argv)
{
    if (argc != 2) {
        fputs("error: inspect takes exactly one reference argument\n", stderr);
        return 2;
    }
    oci_ref_t ref;
    const char *err = NULL;
    if (oci_ref_parse(argv[1], &ref, &err) < 0) {
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
    oci_ref_free(&ref);
    return 0;
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
        return cmd_not_implemented("pull");
    if (!strcmp(sub, "prune"))
        return cmd_not_implemented("prune");
    if (!strcmp(sub, "list") || !strcmp(sub, "ls"))
        return cmd_not_implemented("list");

    fprintf(stderr, "error: unknown oci subcommand: %s\n", sub);
    return print_usage(stderr);
}
