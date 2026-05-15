/* `elfuse oci` subcommand dispatch
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sits on the side of the main argv parser: when argv[1] == "oci" the rest
 * of the command line is forwarded here. Subcommands are pull, inspect,
 * prune, and list. Only inspect parses a reference today; the others return
 * a deterministic "not yet implemented" exit so users can discover the
 * surface without crashes.
 */

#pragma once

/* argc/argv are the slice starting at "oci" (i.e. argv[0] == "oci"). Returns
 * a process exit code suitable for main() to return directly.
 */
int oci_cli_main(int argc, char **argv);
