/* OCI policy.json schema and loader
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Plan 6 C6.1: parse a podman/skopeo-style policy.json out of one of the
 * standard config locations and expose a per-host effective view that
 * fetch.c (in C6.2) consults before applying CLI overrides.
 *
 * Load order:
 *   1. $ELFUSE_POLICY_FILE (when set and non-empty)
 *   2. $XDG_CONFIG_HOME/elfuse/policy.json (fallback: $HOME/.config/elfuse/policy.json)
 *   3. $HOME/Library/Application Support/elfuse/policy.json
 *   4. Built-in default (insecure=false, ca_bundle=NULL, no per-host entries)
 *
 * An $ELFUSE_POLICY_FILE that points at a missing file is a hard error so
 * an operator that explicitly named a path always learns about typos.
 * Missing fallback files silently fall through to the next candidate;
 * a fully empty chain yields the built-in default with source_path == "".
 *
 * Supported schema subset (additional keys at any level are recorded for
 * forward-compat diagnostics but never reject the load):
 *
 *   {
 *     "default":    { "insecure": bool, "ca_bundle": string|null },
 *     "registries": {
 *       "<host>": {
 *         "insecure":  bool,
 *         "ca_bundle": string|null,
 *         "auth_file": string,
 *         "sigstore":  { "publicKey": string }   // C6.3 reservation; ignored
 *       },
 *       ...
 *     }
 *   }
 *
 * String fields starting with "~/" or equal to "~" expand against $HOME at
 * load time. Any other path passes through verbatim. ca_bundle is stat'd
 * during load and a missing target is a hard error; auth_file is not
 * accessed by the loader (the fetcher reads and mode-checks it in C6.2).
 *
 * Thread safety: oci_policy_t is read-only after load. Multiple threads may
 * call oci_policy_lookup concurrently. The loader itself is not reentrant;
 * one fetcher loads its own copy and frees on destruction.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct oci_policy oci_policy_t;

/* Effective per-host view. Strings are owned by the parent oci_policy_t;
 * callers must not free them or use them past oci_policy_free. A NULL
 * string field means the policy did not declare a value at either the
 * per-host entry or the default block, so the caller should fall back to
 * whatever default it would otherwise use.
 */
typedef struct {
    bool insecure;
    const char *ca_bundle;
    const char *auth_file;
    /* C6.3 reservation: a registries["<host>"].sigstore.publicKey field
     * parses into this slot for forward-compat introspection. fetch.c in
     * Plan 6 never reads it; a future sigstore-verify hook lights up
     * after Phase 4+.
     */
    const char *sigstore_public_key;
} oci_policy_effective_t;

/* Load the policy, walking the candidate path chain documented above.
 * On success returns 0 and stores a heap-allocated oci_policy_t in *out
 * which the caller frees via oci_policy_free. On failure returns -1 with
 * errno set; *err_msg (when non-NULL) points at a description owned by
 * the partially constructed policy (released by oci_policy_free even on
 * failure when *out is non-NULL) or a static literal when allocation
 * failed before the struct existed. Pass NULL for err_msg to skip the
 * diagnostic.
 *
 * The loader is tolerant of unknown JSON keys at every level: they are
 * accepted and recorded so future schema extensions (sigstore beyond the
 * minimal subset, registries.d overlays in C6.3, mirror chains, ...) do
 * not require a coordinated reader rollout.
 */
int oci_policy_load(oci_policy_t **out, const char **err_msg);

/* Release a policy. Safe on NULL and on the partially constructed object
 * a failed oci_policy_load may have produced.
 */
void oci_policy_free(oci_policy_t *p);

/* Fill *eff with the merged view for host. Unknown host falls back to the
 * default block. host is matched exactly (case-sensitive); the OCI ref
 * parser already lowercases registry hostnames, so this is the same key
 * shape policy.json uses.
 *
 * eff is always fully populated: fields the policy did not declare come
 * out as NULL strings or as the default-block values (for the insecure
 * flag). A NULL p or NULL host treats the call as a request for the
 * zero-value default.
 */
void oci_policy_lookup(const oci_policy_t *p, const char *host,
                       oci_policy_effective_t *eff);

/* Return the absolute filesystem path of the policy file that produced
 * this object, or "" when the built-in default fired. The pointer is
 * owned by the policy and stays valid until oci_policy_free. NULL p
 * returns "".
 */
const char *oci_policy_source(const oci_policy_t *p);
