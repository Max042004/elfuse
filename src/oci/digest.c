/* Content digests for OCI image blobs
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "digest.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* CC_LONG is 32-bit; clamp every update call so multi-gigabyte layers cannot
 * overflow the CommonCrypto length argument silently. 1 GiB is well below the
 * limit and large enough that the per-call overhead is negligible.
 */
#define DIGESTER_CHUNK_MAX ((size_t) (1u << 30))

struct oci_digester {
    oci_digest_algo_t algo;
    union {
        CC_SHA256_CTX sha256;
        CC_SHA512_CTX sha512;
    } ctx;
};

static const char HEX_LOWER[] = "0123456789abcdef";

static void bin_to_hex_lower(const uint8_t *bin, size_t bin_len, char *out)
{
    for (size_t i = 0; i < bin_len; i++) {
        out[i * 2] = HEX_LOWER[(bin[i] >> 4) & 0xf];
        out[i * 2 + 1] = HEX_LOWER[bin[i] & 0xf];
    }
    out[bin_len * 2] = '\0';
}

const char *oci_digest_algo_name(oci_digest_algo_t algo)
{
    switch (algo) {
    case OCI_DIGEST_SHA256:
        return "sha256";
    case OCI_DIGEST_SHA512:
        return "sha512";
    }
    return NULL;
}

size_t oci_digest_hex_len(oci_digest_algo_t algo)
{
    switch (algo) {
    case OCI_DIGEST_SHA256:
        return OCI_DIGEST_SHA256_HEX_LEN;
    case OCI_DIGEST_SHA512:
        return OCI_DIGEST_SHA512_HEX_LEN;
    }
    return 0;
}

bool oci_digest_algo_from_name(const char *name, oci_digest_algo_t *algo)
{
    if (!name || !algo)
        return false;
    if (!strcmp(name, "sha256")) {
        *algo = OCI_DIGEST_SHA256;
        return true;
    }
    if (!strcmp(name, "sha512")) {
        *algo = OCI_DIGEST_SHA512;
        return true;
    }
    return false;
}

bool oci_digest_hex_valid(oci_digest_algo_t algo, const char *hex)
{
    if (!hex)
        return false;
    size_t want = oci_digest_hex_len(algo);
    if (want == 0)
        return false;
    if (strlen(hex) != want)
        return false;
    for (size_t i = 0; i < want; i++) {
        char c = hex[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok)
            return false;
    }
    return true;
}

bool oci_digest_parse(const char *colon_form,
                      oci_digest_algo_t *out_algo,
                      char *out_hex)
{
    if (!colon_form || !out_algo || !out_hex)
        return false;

    out_hex[0] = '\0';
    const char *colon = strchr(colon_form, ':');
    if (!colon || colon == colon_form)
        return false;

    char name[8];
    size_t name_len = (size_t) (colon - colon_form);
    if (name_len >= sizeof(name))
        return false;
    memcpy(name, colon_form, name_len);
    name[name_len] = '\0';

    oci_digest_algo_t algo;
    if (!oci_digest_algo_from_name(name, &algo))
        return false;

    const char *hex = colon + 1;
    if (!oci_digest_hex_valid(algo, hex))
        return false;

    *out_algo = algo;
    memcpy(out_hex, hex, oci_digest_hex_len(algo) + 1);
    return true;
}

oci_digester_t *oci_digester_new(oci_digest_algo_t algo)
{
    oci_digester_t *d = calloc(1, sizeof(*d));
    if (!d)
        return NULL;
    d->algo = algo;
    switch (algo) {
    case OCI_DIGEST_SHA256:
        (void) CC_SHA256_Init(&d->ctx.sha256);
        break;
    case OCI_DIGEST_SHA512:
        (void) CC_SHA512_Init(&d->ctx.sha512);
        break;
    default:
        free(d);
        return NULL;
    }
    return d;
}

void oci_digester_free(oci_digester_t *d)
{
    free(d);
}

void oci_digester_update(oci_digester_t *d, const void *buf, size_t len)
{
    if (!d || !buf || len == 0)
        return;
    const uint8_t *p = buf;
    while (len > 0) {
        size_t chunk = len > DIGESTER_CHUNK_MAX ? DIGESTER_CHUNK_MAX : len;
        switch (d->algo) {
        case OCI_DIGEST_SHA256:
            (void) CC_SHA256_Update(&d->ctx.sha256, p, (CC_LONG) chunk);
            break;
        case OCI_DIGEST_SHA512:
            (void) CC_SHA512_Update(&d->ctx.sha512, p, (CC_LONG) chunk);
            break;
        }
        p += chunk;
        len -= chunk;
    }
}

size_t oci_digester_finish_hex(oci_digester_t *d, char *out_hex)
{
    if (!d || !out_hex)
        return 0;
    uint8_t md[CC_SHA512_DIGEST_LENGTH];
    size_t bin_len = 0;
    switch (d->algo) {
    case OCI_DIGEST_SHA256:
        (void) CC_SHA256_Final(md, &d->ctx.sha256);
        bin_len = CC_SHA256_DIGEST_LENGTH;
        break;
    case OCI_DIGEST_SHA512:
        (void) CC_SHA512_Final(md, &d->ctx.sha512);
        bin_len = CC_SHA512_DIGEST_LENGTH;
        break;
    default:
        return 0;
    }
    bin_to_hex_lower(md, bin_len, out_hex);
    return bin_len * 2;
}

size_t oci_digest_bytes(oci_digest_algo_t algo,
                        const void *buf,
                        size_t len,
                        char *out_hex)
{
    if (!out_hex)
        return 0;
    oci_digester_t *d = oci_digester_new(algo);
    if (!d)
        return 0;
    oci_digester_update(d, buf, len);
    size_t n = oci_digester_finish_hex(d, out_hex);
    oci_digester_free(d);
    return n;
}
