/*
 * mmap / munmap microbenchmark
 *
 * Compares the fixed mapping lifecycle cost with one-page and full-range
 * writes. The shell harness runs this same static aarch64 binary under elfuse
 * and an OrbStack Linux VM.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

enum touch_mode {
    TOUCH_NONE,
    TOUCH_ONE,
    TOUCH_ALL,
};

enum mapping_variant {
    VARIANT_PRIVATE,
    VARIANT_NORESERVE,
    VARIANT_PROTNONE,
};

static double elapsed_ns(const struct timespec *start,
                         const struct timespec *end)
{
    return (double) (end->tv_sec - start->tv_sec) * 1e9 +
           (double) (end->tv_nsec - start->tv_nsec);
}

static const char *parse_mode(const char *arg, enum touch_mode *mode)
{
    if (!strcmp(arg, "none")) {
        *mode = TOUCH_NONE;
        return "none";
    }
    if (!strcmp(arg, "one")) {
        *mode = TOUCH_ONE;
        return "one";
    }
    if (!strcmp(arg, "all")) {
        *mode = TOUCH_ALL;
        return "all";
    }
    return NULL;
}

static const char *parse_variant(const char *arg,
                                 enum mapping_variant *variant)
{
    if (!strcmp(arg, "private")) {
        *variant = VARIANT_PRIVATE;
        return "private";
    }
    if (!strcmp(arg, "noreserve")) {
        *variant = VARIANT_NORESERVE;
        return "noreserve";
    }
    if (!strcmp(arg, "protnone")) {
        *variant = VARIANT_PROTNONE;
        return "protnone";
    }
    return NULL;
}

static int touch_mapping(volatile unsigned char *mapping,
                         size_t length,
                         enum touch_mode mode)
{
    if (mode == TOUCH_ONE) {
        mapping[0] = 1;
    } else if (mode == TOUCH_ALL) {
        for (size_t offset = 0; offset < length; offset += 4096)
            mapping[offset] = 1;
    }
    return 0;
}

static int run_warmup(unsigned long iterations,
                      size_t length,
                      enum touch_mode mode,
                      enum mapping_variant variant)
{
    for (unsigned long i = 0; i < iterations; i++) {
        int prot = variant == VARIANT_PROTNONE ? PROT_NONE
                                               : PROT_READ | PROT_WRITE;
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        if (variant == VARIANT_NORESERVE)
            flags |= MAP_NORESERVE;
        volatile unsigned char *mapping =
            mmap(NULL, length, prot, flags, -1, 0);
        if (mapping == MAP_FAILED)
            return -1;
        if (variant == VARIANT_PROTNONE &&
            mprotect((void *) mapping, length, PROT_READ | PROT_WRITE) != 0) {
            munmap((void *) mapping, length);
            return -1;
        }
        touch_mapping(mapping, length, mode);
        if (munmap((void *) mapping, length) != 0)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    size_t length = 256 * 1024;
    unsigned long iterations = 5000;
    unsigned long warmup = 100;
    enum touch_mode mode;
    enum mapping_variant variant = VARIANT_PRIVATE;
    const char *mode_name = "one";
    const char *variant_name = "private";
    double mmap_ns = 0, commit_ns = 0, touch_ns = 0, munmap_ns = 0;

    if (argc > 1)
        iterations = strtoul(argv[1], NULL, 10);
    if (argc > 2) {
        mode_name = parse_mode(argv[2], &mode);
        if (!mode_name)
            goto usage;
    } else {
        mode = TOUCH_ONE;
    }
    if (argc > 3)
        warmup = strtoul(argv[3], NULL, 10);
    if (argc > 4)
        length = (size_t) strtoull(argv[4], NULL, 10);
    if (argc > 5) {
        variant_name = parse_variant(argv[5], &variant);
        if (!variant_name)
            goto usage;
    }
    if (argc > 6 || iterations == 0 || length == 0 || length % 4096 != 0)
        goto usage;

    if (run_warmup(warmup, length, mode, variant) != 0) {
        fprintf(stderr, "warmup: %s\n", strerror(errno));
        return 1;
    }

    for (unsigned long i = 0; i < iterations; i++) {
        struct timespec t0, t1, t2, t3, t4;
        int prot = variant == VARIANT_PROTNONE ? PROT_NONE
                                               : PROT_READ | PROT_WRITE;
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        if (variant == VARIANT_NORESERVE)
            flags |= MAP_NORESERVE;

        clock_gettime(CLOCK_MONOTONIC, &t0);
        volatile unsigned char *mapping =
            mmap(NULL, length, prot, flags, -1, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (mapping == MAP_FAILED) {
            fprintf(stderr, "mmap: %s\n", strerror(errno));
            return 1;
        }

        if (variant == VARIANT_PROTNONE) {
            if (mprotect((void *) mapping, length,
                         PROT_READ | PROT_WRITE) != 0) {
                fprintf(stderr, "mprotect: %s\n", strerror(errno));
                munmap((void *) mapping, length);
                return 1;
            }
            clock_gettime(CLOCK_MONOTONIC, &t2);
        } else {
            t2 = t1;
        }

        touch_mapping(mapping, length, mode);
        clock_gettime(CLOCK_MONOTONIC, &t3);

        if (munmap((void *) mapping, length) != 0) {
            fprintf(stderr, "munmap: %s\n", strerror(errno));
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t4);

        mmap_ns += elapsed_ns(&t0, &t1);
        if (variant == VARIANT_PROTNONE)
            commit_ns += elapsed_ns(&t1, &t2);
        touch_ns += elapsed_ns(&t2, &t3);
        munmap_ns += elapsed_ns(&t3, &t4);
    }

    printf("variant=%s mode=%s size_bytes=%zu iterations=%lu warmup=%lu "
           "mmap_ns=%.1f commit_ns=%.1f touch_ns=%.1f munmap_ns=%.1f "
           "total_ns=%.1f\n",
           variant_name, mode_name, length, iterations, warmup,
           mmap_ns / iterations, commit_ns / iterations, touch_ns / iterations,
           munmap_ns / iterations,
           (mmap_ns + commit_ns + touch_ns + munmap_ns) / iterations);
    return 0;

usage:
    fprintf(stderr,
            "usage: %s [iterations] [none|one|all] [warmup] [size-bytes] "
            "[private|noreserve|protnone]\n",
            argv[0]);
    return 2;
}
