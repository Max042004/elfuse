/*
 * /proc/self/* completeness tests
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests:
 *   1. /proc/self/auxv returns valid auxv with AT_PAGESZ=4096
 *   2. /proc/self/environ contains at least one entry
 *   3. /proc/self/cmdline is non-empty
 *   4. /proc/self/maps contains [heap] and [stack]
 *   5. /proc/self/status contains correct PID
 *
 * Syscalls: openat(56), read(63), close(57), getpid(172)
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "test-harness.h"
#include "test-util.h"

int passes = 0, fails = 0;

#define AT_NULL 0
#define AT_PAGESZ 6

static uint64_t parse_status_kb(const char *buf, const char *field)
{
    const char *p = strstr(buf, field);
    if (!p)
        return UINT64_MAX;
    p += strlen(field);
    while (*p == ' ' || *p == '\t')
        p++;
    uint64_t value = 0;
    while (*p >= '0' && *p <= '9')
        value = value * 10 + (uint64_t) (*p++ - '0');
    return value;
}

static uint64_t parse_statm_rss(const char *buf)
{
    const char *p = buf;
    while (*p >= '0' && *p <= '9')
        p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p < '0' || *p > '9')
        return UINT64_MAX;
    uint64_t value = 0;
    while (*p >= '0' && *p <= '9')
        value = value * 10 + (uint64_t) (*p++ - '0');
    return value;
}

int main(void)
{
    char buf[4096] __attribute__((aligned(8)));
    ssize_t n;

    TEST("procfs: /proc/self/auxv readable");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty auxv");
        }
    }

    TEST("procfs: auxv contains AT_PAGESZ=4096");
    {
        n = raw_read_file_nul("/proc/self/auxv", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            bool found = false;
            uint64_t *p = (uint64_t *) buf;
            for (ssize_t i = 0; i + 1 < n / 8; i += 2) {
                if (p[i] == AT_PAGESZ && p[i + 1] == 4096) {
                    found = true;
                    break;
                }
                if (p[i] == AT_NULL)
                    break;
            }
            EXPECT_TRUE(found, "AT_PAGESZ not found");
        }
    }

    TEST("procfs: /proc/self/environ readable");
    {
        n = raw_read_file_nul("/proc/self/environ", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty environ");
        }
    }

    TEST("procfs: /proc/self/cmdline non-empty");
    {
        n = raw_read_file_nul("/proc/self/cmdline", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else if (n > 0) {
            PASS();
        } else {
            FAIL("empty cmdline");
        }
    }

    TEST("procfs: /proc/self/maps contains [stack] and [heap]");
    {
        n = raw_read_file_nul("/proc/self/maps", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                if (strstr(buf, "[stack]") && strstr(buf, "[heap]"))
                    PASS();
                else
                    FAIL("stack or heap not found in maps");
            } else {
                FAIL("empty maps");
            }
        }
    }

    TEST("procfs: /proc/self/status has correct PID");
    {
        long pid = raw_getpid();
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        if (n < 0) {
            FAIL("open failed");
        } else {
            if (n > 0) {
                /* Check Pid: field */
                bool found = false;
                for (ssize_t i = 0; i < n - 5; i++) {
                    if (buf[i] == 'P' && buf[i + 1] == 'i' &&
                        buf[i + 2] == 'd' && buf[i + 3] == ':') {
                        /* Parse the PID value */
                        ssize_t j = i + 4;
                        while (j < n && (buf[j] == ' ' || buf[j] == '\t'))
                            j++;
                        long parsed_pid = 0;
                        while (j < n && buf[j] >= '0' && buf[j] <= '9')
                            parsed_pid = parsed_pid * 10 + (buf[j++] - '0');
                        if (parsed_pid == pid)
                            found = true;
                        break;
                    }
                }
                EXPECT_TRUE(found, "PID mismatch in status");
            } else {
                FAIL("empty status");
            }
        }
    }

    TEST("procfs: lazy pages are absent from VmRSS and statm RSS");
    {
        n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
        uint64_t status_before =
            n > 0 ? parse_status_kb(buf, "VmRSS:") : UINT64_MAX;
        n = raw_read_file_nul("/proc/self/statm", buf, sizeof(buf));
        uint64_t statm_before = n > 0 ? parse_statm_rss(buf) : UINT64_MAX;

        const size_t lazy_len = 64ULL * 1024 * 1024;
        volatile unsigned char *lazy =
            mmap(NULL, lazy_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (lazy == MAP_FAILED || status_before == UINT64_MAX ||
            statm_before == UINT64_MAX) {
            FAIL("setup failed");
        } else {
            n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
            uint64_t status_lazy =
                n > 0 ? parse_status_kb(buf, "VmRSS:") : UINT64_MAX;
            n = raw_read_file_nul("/proc/self/statm", buf, sizeof(buf));
            uint64_t statm_lazy = n > 0 ? parse_statm_rss(buf) : UINT64_MAX;

            lazy[0] = 1;
            n = raw_read_file_nul("/proc/self/status", buf, sizeof(buf));
            uint64_t status_touched =
                n > 0 ? parse_status_kb(buf, "VmRSS:") : UINT64_MAX;
            n = raw_read_file_nul("/proc/self/statm", buf, sizeof(buf));
            uint64_t statm_touched =
                n > 0 ? parse_statm_rss(buf) : UINT64_MAX;

            if (status_lazy == status_before &&
                statm_lazy == statm_before &&
                status_touched == status_lazy + 4 &&
                statm_touched == statm_lazy + 1)
                PASS();
            else
                FAIL("lazy RSS accounting mismatch");
            munmap((void *) lazy, lazy_len);
        }
    }

    SUMMARY("test-procfs");
    return fails > 0 ? 1 : 0;
}
