/*
 * Core I/O syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Read/write, ioctl, splice, sendfile, and copy_file_range operations. All
 * functions are called from syscall_dispatch() in syscall/syscall.c.
 *
 * Poll/select/epoll handlers are in syscall/poll.c. Special FD types (eventfd,
 * signalfd, timerfd) are in syscall/fd.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <termios.h>

#include "utils.h"

#include "core/rosetta.h"
#include "core/shim-globals.h"
#include "hvutil.h"
#include "runtime/procemu.h"
#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/asyncio.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/inotify.h"
#include "syscall/io.h"
#include "syscall/net.h"
#include "syscall/net-identity.h"
#include "syscall/poll.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#define URANDOM_CACHE_SIZE 4096

/* Linux terminal struct types. */

/* Linux struct winsize (same layout as macOS) */
typedef struct {
    uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel;
} linux_winsize_t;

/* Linux struct termios used by TCGETS/TCSETS on aarch64. Speed fields live in
 * Linux termios2, not in this ioctl ABI.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
} linux_termios_t;

typedef struct {
    uint16_t sa_family;
    char sa_data[14];
} linux_sockaddr_t;

typedef struct {
    char ifr_name[LINUX_IFNAMSIZ];
    linux_sockaddr_t ifr_hwaddr;
} linux_ifreq_hwaddr_t;

/* Per-fd lock embedded in the cache so a urandom read on fd A does not
 * serialize behind a concurrent urandom read on fd B. The previous design used
 * a single global mutex covering the whole cache array, which made the per-fd
 * cache pointless under any sibling-vCPU urandom traffic. The lock array is
 * initialized at startup by io_init().
 */
typedef struct {
    pthread_mutex_t lock;
    uint8_t buf[URANDOM_CACHE_SIZE];
    size_t off;
    size_t len;
} urandom_cache_t;

static urandom_cache_t urandom_cache[FD_TABLE_SIZE];

void io_init(void)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++)
        pthread_mutex_init(&urandom_cache[i].lock, NULL);
}

_Static_assert(sizeof(linux_termios_t) == 36,
               "aarch64 Linux TCGETS struct termios must be 36 bytes");

/* Linux struct termios2 used by TCGETS2/TCSETS2 on aarch64. Same layout as
 * termios but adds c_ispeed and c_ospeed at the end.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
    uint32_t c_ispeed, c_ospeed;
} linux_termios2_t;

_Static_assert(sizeof(linux_termios2_t) == 44,
               "aarch64 Linux TCGETS2 struct termios2 must be 44 bytes");

/* Linux <-> macOS c_cc index mapping: linux_mac_cc[linux_idx] = mac_idx. Shared
 * by TCGETS/TCSETS and their termios2 variants.
 *
 * Linux: VINTR=0 VQUIT=1 VERASE=2 VKILL=3 VEOF=4 VTIME=5
 *        VMIN=6 VSWTC=7 VSTART=8 VSTOP=9 VSUSP=10 VEOL=11
 *        VREPRINT=12 VDISCARD=13 VWERASE=14 VLNEXT=15 VEOL2=16
 * macOS: VEOF=0 VEOL=1 VEOL2=2 VERASE=3 VWERASE=4 VKILL=5
 *        VREPRINT=6 (7=spare) VINTR=8 VQUIT=9 VSUSP=10 VDSUSP=11
 *        VSTART=12 VSTOP=13 VLNEXT=14 VDISCARD=15 VMIN=16 VTIME=17
 */
static const int linux_mac_cc[19] = {
    8, 9, 3, 5, 0, 17, 16, -1, 12, 13, 10, 1, 6, 15, 4, 14, 2, -1, -1,
};

static void termios_copy_cc_to_linux(uint8_t linux_cc[19], const cc_t mac_cc[])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        /* cppcheck-suppress negativeIndex
         * RANGE_CHECK guards mac_idx >= 0 before the array access.
         */
        linux_cc[i] = RANGE_CHECK(mac_idx, 0, NCCS) ? mac_cc[mac_idx] : 0;
    }
}

static void termios_copy_cc_to_mac(cc_t mac_cc[], const uint8_t linux_cc[19])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        if (RANGE_CHECK(mac_idx, 0, NCCS))
            mac_cc[mac_idx] = linux_cc[i];
    }
}

static int termios_action_for(unsigned long request)
{
    return (request == LINUX_TCSETSF || request == LINUX_TCSETSF2)   ? TCSAFLUSH
           : (request == LINUX_TCSETSW || request == LINUX_TCSETSW2) ? TCSADRAIN
                                                                     : TCSANOW;
}

static int64_t io_return_zero(host_fd_ref_t *host_ref)
{
    host_fd_ref_close(host_ref);
    return 0;
}

static int64_t linux_siocgifhwaddr(guest_t *g, uint64_t arg)
{
    char raw_name[LINUX_IFNAMSIZ];
    if (guest_read_small(g, arg, raw_name, sizeof(raw_name)) < 0)
        return -LINUX_EFAULT;

    char name[LINUX_IFNAMSIZ + 1];
    memcpy(name, raw_name, LINUX_IFNAMSIZ);
    name[LINUX_IFNAMSIZ] = '\0';

    linux_ifreq_hwaddr_t ifr = {0};
    memcpy(ifr.ifr_name, raw_name, sizeof(ifr.ifr_name));

    uint16_t family = 0;
    uint8_t mac[NET_IDENTITY_MAC_LEN];
    if (net_identity_hwaddr(name, &family, mac) < 0)
        return -LINUX_ENODEV;

    ifr.ifr_hwaddr.sa_family = family;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, sizeof(mac));

    if (guest_write_small(g, arg, &ifr, sizeof(ifr)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t io_wait_fd_or_interrupted(int host_fd, short events)
{
    int wake_fd = wakeup_pipe_read_fd();

    /* poll() ignores entries with a negative fd, so a missing wakeup pipe just
     * drops the second slot.
     */
    struct pollfd fds[2] = {
        {.fd = host_fd, .events = events},
        {.fd = wake_fd, .events = POLLIN},
    };

    for (;;) {
        /* Materialize expired guest interval timers first: ITIMER_REAL is
         * virtual and only converted to a pending SIGALRM by the syscall
         * epilogue, which cannot run while this thread is parked here. The
         * futex wait loops do the same.
         */
        signal_check_timer();

        /* Ignored/default-ignore signals do not interrupt; restartable handlers
         * still need to run promptly through the syscall epilogue.
         */
        if (proc_exit_group_requested() || futex_interrupt_consume() ||
            signal_pending_interruption(NULL))
            return -LINUX_EINTR;

        /* Bounded wait even when the wakeup pipe exists: the pipe is a
         * single-consumer channel, so a sibling thread blocked in read/poll can
         * drain the byte meant to wake this one. The 200 ms recheck guarantees
         * every waiter re-evaluates its own interrupt conditions.
         */
        int ret = poll(fds, 2, 200);
        if (ret < 0)
            return linux_errno();

        if (wake_fd >= 0 && (fds[1].revents & POLLIN))
            wakeup_pipe_drain();
        if (fds[0].revents)
            return 0;
    }
}

/* Route a blocking read/write on a fd that can block (pipe, socket, fifo,
 * char/tty) through the interruptible wait so the vCPU thread stays reachable
 * by hv_vcpus_exit + the wakeup pipe. No-op for regular files, nonblocking fds,
 * and direction mismatches (a POLLIN wait on an O_WRONLY fd would hang; the
 * read then fails EBADF like Linux).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR) to abort.
 */
static int64_t io_block_wait(int fd, int host_fd, short events)
{
    if (!fd_can_block(fd))
        return 0;
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0 || (fl & O_NONBLOCK))
        return 0;
    int acc = fl & O_ACCMODE;
    if ((events & POLLIN) && acc == O_WRONLY)
        return 0;
    if ((events & POLLOUT) && acc == O_RDONLY)
        return 0;
    return io_wait_fd_or_interrupted(host_fd, events);
}

static int64_t io_check_access(int host_fd, short events)
{
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0)
        return linux_errno();
    int acc = fl & O_ACCMODE;
    if ((events & POLLIN) && acc == O_WRONLY)
        return -LINUX_EBADF;
    if ((events & POLLOUT) && acc == O_RDONLY)
        return -LINUX_EBADF;
    return 0;
}

void urandom_fd_reset_cache(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    /* Preserve the embedded lock; reset only the entropy fields. memset of the
     * whole struct would clobber the mutex state.
     */
    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    memset(c->buf, 0, sizeof(c->buf));
    c->off = 0;
    c->len = 0;
    pthread_mutex_unlock(&c->lock);
}

void urandom_fd_cleanup(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    urandom_fd_reset_cache(guest_fd);
}

static int64_t urandom_check_readable(int guest_fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap) || snap.type != FD_URANDOM)
        return -LINUX_EBADF;
    if ((snap.linux_flags & 3) == LINUX_O_WRONLY)
        return -LINUX_EBADF;
    return 0;
}

static int64_t urandom_fill_iov(int guest_fd,
                                const struct iovec *iov,
                                int iovcnt)
{
    int64_t err = urandom_check_readable(guest_fd);
    if (err < 0)
        return err;

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > (size_t) SSIZE_MAX - total)
            return -LINUX_EINVAL;
        total += iov[i].iov_len;
    }
    if (total == 0)
        return 0;

    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    size_t done = 0;
    for (int i = 0; i < iovcnt && done < total; i++) {
        uint8_t *dst = iov[i].iov_base;
        size_t iov_done = 0;
        size_t iov_len = iov[i].iov_len;
        if (iov_len > total - done)
            iov_len = total - done;
        while (iov_done < iov_len) {
            if (c->off == c->len) {
                arc4random_buf(c->buf, sizeof(c->buf));
                c->off = 0;
                c->len = sizeof(c->buf);
            }
            size_t chunk = c->len - c->off;
            if (chunk > iov_len - iov_done)
                chunk = iov_len - iov_done;
            memcpy(dst + iov_done, c->buf + c->off, chunk);
            c->off += chunk;
            iov_done += chunk;
            done += chunk;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return (int64_t) done;
}

static int64_t validate_iov_total(guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt <= 0 || iovcnt > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva + (uint64_t) i * sizeof(giov), &giov,
                             sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        if (giov.iov_len > (uint64_t) SSIZE_MAX - total)
            return -LINUX_EINVAL;
        total += (size_t) giov.iov_len;
    }
    return 0;
}

static int64_t urandom_read(guest_t *g,
                            int guest_fd,
                            uint64_t buf_gva,
                            uint64_t count)
{
    if (count > SSIZE_MAX)
        count = SSIZE_MAX;
    if (count == 0) {
        struct iovec empty = {0};
        return urandom_fill_iov(guest_fd, &empty, 1);
    }

    uint64_t avail = 0;
    void *dst = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!dst)
        return -LINUX_EFAULT;
    if (count > avail)
        count = avail;

    struct iovec iov = {.iov_base = dst, .iov_len = (size_t) count};
    int64_t rc = urandom_fill_iov(guest_fd, &iov, 1);

    /* This slow path runs when the shim's identity-class fast path could not
     * serve the read: either the request was larger than the shim's inline
     * limit, or the ring was empty. Refill the shim's entropy ring before
     * returning so a subsequent read(/dev/urandom) from the same vCPU sees a
     * populated ring and stays on the fast path.
     */
    shim_globals_refill_urandom_ring(g);
    return rc;
}

static bool rosetta_ioctl_target_fd(guest_t *g, int host_fd)
{
    if (!g->is_rosetta)
        return false;

    /* Rosetta opens /proc/self/exe (which under rosetta resolves to the rosetta
     * translator, not elfuse) and issues the VZ probe ioctls on that
     * descriptor. Match against ROSETTA_PATH so the gate triggers regardless of
     * where elfuse itself lives on disk.
     */
    char resolved[PATH_MAX];
    if (fcntl(host_fd, F_GETPATH, resolved) < 0)
        return false;
    if (strcmp(resolved, ROSETTA_PATH) != 0)
        return false;

    /* Defense in depth: require the syscall to originate from inside the
     * rosetta translator image. The /proc/self/exe redirection makes the
     * launcher fd reachable to any code running under a rosetta-enabled VM, so
     * without this check a guest-launched helper that opened /proc/self/exe
     * could exercise the synthetic VZ probe path. Today the responses are
     * public constants, but the gate guards against future synthetic responses
     * that leak host state. ELR_EL1 carries the EL0 return PC captured at SVC
     * entry on aarch64.
     *
     * Skip if the rosetta image bounds are not yet known (pre-finalize); the
     * F_GETPATH match above is the only gate in that window, and
     * rosetta_finalize publishes the bounds before issuing any ioctl.
     */
    if (g->rosetta_va_base && g->rosetta_size) {
        if (!current_thread)
            return false;
        uint64_t pc = vcpu_get_sysreg(current_thread->vcpu, HV_SYS_REG_ELR_EL1);
        if (pc < g->rosetta_va_base ||
            pc - g->rosetta_va_base >= g->rosetta_size)
            return false;
    }
    return true;
}

/* Returns true if request matches one of the Rosetta VZ probe ioctls. */
static bool rosetta_vz_request(uint64_t request)
{
    return request == ROSETTA_VZ_CHECK || request == ROSETTA_VZ_CAPS ||
           request == ROSETTA_VZ_ACTIVATE;
}

/* Handle the Rosetta VZ probe ioctl trio. Writes synthetic responses to the
 * guest buffer at arg and returns the value the guest sees (1 on success,
 * negative Linux errno on a guest_write fault). Caller is responsible for
 * dispatch gating (see rosetta_vz_request + rosetta_ioctl_target_fd).
 */
static int64_t rosetta_vz_ioctl(guest_t *g, uint64_t request, uint64_t arg)
{
    switch (request) {
    case ROSETTA_VZ_CHECK: {
        static const char rosetta_sig[ROSETTA_VZ_SIG_LEN] =
            "Our hard work\nby these words guarded\n"
            "please don't steal\n\xc2\xa9 Apple Inc";
        if (guest_write(g, arg, rosetta_sig, sizeof(rosetta_sig)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_CAPS: {
        /* caps is zero-initialized: VZ_SECONDARY and the trailing NUL of any
         * partially-copied binary path are already in place.
         */
        uint8_t caps[ROSETTA_CAPS_SIZE] = {0};
        caps[ROSETTA_CAPS_VZ_ENABLE] = 1;
        static const char fake_sock_path[] = ROSETTAD_SOCKET_PATH;
        memcpy(&caps[ROSETTA_CAPS_SOCKET_PATH], fake_sock_path,
               sizeof(fake_sock_path));
        /* Snapshot the caps binary path under the rosetta path lock so a
         * concurrent execve cannot tear the string between length probe and
         * copy. Inline buffer matches the cap exactly; the snapshot helper
         * bounds the write itself.
         */
        char bin[ROSETTA_CAPS_BINARY_PATH_LEN];
        size_t bin_n = rosettad_snapshot_caps_binary_path(bin, sizeof(bin));
        if (bin_n > 0)
            memcpy(&caps[ROSETTA_CAPS_BINARY_PATH], bin, bin_n);
        if (guest_write(g, arg, caps, sizeof(caps)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_ACTIVATE:
        return 1;
    }
    /* Caller gates dispatch; this is unreachable in practice. */
    return -LINUX_ENOTTY;
}

/* termios flag translation helpers. */

/* Linux aarch64 c_iflag bits (from asm-generic/termbits-common.h). Low 9 bits
 * (IGNBRK..ICRNL) match macOS exactly. Bits from 0x200 onward differ: Linux
 * IUCLC=0x200 has no macOS equivalent; Linux IXON=0x400/IXOFF=0x1000 vs macOS
 * IXON=0x200/IXOFF=0x400.
 */
#define LINUX_IFLAG_LOW_MASK 0x1ff /* bits 0-8: same on Linux and macOS */
#define LINUX_IXON 0x0400
#define LINUX_IXOFF 0x1000
#define LINUX_IMAXBEL 0x2000 /* same value on both */
#define LINUX_IUTF8 0x4000   /* same value on both */

/* Translate Linux c_iflag to macOS c_iflag. */
static tcflag_t linux_iflag_to_mac(uint32_t lf)
{
    tcflag_t mf = lf & LINUX_IFLAG_LOW_MASK; /* IGNBRK..ICRNL identical */
    /* IXANY=0x800 is the same on both; pass through */
    if (lf & 0x800)
        mf |= IXANY;
    if (lf & LINUX_IXON)
        mf |= IXON; /* Linux 0x400 -> macOS 0x200 */
    if (lf & LINUX_IXOFF)
        mf |= IXOFF; /* Linux 0x1000 -> macOS 0x400 */
    if (lf & LINUX_IMAXBEL)
        mf |= IMAXBEL;
    if (lf & LINUX_IUTF8)
        mf |= IUTF8;
    /* IUCLC (Linux 0x200) has no macOS equivalent; drop it */
    return mf;
}

/* Translate macOS c_iflag to Linux c_iflag. */
static uint32_t mac_iflag_to_linux(tcflag_t mf)
{
    uint32_t lf = mf & LINUX_IFLAG_LOW_MASK; /* IGNBRK..ICRNL identical */
    if (mf & IXANY)
        lf |= 0x800;
    if (mf & IXON)
        lf |= LINUX_IXON;
    if (mf & IXOFF)
        lf |= LINUX_IXOFF;
    if (mf & IMAXBEL)
        lf |= LINUX_IMAXBEL;
    if (mf & IUTF8)
        lf |= LINUX_IUTF8;
    return lf;
}

/* Linux aarch64 c_oflag bits (asm-generic/termbits-common.h + termbits.h). Only
 * OPOST (0x01) has the same value on both platforms. macOS 0x02 = ONLCR; Linux
 * 0x02 = OLCUC (output lowercase->uppercase, rare). macOS 0x04 = OXTABS; Linux
 * 0x04 = ONLCR. All other bits shift by one. OLCUC (Linux 0x002, output
 * lowercase->uppercase) has no macOS equivalent and is silently dropped. macOS
 * uses 0x002 for ONLCR.
 */
#define LINUX_OPOST 0x001
#define LINUX_ONLCR 0x004  /* macOS ONLCR=0x002 */
#define LINUX_OCRNL 0x008  /* macOS OCRNL=0x010 */
#define LINUX_ONOCR 0x010  /* macOS ONOCR=0x020 */
#define LINUX_ONLRET 0x020 /* macOS ONLRET=0x040 */
#define LINUX_OFILL 0x040  /* macOS OFILL=0x080 */
#define LINUX_OFDEL 0x080  /* macOS OFDEL=0x020000 */
/* Linux NLDLY/CRDLY/TABDLY/BSDLY/VTDLY/FFDLY have no macOS equivalents */

/* Translate Linux c_oflag to macOS c_oflag. */
static tcflag_t linux_oflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    if (lf & LINUX_OPOST)
        mf |= OPOST;
    /* LINUX_OLCUC (0x002) has no macOS equivalent; drop it */
    if (lf & LINUX_ONLCR)
        mf |= ONLCR;
    if (lf & LINUX_OCRNL)
        mf |= OCRNL;
    if (lf & LINUX_ONOCR)
        mf |= ONOCR;
    if (lf & LINUX_ONLRET)
        mf |= ONLRET;
    if (lf & LINUX_OFILL)
        mf |= OFILL;
    if (lf & LINUX_OFDEL)
        mf |= OFDEL;
    /* NLDLY, CRDLY, TABDLY, BSDLY, VTDLY, FFDLY: no macOS equivalents */
    return mf;
}

/* Translate macOS c_oflag to Linux c_oflag. */
static uint32_t mac_oflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    if (mf & OPOST)
        lf |= LINUX_OPOST;
    if (mf & ONLCR)
        lf |= LINUX_ONLCR;
    if (mf & OCRNL)
        lf |= LINUX_OCRNL;
    if (mf & ONOCR)
        lf |= LINUX_ONOCR;
    if (mf & ONLRET)
        lf |= LINUX_ONLRET;
    if (mf & OFILL)
        lf |= LINUX_OFILL;
    if (mf & OFDEL)
        lf |= LINUX_OFDEL;
    return lf;
}

/* Linux aarch64 c_cflag bits (asm-generic/termbits.h). All standard flags
 * differ from macOS: macOS shifts everything left by 4 bits (e.g., Linux
 * CS8=0x30, macOS CS8=0x300; Linux CSTOPB=0x40, macOS=0x400). The CBAUD field
 * (Linux 0x0000100f) encodes baud rate symbolically; macOS uses raw numeric
 * speeds via cfgetispeed/cfsetispeed, so termios translation drops CBAUD from
 * c_cflag and always uses the speed accessors.
 */
#define LINUX_CSIZE 0x0030
#define LINUX_CS5 0x0000
#define LINUX_CS6 0x0010
#define LINUX_CS7 0x0020
#define LINUX_CS8 0x0030
#define LINUX_CSTOPB 0x0040
#define LINUX_CREAD 0x0080
#define LINUX_PARENB 0x0100
#define LINUX_PARODD 0x0200
#define LINUX_HUPCL 0x0400
#define LINUX_CLOCAL 0x0800
/* LINUX_CBAUD 0x0000100f and LINUX_CBAUDEX 0x00001000 encode baud in c_cflag;
 * macOS uses dedicated speed fields, so termios translation ignores CBAUD on
 * translation. TCGETS2/TCSETS2 use BOTHER to signal numeric c_ispeed/c_ospeed.
 */
#define LINUX_CBAUD 0x100f
#define LINUX_BOTHER 0x1000

/* Decode a Linux CBAUD field value to a numeric baud rate.
 * Returns the numeric rate, or 0 for B0 / unknown. Standard rates B0-B38400 are
 * in the low nibble (0-15); extended rates B57600-B4000000 use CBAUDEX (0x1000)
 * + low nibble.
 */
static speed_t linux_cbaud_to_speed(uint32_t cbaud)
{
    static const speed_t std_rates[16] = {
        0,   50,   75,   110,  134,  150,  200,   300,
        600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
    };
    static const speed_t ext_rates[16] = {
        0,       57600,   115200,  230400,  460800,  500000,  576000,  921600,
        1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
    };
    uint32_t rate_idx = cbaud & 0xF;

    if (cbaud < 16)
        return std_rates[cbaud];
    if (cbaud & LINUX_BOTHER)
        return ext_rates[rate_idx];
    return 0;
}

/* Translate Linux c_cflag to macOS c_cflag. */
static tcflag_t linux_cflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    /* CSIZE: Linux CS5=0x00, CS6=0x10, CS7=0x20, CS8=0x30
     *        macOS CS5=0x00, CS6=0x100, CS7=0x200, CS8=0x300
     */
    switch (lf & LINUX_CSIZE) {
    case LINUX_CS5:
        mf |= CS5;
        break;
    case LINUX_CS6:
        mf |= CS6;
        break;
    case LINUX_CS7:
        mf |= CS7;
        break;
    case LINUX_CS8:
        mf |= CS8;
        break;
    default:
        break;
    }
    if (lf & LINUX_CSTOPB)
        mf |= CSTOPB;
    if (lf & LINUX_CREAD)
        mf |= CREAD;
    if (lf & LINUX_PARENB)
        mf |= PARENB;
    if (lf & LINUX_PARODD)
        mf |= PARODD;
    if (lf & LINUX_HUPCL)
        mf |= HUPCL;
    if (lf & LINUX_CLOCAL)
        mf |= CLOCAL;
    /* CBAUD/CBAUDEX: drop (baud rate comes from c_ispeed/c_ospeed fields) */
    return mf;
}

/* Translate macOS c_cflag to Linux c_cflag. */
static uint32_t mac_cflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    switch (mf & CSIZE) {
    case CS5:
        lf |= LINUX_CS5;
        break;
    case CS6:
        lf |= LINUX_CS6;
        break;
    case CS7:
        lf |= LINUX_CS7;
        break;
    case CS8:
        lf |= LINUX_CS8;
        break;
    default:
        break;
    }
    if (mf & CSTOPB)
        lf |= LINUX_CSTOPB;
    if (mf & CREAD)
        lf |= LINUX_CREAD;
    if (mf & PARENB)
        lf |= LINUX_PARENB;
    if (mf & PARODD)
        lf |= LINUX_PARODD;
    if (mf & HUPCL)
        lf |= LINUX_HUPCL;
    if (mf & CLOCAL)
        lf |= LINUX_CLOCAL;
    return lf;
}

/* Linux aarch64 c_lflag bits (asm-generic/termbits.h). Virtually every flag has
 * a different value from macOS. Only ECHO (0x0008) is the same on both
 * platforms. XCASE (Linux 0x004, rarely used, no macOS equivalent) is dropped;
 * macOS 0x004 has different semantics and is not translated here.
 */
#define LINUX_ISIG 0x00001
#define LINUX_ICANON 0x00002
#define LINUX_ECHO 0x00008 /* same on macOS */
#define LINUX_ECHOE 0x00010
#define LINUX_ECHOK 0x00020
#define LINUX_ECHONL 0x00040
#define LINUX_NOFLSH 0x00080
#define LINUX_TOSTOP 0x00100
#define LINUX_ECHOCTL 0x00200
#define LINUX_ECHOPRT 0x00400
#define LINUX_ECHOKE 0x00800
#define LINUX_FLUSHO 0x01000
#define LINUX_PENDIN 0x04000
#define LINUX_IEXTEN 0x08000
#define LINUX_EXTPROC 0x10000

/* Translate Linux c_lflag to macOS c_lflag. */
static tcflag_t linux_lflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    if (lf & LINUX_ISIG)
        mf |= ISIG;
    if (lf & LINUX_ICANON)
        mf |= ICANON;
    /* LINUX_XCASE (0x004) has no macOS equivalent; drop it */
    if (lf & LINUX_ECHO)
        mf |= ECHO;
    if (lf & LINUX_ECHOE)
        mf |= ECHOE;
    if (lf & LINUX_ECHOK)
        mf |= ECHOK;
    if (lf & LINUX_ECHONL)
        mf |= ECHONL;
    if (lf & LINUX_NOFLSH)
        mf |= NOFLSH;
    if (lf & LINUX_TOSTOP)
        mf |= TOSTOP;
    if (lf & LINUX_ECHOCTL)
        mf |= ECHOCTL;
    if (lf & LINUX_ECHOPRT)
        mf |= ECHOPRT;
    if (lf & LINUX_ECHOKE)
        mf |= ECHOKE;
    if (lf & LINUX_FLUSHO)
        mf |= FLUSHO;
    if (lf & LINUX_PENDIN)
        mf |= PENDIN;
    if (lf & LINUX_IEXTEN)
        mf |= IEXTEN;
    if (lf & LINUX_EXTPROC)
        mf |= EXTPROC;
    return mf;
}

/* Translate macOS c_lflag to Linux c_lflag. */
static uint32_t mac_lflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    if (mf & ISIG)
        lf |= LINUX_ISIG;
    if (mf & ICANON)
        lf |= LINUX_ICANON;
    if (mf & ECHO)
        lf |= LINUX_ECHO;
    if (mf & ECHOE)
        lf |= LINUX_ECHOE;
    if (mf & ECHOK)
        lf |= LINUX_ECHOK;
    if (mf & ECHONL)
        lf |= LINUX_ECHONL;
    if (mf & NOFLSH)
        lf |= LINUX_NOFLSH;
    if (mf & TOSTOP)
        lf |= LINUX_TOSTOP;
    if (mf & ECHOCTL)
        lf |= LINUX_ECHOCTL;
    if (mf & ECHOPRT)
        lf |= LINUX_ECHOPRT;
    if (mf & ECHOKE)
        lf |= LINUX_ECHOKE;
    if (mf & FLUSHO)
        lf |= LINUX_FLUSHO;
    if (mf & PENDIN)
        lf |= LINUX_PENDIN;
    if (mf & IEXTEN)
        lf |= LINUX_IEXTEN;
    if (mf & EXTPROC)
        lf |= LINUX_EXTPROC;
    return lf;
}

/* read/write and positional variants. */

/* Open a host fd reference for regular I/O, checking type and seals under
 * fd_lock for thread safety.
 *
 * Returns -LINUX_EBADF for path-only or closed fds, -LINUX_EPERM for
 * write-sealed fds (when check_write_seal is set), or 0 on success.
 */
static int64_t host_fd_ref_open_checked(int guest_fd,
                                        host_fd_ref_t *ref,
                                        bool check_write_seal)
{
    if (check_write_seal) {
        fd_entry_t snap;
        if (!fd_snapshot(guest_fd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_PATH)
            return -LINUX_EBADF;
        if (snap.seals & LINUX_F_SEAL_WRITE)
            return -LINUX_EPERM;
        return host_fd_ref_open(guest_fd, ref) < 0 ? -LINUX_EBADF : 0;
    }
    return host_fd_ref_open_io(guest_fd, ref);
}

static int64_t host_fd_ref_open_regular_io(int guest_fd, host_fd_ref_t *ref)
{
    return host_fd_ref_open_io(guest_fd, ref);
}

static int64_t proc_try_read_intercept(int fd,
                                       int host_fd,
                                       void *buf,
                                       size_t count,
                                       int64_t offset,
                                       int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_read(fd, buf, count, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

static int64_t proc_try_readv_intercept(int fd,
                                        int host_fd,
                                        const struct iovec *iov,
                                        int iovcnt,
                                        int64_t offset,
                                        int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_readv(fd, iov, iovcnt, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

/* Sendfile/copy_file_range chunk read: route the chunk through proc_intercept
 * when the source fd is a synthetic /proc node, otherwise fall through
 * (INT64_MIN). For the streaming (use_pread=0) variant the input offset is
 * irrelevant; the helper queries the live host fd cursor.
 */
static int64_t proc_try_chunk_read_intercept(int fd,
                                             int host_fd,
                                             void *buf,
                                             size_t count,
                                             int64_t offset,
                                             int use_pread)
{
    if (!use_pread) {
        offset = lseek(host_fd, 0, SEEK_CUR);
        if (offset < 0)
            return INT64_MIN;
    }
    return proc_try_read_intercept(fd, host_fd, buf, count, offset, use_pread);
}

static int64_t proc_try_writev_intercept(int fd,
                                         int host_fd,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         int64_t offset,
                                         int use_pwrite)
{
    if (!proc_intercept_write_candidate(fd))
        return INT64_MIN;

    size_t total = 0;
    char stack_buf[256];
    char *buf = stack_buf;
    char *heap = NULL;
    ssize_t written = 0;
    int handled;

    for (int i = 0; i < iovcnt; i++)
        total += iov[i].iov_len;
    if (total > sizeof(stack_buf)) {
        heap = malloc(total);
        if (!heap)
            return -LINUX_ENOMEM;
        buf = heap;
    }

    size_t off = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len)
            memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    handled = proc_intercept_write(fd, host_fd, buf, total, offset, use_pwrite,
                                   &written);
    free(heap);
    if (handled < 0)
        return linux_errno();
    if (handled > 0)
        return written;
    return INT64_MIN;
}

static int64_t io_write_result(ssize_t ret)
{
    if (ret >= 0)
        return ret;

    int saved_errno = errno;
    if (saved_errno == EPIPE)
        signal_queue(LINUX_SIGPIPE);
    errno = saved_errno;
    return linux_errno();
}

int64_t sys_write(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    int type = fd_get_type(fd);
    if (type == FD_FUSE_DEV)
        return fuse_dev_write(g, fd, buf_gva, count);
    if (type == FD_EVENTFD)
        return eventfd_write(fd, g, buf_gva, count);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: write(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    host_iov_buf_t source;
    err = host_iov_prepare_read_range(g, buf_gva, count, &source);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_writev_intercept(
            fd, host_ref.fd, source.iov, source.iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&source);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    /* A blocking write on a full pipe/socket buffer would park this vCPU thread
     * in an uninterruptible host write() where the preempt thread's
     * hv_vcpus_exit cannot reach it. Wait for POLLOUT (or a guest signal)
     * first. Unlike the socket send paths there is no per-call nonblocking flag
     * for write(), so the tiny window where the buffer refills between the wait
     * and write() can still block; that matches sys_read and the receive paths.
     */
    int64_t wwait = io_block_wait(fd, host_ref.fd, POLLOUT);
    if (wwait < 0) {
        host_iov_free(&source);
        host_fd_ref_close(&host_ref);
        return wwait;
    }

    ssize_t ret = writev(host_ref.fd, source.iov, source.iovcnt);
    host_iov_free(&source);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

int64_t sys_read(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    /* Read the type once under fd_lock so a concurrent close/reopen cannot make
     * different dispatch checks disagree. Each handler still re-validates
     * internally and returns EBADF if its slot changed.
     */
    int type = fd_get_type(fd);
    switch (type) {
    case FD_FUSE_DEV:
        return fuse_dev_read(fd, g, buf_gva, count);
    case FD_FUSE_FILE:
        return fuse_read_fd(g, fd, buf_gva, count);
    case FD_EVENTFD:
        return eventfd_read(fd, g, buf_gva, count);
    case FD_SIGNALFD:
        return signalfd_read(fd, g, buf_gva, count);
    case FD_TIMERFD:
        return timerfd_read(fd, g, buf_gva, count);
    case FD_INOTIFY:
        return inotify_read(fd, g, buf_gva, count);
    case FD_NETLINK:
        return netlink_read(fd, g, buf_gva, count);
    case FD_URANDOM:
        return urandom_read(g, fd, buf_gva, count);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux: read(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    /* Validate the writable VMA prefix without walking/materializing lazy PTEs.
     * The host read below may return EOF, EINTR, or only a few bytes; resolving
     * the destination directly with count would eagerly COW the whole request
     * before knowing how much data exists. mmap_lock makes the region snapshot
     * safe; a concurrent mapping change after unlock has the same user-buffer
     * race Linux permits around copy_to_user. */
    uint64_t writable = 0;
    pthread_mutex_lock(&mmap_lock);
    while (writable < count) {
        uint64_t cur = buf_gva + writable;
        if (cur < buf_gva)
            break;
        const guest_region_t *r = guest_region_find(g, cur);
        if (!r || !(r->prot & LINUX_PROT_WRITE))
            break;
        uint64_t chunk = r->end - cur;
        if (chunk > count - writable)
            chunk = count - writable;
        writable += chunk;
    }
    pthread_mutex_unlock(&mmap_lock);
    if (writable == 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    count = writable;

    uint8_t stack_stage[16384];
    void *stage = stack_stage;
    bool mapped_stage = count > sizeof(stack_stage);
    if (mapped_stage) {
        stage = mmap(NULL, (size_t) count, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
        if (stage == MAP_FAILED) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOMEM;
        }
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted =
            proc_try_read_intercept(fd, host_ref.fd, stage, count, offset, 0);
        if (intercepted != INT64_MIN) {
            if (intercepted > 0 &&
                guest_write(g, buf_gva, stage, (size_t) intercepted) < 0)
                intercepted = -LINUX_EFAULT;
            if (mapped_stage)
                munmap(stage, (size_t) count);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    /* Wait interruptibly when the fd can block on a read (pipe, socket, fifo,
     * char/tty). Regular files never block and skip this.
     */
    int64_t rwait = io_block_wait(fd, host_ref.fd, POLLIN);
    if (rwait < 0) {
        if (mapped_stage)
            munmap(stage, (size_t) count);
        host_fd_ref_close(&host_ref);
        return rwait;
    }

    ssize_t ret = read(host_ref.fd, stage, (size_t) count);
    if (ret > 0 && guest_write(g, buf_gva, stage, (size_t) ret) < 0)
        ret = -1, errno = EFAULT;
    if (mapped_stage)
        munmap(stage, (size_t) count);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : ret;
}

int64_t sys_pread64(guest_t *g,
                    int fd,
                    uint64_t buf_gva,
                    uint64_t count,
                    int64_t offset)
{
    if (fuse_is_file_fd(fd))
        return fuse_pread_fd(g, fd, buf_gva, count, offset);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux: pread(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    int64_t intercepted =
        proc_try_read_intercept(fd, host_ref.fd, buf, count, offset, 1);
    if (intercepted != INT64_MIN) {
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pread(host_ref.fd, buf, count, offset);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : ret;
}

int64_t sys_pwrite64(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: pwrite(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    host_iov_buf_t source;
    err = host_iov_prepare_read_range(g, buf_gva, count, &source);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_writev_intercept(fd, host_ref.fd, source.iov,
                                                    source.iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&source);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwritev(host_ref.fd, source.iov, source.iovcnt, offset);
    host_iov_free(&source);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

/* Helper: build host iovec array from guest iovec array. Uses guest_read for
 * the iovec array (may cross 2MiB block boundary) and guest_ptr_avail for each
 * buffer (caps to contiguous bytes). required_perms: MEM_PERM_W for readv (host
 * writes to guest buffers),
 *                 MEM_PERM_R for writev (host reads from guest buffers).
 * Returns 0 on success, -LINUX_EFAULT on bad guest pointer.
 */
static void host_iov_init(host_iov_buf_t *buf)
{
    buf->iov = buf->stack;
    buf->heap = NULL;
    buf->bounce = NULL;
    buf->iovcnt = 0;
    buf->capacity = SYSCALL_IOV_STACK_MAX;
}

static void *host_iov_alloc_bounce(host_iov_buf_t *buf, size_t length)
{
    void *bounce = malloc(length);
    if (!bounce)
        return NULL;
    free(buf->heap);
    buf->heap = NULL;
    buf->bounce = bounce;
    buf->iov = buf->stack;
    buf->iov[0] = (struct iovec) {.iov_base = bounce, .iov_len = length};
    buf->iovcnt = 1;
    buf->capacity = SYSCALL_IOV_STACK_MAX;
    return bounce;
}

#define HOST_ZERO_SOURCE_SIZE (1U << 20)
static pthread_once_t host_zero_source_once = PTHREAD_ONCE_INIT;
static void *host_zero_source;

static void host_zero_source_init(void)
{
    void *p = mmap(NULL, HOST_ZERO_SOURCE_SIZE, PROT_READ,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p != MAP_FAILED)
        host_zero_source = p;
}

static bool is_guest_zero_page_ptr(const guest_t *g, const void *ptr)
{
    uintptr_t zero = (uintptr_t) g->host_base + g->lazy_zero_gpa;
    uintptr_t p = (uintptr_t) ptr;
    return p >= zero && p < zero + GUEST_PAGE_SIZE;
}

/* Resolve one readable source chunk. Consecutive COW-zero aliases all point at
 * the same 4 KiB GPA, so the generic contiguity walker stops at every page.
 * Verify those pages one by one, then represent up to 1 MiB of the logical run
 * with a process-global zero buffer. This preserves guest laziness while
 * keeping large untouched ranges well below the host IOV_MAX limit. */
static int resolve_host_read_chunk(guest_t *g,
                                   uint64_t gva,
                                   uint64_t remaining,
                                   void **base_out,
                                   uint64_t *length_out)
{
    uint64_t avail = 0;
    void *base = guest_ptr_bound(g, gva, &avail, MEM_PERM_R, remaining);
    if (!base)
        return -1;
    uint64_t length = remaining < avail ? remaining : avail;
    if (is_guest_zero_page_ptr(g, base)) {
        pthread_once(&host_zero_source_once, host_zero_source_init);
        if (!host_zero_source) {
            *base_out = base;
            *length_out = length;
            return 0;
        }
        uint64_t cap = remaining < HOST_ZERO_SOURCE_SIZE
                           ? remaining
                           : HOST_ZERO_SOURCE_SIZE;
        while (length < cap) {
            uint64_t next_avail = 0;
            void *next = guest_ptr_bound(g, gva + length, &next_avail,
                                         MEM_PERM_R, cap - length);
            if (!next || !is_guest_zero_page_ptr(g, next))
                break;
            uint64_t add =
                cap - length < next_avail ? cap - length : next_avail;
            length += add;
        }
        base = host_zero_source;
    }
    *base_out = base;
    *length_out = length;
    return 0;
}

static int host_iov_append(host_iov_buf_t *buf, void *base, size_t length)
{
    if (buf->iovcnt == buf->capacity) {
        if (buf->capacity >= SYSCALL_IOV_MAX)
            return 1; /* representable prefix; host syscall returns short */
        int next = buf->capacity * 2;
        if (next > SYSCALL_IOV_MAX)
            next = SYSCALL_IOV_MAX;
        struct iovec *grown = malloc((size_t) next * sizeof(*grown));
        if (!grown)
            return -1;
        memcpy(grown, buf->iov, (size_t) buf->iovcnt * sizeof(*grown));
        free(buf->heap);
        buf->heap = grown;
        buf->iov = grown;
        buf->capacity = next;
    }
    buf->iov[buf->iovcnt++] =
        (struct iovec) {.iov_base = base, .iov_len = length};
    return 0;
}

static int64_t build_host_iov(guest_t *g,
                              uint64_t iov_gva,
                              int iovcnt,
                              host_iov_buf_t *buf,
                              int required_perms)
{
    linux_iovec_t stack_giov[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *guest_iov = stack_giov;
    linux_iovec_t *heap = NULL;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        heap = malloc((size_t) iovcnt * sizeof(*guest_iov));
        if (!heap)
            return -LINUX_ENOMEM;
        guest_iov = heap;
    }
    if (guest_read(g, iov_gva, guest_iov,
                   (size_t) iovcnt * sizeof(*guest_iov)) < 0) {
        free(heap);
        return -LINUX_EFAULT;
    }
    bool needs_bounce = false;
    for (int i = 0; i < iovcnt; i++) {
        if (guest_iov[i].iov_len == 0) {
            if (host_iov_append(buf, NULL, 0) < 0) {
                free(heap);
                return -LINUX_ENOMEM;
            }
            continue;
        }
        uint64_t cur = guest_iov[i].iov_base;
        uint64_t remaining = guest_iov[i].iov_len;
        while (remaining > 0) {
            uint64_t chunk;
            void *base;
            if (required_perms == MEM_PERM_R) {
                if (resolve_host_read_chunk(g, cur, remaining, &base, &chunk) <
                    0) {
                    free(heap);
                    return -LINUX_EFAULT;
                }
            } else {
                uint64_t avail = 0;
                base =
                    guest_ptr_bound(g, cur, &avail, required_perms, remaining);
                if (!base) {
                    free(heap);
                    return -LINUX_EFAULT;
                }
                chunk = remaining < avail ? remaining : avail;
            }
            if (!base) {
                free(heap);
                return -LINUX_EFAULT;
            }
            int append = host_iov_append(buf, base, (size_t) chunk);
            if (append < 0) {
                free(heap);
                return -LINUX_ENOMEM;
            }
            if (append > 0) {
                needs_bounce = true;
                break;
            }
            cur += chunk;
            remaining -= chunk;
            if (required_perms != MEM_PERM_R)
                break;
        }
        if (remaining > 0)
            break;
    }
    if (needs_bounce) {
        size_t total = 0;
        for (int i = 0; i < iovcnt; i++) {
            if (guest_iov[i].iov_len > (uint64_t) SSIZE_MAX - total) {
                free(heap);
                return -LINUX_EINVAL;
            }
            total += (size_t) guest_iov[i].iov_len;
        }
        uint8_t *bounce = host_iov_alloc_bounce(buf, total);
        if (!bounce) {
            free(heap);
            return -LINUX_ENOMEM;
        }
        size_t copied = 0;
        for (int i = 0; i < iovcnt; i++) {
            size_t len = (size_t) guest_iov[i].iov_len;
            if (len && guest_read(g, guest_iov[i].iov_base, bounce + copied,
                                  len) < 0) {
                free(heap);
                return -LINUX_EFAULT;
            }
            copied += len;
        }
    }
    free(heap);
    return 0;
}

int64_t host_iov_prepare(guest_t *g,
                         uint64_t iov_gva,
                         int iovcnt,
                         int required_perms,
                         host_iov_buf_t *buf)
{
    host_iov_init(buf);

    if (iovcnt <= 0 || iovcnt > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;

    int64_t err = build_host_iov(g, iov_gva, iovcnt, buf, required_perms);
    if (err < 0) {
        host_iov_free(buf);
        return err;
    }

    return 0;
}

int64_t host_iov_prepare_msg(guest_t *g,
                             uint64_t iov_gva,
                             int iovcnt,
                             int required_perms,
                             host_iov_buf_t *buf)
{
    if (iovcnt == 0) {
        host_iov_init(buf);
        return 0;
    }
    return host_iov_prepare(g, iov_gva, iovcnt, required_perms, buf);
}

int64_t host_iov_prepare_read_range(guest_t *g,
                                    uint64_t gva,
                                    uint64_t length,
                                    host_iov_buf_t *buf)
{
    host_iov_init(buf);
    if (length == 0)
        return 0;
    uint64_t cur = gva, remaining = length;
    bool needs_bounce = false;
    while (remaining > 0) {
        uint64_t chunk;
        void *base;
        if (resolve_host_read_chunk(g, cur, remaining, &base, &chunk) < 0)
            return -LINUX_EFAULT;
        int append = host_iov_append(buf, base, (size_t) chunk);
        if (append < 0) {
            host_iov_free(buf);
            return -LINUX_ENOMEM;
        }
        if (append > 0) {
            needs_bounce = true;
            break;
        }
        cur += chunk;
        remaining -= chunk;
    }
    if (needs_bounce) {
        if (length > SSIZE_MAX) {
            host_iov_free(buf);
            return -LINUX_EINVAL;
        }
        void *bounce = host_iov_alloc_bounce(buf, (size_t) length);
        if (!bounce) {
            host_iov_free(buf);
            return -LINUX_ENOMEM;
        }
        if (guest_read(g, gva, bounce, (size_t) length) < 0) {
            host_iov_free(buf);
            return -LINUX_EFAULT;
        }
    }
    return 0;
}

void host_iov_free(host_iov_buf_t *buf)
{
    free(buf->heap);
    free(buf->bounce);
    buf->heap = NULL;
    buf->bounce = NULL;
    buf->iov = NULL;
    buf->iovcnt = 0;
    buf->capacity = 0;
}

static int64_t single_guest_iov(guest_t *g,
                                uint64_t iov_gva,
                                linux_iovec_t *iov)
{
    if (guest_read_small(g, iov_gva, iov, sizeof(*iov)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

/* Linux returns 0 for zero-iovcnt vector I/O once the fd validates:
 * import_iovec() yields an empty iterator and do_iter_read/do_iter_write return
 * before the file offset is touched, so even pwritev2(RWF_APPEND) leaves the
 * position alone. macOS readv/writev instead reject iovcnt == 0 with EINVAL, so
 * short-circuit before any host call -- the append path's SEEK_END would
 * otherwise move the shared offset. The iov pointer is not dereferenced (Linux
 * ignores it for an empty vector), and negative counts keep flowing into
 * host_iov_prepare's EINVAL.
 *
 * The checks Linux runs before its empty-vector return still apply, in this
 * order: the positional variants fail non-seekable files with ESPIPE
 * (FMODE_PREAD/FMODE_PWRITE in do_preadv/do_pwritev), and all variants fail
 * wrong-direction fds with EBADF (FMODE_READ/FMODE_WRITE in
 * do_iter_read/do_iter_write). Both are probed on the host fd, whose open mode
 * mirrors the guest's for host-backed types; fd_table linux_flags cannot be
 * used because pipe/socket entries only track CLOEXEC there. Virtual
 * multiplexed fds (eventfd/timerfd/signalfd/...) sit on host pipes or kqueues
 * whose mode says nothing about the guest-visible fd (the Linux anon-inode
 * equivalents are O_RDWR), so they validate existence only. No F_SEAL_WRITE
 * check: Linux never reaches the write path for an empty vector, so a
 * write-sealed memfd returns 0 here too.
 */
static int64_t vec_zero_iovcnt(int fd, bool op_is_write, bool positional)
{
    fd_entry_t snap;
    if (!fd_snapshot(fd, &snap) || snap.type == FD_PATH)
        return -LINUX_EBADF;

    bool host_mode_mirrors_guest =
        snap.type == FD_REGULAR || snap.type == FD_DIR ||
        snap.type == FD_PIPE || snap.type == FD_SOCKET ||
        snap.type == FD_STDIO || snap.type == FD_URANDOM;
    if (!host_mode_mirrors_guest)
        return 0;

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    int64_t ret = 0;
    if (positional && lseek(host_ref.fd, 0, SEEK_CUR) < 0 && errno == ESPIPE)
        ret = -LINUX_ESPIPE;
    if (ret == 0) {
        int fl = fcntl(host_ref.fd, F_GETFL);
        int accmode = fl >= 0 ? (fl & O_ACCMODE) : O_RDWR;
        if (op_is_write ? accmode == O_RDONLY : accmode == O_WRONLY)
            ret = -LINUX_EBADF;
    }
    host_fd_ref_close(&host_ref);
    return ret;
}

int64_t sys_readv(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 0)
        return vec_zero_iovcnt(fd, false, false);
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        if (fd_get_type(fd) == FD_URANDOM &&
            giov.iov_len > (uint64_t) SSIZE_MAX) {
            err = urandom_check_readable(fd);
            if (err < 0)
                return err;
            return -LINUX_EINVAL;
        }
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types need their custom read handlers because glibc may use
     * readv() instead of read() for the same logical operation. Delegate scalar
     * special fds to the first iov entry's buffer. Use the first iov's length
     * (not the sum of all iovs) because the data goes into giov[0].iov_base
     * which is only giov[0].iov_len bytes long.
     */
    int type = fd_get_type(fd);
    if (type == FD_URANDOM) {
        int64_t err = urandom_check_readable(fd);
        if (err < 0)
            return err;
        err = validate_iov_total(g, iov_gva, iovcnt);
        if (err < 0)
            return err;
        host_iov_buf_t host_iov;
        err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
        if (err < 0)
            return err;
        int64_t ret = urandom_fill_iov(fd, host_iov.iov, host_iov.iovcnt);
        host_iov_free(&host_iov);
        /* Mirror sys_read's slow-path refill so a readv consumer that drains
         * the shim ring leaves it ready for the next call, instead of forcing
         * every subsequent EL1 fast-path attempt back through HVC until some
         * other path triggers a refill.
         */
        shim_globals_refill_urandom_ring(g);
        return ret;
    }
    if (type == FD_EVENTFD || type == FD_SIGNALFD || type == FD_TIMERFD ||
        type == FD_INOTIFY) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;
        /* Use guest_read for the iov array since guest_ptr alone is unsafe if
         * the array spans a 2MiB block boundary.
         */
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }
    if (!host_iov_has_payload(&host_iov)) {
        err = io_check_access(host_ref.fd, POLLIN);
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return err < 0 ? err : 0;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_readv_intercept(
            fd, host_ref.fd, host_iov.iov, host_iov.iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    int64_t rwait = io_block_wait(fd, host_ref.fd, POLLIN);
    if (rwait < 0) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return rwait;
    }

    ssize_t ret = readv(host_ref.fd, host_iov.iov, host_iov.iovcnt);
    int64_t result = ret < 0 ? linux_errno() : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_writev(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 0)
        return vec_zero_iovcnt(fd, true, false);
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_write(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types: glibc may use writev() for eventfd wakeup writes.
     * Delegate using the first iov entry. Use giov.iov_len (not the sum of all
     * iovs) because the data is at giov.iov_base which is only giov.iov_len
     * bytes. eventfd expects exactly 8 bytes.
     */
    if (fd_get_type(fd) == FD_EVENTFD) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return eventfd_write(fd, g, giov.iov_base, giov.iov_len);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }
    if (!host_iov_has_payload(&host_iov)) {
        err = io_check_access(host_ref.fd, POLLOUT);
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return err < 0 ? err : 0;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_writev_intercept(
            fd, host_ref.fd, host_iov.iov, host_iov.iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    int64_t wwait = io_block_wait(fd, host_ref.fd, POLLOUT);
    if (wwait < 0) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return wwait;
    }

    ssize_t ret = writev(host_ref.fd, host_iov.iov, host_iov.iovcnt);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_preadv(guest_t *g,
                   int fd,
                   uint64_t iov_gva,
                   int iovcnt,
                   int64_t offset)
{
    if (iovcnt == 0) {
        /* do_preadv rejects a negative offset before looking up the fd, so
         * EINVAL outranks EBADF here; nonzero counts keep getting EINVAL from
         * the host preadv instead.
         */
        if (offset < 0)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, false, true);
    }
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pread64(g, fd, giov.iov_base, giov.iov_len, offset);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_readv_intercept(
        fd, host_ref.fd, host_iov.iov, host_iov.iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = preadv(host_ref.fd, host_iov.iov, host_iov.iovcnt, offset);
    int64_t result = ret < 0 ? linux_errno() : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_pwritev(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset)
{
    if (iovcnt == 0) {
        /* Same ordering as sys_preadv: negative offset EINVAL first. */
        if (offset < 0)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, true, true);
    }
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pwrite64(g, fd, giov.iov_base, giov.iov_len, offset);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_writev_intercept(
        fd, host_ref.fd, host_iov.iov, host_iov.iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwritev(host_ref.fd, host_iov.iov, host_iov.iovcnt, offset);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

static int64_t sys_pwritev_append(guest_t *g,
                                  int fd,
                                  uint64_t iov_gva,
                                  int iovcnt,
                                  bool update_file_offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    ssize_t ret;
    if (update_file_offset) {
        if (lseek(host_ref.fd, 0, SEEK_END) < 0) {
            ret = -1;
        } else {
            ret = writev(host_ref.fd, host_iov.iov, host_iov.iovcnt);
        }
    } else {
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            ret = -1;
        } else {
            ret =
                pwritev(host_ref.fd, host_iov.iov, host_iov.iovcnt, st.st_size);
        }
    }

    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

/* Linux RWF_* flags for preadv2/pwritev2 (include/uapi/linux/fs.h) */
#define RWF_HIPRI 0x00000001  /* High priority hint (best-effort) */
#define RWF_DSYNC 0x00000002  /* Per-I/O data integrity sync */
#define RWF_SYNC 0x00000004   /* Per-I/O file integrity sync */
#define RWF_NOWAIT 0x00000008 /* Nonblocking hint (best-effort) */
#define RWF_APPEND 0x00000010 /* Append mode (pwritev2 only) */
#define RWF_SUPPORTED \
    (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND)

int64_t sys_preadv2(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset,
                    int flags)
{
    /* Linux validates RWF flags only once the write/read actually proceeds
     * (kiocb_set_rw_flags sits behind the empty-vector return in
     * do_iter_read/do_iter_write), so an empty vector short-circuits before the
     * flag checks. Offset -1 selects do_readv (no seekability check); any other
     * negative offset fails EINVAL before the fd lookup.
     */
    if (iovcnt == 0) {
        if (offset < -1)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, false, offset != -1);
    }
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    if (flags & RWF_APPEND)
        return -LINUX_EINVAL; /* RWF_APPEND is write-only */
    /* RWF_HIPRI, RWF_NOWAIT: best-effort hints, safe to ignore. RWF_DSYNC,
     * RWF_SYNC: no effect on reads.
     */
    if (offset == -1)
        return sys_readv(g, fd, iov_gva, iovcnt);
    return sys_preadv(g, fd, iov_gva, iovcnt, offset);
}

int64_t sys_pwritev2(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     int iovcnt,
                     int64_t offset,
                     int flags)
{
    /* Same ordering as sys_preadv2: empty vectors return before RWF flag
     * validation, which also keeps RWF_APPEND from moving the offset.
     */
    if (iovcnt == 0) {
        if (offset < -1)
            return -LINUX_EINVAL;
        return vec_zero_iovcnt(fd, true, offset != -1);
    }
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    int64_t r;
    if (flags & RWF_APPEND)
        r = sys_pwritev_append(g, fd, iov_gva, iovcnt, offset == -1);
    else if (offset == -1)
        r = sys_writev(g, fd, iov_gva, iovcnt);
    else
        r = sys_pwritev(g, fd, iov_gva, iovcnt, offset);
    /* RWF_SYNC/RWF_DSYNC: sync after successful write */
    if (r > 0 && (flags & (RWF_SYNC | RWF_DSYNC))) {
        host_fd_ref_t host_ref;
        if (host_fd_ref_open_regular_io(fd, &host_ref) == 0) {
            fsync(host_ref.fd);
            host_fd_ref_close(&host_ref);
        }
    }
    return r;
}

/* terminal I/O. */

int64_t sys_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    /* FIOCLEX/FIONCLEX are the ioctl form of fcntl(F_SETFD): they set/clear the
     * guest close-on-exec flag, which lives in fd_table linux_flags (not the
     * host fd's FD_CLOEXEC, which is per-descriptor and would be lost on the
     * dup that host_fd_ref hands multi-threaded callers, so mirror the F_SETFD
     * path in sys_fcntl). They need no host fd, so dispatch them before
     * host_fd_ref_open_regular_io(): that helper rejects O_PATH (FD_PATH) fds
     * with EBADF, but Linux allows these ioctls -- like fcntl(F_SETFD) -- on
     * O_PATH descriptors. Validate the slot and mutate the flag in a single
     * fd_lock section so there is no validate-then-mutate window in which a
     * concurrent close/reuse could flip CLOEXEC on a different file that took
     * the slot. The arg is ignored.
     */
    if (request == LINUX_FIOCLEX || request == LINUX_FIONCLEX) {
        if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
            return -LINUX_EBADF;
        pthread_mutex_lock(&fd_lock);
        if (fd_table[fd].type == FD_CLOSED) {
            pthread_mutex_unlock(&fd_lock);
            return -LINUX_EBADF;
        }
        if (request == LINUX_FIOCLEX)
            fd_table[fd].linux_flags |= LINUX_O_CLOEXEC;
        else
            fd_table[fd].linux_flags &= ~LINUX_O_CLOEXEC;
        pthread_mutex_unlock(&fd_lock);
        return 0;
    }

    if (request == LINUX_SIOCGIFHWADDR) {
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_PATH)
            return -LINUX_EBADF;
        if (snap.type != FD_SOCKET)
            return -LINUX_ENOTTY;
        return linux_siocgifhwaddr(g, arg);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;
    int host_fd = host_ref.fd;

    /* Rosetta's Virtualization.framework probe ioctls are issued on the
     * /proc/self/exe launcher fd very early at startup. Gate on that actual
     * host file rather than on every fd in a Rosetta guest, but do not key on
     * ROSETTA_PATH itself: the probe is against the launcher, not the
     * translator image.
     */
    if (rosetta_vz_request(request) && rosetta_ioctl_target_fd(g, host_fd)) {
        int64_t r = rosetta_vz_ioctl(g, request, arg);
        host_fd_ref_close(&host_ref);
        return r;
    }

    switch (request) {
    case LINUX_TIOCSPGRP: {
        /* Set foreground process group for controlling terminal. */
        int32_t pgrp = 0;
        host_fd_ref_close(&host_ref);
        if (guest_read_small(g, arg, &pgrp, sizeof(pgrp)) < 0)
            return -LINUX_EFAULT;
        proc_set_fg_pgrp((int64_t) pgrp);
        return 0;
    }
    case LINUX_TIOCSCTTY:
        /* Set controlling terminal.  arg is a flag (usually 0). */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(1);
        return 0;
    case LINUX_TIOCNOTTY:
        /* Detach from controlling terminal. */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(0);
        return 0;
    case LINUX_TIOCGSID: {
        /* Get session ID of the controlling terminal. */
        int32_t val = (int32_t) proc_get_sid();
        host_fd_ref_close(&host_ref);
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    case LINUX_TIOCGWINSZ: {
        /* Get terminal window size */
        (void) proc_pty_master_adopt(fd);
        struct winsize ws;
        if (ioctl(host_fd, TIOCGWINSZ, &ws) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_winsize_t lws = {
            .ws_row = ws.ws_row,
            .ws_col = ws.ws_col,
            .ws_xpixel = ws.ws_xpixel,
            .ws_ypixel = ws.ws_ypixel,
        };
        if (guest_write_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case LINUX_TIOCSWINSZ: {
        /* Set terminal window size. Same struct as TIOCGWINSZ; foot, sshd,
         * tmux, and any libvte-derived emulator call this on the PTY master
         * after spawning the slave child. Without it, terminal startup fails
         * with -ENOTTY from the default arm below.
         *
         * A master received through SCM_RIGHTS bypasses /dev/ptmx open
         * interception, so lazily create its keepalive before the host ioctl.
         * The helper is a no-op for non-pty fds; the real ioctl below still
         * supplies the final errno.
         */
        linux_winsize_t lws;
        if (guest_read_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct winsize ws = {
            .ws_row = lws.ws_row,
            .ws_col = lws.ws_col,
            .ws_xpixel = lws.ws_xpixel,
            .ws_ypixel = lws.ws_ypixel,
        };
        (void) proc_pty_master_adopt(fd);
        int rc = ioctl(host_fd, TIOCSWINSZ, &ws);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TCGETS: {
        /* Get terminal attributes. c_cc index mapping is in file-scope
         * linux_mac_cc[].
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios_t lt = {0};
        lt.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt.c_oflag = mac_oflag_to_linux(t.c_oflag);
        lt.c_cflag = mac_cflag_to_linux(t.c_cflag);
        lt.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt.c_cc, t.c_cc);
        if (guest_write_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS:
    case LINUX_TCSETSW:
    case LINUX_TCSETSF: {
        linux_termios_t lt;
        if (guest_read_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY; /* Not a terminal */
        }
        t.c_iflag = linux_iflag_to_mac(lt.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt.c_cc);
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCGETS2: {
        /* termios2 variant: same as TCGETS but with c_ispeed/c_ospeed. Set
         * BOTHER in c_cflag so the guest uses the numeric speed fields rather
         * than decoding CBAUD (which mac_cflag_to_linux drops).
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios2_t lt2 = {0};
        lt2.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt2.c_oflag = mac_oflag_to_linux(t.c_oflag);
        lt2.c_cflag = mac_cflag_to_linux(t.c_cflag) | LINUX_BOTHER;
        lt2.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt2.c_cc, t.c_cc);
        lt2.c_ispeed = (uint32_t) cfgetispeed(&t);
        lt2.c_ospeed = (uint32_t) cfgetospeed(&t);
        if (guest_write_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS2:
    case LINUX_TCSETSW2:
    case LINUX_TCSETSF2: {
        /* termios2 set: decode CBAUD for standard rates, use c_ispeed/ c_ospeed
         * when BOTHER is set.
         */
        linux_termios2_t lt2;
        if (guest_read_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        t.c_iflag = linux_iflag_to_mac(lt2.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt2.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt2.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt2.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt2.c_cc);
        /* Resolve baud rate: BOTHER means use numeric c_ispeed/c_ospeed;
         * otherwise decode the standard CBAUD index to a numeric rate.
         */
        uint32_t cbaud = lt2.c_cflag & LINUX_CBAUD;
        speed_t ispeed, ospeed;
        if (cbaud == LINUX_BOTHER) {
            ispeed = (speed_t) lt2.c_ispeed;
            ospeed = (speed_t) lt2.c_ospeed;
        } else {
            speed_t rate = linux_cbaud_to_speed(cbaud);
            ispeed = rate;
            ospeed = rate;
        }
        if (cfsetispeed(&t, ispeed) < 0 || cfsetospeed(&t, ospeed) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCGPGRP: {
        /* Get foreground process group from guest state. */
        host_fd_ref_close(&host_ref);
        int32_t val = (int32_t) proc_get_fg_pgrp();
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_FIONREAD: {
        /* Get bytes available for reading */
        int avail = 0;
        if (ioctl(host_fd, FIONREAD, &avail) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int32_t val = (int32_t) avail;
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCGPTN: {
        /* Get the slave pty number associated with a /dev/ptmx master fd. Pass
         * the guest fd: proc_pty_master_adopt snapshots the canonical (host_fd,
         * generation) under fd_lock, performs the slave open on a private dup,
         * then re-validates the slot before publishing the keepalive. Passing
         * the per-syscall host_fd_ref dup or a raw host fd would race with
         * sibling close+reuse.
         */
        uint32_t val = proc_pty_master_adopt(fd);
        if (val == UINT32_MAX) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_FIOASYNC: {
        /* Set/clear O_ASYNC (SIGIO-driven I/O). This is the ioctl form of
         * fcntl(F_SETFL, O_ASYNC): unify both onto the same armed bit and
         * kqueue watcher (asyncio.c) so the two entry points cannot drift.
         * Snapshot only for the slot generation; asyncio_apply rescans under
         * fd_lock for each alias's backing fd and class.
         */
        int32_t on = 0;
        if (guest_read_small(g, arg, &on, sizeof(on)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        fd_entry_t snap;
        if (!fd_snapshot(fd, &snap)) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EBADF;
        }
        asyncio_apply(fd, snap.generation, on != 0);
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCSPTLCK: {
        /* Lock/unlock the slave side of a pty. glibc unlockpt() always passes 0
         * (unlock); util-linux's setlock(1) passes 1 to lock. macOS exposes
         * unlockpt(3) but no re-lock primitive, so the lock branch is accepted
         * as a best-effort no-op for real ptmx masters rather than surfacing as
         * -EINVAL: an application probing the result would otherwise misread
         * the failure as "this kernel has no devpts".
         */
        int32_t lock = 0;
        if (guest_read_small(g, arg, &lock, sizeof(lock)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int rc = 0;
        if (lock == 0) {
            rc = unlockpt(host_fd);
        } else {
            char slave[64];
            if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_ENOTTY;
            }
        }
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }
    case LINUX_TIOCGPTPEER: {
        /* Return a fresh fd referring to the slave side of a /dev/ptmx master.
         * Linux added this in 4.13 so callers can avoid the ptsname(3) round
         * trip and any /dev/pts visibility races. The arg holds open(2)-style
         * flags. Restrict to the bits Linux's pty driver actually honors
         * (accmode + O_NOCTTY + O_NONBLOCK + O_CLOEXEC); any other bit, in
         * particular O_CREAT / O_TRUNC / O_EXCL / O_PATH, would be silently
         * ignored on Linux and is rejected with EINVAL here so misuse does not
         * leak nonsense flags into the guest fd table.
         */
        int linux_flags = (int) arg;
        const int allowed = LINUX_O_ACCMODE | LINUX_O_NOCTTY |
                            LINUX_O_NONBLOCK | LINUX_O_CLOEXEC;
        if (linux_flags & ~allowed) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        char slave[64];
        if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        int oflags = translate_open_flags(linux_flags);
        int host_slave_fd = open(slave, oflags);
        if (host_slave_fd < 0) {
            int saved_errno = errno;
            host_fd_ref_close(&host_ref);
            errno = saved_errno;
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        int guest_fd = fd_alloc(FD_REGULAR, host_slave_fd, NULL);
        if (guest_fd < 0) {
            close(host_slave_fd);
            return -LINUX_EMFILE;
        }
        /* Track CLOEXEC + accmode in the guest table so exec honors them; the
         * host fd's own FD_CLOEXEC is per-descriptor and would be lost on the
         * dup that host_fd_ref hands multi-threaded callers.
         */
        fd_publish_linux_flags(guest_fd, linux_flags);
        return guest_fd;
    }

    case LINUX_FIONBIO: {
        /* Set/clear O_NONBLOCK on the fd. Linux FIONBIO takes an int* arg:
         * nonzero enables non-blocking, zero disables it. libuv's
         * uv__nonblock_ioctl() (its default on Linux) issues this on pipe and
         * socket fds at setup; without it the guest's uv_pipe_open() fails with
         * ENOTTY and Node's stdio stream construction throws.
         */
        int32_t on = 0;
        if (guest_read_small(g, arg, &on, sizeof(on)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int flags = fcntl(host_fd, F_GETFL);
        if (flags < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        int r = fcntl(host_fd, F_SETFL, flags);
        host_fd_ref_close(&host_ref);
        return r < 0 ? linux_errno() : 0;
    }

    default:
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOTTY;
    }
}

/* file space/copy. */

int64_t sys_fallocate(int fd, int mode, int64_t offset, int64_t len)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux validates offset >= 0 and len > 0 */
    if (offset < 0 || len <= 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }

    /* FALLOC_FL_PUNCH_HOLE always requires FALLOC_FL_KEEP_SIZE on Linux; map
     * both to macOS F_PUNCHHOLE on the host fd, with a pwrite-zeros fallback
     * for misalignment.
     *
     * The Linux semantic is "reads in [offset, offset+len) return zero; file
     * size unchanged". macOS F_PUNCHHOLE enforces filesystem block alignment on
     * both ends and rejects sub-block requests with EINVAL -- that one-byte
     * probe (offset=0 len=1) foot's wl_shm pool issues surfaces as
     * "fallocate(FALLOC_FL_PUNCH_HOLE) not supported (Invalid argument)"
     * otherwise, and foot disables punch-hole for the whole session.
     *
     * Writing zeros over the region produces the same observable result: reads
     * return zero, file size unchanged. The disk-space deallocation
     * optimisation is lost on the pwrite path, but the probe succeeds, so foot
     * keeps punch-hole enabled and the later, properly aligned calls
     * (page-sized buffers) still take the F_PUNCHHOLE fast path.
     */
    const int kPunchHole =
        LINUX_FALLOC_FL_PUNCH_HOLE | LINUX_FALLOC_FL_KEEP_SIZE;
    if (mode == kPunchHole) {
        struct fpunchhole hole = {
            .fp_flags = 0,
            .reserved = 0,
            .fp_offset = (off_t) offset,
            .fp_length = (off_t) len,
        };
        if (fcntl(host_ref.fd, F_PUNCHHOLE, &hole) == 0) {
            host_fd_ref_close(&host_ref);
            return 0;
        }
        /* EINVAL: misaligned, sub-block, or non-regular file. pwrite zeros only
         * through the current EOF so KEEP_SIZE remains guest-visible. Any other
         * host errno propagates verbatim.
         */
        if (errno != EINVAL) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        if (offset >= st.st_size) {
            host_fd_ref_close(&host_ref);
            return 0;
        }
        int64_t remaining = st.st_size - offset;
        if (remaining > len)
            remaining = len;

        static const char zeros[4096];
        off_t cur = (off_t) offset;
        while (remaining > 0) {
            size_t chunk = remaining > (int64_t) sizeof(zeros)
                               ? sizeof(zeros)
                               : (size_t) remaining;
            ssize_t nw = pwrite(host_ref.fd, zeros, chunk, cur);
            if (nw < 0) {
                if (errno == EINTR)
                    continue;
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }
            if (nw == 0)
                break; /* defensive; pwrite on a regular file should not 0 */
            cur += nw;
            remaining -= nw;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    /* mode 0 = basic allocation -> ftruncate fallback. Anything else (collapse
     * range, zero range, insert range, unshare range) stays unsupported and
     * surfaces as -EOPNOTSUPP for the guest to handle.
     */
    if (mode != 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    struct stat st;
    if (fstat(host_ref.fd, &st) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* Extend file if needed (ftruncate only extends, does not shrink) */
    int64_t new_size = offset + len;
    if (new_size < offset) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFBIG; /* Overflow check */
    }
    if (new_size > st.st_size) {
        if (ftruncate(host_ref.fd, new_size) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

/* Scratch buffer size for the file-copy syscall emulations. Heap-allocated per
 * call rather than placed on the stack: guest threads run on host pthreads
 * whose stacks are far smaller than a 64KiB frame would tolerate.
 */
#define IO_COPY_BUF_SIZE (64 * 1024)

/* Chunked read/write copy shared by sendfile and copy_file_range. Reads from
 * in_hfd (honoring proc_try_chunk_read_intercept for /proc-backed guest fd
 * in_gfd) and writes to out_hfd. A non-negative *off_in / *off_out selects
 * pread/pwrite at that offset and is advanced by the bytes moved; -1 selects
 * read/write against the fd's own position. Queues SIGPIPE on EPIPE. Stops on
 * EOF or short write.
 *
 * Returns the byte count moved, or a negative Linux errno only when the very
 * first read or write failed (partial transfers report the count so the caller
 * can still write offsets back).
 */
static int64_t copy_fd_range(int in_gfd,
                             int in_hfd,
                             int out_hfd,
                             int64_t *off_in,
                             int64_t *off_out,
                             uint64_t len)
{
    char *buf = malloc(IO_COPY_BUF_SIZE);
    if (!buf)
        return -LINUX_ENOMEM;

    size_t total = 0, remaining = len;
    int64_t ret;
    while (remaining > 0) {
        size_t chunk =
            remaining > IO_COPY_BUF_SIZE ? IO_COPY_BUF_SIZE : remaining;
        ssize_t nr;
        if (*off_in >= 0) {
            int64_t intercepted = proc_try_chunk_read_intercept(
                in_gfd, in_hfd, buf, chunk, *off_in, 1);
            nr = (intercepted != INT64_MIN)
                     ? intercepted
                     : pread(in_hfd, buf, chunk, *off_in);
        } else {
            int64_t intercepted =
                proc_try_chunk_read_intercept(in_gfd, in_hfd, buf, chunk, 0, 0);
            nr = (intercepted != INT64_MIN) ? intercepted
                                            : read(in_hfd, buf, chunk);
        }
        if (nr < 0) {
            ret = total > 0 ? (int64_t) total : linux_errno();
            goto done;
        }
        if (nr == 0)
            break; /* EOF */

        ssize_t nw = (*off_out >= 0) ? pwrite(out_hfd, buf, nr, *off_out)
                                     : write(out_hfd, buf, nr);
        if (nw < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            ret = total > 0 ? (int64_t) total : linux_errno();
            goto done;
        }

        total += nw;
        remaining -= nw;
        if (*off_in >= 0)
            *off_in += nw;
        if (*off_out >= 0)
            *off_out += nw;
        if (nw < nr) {
            /* Short write. For position-based input, read() already consumed
             * all nr bytes but only nw were sent, so rewind the input fd by the
             * unsent nr - nw so a later call re-reads them. Linux advances the
             * input only by bytes actually transferred. For offset-based input,
             * pread left the position untouched and off_in advanced by nw only,
             * so there is nothing to undo. Best-effort: a non-seekable input
             * (which sendfile/copy_file_range do not accept) simply keeps the
             * prior behavior.
             */
            if (*off_in < 0)
                (void) lseek(in_hfd, (off_t) (nw - nr), SEEK_CUR);
            break;
        }
    }
    ret = (int64_t) total;

done:
    free(buf);
    return ret;
}

int64_t sys_sendfile(guest_t *g,
                     int out_fd,
                     int in_fd,
                     uint64_t offset_gva,
                     uint64_t count)
{
    host_fd_ref_t out_ref, in_ref;
    int64_t err = host_fd_ref_open_regular_io(out_fd, &out_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(in_fd, &in_ref);
    if (err < 0) {
        host_fd_ref_close(&out_ref);
        return err;
    }

    /* macOS sendfile() requires a socket destination, so sendfile emulation
     * uses a pread/write loop for general file-to-file copies.
     */
    int64_t offset = -1;
    if (offset_gva != 0) {
        if (guest_read_small(g, offset_gva, &offset, sizeof(offset)) < 0) {
            err = -LINUX_EFAULT;
            goto out_sendfile;
        }
        if (offset < 0) {
            err = -LINUX_EINVAL;
            goto out_sendfile;
        }
    }

    /* sendfile has no output offset, so out always uses write(). */
    int64_t off_out = -1;
    int64_t moved =
        copy_fd_range(in_fd, in_ref.fd, out_ref.fd, &offset, &off_out, count);
    if (moved < 0) {
        err = moved;
        goto out_sendfile;
    }
    size_t total = (size_t) moved;

    /* Write back updated offset (even on partial transfer). Preserve partial
     * success: if bytes were transferred but offset writeback fails, return the
     * count rather than -EFAULT.
     */
    if (offset_gva != 0) {
        if (guest_write_small(g, offset_gva, &offset, sizeof(offset)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_sendfile:
    host_fd_ref_close(&in_ref);
    host_fd_ref_close(&out_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

int64_t sys_copy_file_range(guest_t *g,
                            int fd_in,
                            uint64_t off_in_gva,
                            int fd_out,
                            uint64_t off_out_gva,
                            uint64_t len,
                            unsigned int flags)
{
    /* Linux reserves flags for future use and rejects any nonzero value. */
    if (flags != 0)
        return -LINUX_EINVAL;

    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Read optional offsets from guest memory */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva != 0) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }
    if (off_out_gva != 0) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }

    /* Emulate with a pread/pwrite loop. */
    int64_t moved =
        copy_fd_range(fd_in, in_ref.fd, out_ref.fd, &off_in, &off_out, len);
    if (moved < 0) {
        err = moved;
        goto out_copy_file_range;
    }
    size_t total = (size_t) moved;

    /* Write back updated offsets (even on partial transfer). Preserve partial
     * success on writeback failure.
     */
    if (off_in_gva != 0) {
        if (guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }
    if (off_out_gva != 0) {
        if (guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_copy_file_range:
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

/* splice/tee. */

/* splice: emulate by reading from in_fd and writing to out_fd */
int64_t sys_splice(guest_t *g,
                   int fd_in,
                   uint64_t off_in_gva,
                   int fd_out,
                   uint64_t off_out_gva,
                   size_t len,
                   unsigned int flags)
{
    (void) flags;
    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Handle offsets */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }
    if (off_out_gva) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }

    /* Emulate with a read/write loop over a heap buffer. splice fully drains
     * each read chunk (inner write loop) rather than stopping on a short write,
     * so it does not share copy_fd_range.
     */
    uint8_t *buf = malloc(IO_COPY_BUF_SIZE);
    if (!buf) {
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return -LINUX_ENOMEM;
    }
    size_t chunk = len > IO_COPY_BUF_SIZE ? IO_COPY_BUF_SIZE : len;

    size_t total = 0;
    int saved_errno = 0;   /* Preserve errno across guest_write */
    bool rw_error = false; /* Track whether read or write failed */
    int64_t ret;
    while (total < len) {
        size_t n = (len - total) > chunk ? chunk : (len - total);
        ssize_t r = (off_in >= 0) ? pread(in_ref.fd, buf, n, off_in)
                                  : read(in_ref.fd, buf, n);
        if (r < 0) {
            rw_error = true;
            saved_errno = errno;
            break;
        }
        if (r == 0)
            break; /* EOF */
        if (off_in >= 0)
            off_in += r;

        size_t written = 0;
        while (written < (size_t) r) {
            ssize_t w =
                (off_out >= 0)
                    ? pwrite(out_ref.fd, buf + written, r - written, off_out)
                    : write(out_ref.fd, buf + written, r - written);
            if (w <= 0) {
                if (w < 0) {
                    rw_error = true;
                    saved_errno = errno;
                }
                if (w < 0 && saved_errno == EPIPE)
                    signal_queue(LINUX_SIGPIPE);
                total += written; /* Account for partial bytes written */
                /* Position-based input: read() consumed all r bytes but only
                 * written were moved, so rewind the input fd by r - written to
                 * match Linux advancing only by bytes transferred. Best-effort;
                 * a pipe input (common for splice) cannot seek and keeps the
                 * prior behavior. saved_errno is restored at done.
                 */
                if (off_in < 0 && written < (size_t) r)
                    (void) lseek(in_ref.fd, (off_t) ((ssize_t) written - r),
                                 SEEK_CUR);
                goto done;
            }
            written += w;
            if (off_out >= 0)
                off_out += w;
        }
        total += r;
    }

done:
    /* Write back updated offsets, then pick the return value. Preserve partial
     * transfer success: if bytes were already moved, return that count even
     * when an offset writeback faults (consistent with
     * sendfile/copy_file_range). A failed off_in writeback skips the off_out
     * writeback, matching the kernel.
     */
    if (off_in_gva && off_in >= 0 &&
        guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
        ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    } else if (off_out_gva && off_out >= 0 &&
               guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) <
                   0) {
        ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    } else if (total > 0) {
        ret = (int64_t) total;
    } else if (rw_error) {
        /* Restore saved_errno; the guest writes above may have clobbered it. */
        errno = saved_errno;
        ret = linux_errno();
    } else {
        ret = 0;
    }

    free(buf);
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    return ret;
}

/* vmsplice: emulate as writev to the pipe fd */
int64_t sys_vmsplice(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     unsigned long nr_segs,
                     unsigned int flags)
{
    (void) flags;
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;
    if (nr_segs > 1024) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL; /* UIO_MAXIOV */
    }

    size_t total = 0;
    for (unsigned long i = 0; i < nr_segs; i++) {
        linux_iovec_t liov;
        if (guest_read_small(g, iov_gva + i * sizeof(linux_iovec_t), &liov,
                             sizeof(liov)) < 0) {
            host_fd_ref_close(&host_ref);
            return total > 0 ? (int64_t) total : -LINUX_EFAULT;
        }

        if (liov.iov_len == 0)
            continue;
        host_iov_buf_t source;
        int64_t source_err = host_iov_prepare_read_range(g, liov.iov_base,
                                                         liov.iov_len, &source);
        if (source_err < 0)
            return host_fd_ref_close(&host_ref),
                   (total > 0 ? (int64_t) total : source_err);

        ssize_t w = writev(host_ref.fd, source.iov, source.iovcnt);
        if (w < 0) {
            host_iov_free(&source);
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            err = total > 0 ? (int64_t) total : linux_errno();
            host_fd_ref_close(&host_ref);
            return err;
        }
        size_t requested = 0;
        for (int j = 0; j < source.iovcnt; j++)
            requested += source.iov[j].iov_len;
        host_iov_free(&source);
        total += w;
        if ((size_t) w < requested)
            break;
    }

    host_fd_ref_close(&host_ref);
    return (int64_t) total;
}

/* tee: copy data between two pipes without consuming it. Full emulation would
 * need pipe peeking semantics that macOS does not expose; report EINVAL rather
 * than consuming data incorrectly.
 */
int64_t sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    (void) fd_in;
    (void) fd_out;
    (void) len;
    (void) flags;
    return -LINUX_EINVAL;
}
