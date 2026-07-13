/*
 * Socket/networking syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Translates Linux aarch64 socket syscalls into macOS equivalents. Key
 * differences handled:
 *   - Address families: Linux AF_INET6=10, macOS AF_INET6=30
 *   - sockaddr layout: macOS has sa_len byte, Linux does not
 *   - Socket type flags: Linux packs SOCK_NONBLOCK/SOCK_CLOEXEC into type
 *   - Socket options: SOL_SOCKET option constants differ
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

#include "core/rosetta.h"
#include "debug/log.h"
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/uio.h>

#include "syscall/internal.h"
#include "syscall/net.h"
#include "syscall/net-abi.h"
#include "syscall/net-absock.h"
#include "syscall/net-sockopt.h"
#include "syscall/proc.h"
#include "syscall/io.h"
#include "syscall/signal.h"

/* Linux MSG_OOB: urgent-data receive, never gated on readiness. */
#define LINUX_MSG_OOB 0x01
/* Linux MSG_DONTWAIT: recv/send skip the interruptible wait when set. */
#define LINUX_MSG_DONTWAIT 0x40

/* Wait for a blocking socket op (recv/accept/connect/send) to become ready or
 * be interrupted by a guest signal, so a vCPU thread parked in the host call
 * stays reachable by hv_vcpus_exit + the wakeup pipe. No-op for nonblocking fds
 * and for MSG_DONTWAIT callers. Pass msg_flags = 0 for ops with no flags
 * argument (accept, connect).
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR) to abort.
 */
int64_t net_wait_or_interrupted(int host_fd, short events, int msg_flags)
{
    if (msg_flags & LINUX_MSG_DONTWAIT)
        return 0;
    int fl = fcntl(host_fd, F_GETFL);
    if (fl < 0 || (fl & O_NONBLOCK))
        return 0;
    return io_wait_fd_or_interrupted(host_fd, events);
}

/* Linux clamps a socket receive's low-water target to one byte (sock_rcvlowat
 * returns v ?: 1), so a zero-payload recv/recvfrom/recvmsg on an empty socket
 * blocks -- or fails EAGAIN when nonblocking -- instead of returning 0 the way
 * the macOS host call does. (read() is the exception: sock_read_iter returns 0
 * for a zero count, so sys_read stays untouched.) Gate the host call on
 * readability: an interruptible wait for blocking callers, a zero-timeout
 * readiness probe for nonblocking ones. EOF counts as readable in both, and
 * the host call then returns 0 like Linux.
 *
 * Returns 0 to proceed or a negative Linux errno (EINTR/EAGAIN).
 */
int64_t net_recv_zero_payload_gate(int host_fd, int msg_flags)
{
    /* Linux's urgent-data receive path never waits for readiness: with no
     * urgent data queued, recv(MSG_OOB) fails EINVAL immediately whether the
     * socket blocks or not (tcp_recv_urg, unix_stream_recv_urg; verified on
     * 6.12). Pass straight to the host call, which fails the same way.
     */
    if (msg_flags & LINUX_MSG_OOB)
        return 0;
    if (sock_op_should_block(host_fd, msg_flags))
        return io_wait_fd_or_interrupted(host_fd, POLLIN);
    struct pollfd pfd = {.fd = host_fd, .events = POLLIN};
    int ready = poll(&pfd, 1, 0);
    if (ready < 0)
        return linux_errno();
    if (ready == 0)
        return -LINUX_EAGAIN;
    return 0;
}

/* True when a socket send/recv should wait interruptibly and retry rather than
 * surface EAGAIN: the guest asked for blocking semantics (no MSG_DONTWAIT, fd
 * not O_NONBLOCK). The send/recv paths probe with a per-call MSG_DONTWAIT and
 * loop on EAGAIN when this holds, so a post-readiness buffer-full/steal race
 * retries instead of parking the vCPU in an uninterruptible host call. Using
 * MSG_DONTWAIT rather than toggling the fd's O_NONBLOCK keeps the flag off the
 * shared open file description, so a sibling thread on the same fd is never hit
 * with a spurious EAGAIN.
 */
bool sock_op_should_block(int host_fd, int msg_flags)
{
    if (msg_flags & LINUX_MSG_DONTWAIT)
        return false;
    int fl = fcntl(host_fd, F_GETFL);
    return fl >= 0 && !(fl & O_NONBLOCK);
}

/* Drive an already-nonblocking connect to completion or interruption: start it,
 * wait for POLLOUT (or a guest signal), then read SO_ERROR.
 *
 * Returns 0 on success or a negative Linux errno. Assumes the caller set
 * O_NONBLOCK and will restore the original flags.
 */
static int64_t connect_nonblock_wait(int host_fd,
                                     const struct sockaddr *sa,
                                     socklen_t len)
{
    if (connect(host_fd, sa, len) == 0)
        return 0;
    if (errno != EINPROGRESS && errno != EINTR)
        return linux_errno();

    int64_t waited = io_wait_fd_or_interrupted(host_fd, POLLOUT);
    if (waited < 0)
        return waited; /* EINTR: connect continues in the background per Linux
                        */

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(host_fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0)
        soerr = errno;
    if (soerr) {
        errno = soerr;
        return linux_errno();
    }
    return 0;
}

/* Blocking connect that stays interruptible by a guest signal. Flips the socket
 * nonblocking, drives the connect via connect_nonblock_wait, and restores the
 * guest's file-status flags exactly once. A socket already in nonblocking mode,
 * or one that cannot be flipped, falls back to a plain connect (best-effort
 * interruptibility, never a lost connect); its EINPROGRESS surfaces unchanged.
 */
static int64_t connect_or_interrupted(int host_fd,
                                      const struct sockaddr *sa,
                                      socklen_t len)
{
    int fl = fcntl(host_fd, F_GETFL);
    bool blocking = fl >= 0 && !(fl & O_NONBLOCK);
    if (!blocking || fcntl(host_fd, F_SETFL, fl | O_NONBLOCK) < 0)
        return connect(host_fd, sa, len) < 0 ? linux_errno() : 0;

    int64_t result = connect_nonblock_wait(host_fd, sa, len);
    fcntl(host_fd, F_SETFL, fl);
    return result;
}

/* Syscall implementations. */

static bool rosetta_socket_shim_enabled(guest_t *g)
{
    if (!g || !g->is_rosetta)
        return false;

    size_t cmdline_len = 0;
    const char *cmdline = proc_get_cmdline(&cmdline_len);
    size_t rosetta_len = strlen(ROSETTA_PATH);

    return cmdline && cmdline_len > rosetta_len &&
           memcmp(cmdline, ROSETTA_PATH, rosetta_len + 1) == 0;
}

static bool rosettad_connect_target(const struct sockaddr_storage *mac_sa)
{
    if (!mac_sa || mac_sa->ss_family != AF_UNIX)
        return false;
    const struct sockaddr_un *sun = (const struct sockaddr_un *) mac_sa;
    return strcmp(sun->sun_path, ROSETTAD_SOCKET_PATH) == 0;
}

static bool rosetta_seqpacket_placeholder(guest_t *g, int guest_fd, int host_fd)
{
    int cached_type = 0;
    if (!rosetta_socket_shim_enabled(g) ||
        !net_socket_cached_int_get(guest_fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE,
                                   &cached_type) ||
        cached_type != LINUX_SOCK_SEQPACKET || rosettad_is_socket(host_fd))
        return false;

    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (getsockopt(host_fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) < 0)
        return false;

    return (so_type & 0xF) == SOCK_STREAM;
}

int64_t sys_socket(guest_t *g, int domain, int type, int protocol)
{
    /* AF_NETLINK: synthetic emulation, no macOS equivalent */
    if (domain == LINUX_AF_NETLINK)
        return netlink_socket(protocol, type);

    int mac_domain = translate_af_to_mac(domain);
    int real_type = extract_sock_type(type);
    int nonblock = extract_sock_nonblock(type);
    int cloexec = extract_sock_cloexec(type);

    int original_type = real_type;
    if (mac_domain == AF_UNIX && real_type == LINUX_SOCK_SEQPACKET) {
        real_type = SOCK_STREAM;
    }

    /* Rosetta opens AF_UNIX SOCK_SEQPACKET to talk to rosettad. macOS does not
     * support SOCK_SEQPACKET on AF_UNIX, so while the translator process is
     * active we create an unconnected SOCK_STREAM placeholder instead.
     * sys_connect() upgrades only the specific rosettad path to the private
     * socketpair/handler transport; any other connect on this placeholder fails
     * so unrelated Unix IPC is not silently downgraded to STREAM.
     */
    if (rosetta_socket_shim_enabled(g) && mac_domain == AF_UNIX &&
        original_type == LINUX_SOCK_SEQPACKET) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return linux_errno();
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        if ((nonblock && fd_set_nonblock(fd) < 0) ||
            (cloexec && fd_set_cloexec(fd) < 0)) {
            close(fd);
            return linux_errno();
        }

        int gfd = fd_alloc(FD_SOCKET, fd, absock_unregister_fd);
        if (gfd < 0) {
            close(fd);
            return -LINUX_EMFILE;
        }
        if (cloexec)
            fd_table[gfd].linux_flags |= LINUX_O_CLOEXEC;
        net_socket_cache_init_defaults(gfd, domain, original_type);
        return gfd;
    }

    int fd = socket(mac_domain, real_type, protocol);
    if (fd < 0)
        return linux_errno();

    /* Apply SOCK_NONBLOCK and SOCK_CLOEXEC */
    if ((nonblock && fd_set_nonblock(fd) < 0) ||
        (cloexec && fd_set_cloexec(fd) < 0)) {
        close(fd);
        return linux_errno();
    }

    /* Suppress SIGPIPE on this socket (macOS-specific) */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    int gfd = fd_alloc(FD_SOCKET, fd, absock_unregister_fd);
    if (gfd < 0) {
        close(fd);
        return -LINUX_EMFILE;
    }

    int linux_flags = 0;
    if (cloexec)
        linux_flags |= LINUX_O_CLOEXEC;
    fd_table[gfd].linux_flags = linux_flags;
    net_socket_cache_init_defaults(gfd, domain, original_type);

    return gfd;
}

int64_t sys_socketpair(guest_t *g,
                       int domain,
                       int type,
                       int protocol,
                       uint64_t sv_gva)
{
    int mac_domain = translate_af_to_mac(domain);
    int real_type = extract_sock_type(type);
    int nonblock = extract_sock_nonblock(type);
    int cloexec = extract_sock_cloexec(type);

    int original_type = real_type;
    if (mac_domain == AF_UNIX && real_type == LINUX_SOCK_SEQPACKET) {
        real_type = SOCK_DGRAM;
    }

    int fds[2];
    if (socketpair(mac_domain, real_type, protocol, fds) < 0)
        return linux_errno();

    /* Apply flags */
    for (int i = 0; i < 2; i++) {
        if ((nonblock && fd_set_nonblock(fds[i]) < 0) ||
            (cloexec && fd_set_cloexec(fds[i]) < 0)) {
            close(fds[0]);
            close(fds[1]);
            return linux_errno();
        }
        int one = 1;
        setsockopt(fds[i], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    }

    int gfd0 = fd_alloc(FD_SOCKET, fds[0], absock_unregister_fd);
    if (gfd0 < 0) {
        close(fds[0]);
        close(fds[1]);
        return -LINUX_EMFILE;
    }
    int gfd1 = fd_alloc(FD_SOCKET, fds[1], absock_unregister_fd);
    if (gfd1 < 0) {
        fd_mark_closed(gfd0);
        close(fds[0]);
        close(fds[1]);
        return -LINUX_EMFILE;
    }

    int linux_flags = cloexec ? LINUX_O_CLOEXEC : 0;
    fd_table[gfd0].linux_flags = linux_flags;
    fd_table[gfd1].linux_flags = linux_flags;
    net_socket_cache_init_defaults(gfd0, domain, original_type);
    net_socket_cache_init_defaults(gfd1, domain, original_type);

    int32_t guest_fds[2] = {gfd0, gfd1};
    if (guest_write_small(g, sv_gva, guest_fds, sizeof(guest_fds)) < 0) {
        fd_mark_closed(gfd0);
        close(fds[0]);
        fd_mark_closed(gfd1);
        close(fds[1]);
        return -LINUX_EFAULT;
    }

    return 0;
}

int64_t sys_bind(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen)
{
    /* Netlink sockets use synthetic fd; dispatch to netlink handler */
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_bind(fd, g, addr_gva, addrlen);

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    uint8_t linux_sa[128];
    if (addrlen > sizeof(linux_sa)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (guest_read(g, addr_gva, linux_sa, addrlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    struct sockaddr_storage mac_sa;
    int mac_len;

    /* Abstract Unix socket: rewrite to filesystem path */
    int absock_idx = -1;
    if (absock_is_abstract_unix(linux_sa, addrlen)) {
        absock_init_cleanup();
        int bind_len;
        absock_idx =
            absock_bind_prepare(linux_sa, addrlen, &mac_sa, fd, &bind_len);
        if (absock_idx == -2) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EADDRINUSE;
        }
        if (absock_idx < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        mac_len = bind_len;
    } else {
        mac_len = linux_to_mac_sockaddr(linux_sa, addrlen, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
    }

    if (bind(host_ref.fd, (struct sockaddr *) &mac_sa, (socklen_t) mac_len) <
        0) {
        if (absock_idx >= 0)
            absock_bind_rollback(absock_idx);
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    if (absock_idx >= 0)
        absock_bind_commit(absock_idx);

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_listen(int fd, int backlog)
{
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    if (listen(host_ref.fd, backlog) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    net_socket_cache_set_index(fd, SOCK_OPT_ACCEPTCONN, 1);
    return 0;
}

/* Shared implementation for accept and accept4. */
static int64_t do_accept(guest_t *g,
                         int fd,
                         uint64_t addr_gva,
                         uint64_t addrlen_gva,
                         int nonblock,
                         int cloexec)
{
    if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
        return -LINUX_EBADF;

    host_fd_ref_t host_ref = {.fd = -1, .owned = false};
    uint64_t listener_generation = 0;
    int listener_passcred_fallback = 0;
    int listener_type = FD_CLOSED;

    if (thread_is_single_active()) {
        if (host_fd_ref_open(fd, &host_ref) < 0)
            return -LINUX_EBADF;
        listener_type = fd_table[fd].type;
        listener_generation = fd_table[fd].generation;
        if (listener_type == FD_SOCKET)
            (void) sock_opt_get(&fd_table[fd], SOCK_OPT_PASSCRED,
                                &listener_passcred_fallback);
    } else {
        fd_entry_t listener_snap = {.type = FD_CLOSED};
        int host_fd = fd_snapshot_and_dup(fd, &listener_snap);
        if (host_fd < 0)
            return -LINUX_EBADF;
        host_ref.fd = host_fd;
        host_ref.owned = true;
        listener_type = listener_snap.type;
        listener_generation = listener_snap.generation;
        if (listener_type == FD_SOCKET)
            (void) sock_opt_get(&listener_snap, SOCK_OPT_PASSCRED,
                                &listener_passcred_fallback);
    }

    if (listener_type != FD_SOCKET) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOTSOCK;
    }

    int64_t waited = net_wait_or_interrupted(host_ref.fd, POLLIN, 0);
    if (waited < 0) {
        host_fd_ref_close(&host_ref);
        return waited;
    }

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    int new_fd = accept(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len);
    host_fd_ref_close(&host_ref);
    if (new_fd < 0)
        return linux_errno();

    int listener_passcred = listener_passcred_fallback;
    (void) net_socket_cached_int_get_if_generation(
        fd, listener_generation, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
        &listener_passcred);

    if ((nonblock && fd_set_nonblock(new_fd) < 0) ||
        (cloexec && fd_set_cloexec(new_fd) < 0)) {
        close(new_fd);
        return linux_errno();
    }

    int one = 1;
    setsockopt(new_fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    int gfd = fd_alloc(FD_SOCKET, new_fd, absock_unregister_fd);
    if (gfd < 0) {
        close(new_fd);
        return -LINUX_EMFILE;
    }
    fd_table[gfd].linux_flags = cloexec ? LINUX_O_CLOEXEC : 0;
    net_socket_cache_init_accept(gfd, listener_passcred);

    /* Write back peer address if requested. The accept has already succeeded
     * and gfd is valid; EFAULT here mirrors Linux kernel behavior (close the
     * new fd and return -EFAULT).
     */
    if (addr_gva) {
        if (!addrlen_gva) {
            close(new_fd);
            fd_mark_closed(gfd);
            return -LINUX_EFAULT;
        }
        uint32_t guest_addrlen;
        if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                             sizeof(guest_addrlen)) < 0) {
            close(new_fd);
            fd_mark_closed(gfd);
            return -LINUX_EFAULT;
        }
        uint8_t linux_sa[128];
        int out_len =
            mac_to_linux_sockaddr((struct sockaddr *) &mac_sa, mac_len,
                                  linux_sa, (uint32_t) sizeof(linux_sa));
        if (out_len > 0) {
            uint32_t actual_len = (uint32_t) out_len;
            uint32_t write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            /* Write back actual (not truncated) length per Linux semantics. */
            if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0 ||
                guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                close(new_fd);
                fd_mark_closed(gfd);
                return -LINUX_EFAULT;
            }
        }
    }

    return gfd;
}

int64_t sys_accept(guest_t *g, int fd, uint64_t addr_gva, uint64_t addrlen_gva)
{
    return do_accept(g, fd, addr_gva, addrlen_gva, 0, 0);
}

int64_t sys_accept4(guest_t *g,
                    int fd,
                    uint64_t addr_gva,
                    uint64_t addrlen_gva,
                    int flags)
{
    int nonblock = (flags & LINUX_SOCK_NONBLOCK) != 0;
    int cloexec = (flags & LINUX_SOCK_CLOEXEC) != 0;
    return do_accept(g, fd, addr_gva, addrlen_gva, nonblock, cloexec);
}

int64_t sys_connect(guest_t *g, int fd, uint64_t addr_gva, uint32_t addrlen)
{
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    uint8_t linux_sa[128];
    if (addrlen > sizeof(linux_sa)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (guest_read(g, addr_gva, linux_sa, addrlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    struct sockaddr_storage mac_sa;
    int mac_len;

    /* Abstract Unix socket: rewrite to filesystem path */
    if (absock_is_abstract_unix(linux_sa, addrlen)) {
        mac_len = absock_rewrite_connect(linux_sa, addrlen, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ECONNREFUSED;
        }
    } else {
        mac_len = linux_to_mac_sockaddr(linux_sa, addrlen, &mac_sa);
        if (mac_len < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
    }

    /* glibc probes UDP connect(addr, port 0) during getaddrinfo() source
     * address selection. Linux accepts this; macOS rejects it. Use discard port
     * 9 for the host-only probe so getsockname() can still discover the
     * selected local address.
     */
    int so_type = 0;
    socklen_t so_type_len = sizeof(so_type);
    if (sockaddr_has_zero_port(&mac_sa) &&
        getsockopt(host_ref.fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) ==
            0 &&
        so_type == SOCK_DGRAM) {
        struct sockaddr_storage probe_sa = mac_sa;
        sockaddr_set_port(&probe_sa, htons(9));
        if (connect(host_ref.fd, (struct sockaddr *) &probe_sa,
                    (socklen_t) mac_len) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    /* Upgrade the translator's fake AF_UNIX/SOCK_SEQPACKET placeholder to the
     * private rosettad bridge only when it actually connects to the rosettad
     * Unix path from the VZ_CAPS payload.
     */
    int cached_type = 0;
    bool shimmed_seqpacket = rosetta_seqpacket_placeholder(g, fd, host_ref.fd);
    if (shimmed_seqpacket &&
        net_socket_cached_int_get(fd, LINUX_SOL_SOCKET, LINUX_SO_TYPE,
                                  &cached_type) &&
        rosettad_connect_target(&mac_sa)) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        int one = 1;
        setsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        setsockopt(pair[1], SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

        int old_status = fcntl(host_ref.fd, F_GETFL, 0);
        fd_entry_t snap;
        bool have_snap = fd_snapshot(fd, &snap);
        if ((old_status >= 0 && (old_status & O_NONBLOCK) &&
             fd_set_nonblock(pair[0]) < 0) ||
            (have_snap && (snap.linux_flags & LINUX_O_CLOEXEC) &&
             fd_set_cloexec(pair[0]) < 0)) {
            close(pair[0]);
            close(pair[1]);
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }

        if (fd_alloc_at(fd, FD_SOCKET, pair[0], absock_unregister_fd, NULL) <
            0) {
            close(pair[0]);
            close(pair[1]);
            host_fd_ref_close(&host_ref);
            return -LINUX_EMFILE;
        }
        if (have_snap)
            fd_table[fd].linux_flags = snap.linux_flags;
        net_socket_cache_init_defaults(fd, LINUX_AF_UNIX, cached_type);

        if (rosettad_start_handler(pair[1], pair[0]) < 0) {
            close(pair[1]);
            log_warn(
                "sys_connect: rosettad handler thread failed to start; "
                "rosetta will see EOF on its socketpair");
        }

        host_fd_ref_close(&host_ref);
        return 0;
    }

    if (shimmed_seqpacket) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EPROTOTYPE;
    }

    int64_t crc = connect_or_interrupted(
        host_ref.fd, (struct sockaddr *) &mac_sa, (socklen_t) mac_len);
    host_fd_ref_close(&host_ref);
    return crc;
}

/* Convert a resolved macOS sockaddr to Linux form and write it, plus its actual
 * (untruncated) length, back to the guest, honoring the guest-supplied addrlen
 * cap. Closes host_ref on every path. Shared tail of getsockname/getpeername.
 */
static int64_t sockaddr_writeback(guest_t *g,
                                  host_fd_ref_t *host_ref,
                                  const struct sockaddr_storage *mac_sa,
                                  socklen_t mac_len,
                                  uint64_t addr_gva,
                                  uint64_t addrlen_gva,
                                  uint32_t guest_addrlen)
{
    uint8_t linux_sa[128];
    int out_len =
        mac_to_linux_sockaddr((const struct sockaddr *) mac_sa, mac_len,
                              linux_sa, (uint32_t) sizeof(linux_sa));
    if (out_len < 0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EINVAL;
    }

    uint32_t actual_len = (uint32_t) out_len, write_len = actual_len;
    if (write_len > guest_addrlen)
        write_len = guest_addrlen;
    if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EFAULT;
    }
    /* Write back actual (not truncated) length per Linux semantics */
    if (guest_write_small(g, addrlen_gva, &actual_len, sizeof(actual_len)) <
        0) {
        host_fd_ref_close(host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(host_ref);
    return 0;
}

int64_t sys_getsockname(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_getsockname(fd, g, addr_gva, addrlen_gva);

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    if (getsockname(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    uint32_t guest_addrlen;
    if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                         sizeof(guest_addrlen)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    /* Check if this is a filesystem socket backing an abstract socket */
    uint8_t linux_sa[128];
    if (mac_sa.ss_family == AF_UNIX) {
        struct sockaddr_un *sun = (struct sockaddr_un *) &mac_sa;
        uint8_t abs_name[108];
        uint32_t abs_len = 0;
        if (absock_reverse_lookup(sun->sun_path, abs_name, &abs_len)) {
            /* Reconstruct abstract Linux sockaddr */
            uint32_t total = 2 + 1 + abs_len;
            uint16_t fam = LINUX_AF_UNIX;
            memset(linux_sa, 0, sizeof(linux_sa));
            memcpy(linux_sa, &fam, 2);
            memcpy(linux_sa + 3, abs_name, abs_len);

            uint32_t actual_len = total, write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            if (guest_write_small(g, addr_gva, linux_sa, write_len) < 0 ||
                guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            host_fd_ref_close(&host_ref);
            return 0;
        }
    }

    return sockaddr_writeback(g, &host_ref, &mac_sa, mac_len, addr_gva,
                              addrlen_gva, guest_addrlen);
}

int64_t sys_getpeername(guest_t *g,
                        int fd,
                        uint64_t addr_gva,
                        uint64_t addrlen_gva)
{
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    if (getpeername(host_ref.fd, (struct sockaddr *) &mac_sa, &mac_len) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    uint32_t guest_addrlen;
    if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                         sizeof(guest_addrlen)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    return sockaddr_writeback(g, &host_ref, &mac_sa, mac_len, addr_gva,
                              addrlen_gva, guest_addrlen);
}

int64_t sys_sendto(guest_t *g,
                   int fd,
                   uint64_t buf_gva,
                   uint64_t len,
                   int linux_flags,
                   uint64_t dest_gva,
                   uint32_t addrlen)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_send(fd, g, buf_gva, len);

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    host_iov_buf_t source;
    int64_t source_err = host_iov_prepare_read_range(g, buf_gva, len, &source);
    if (source_err < 0) {
        host_fd_ref_close(&host_ref);
        return source_err;
    }

    int mac_flags = translate_msg_flags(linux_flags);
    /* MSG_NOSIGNAL (0x4000): suppress SIGPIPE on EPIPE. macOS has no
     * MSG_NOSIGNAL; elfuse handles it by not queuing SIGPIPE.
     */
    int suppress_sigpipe = (linux_flags & 0x4000);

    /* sendto with a NULL destination is send(); merge both forms. */
    struct sockaddr_storage mac_sa;
    struct sockaddr *dest = NULL;
    socklen_t dest_len = 0;
    if (dest_gva && addrlen > 0) {
        uint8_t linux_sa[128];
        if (addrlen > sizeof(linux_sa)) {
            host_iov_free(&source);
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        if (guest_read(g, dest_gva, linux_sa, addrlen) < 0) {
            host_iov_free(&source);
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int mac_len = linux_to_mac_sockaddr(linux_sa, addrlen, &mac_sa);
        if (mac_len < 0) {
            host_iov_free(&source);
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        dest = (struct sockaddr *) &mac_sa;
        dest_len = (socklen_t) mac_len;
    }

    bool blocking = len > 0 && sock_op_should_block(host_ref.fd, linux_flags);
    int host_flags = mac_flags | (blocking ? MSG_DONTWAIT : 0);
    struct msghdr msg = {
        .msg_name = dest,
        .msg_namelen = dest_len,
        .msg_iov = source.iov,
        .msg_iovlen = source.iovcnt,
    };
    ssize_t ret;
    for (;;) {
        if (blocking) {
            int64_t waited = io_wait_fd_or_interrupted(host_ref.fd, POLLOUT);
            if (waited < 0) {
                host_iov_free(&source);
                host_fd_ref_close(&host_ref);
                return waited;
            }
        }
        ret = sendmsg(host_ref.fd, &msg, host_flags);
        if (!(blocking && ret < 0 && errno == EAGAIN))
            break;
    }
    host_iov_free(&source);
    host_fd_ref_close(&host_ref);
    if (ret < 0) {
        if (errno == EPIPE && !suppress_sigpipe)
            signal_queue(LINUX_SIGPIPE);
        return linux_errno();
    }
    return ret;
}

int64_t sys_recvfrom(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t len,
                     int flags,
                     uint64_t src_gva,
                     uint64_t addrlen_gva)
{
    if (fd_get_type(fd) == FD_NETLINK)
        return netlink_recv(fd, g, buf_gva, len, flags, src_gva, addrlen_gva);

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    uint64_t avail = 0;
    void *buf =
        len > 0 ? guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, len) : NULL;
    if (!buf && len > 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (len > avail)
        len = avail;

    int mac_flags = translate_msg_flags(flags);

    /* A single interruptible wait (not a MSG_DONTWAIT probe loop) preserves
     * MSG_WAITALL semantics; the tiny ready-then-stolen window can still
     * block, matching sys_read. A zero-length recv takes the readiness gate
     * instead: unlike read(), Linux blocks it on an empty socket.
     */
    int64_t waited = len > 0
                         ? net_wait_or_interrupted(host_ref.fd, POLLIN, flags)
                         : net_recv_zero_payload_gate(host_ref.fd, flags);
    if (waited < 0) {
        host_fd_ref_close(&host_ref);
        return waited;
    }

    struct sockaddr_storage mac_sa;
    socklen_t mac_len = sizeof(mac_sa);

    ssize_t ret;
    if (src_gva && addrlen_gva) {
        ret = recvfrom(host_ref.fd, buf, len, mac_flags,
                       (struct sockaddr *) &mac_sa, &mac_len);
    } else {
        ret = recv(host_ref.fd, buf, len, mac_flags);
    }
    if (ret < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* Write back source address if requested. */
    if (src_gva) {
        if (!addrlen_gva) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        uint32_t guest_addrlen;
        if (guest_read_small(g, addrlen_gva, &guest_addrlen,
                             sizeof(guest_addrlen)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        uint8_t linux_sa[128];
        int out_len =
            mac_to_linux_sockaddr((struct sockaddr *) &mac_sa, mac_len,
                                  linux_sa, (uint32_t) sizeof(linux_sa));
        if (out_len > 0) {
            uint32_t actual_len = (uint32_t) out_len;
            uint32_t write_len = actual_len;
            if (write_len > guest_addrlen)
                write_len = guest_addrlen;
            if (guest_write_small(g, src_gva, linux_sa, write_len) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
            /* Write back actual length (Linux returns full size even if the
             * address was truncated to fit the buffer).
             */
            if (guest_write_small(g, addrlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_EFAULT;
            }
        }
    }

    host_fd_ref_close(&host_ref);
    return ret;
}

/* Translate a Linux (level, optname) socket-option pair to the macOS pair for
 * the level dispatch common to setsockopt/getsockopt.
 *
 * Returns true on success with the mac_level and mac_optname out-params set;
 * false when the option is unknown for a recognized level (caller returns
 * -ENOPROTOOPT). Both out-params must be pre-seeded with the Linux values so an
 * unrecognized level passes through unchanged for the host to reject.
 *
 * The small-int options (including all four TCP keepalive/nodelay options) are
 * handled by translate_small_int_sockopt before this is reached, and
 * IP_MTU_DISCOVER / IP_RECVERR are handled by an earlier return, so neither
 * reaches this dispatch.
 */
static bool translate_sockopt_level(int level,
                                    int optname,
                                    int *mac_level,
                                    int *mac_optname)
{
    if (level == LINUX_SOL_SOCKET) {
        *mac_level = SOL_SOCKET;
        *mac_optname = translate_sockopt(optname);
        return *mac_optname >= 0;
    }
    if (level == LINUX_IPPROTO_TCP) {
        *mac_level = IPPROTO_TCP;
        return true;
    }
    if (level == LINUX_IPPROTO_IP) {
        *mac_level = IPPROTO_IP;
        *mac_optname = translate_ip_sockopt_to_mac(optname);
        return *mac_optname >= 0;
    }
    if (level == LINUX_IPPROTO_IPV6) {
        *mac_level = IPPROTO_IPV6;
        if (optname == LINUX_IPV6_V6ONLY)
            *mac_optname = IPV6_V6ONLY;
    }
    return true;
}

static bool cached_setsockopt_may_succeed(int level, int optname)
{
    if (level == LINUX_SOL_SOCKET) {
        switch (optname) {
        case LINUX_SO_KEEPALIVE:
        case LINUX_SO_REUSEADDR:
        case LINUX_SO_REUSEPORT:
        case LINUX_SO_BROADCAST:
        case LINUX_SO_DONTROUTE:
        case LINUX_SO_OOBINLINE:
        case LINUX_SO_RCVLOWAT:
        case LINUX_SO_RCVBUF:
        case LINUX_SO_SNDBUF:
            return true;
        default:
            return false;
        }
    }

    return (level == LINUX_IPPROTO_TCP &&
            (optname == LINUX_TCP_NODELAY || optname == LINUX_TCP_KEEPIDLE ||
             optname == LINUX_TCP_KEEPINTVL || optname == LINUX_TCP_KEEPCNT)) ||
           (level == LINUX_IPPROTO_IP &&
            (optname == LINUX_IP_TOS || optname == LINUX_IP_TTL ||
             optname == LINUX_IP_HDRINCL || optname == LINUX_IP_PKTINFO ||
             optname == LINUX_IP_RECVTTL || optname == LINUX_IP_RECVTOS));
}

static bool readonly_setsockopt(int level, int optname)
{
    return level == LINUX_SOL_SOCKET &&
           (optname == LINUX_SO_TYPE || optname == LINUX_SO_ERROR ||
            optname == LINUX_SO_ACCEPTCONN || optname == LINUX_SO_SNDLOWAT);
}

int64_t sys_setsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint32_t optlen)
{
    int small_int_opt = socket_opt_uses_small_int(level, optname);

    /* SO_PASSCRED: emulated entirely in elfuse. Cache the flag value so
     * getsockopt returns it and recvmsg knows to inject SCM_CREDENTIALS. macOS
     * has no equivalent. Do not forward.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PASSCRED) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        value = socket_small_int_normalize(level, optname, value);
        net_socket_cached_int_set(fd, LINUX_SOL_SOCKET, LINUX_SO_PASSCRED,
                                  value);
        return 0;
    }

    if (level == LINUX_IPPROTO_IP && optname == LINUX_IP_MTU_DISCOVER) {
        /* P2P networking tools (libp2p, syncthing, WireGuard userland,
         * Tailscale's bundled tailscaled) set IP_MTU_DISCOVER early in connect
         * and abort on -ENOPROTOOPT. macOS has no direct equivalent; accept the
         * option, cache the Linux PMTUD mode for getsockopt round-trip, and
         * where the host can honour it, push the closest IP_DONTFRAG setting
         * onto the underlying socket. Linux PMTUD modes:
         *   0 DONT  / 1 WANT  -> allow fragmentation (DONTFRAG off)
         *   2 DO   / 3 PROBE  / 4 INTERFACE -> set DF (DONTFRAG on)
         *   5 OMIT -> behave like DONT (best-effort)
         */
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        net_socket_cached_int_set(fd, LINUX_IPPROTO_IP, LINUX_IP_MTU_DISCOVER,
                                  value);
        host_fd_ref_t hr;
        if (host_fd_ref_open(fd, &hr) == 0) {
            int dontfrag = (value >= 2 && value <= 4) ? 1 : 0;
            (void) setsockopt(hr.fd, IPPROTO_IP, IP_DONTFRAG, &dontfrag,
                              sizeof(dontfrag));
            host_fd_ref_close(&hr);
        }
        return 0;
    }
    if (level == LINUX_IPPROTO_IP && optname == LINUX_IP_RECVERR) {
        /* No macOS equivalent for the Linux extended-error queue. Accept and
         * discard; the queue stays empty, so subsequent recvmsg with
         * MSG_ERRQUEUE returns -EAGAIN as Linux would for a quiescent
         * connection.
         */
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (optlen == 0 || optlen > sizeof(int))
            return -LINUX_EINVAL;
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        (void) value;
        return 0;
    }

    if (readonly_setsockopt(level, optname)) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        return -LINUX_ENOPROTOOPT;
    }

    if (optlen > 0 && optlen <= sizeof(int) && small_int_opt) {
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0)
            return -LINUX_EFAULT;
        value = socket_small_int_normalize(level, optname, value);

        int cached_value = 0;
        int cached_mac_level = level, cached_mac_optname = optname;
        if (cached_setsockopt_may_succeed(level, optname) &&
            translate_small_int_sockopt(level, optname, &cached_mac_level,
                                        &cached_mac_optname) &&
            net_socket_cached_int_get(fd, level, optname, &cached_value) &&
            cached_value == value)
            return 0;
    }

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    int mac_level = level, mac_optname = optname;

    if (small_int_opt &&
        translate_small_int_sockopt(level, optname, &mac_level, &mac_optname)) {
        goto setsockopt_translated;
    }

    if (!translate_sockopt_level(level, optname, &mac_level, &mac_optname)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOPROTOOPT;
    }

setsockopt_translated:
    if (optlen <= sizeof(int) && small_int_opt) {
        if (optlen == 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        int value = 0;
        if (guest_read_small(g, optval_gva, &value, optlen) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        value = socket_small_int_normalize(level, optname, value);

        /* The cached-value short-circuit (return 0 when the socket already
         * holds this value) ran before host_fd_ref_open for every small-int
         * option with optlen > 0, so it is not repeated here.
         *
         * Linux accepts shorter optlen for many int-valued options and
         * zero-extends the value. macOS rejects optlen < sizeof(int) with
         * EINVAL (notably for IP_TOS / IP_TTL / IP_PKTINFO / IP_RECVTTL /
         * IP_RECVTOS). The value has already been zero-extended into an int, so
         * always call the host with sizeof(int).
         */
        if (setsockopt(host_ref.fd, mac_level, mac_optname, &value,
                       sizeof(value)) < 0) {
            log_debug("setsockopt(fd=%d, level=%d/%d, opt=%d/%d, len=%u): %s",
                      fd, level, mac_level, optname, mac_optname, optlen,
                      strerror(errno));
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        net_socket_cached_int_set(fd, level, optname, value);
        host_fd_ref_close(&host_ref);
        return 0;
    }

    uint8_t optval[256];
    if (optlen > sizeof(optval)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }
    if (optlen > 0 && guest_read(g, optval_gva, optval, optlen) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (setsockopt(host_ref.fd, mac_level, mac_optname, optval,
                   (socklen_t) optlen) < 0) {
        log_debug("setsockopt(fd=%d, level=%d/%d, opt=%d/%d, len=%u): %s", fd,
                  level, mac_level, optname, mac_optname, optlen,
                  strerror(errno));
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

/* Mirrors Linux ip_sockglue copyval: when an IP-level getsockopt has a caller
 * buffer shorter than int and the int-sized value fits in a byte, report and
 * write a single byte. Otherwise leaves actual_len untouched.
 */
static inline uint32_t ip_copyval_clamp(int level,
                                        uint32_t guest_optlen,
                                        int value,
                                        uint32_t actual_len)
{
    if (level == LINUX_IPPROTO_IP && guest_optlen > 0 &&
        guest_optlen < sizeof(int) && value >= 0 && value <= 255)
        return 1;
    return actual_len;
}

int64_t sys_getsockopt(guest_t *g,
                       int fd,
                       int level,
                       int optname,
                       uint64_t optval_gva,
                       uint64_t optlen_gva)
{
    uint32_t guest_optlen;
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0)
        return -LINUX_EFAULT;

    /* SO_PEERCRED: synthesize struct ucred from guest identity. macOS has
     * LOCAL_PEERCRED but returns a different struct; fabricate the Linux ucred
     * with the guest's own PID/UID/GID, which is correct for AF_UNIX sockets
     * within the same elfuse instance.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_PEERCRED) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        linux_ucred_t cred = {
            .pid = (int32_t) proc_get_pid(),
            .uid = proc_get_uid(),
            .gid = proc_get_gid(),
        };
        uint32_t out_len = sizeof(cred);
        if (guest_optlen < out_len)
            out_len = guest_optlen;
        if (out_len > 0 && guest_write_small(g, optval_gva, &cred, out_len) < 0)
            return -LINUX_EFAULT;
        uint32_t actual_len = sizeof(cred);
        if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) <
            0)
            return -LINUX_EFAULT;
        return 0;
    }

    if (level == LINUX_IPPROTO_IP &&
        (optname == LINUX_IP_MTU_DISCOVER || optname == LINUX_IP_RECVERR)) {
        if (!net_socket_fd_is_valid(fd))
            return -LINUX_EBADF;
        if (guest_optlen >= sizeof(int)) {
            /* IP_MTU_DISCOVER round-trips through the per-fd cache so
             * getsockopt reports what the guest last wrote via setsockopt.
             * IP_RECVERR has no cache (the extended-error queue stays
             * permanently empty), so it always reports 1.
             */
            int val = 1;
            if (optname == LINUX_IP_MTU_DISCOVER)
                (void) net_socket_cached_int_get(fd, level, optname, &val);
            uint32_t out_len = sizeof(int);
            if (guest_write_small(g, optval_gva, &val, sizeof(val)) < 0)
                return -LINUX_EFAULT;
            if (guest_write_small(g, optlen_gva, &out_len, sizeof(out_len)) < 0)
                return -LINUX_EFAULT;
        }
        return 0;
    }

    if (socket_opt_uses_small_int(level, optname)) {
        int value = 0;
        if (net_socket_cached_int_get(fd, level, optname, &value)) {
            uint32_t actual_len =
                ip_copyval_clamp(level, guest_optlen, value, sizeof(int));
            uint32_t write_len = actual_len;
            if (write_len > guest_optlen)
                write_len = guest_optlen;
            if (write_len > 0 &&
                guest_write_small(g, optval_gva, &value, write_len) < 0)
                return -LINUX_EFAULT;
            if (guest_write_small(g, optlen_gva, &actual_len,
                                  sizeof(actual_len)) < 0)
                return -LINUX_EFAULT;
            return 0;
        }
    }

    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    int mac_level = level, mac_optname = optname;
    int small_int_opt = socket_opt_uses_small_int(level, optname);

    if (small_int_opt &&
        translate_small_int_sockopt(level, optname, &mac_level, &mac_optname)) {
        goto getsockopt_translated;
    }

    if (!translate_sockopt_level(level, optname, &mac_level, &mac_optname)) {
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOPROTOOPT;
    }

getsockopt_translated:
    if (guest_read_small(g, optlen_gva, &guest_optlen, sizeof(guest_optlen)) <
        0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    if (small_int_opt) {
        int value = 0;
        socklen_t mac_optlen = sizeof(value);
        uint32_t actual_len, write_len;
        int used_cache = net_socket_cached_int_get(fd, level, optname, &value);

        if (!used_cache) {
            if (getsockopt(host_ref.fd, mac_level, mac_optname, &value,
                           &mac_optlen) < 0) {
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }

            if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE)
                value &= 0xF;

            if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR &&
                value != 0) {
                errno = value;
                value = (int) (-linux_errno());
            }

            net_socket_cached_int_set(fd, level, optname, value);
        }

        actual_len = used_cache ? sizeof(int) : (uint32_t) mac_optlen;
        actual_len = ip_copyval_clamp(level, guest_optlen, value, actual_len);
        write_len = actual_len;
        if (write_len > guest_optlen)
            write_len = guest_optlen;
        if (write_len > 0 &&
            guest_write_small(g, optval_gva, &value, write_len) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) <
            0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }

        host_fd_ref_close(&host_ref);
        return 0;
    }

    uint8_t optval[256];
    socklen_t mac_optlen = (socklen_t) guest_optlen;
    if (mac_optlen > sizeof(optval))
        mac_optlen = sizeof(optval);

    if (getsockopt(host_ref.fd, mac_level, mac_optname, optval, &mac_optlen) <
        0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* SO_TYPE: macOS returns the raw socket type. On Linux, getsockopt SO_TYPE
     * returns the base type without SOCK_NONBLOCK/SOCK_CLOEXEC flags, and the
     * numeric values happen to match (SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_RAW=3).
     * Strip any flag bits for safety.
     */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE &&
        mac_optlen >= (socklen_t) sizeof(int)) {
        int *type_val = (int *) optval;
        *type_val &= 0xF; /* Keep only the base socket type */
    }

    /* SO_ERROR: macOS returns a macOS errno value; translate to Linux. */
    if (level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR &&
        mac_optlen >= (socklen_t) sizeof(int)) {
        int *err_val = (int *) optval;
        if (*err_val != 0) {
            errno = *err_val;
            *err_val = (int) (-linux_errno());
        }
    }

    /* Write option value, truncating to guest buffer size if needed. Write back
     * actual length (not truncated) per Linux semantics: Linux getsockopt
     * returns the real option size so the caller can detect truncation and
     * retry with a larger buffer.
     */
    uint32_t actual_len = (uint32_t) mac_optlen, write_len = actual_len;
    if (write_len > guest_optlen)
        write_len = guest_optlen;
    if (guest_write_small(g, optval_gva, optval, write_len) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (guest_write_small(g, optlen_gva, &actual_len, sizeof(actual_len)) < 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }

    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_shutdown(int fd, int how)
{
    host_fd_ref_t host_ref;
    if (host_fd_ref_open(fd, &host_ref) < 0)
        return -LINUX_EBADF;

    /* Shutdown constants are identical on Linux and macOS */
    if (shutdown(host_ref.fd, how) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    host_fd_ref_close(&host_ref);
    return 0;
}
