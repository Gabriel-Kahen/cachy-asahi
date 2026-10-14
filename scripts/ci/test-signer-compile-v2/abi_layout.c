/* SPDX-License-Identifier: MIT
 * Compile to ET_REL only. NEVER execute or link this header-layout helper.
 * Exact actual selected compiler/header provenance is a separate Root input.
 * Layout values do not admit kernel handlers, loaders, threads or signer APIs.
 */
#include <asm/unistd.h>
#include <linux/ioctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Only selected little-endian aarch64 ABI"
#endif
#ifdef WITNESS_SUPPORTED_THREADS
#error "Thread policy remains disabled"
#endif
/* Exactly the shim's source wire structs. This is NOT libc layout evidence. */
struct vector { void *base; unsigned long size; };
struct message { void *name; unsigned name_size; struct vector *vectors; unsigned long count;
                 void *control; unsigned long control_size; unsigned flags; };
struct rights { unsigned long size; int level,kind,fd,padding; };
_Static_assert((unsigned long long)(sizeof(struct seccomp_data)) == 0x40ULL, "sizeof.seccomp_data");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_data, nr)) == 0x0ULL, "offsetof.seccomp_data.nr");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_data, arch)) == 0x4ULL, "offsetof.seccomp_data.arch");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_data, instruction_pointer)) == 0x8ULL, "offsetof.seccomp_data.instruction_pointer");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_data, args)) == 0x10ULL, "offsetof.seccomp_data.args");
_Static_assert((unsigned long long)(sizeof(struct seccomp_notif)) == 0x50ULL, "sizeof.seccomp_notif");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif, id)) == 0x0ULL, "offsetof.seccomp_notif.id");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif, pid)) == 0x8ULL, "offsetof.seccomp_notif.pid");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif, flags)) == 0xcULL, "offsetof.seccomp_notif.flags");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif, data)) == 0x10ULL, "offsetof.seccomp_notif.data");
_Static_assert((unsigned long long)(sizeof(struct seccomp_notif_resp)) == 0x18ULL, "sizeof.seccomp_notif_resp");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, id)) == 0x0ULL, "offsetof.seccomp_notif_resp.id");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, val)) == 0x8ULL, "offsetof.seccomp_notif_resp.val");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, error)) == 0x10ULL, "offsetof.seccomp_notif_resp.error");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, flags)) == 0x14ULL, "offsetof.seccomp_notif_resp.flags");
_Static_assert((unsigned long long)(sizeof(struct seccomp_notif_sizes)) == 0x6ULL, "sizeof.seccomp_notif_sizes");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_notif)) == 0x0ULL, "offsetof.seccomp_notif_sizes.seccomp_notif");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_notif_resp)) == 0x2ULL, "offsetof.seccomp_notif_sizes.seccomp_notif_resp");
_Static_assert((unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_data)) == 0x4ULL, "offsetof.seccomp_notif_sizes.seccomp_data");
_Static_assert((unsigned long long)(sizeof(struct sock_filter)) == 0x8ULL, "sizeof.sock_filter");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_filter, code)) == 0x0ULL, "offsetof.sock_filter.code");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_filter, jt)) == 0x2ULL, "offsetof.sock_filter.jt");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_filter, jf)) == 0x3ULL, "offsetof.sock_filter.jf");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_filter, k)) == 0x4ULL, "offsetof.sock_filter.k");
_Static_assert((unsigned long long)(sizeof(struct sock_fprog)) == 0x10ULL, "sizeof.sock_fprog");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_fprog, len)) == 0x0ULL, "offsetof.sock_fprog.len");
_Static_assert((unsigned long long)(__builtin_offsetof(struct sock_fprog, filter)) == 0x8ULL, "offsetof.sock_fprog.filter");
_Static_assert((unsigned long long)(sizeof(struct pollfd)) == 0x8ULL, "sizeof.pollfd");
_Static_assert((unsigned long long)(__builtin_offsetof(struct pollfd, fd)) == 0x0ULL, "offsetof.pollfd.fd");
_Static_assert((unsigned long long)(__builtin_offsetof(struct pollfd, events)) == 0x4ULL, "offsetof.pollfd.events");
_Static_assert((unsigned long long)(__builtin_offsetof(struct pollfd, revents)) == 0x6ULL, "offsetof.pollfd.revents");
_Static_assert((unsigned long long)(sizeof(struct vector)) == 0x10ULL, "shim_wire.sizeof.vector");
_Static_assert((unsigned long long)(__builtin_offsetof(struct vector, base)) == 0x0ULL, "shim_wire.offsetof.vector.base");
_Static_assert((unsigned long long)(__builtin_offsetof(struct vector, size)) == 0x8ULL, "shim_wire.offsetof.vector.size");
_Static_assert((unsigned long long)(sizeof(struct message)) == 0x38ULL, "shim_wire.sizeof.message");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, name)) == 0x0ULL, "shim_wire.offsetof.message.name");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, name_size)) == 0x8ULL, "shim_wire.offsetof.message.name_size");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, vectors)) == 0x10ULL, "shim_wire.offsetof.message.vectors");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, count)) == 0x18ULL, "shim_wire.offsetof.message.count");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, control)) == 0x20ULL, "shim_wire.offsetof.message.control");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, control_size)) == 0x28ULL, "shim_wire.offsetof.message.control_size");
_Static_assert((unsigned long long)(__builtin_offsetof(struct message, flags)) == 0x30ULL, "shim_wire.offsetof.message.flags");
_Static_assert((unsigned long long)(sizeof(struct rights)) == 0x18ULL, "shim_wire.sizeof.rights");
_Static_assert((unsigned long long)(__builtin_offsetof(struct rights, size)) == 0x0ULL, "shim_wire.offsetof.rights.size");
_Static_assert((unsigned long long)(__builtin_offsetof(struct rights, level)) == 0x8ULL, "shim_wire.offsetof.rights.level");
_Static_assert((unsigned long long)(__builtin_offsetof(struct rights, kind)) == 0xcULL, "shim_wire.offsetof.rights.kind");
_Static_assert((unsigned long long)(__builtin_offsetof(struct rights, fd)) == 0x10ULL, "shim_wire.offsetof.rights.fd");
_Static_assert((unsigned long long)(__builtin_offsetof(struct rights, padding)) == 0x14ULL, "shim_wire.offsetof.rights.padding");
_Static_assert((unsigned long long)(sizeof(long)) == 0x8ULL, "sizeof.long");
_Static_assert((unsigned long long)(sizeof(void *)) == 0x8ULL, "sizeof.void_pointer");
_Static_assert((unsigned long long)(sizeof(unsigned int)) == 0x4ULL, "sizeof.unsigned_int");
_Static_assert((unsigned long long)(sizeof(unsigned short)) == 0x2ULL, "sizeof.unsigned_short");
_Static_assert((unsigned long long)(sizeof(unsigned long long)) == 0x8ULL, "sizeof.unsigned_long_long");
_Static_assert((unsigned long long)(SECCOMP_IOCTL_NOTIF_RECV) == 0xc0502100ULL, "SECCOMP_IOCTL_NOTIF_RECV");
_Static_assert((unsigned long long)(SECCOMP_IOCTL_NOTIF_SEND) == 0xc0182101ULL, "SECCOMP_IOCTL_NOTIF_SEND");
_Static_assert((unsigned long long)(SECCOMP_IOCTL_NOTIF_ID_VALID) == 0x40082102ULL, "SECCOMP_IOCTL_NOTIF_ID_VALID");
_Static_assert((unsigned long long)(SECCOMP_USER_NOTIF_FLAG_CONTINUE) == 0x1ULL, "SECCOMP_USER_NOTIF_FLAG_CONTINUE");
_Static_assert((unsigned long long)(SECCOMP_FILTER_FLAG_NEW_LISTENER) == 0x8ULL, "SECCOMP_FILTER_FLAG_NEW_LISTENER");
_Static_assert((unsigned long long)(SECCOMP_SET_MODE_FILTER) == 0x1ULL, "SECCOMP_SET_MODE_FILTER");
_Static_assert((unsigned long long)(SECCOMP_GET_ACTION_AVAIL) == 0x2ULL, "SECCOMP_GET_ACTION_AVAIL");
_Static_assert((unsigned long long)(SECCOMP_GET_NOTIF_SIZES) == 0x3ULL, "SECCOMP_GET_NOTIF_SIZES");
_Static_assert((unsigned long long)(SECCOMP_RET_USER_NOTIF) == 0x7fc00000ULL, "SECCOMP_RET_USER_NOTIF");
_Static_assert((unsigned long long)(SECCOMP_RET_ALLOW) == 0x7fff0000ULL, "SECCOMP_RET_ALLOW");
_Static_assert((unsigned long long)(SECCOMP_RET_ERRNO) == 0x50000ULL, "SECCOMP_RET_ERRNO");
_Static_assert((unsigned long long)(SECCOMP_RET_KILL_PROCESS) == 0x80000000ULL, "SECCOMP_RET_KILL_PROCESS");
_Static_assert((unsigned long long)(AUDIT_ARCH_AARCH64) == 0xc00000b7ULL, "AUDIT_ARCH_AARCH64");
_Static_assert((unsigned long long)(PR_SET_NO_NEW_PRIVS) == 0x26ULL, "PR_SET_NO_NEW_PRIVS");
_Static_assert((unsigned long long)(PR_SET_SECCOMP) == 0x16ULL, "PR_SET_SECCOMP");
_Static_assert((unsigned long long)(PR_SET_MM) == 0x23ULL, "PR_SET_MM");
_Static_assert((unsigned long long)(PR_SET_PTRACER) == 0x59616d61ULL, "PR_SET_PTRACER");
_Static_assert((unsigned long long)(PR_SET_DUMPABLE) == 0x4ULL, "PR_SET_DUMPABLE");
_Static_assert((unsigned long long)(AT_EMPTY_PATH) == 0x1000ULL, "AT_EMPTY_PATH");
_Static_assert((unsigned long long)(FD_CLOEXEC) == 0x1ULL, "FD_CLOEXEC");
_Static_assert((unsigned long long)(F_SETFD) == 0x2ULL, "F_SETFD");
_Static_assert((unsigned long long)(O_RDONLY) == 0x0ULL, "O_RDONLY");
_Static_assert((unsigned long long)(O_NONBLOCK) == 0x800ULL, "O_NONBLOCK");
_Static_assert((unsigned long long)(O_NOFOLLOW) == 0x20000ULL, "O_NOFOLLOW");
_Static_assert((unsigned long long)(O_CLOEXEC) == 0x80000ULL, "O_CLOEXEC");
_Static_assert((unsigned long long)(POLLIN) == 0x1ULL, "POLLIN");
_Static_assert((unsigned long long)(POLLERR) == 0x8ULL, "POLLERR");
_Static_assert((unsigned long long)(POLLHUP) == 0x10ULL, "POLLHUP");
_Static_assert((unsigned long long)(POLLNVAL) == 0x20ULL, "POLLNVAL");
_Static_assert((unsigned long long)(CLONE_VM) == 0x100ULL, "CLONE_VM");
_Static_assert((unsigned long long)(CLONE_FS) == 0x200ULL, "CLONE_FS");
_Static_assert((unsigned long long)(CLONE_FILES) == 0x400ULL, "CLONE_FILES");
_Static_assert((unsigned long long)(CLONE_SIGHAND) == 0x800ULL, "CLONE_SIGHAND");
_Static_assert((unsigned long long)(CLONE_THREAD) == 0x10000ULL, "CLONE_THREAD");
_Static_assert((unsigned long long)(CLONE_SYSVSEM) == 0x40000ULL, "CLONE_SYSVSEM");
_Static_assert((unsigned long long)(CLONE_SETTLS) == 0x80000ULL, "CLONE_SETTLS");
_Static_assert((unsigned long long)(CLONE_PARENT_SETTID) == 0x100000ULL, "CLONE_PARENT_SETTID");
_Static_assert((unsigned long long)(CLONE_CHILD_CLEARTID) == 0x200000ULL, "CLONE_CHILD_CLEARTID");
_Static_assert((unsigned long long)(__NR_execveat) == 0x119ULL, "__NR_execveat");
_Static_assert((unsigned long long)(__NR_brk) == 0xd6ULL, "__NR_brk");
_Static_assert((unsigned long long)(__NR_clone) == 0xdcULL, "__NR_clone");
_Static_assert((unsigned long long)(__NR_clone3) == 0x1b3ULL, "__NR_clone3");
_Static_assert((unsigned long long)(__NR_execve) == 0xddULL, "__NR_execve");
_Static_assert((unsigned long long)(__NR_seccomp) == 0x115ULL, "__NR_seccomp");
_Static_assert((unsigned long long)(__NR_prctl) == 0xa7ULL, "__NR_prctl");
_Static_assert((unsigned long long)(__NR_sendmsg) == 0xd3ULL, "__NR_sendmsg");
_Static_assert((unsigned long long)(__NR_close) == 0x39ULL, "__NR_close");
_Static_assert((unsigned long long)(__NR_dup3) == 0x18ULL, "__NR_dup3");
_Static_assert((unsigned long long)(__NR_fcntl) == 0x19ULL, "__NR_fcntl");
_Static_assert((unsigned long long)(__NR_getpid) == 0xacULL, "__NR_getpid");
_Static_assert((unsigned long long)(__NR_exit_group) == 0x5eULL, "__NR_exit_group");
_Static_assert((unsigned long long)(__NR_pidfd_open) == 0x1b2ULL, "__NR_pidfd_open");
_Static_assert((unsigned long long)(__NR_pidfd_send_signal) == 0x1a8ULL, "__NR_pidfd_send_signal");
_Static_assert((unsigned long long)(__NR_ptrace) == 0x75ULL, "__NR_ptrace");
_Static_assert((unsigned long long)(__NR_process_vm_writev) == 0x10fULL, "__NR_process_vm_writev");
_Static_assert((unsigned long long)(__NR_pidfd_getfd) == 0x1b6ULL, "__NR_pidfd_getfd");
_Static_assert((unsigned long long)(__NR_unshare) == 0x61ULL, "__NR_unshare");
_Static_assert((unsigned long long)(__NR_setns) == 0x10cULL, "__NR_setns");
_Static_assert((unsigned long long)(__NR_io_uring_setup) == 0x1a9ULL, "__NR_io_uring_setup");
_Static_assert((unsigned long long)(BPF_LD+BPF_W+BPF_ABS) == 0x20ULL, "BPF_LD_W_ABS");
_Static_assert((unsigned long long)(BPF_JMP+BPF_JEQ+BPF_K) == 0x15ULL, "BPF_JMP_JEQ_K");
_Static_assert((unsigned long long)(BPF_RET+BPF_K) == 0x6ULL, "BPF_RET_K");
_Static_assert((unsigned long long)(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID) == 0x3d0f00ULL, "thread_clone_mask");

__attribute__((used, section(".witness_abi"), aligned(8)))
const unsigned long long witness_abi[] = {
    0x3149424154495757ULL, 1ULL, 116ULL,
    (unsigned long long)(sizeof(struct seccomp_data)), /* sizeof.seccomp_data */
    (unsigned long long)(__builtin_offsetof(struct seccomp_data, nr)), /* offsetof.seccomp_data.nr */
    (unsigned long long)(__builtin_offsetof(struct seccomp_data, arch)), /* offsetof.seccomp_data.arch */
    (unsigned long long)(__builtin_offsetof(struct seccomp_data, instruction_pointer)), /* offsetof.seccomp_data.instruction_pointer */
    (unsigned long long)(__builtin_offsetof(struct seccomp_data, args)), /* offsetof.seccomp_data.args */
    (unsigned long long)(sizeof(struct seccomp_notif)), /* sizeof.seccomp_notif */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif, id)), /* offsetof.seccomp_notif.id */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif, pid)), /* offsetof.seccomp_notif.pid */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif, flags)), /* offsetof.seccomp_notif.flags */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif, data)), /* offsetof.seccomp_notif.data */
    (unsigned long long)(sizeof(struct seccomp_notif_resp)), /* sizeof.seccomp_notif_resp */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, id)), /* offsetof.seccomp_notif_resp.id */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, val)), /* offsetof.seccomp_notif_resp.val */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, error)), /* offsetof.seccomp_notif_resp.error */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_resp, flags)), /* offsetof.seccomp_notif_resp.flags */
    (unsigned long long)(sizeof(struct seccomp_notif_sizes)), /* sizeof.seccomp_notif_sizes */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_notif)), /* offsetof.seccomp_notif_sizes.seccomp_notif */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_notif_resp)), /* offsetof.seccomp_notif_sizes.seccomp_notif_resp */
    (unsigned long long)(__builtin_offsetof(struct seccomp_notif_sizes, seccomp_data)), /* offsetof.seccomp_notif_sizes.seccomp_data */
    (unsigned long long)(sizeof(struct sock_filter)), /* sizeof.sock_filter */
    (unsigned long long)(__builtin_offsetof(struct sock_filter, code)), /* offsetof.sock_filter.code */
    (unsigned long long)(__builtin_offsetof(struct sock_filter, jt)), /* offsetof.sock_filter.jt */
    (unsigned long long)(__builtin_offsetof(struct sock_filter, jf)), /* offsetof.sock_filter.jf */
    (unsigned long long)(__builtin_offsetof(struct sock_filter, k)), /* offsetof.sock_filter.k */
    (unsigned long long)(sizeof(struct sock_fprog)), /* sizeof.sock_fprog */
    (unsigned long long)(__builtin_offsetof(struct sock_fprog, len)), /* offsetof.sock_fprog.len */
    (unsigned long long)(__builtin_offsetof(struct sock_fprog, filter)), /* offsetof.sock_fprog.filter */
    (unsigned long long)(sizeof(struct pollfd)), /* sizeof.pollfd */
    (unsigned long long)(__builtin_offsetof(struct pollfd, fd)), /* offsetof.pollfd.fd */
    (unsigned long long)(__builtin_offsetof(struct pollfd, events)), /* offsetof.pollfd.events */
    (unsigned long long)(__builtin_offsetof(struct pollfd, revents)), /* offsetof.pollfd.revents */
    (unsigned long long)(sizeof(struct vector)), /* shim_wire.sizeof.vector */
    (unsigned long long)(__builtin_offsetof(struct vector, base)), /* shim_wire.offsetof.vector.base */
    (unsigned long long)(__builtin_offsetof(struct vector, size)), /* shim_wire.offsetof.vector.size */
    (unsigned long long)(sizeof(struct message)), /* shim_wire.sizeof.message */
    (unsigned long long)(__builtin_offsetof(struct message, name)), /* shim_wire.offsetof.message.name */
    (unsigned long long)(__builtin_offsetof(struct message, name_size)), /* shim_wire.offsetof.message.name_size */
    (unsigned long long)(__builtin_offsetof(struct message, vectors)), /* shim_wire.offsetof.message.vectors */
    (unsigned long long)(__builtin_offsetof(struct message, count)), /* shim_wire.offsetof.message.count */
    (unsigned long long)(__builtin_offsetof(struct message, control)), /* shim_wire.offsetof.message.control */
    (unsigned long long)(__builtin_offsetof(struct message, control_size)), /* shim_wire.offsetof.message.control_size */
    (unsigned long long)(__builtin_offsetof(struct message, flags)), /* shim_wire.offsetof.message.flags */
    (unsigned long long)(sizeof(struct rights)), /* shim_wire.sizeof.rights */
    (unsigned long long)(__builtin_offsetof(struct rights, size)), /* shim_wire.offsetof.rights.size */
    (unsigned long long)(__builtin_offsetof(struct rights, level)), /* shim_wire.offsetof.rights.level */
    (unsigned long long)(__builtin_offsetof(struct rights, kind)), /* shim_wire.offsetof.rights.kind */
    (unsigned long long)(__builtin_offsetof(struct rights, fd)), /* shim_wire.offsetof.rights.fd */
    (unsigned long long)(__builtin_offsetof(struct rights, padding)), /* shim_wire.offsetof.rights.padding */
    (unsigned long long)(sizeof(long)), /* sizeof.long */
    (unsigned long long)(sizeof(void *)), /* sizeof.void_pointer */
    (unsigned long long)(sizeof(unsigned int)), /* sizeof.unsigned_int */
    (unsigned long long)(sizeof(unsigned short)), /* sizeof.unsigned_short */
    (unsigned long long)(sizeof(unsigned long long)), /* sizeof.unsigned_long_long */
    (unsigned long long)(SECCOMP_IOCTL_NOTIF_RECV), /* SECCOMP_IOCTL_NOTIF_RECV */
    (unsigned long long)(SECCOMP_IOCTL_NOTIF_SEND), /* SECCOMP_IOCTL_NOTIF_SEND */
    (unsigned long long)(SECCOMP_IOCTL_NOTIF_ID_VALID), /* SECCOMP_IOCTL_NOTIF_ID_VALID */
    (unsigned long long)(SECCOMP_USER_NOTIF_FLAG_CONTINUE), /* SECCOMP_USER_NOTIF_FLAG_CONTINUE */
    (unsigned long long)(SECCOMP_FILTER_FLAG_NEW_LISTENER), /* SECCOMP_FILTER_FLAG_NEW_LISTENER */
    (unsigned long long)(SECCOMP_SET_MODE_FILTER), /* SECCOMP_SET_MODE_FILTER */
    (unsigned long long)(SECCOMP_GET_ACTION_AVAIL), /* SECCOMP_GET_ACTION_AVAIL */
    (unsigned long long)(SECCOMP_GET_NOTIF_SIZES), /* SECCOMP_GET_NOTIF_SIZES */
    (unsigned long long)(SECCOMP_RET_USER_NOTIF), /* SECCOMP_RET_USER_NOTIF */
    (unsigned long long)(SECCOMP_RET_ALLOW), /* SECCOMP_RET_ALLOW */
    (unsigned long long)(SECCOMP_RET_ERRNO), /* SECCOMP_RET_ERRNO */
    (unsigned long long)(SECCOMP_RET_KILL_PROCESS), /* SECCOMP_RET_KILL_PROCESS */
    (unsigned long long)(AUDIT_ARCH_AARCH64), /* AUDIT_ARCH_AARCH64 */
    (unsigned long long)(PR_SET_NO_NEW_PRIVS), /* PR_SET_NO_NEW_PRIVS */
    (unsigned long long)(PR_SET_SECCOMP), /* PR_SET_SECCOMP */
    (unsigned long long)(PR_SET_MM), /* PR_SET_MM */
    (unsigned long long)(PR_SET_PTRACER), /* PR_SET_PTRACER */
    (unsigned long long)(PR_SET_DUMPABLE), /* PR_SET_DUMPABLE */
    (unsigned long long)(AT_EMPTY_PATH), /* AT_EMPTY_PATH */
    (unsigned long long)(FD_CLOEXEC), /* FD_CLOEXEC */
    (unsigned long long)(F_SETFD), /* F_SETFD */
    (unsigned long long)(O_RDONLY), /* O_RDONLY */
    (unsigned long long)(O_NONBLOCK), /* O_NONBLOCK */
    (unsigned long long)(O_NOFOLLOW), /* O_NOFOLLOW */
    (unsigned long long)(O_CLOEXEC), /* O_CLOEXEC */
    (unsigned long long)(POLLIN), /* POLLIN */
    (unsigned long long)(POLLERR), /* POLLERR */
    (unsigned long long)(POLLHUP), /* POLLHUP */
    (unsigned long long)(POLLNVAL), /* POLLNVAL */
    (unsigned long long)(CLONE_VM), /* CLONE_VM */
    (unsigned long long)(CLONE_FS), /* CLONE_FS */
    (unsigned long long)(CLONE_FILES), /* CLONE_FILES */
    (unsigned long long)(CLONE_SIGHAND), /* CLONE_SIGHAND */
    (unsigned long long)(CLONE_THREAD), /* CLONE_THREAD */
    (unsigned long long)(CLONE_SYSVSEM), /* CLONE_SYSVSEM */
    (unsigned long long)(CLONE_SETTLS), /* CLONE_SETTLS */
    (unsigned long long)(CLONE_PARENT_SETTID), /* CLONE_PARENT_SETTID */
    (unsigned long long)(CLONE_CHILD_CLEARTID), /* CLONE_CHILD_CLEARTID */
    (unsigned long long)(__NR_execveat), /* __NR_execveat */
    (unsigned long long)(__NR_brk), /* __NR_brk */
    (unsigned long long)(__NR_clone), /* __NR_clone */
    (unsigned long long)(__NR_clone3), /* __NR_clone3 */
    (unsigned long long)(__NR_execve), /* __NR_execve */
    (unsigned long long)(__NR_seccomp), /* __NR_seccomp */
    (unsigned long long)(__NR_prctl), /* __NR_prctl */
    (unsigned long long)(__NR_sendmsg), /* __NR_sendmsg */
    (unsigned long long)(__NR_close), /* __NR_close */
    (unsigned long long)(__NR_dup3), /* __NR_dup3 */
    (unsigned long long)(__NR_fcntl), /* __NR_fcntl */
    (unsigned long long)(__NR_getpid), /* __NR_getpid */
    (unsigned long long)(__NR_exit_group), /* __NR_exit_group */
    (unsigned long long)(__NR_pidfd_open), /* __NR_pidfd_open */
    (unsigned long long)(__NR_pidfd_send_signal), /* __NR_pidfd_send_signal */
    (unsigned long long)(__NR_ptrace), /* __NR_ptrace */
    (unsigned long long)(__NR_process_vm_writev), /* __NR_process_vm_writev */
    (unsigned long long)(__NR_pidfd_getfd), /* __NR_pidfd_getfd */
    (unsigned long long)(__NR_unshare), /* __NR_unshare */
    (unsigned long long)(__NR_setns), /* __NR_setns */
    (unsigned long long)(__NR_io_uring_setup), /* __NR_io_uring_setup */
    (unsigned long long)(BPF_LD+BPF_W+BPF_ABS), /* BPF_LD_W_ABS */
    (unsigned long long)(BPF_JMP+BPF_JEQ+BPF_K), /* BPF_JMP_JEQ_K */
    (unsigned long long)(BPF_RET+BPF_K), /* BPF_RET_K */
    (unsigned long long)(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID), /* thread_clone_mask */
};
