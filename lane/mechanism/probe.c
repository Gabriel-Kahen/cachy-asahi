/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "caa-owned-userns.h"
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

static pid_t children[2];
static unsigned checks;
static void cleanup(void) {
        for (unsigned i = 0; i < 2; i++)
                if (children[i] > 0)
                        (void) kill(children[i], SIGKILL);
        for (unsigned i = 0; i < 2; i++)
                if (children[i] > 0) {
                        int status;
                        if (waitpid(children[i], &status, 0) != children[i])
                                _exit(126);
                        children[i] = 0;
                }
}
static void check(int value, const char *stage) {
        if (!value) {
                fprintf(stderr, "CAA_USERNS_PROBE_FAIL %s errno=%d\n", stage, errno);
                exit(1);
        }
        checks++;
}
static struct stat metadata(pid_t pid, const char *leaf) {
        char path[96];
        struct stat value;
        check(snprintf(path, sizeof(path), "/proc/%ld/%s", (long) pid, leaf) < (int) sizeof(path), "bounded-proc-path");
        check(stat(path, &value) == 0, "proc-metadata-readable");
        return value;
}
static int same(struct stat a, struct stat b) { return a.st_dev == b.st_dev && a.st_ino == b.st_ino; }
static void signal_event(int fd) {
        uint64_t one = 1;
        check(write(fd, &one, sizeof(one)) == sizeof(one), "eventfd-write");
}
static void await_event(int fd) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        uint64_t one;
        check(poll(&p, 1, 3000) == 1 && p.revents == POLLIN, "bounded-eventfd-ready");
        check(read(fd, &one, sizeof(one)) == sizeof(one) && one == 1, "exact-eventfd-read");
}
static void freeze_child(void) { for (;;) pause(); }
int main(int argc, char **argv) {
        int native = argc == 2 && strcmp(argv[1], "--native-preflight") == 0;
        int (*setup_identity)(void) = caa_owned_userns_child;
        check(setup_identity != NULL, "same-setup-wrapper");
        check(argc == 2 && (native || strcmp(argv[1], "--mechanism") == 0), "fixed-mode");
        check(getuid() != 0 && getuid() == geteuid() && getgid() == getegid(), "ordinary-nonroot-caller");
        check(atexit(cleanup) == 0, "cleanup-registration");
        struct stat root = metadata(getpid(), "root"), user = metadata(getpid(), "ns/user");
        struct stat mount = metadata(getpid(), "ns/mnt"), pidns = metadata(getpid(), "ns/pid");
        if (native) {
                struct stat pid1 = metadata(1, "root");
                /* Both original directions must be accessible. Equality itself
                 * may be either true or false in the upstream PID1 assertions. */
                check(same(pid1, metadata(1, "root")), "pid1-both-orders-readable");
        }
        int ready = eventfd(0, EFD_CLOEXEC), proceed = eventfd(0, EFD_CLOEXEC);
        check(ready >= 0 && proceed >= 0, "eventfds");
        pid_t parent = getpid();
        children[0] = fork();
        check(children[0] >= 0, "child1-fork");
        if (children[0] == 0) {
                children[0] = children[1] = 0;
                check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent, "child1-owned-lifetime");
                signal_event(ready);
                freeze_child();
        }
        await_event(ready);
        check(same(root, metadata(children[0], "root")), "original-child1-same-root");
        children[1] = fork();
        check(children[1] >= 0, "child2-fork");
        if (children[1] == 0) {
                children[0] = children[1] = 0;
                check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent, "child2-owned-lifetime");
                unsigned stage = 0;
                int r = caa_owned_userns_child_full(&stage);
                if (r < 0) fprintf(stderr, "CAA_USERNS_SETUP_FAILURE stage=%u errno=%d\n", stage, -r);
                if (r < 0) errno = -r;
                check(r == 0, "child2-userns-self-map-chroot-only");
                check(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && getppid() == parent, "child2-still-owned");
                signal_event(ready);
                await_event(proceed);
                check(chroot("/usr") == 0, "actual-original-chroot-usr");
                signal_event(ready);
                freeze_child();
        }
        await_event(ready);
        struct stat before = metadata(children[1], "root");
        check(same(root, before), "userns-only-self-child2-SAME");
        check(same(before, root), "userns-only-child2-self-SAME");
        check(!same(user, metadata(children[1], "ns/user")), "only-child2-new-userns");
        check(same(mount, metadata(children[1], "ns/mnt")), "child2-mountns-unchanged");
        check(same(pidns, metadata(children[1], "ns/pid")), "child2-pidns-unchanged");
        signal_event(proceed);
        await_event(ready);
        struct stat after = metadata(children[1], "root");
        check(!same(root, after), "real-chroot-self-child2-DIFFERENT");
        check(!same(after, root), "real-chroot-child2-self-DIFFERENT");
        struct stat usr;
        check(stat("/usr", &usr) == 0 && same(usr, after), "exact-chroot-usr-root");
        check(same(user, metadata(getpid(), "ns/user")), "parent-userns-unchanged");
        check(same(mount, metadata(getpid(), "ns/mnt")), "parent-mountns-unchanged");
        check(same(pidns, metadata(getpid(), "ns/pid")), "parent-pidns-unchanged");
        cleanup();
        check(close(ready) == 0 && close(proceed) == 0, "owned-eventfds-closed");
        printf("{\"schema\":1,\"status\":\"PASS_OWNED_USERNS_CHROOT_MECHANISM_ONLY\",\"mode\":\"%s\",\"parent_namespace\":\"UNCHANGED\",\"child_namespace\":\"USER_ONLY\",\"mapping\":\"SELF_ONLY\",\"retained_capabilities\":\"SYS_CHROOT_ONLY\",\"before_chroot\":[true,true],\"after_chroot\":[false,false],\"original_child1\":true,\"chroot\":\"/usr\",\"retirement\":\"BOTH_OWNED_CHILDREN_REAPED\",\"checks\":%u,\"systemd_test\":\"NOT_EXECUTED\",\"native_ARM\":\"NOT_ESTABLISHED_BY_THIS_PROBE\"}\n", native ? "native-preflight" : "mechanism", checks);
        return 0;
}
