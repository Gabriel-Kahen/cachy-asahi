/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Called ONLY in the already-forked chroot test child. No exec, mount or PID ns. */
static int caa_owned_userns_write(const char *path, const char *value) {
        int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;
        size_t size = strlen(value);
        ssize_t n = write(fd, value, size);
        int error = n < 0 ? errno : EIO;
        if (close(fd) < 0 && n == (ssize_t) size)
                return -errno;
        return n == (ssize_t) size ? 0 : -error;
}

static int caa_owned_userns_map(const char *path, unsigned expected) {
        char raw[128];
        int fd = open(path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;
        ssize_t n = read(fd, raw, sizeof(raw)-1);
        int error = errno;
        if (close(fd) < 0 && n >= 0)
                return -errno;
        if (n <= 0 || n >= (ssize_t) sizeof(raw)-1)
                return n < 0 ? -error : -EIO;
        raw[n] = 0;
        unsigned inside, outside, count;
        char extra;
        return sscanf(raw, "%u %u %u %c", &inside, &outside, &count, &extra) == 3 &&
                inside == 0 && outside == expected && count == 1 ? 0 : -EINVAL;
}

static int caa_owned_userns_child_full(unsigned *stage) {
        struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
        struct __user_cap_data_struct data[2] = {0};
        uid_t uid = getuid();
        gid_t gid = getgid();
        char map[64];
        int r;

        if (stage) *stage = 1;
        if (uid == 0 || uid != geteuid() || gid != getegid())
                return -EPERM;
        if (syscall(SYS_capget, &header, data) < 0)
                return -errno;
        for (unsigned i = 0; i < 2; i++)
                if (data[i].effective || data[i].permitted)
                        return -EPERM;
        /* Remove any inherited-only session bits in this child, never add one. */
        memset(data, 0, sizeof(data));
        if (stage) *stage = 12;
        if (syscall(SYS_capset, &header, data) < 0)
                return -errno;
        if (stage) *stage = 2;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                return -errno;
        if (stage) *stage = 3;
        if (unshare(CLONE_NEWUSER) < 0)
                return -errno;
        /* Kernel grants capabilities only in this new, owned namespace. Map
         * exactly the caller, deny setgroups, then immediately retain CHROOT only. */
        if (stage) *stage = 4;
        r = caa_owned_userns_write("/proc/self/setgroups", "deny\n");
        if (r < 0)
                return r;
        if (snprintf(map, sizeof(map), "0 %u 1\n", (unsigned) uid) >= (int) sizeof(map))
                return -EOVERFLOW;
        if (stage) *stage = 5;
        r = caa_owned_userns_write("/proc/self/uid_map", map);
        if (r < 0)
                return r;
        if (snprintf(map, sizeof(map), "0 %u 1\n", (unsigned) gid) >= (int) sizeof(map))
                return -EOVERFLOW;
        if (stage) *stage = 6;
        r = caa_owned_userns_write("/proc/self/gid_map", map);
        if (r < 0)
                return r;
        memset(data, 0, sizeof(data));
        data[CAP_SYS_CHROOT / 32].effective = UINT32_C(1) << (CAP_SYS_CHROOT % 32);
        data[CAP_SYS_CHROOT / 32].permitted = data[CAP_SYS_CHROOT / 32].effective;
        if (stage) *stage = 7;
        if (syscall(SYS_capset, &header, data) < 0)
                return -errno;
        if (stage) *stage = 8;
        memset(data, 0, sizeof(data));
        if (syscall(SYS_capget, &header, data) < 0)
                return -errno;
        if (stage) *stage = 9;
        if (data[0].effective != (UINT32_C(1) << CAP_SYS_CHROOT) ||
            data[0].permitted != data[0].effective || data[0].inheritable ||
            data[1].effective || data[1].permitted || data[1].inheritable ||
            getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0)
                return -EPERM;
        if (stage) *stage = 10;
        r = caa_owned_userns_map("/proc/self/uid_map", uid);
        if (r < 0)
                return r;
        if (stage) *stage = 11;
        return caa_owned_userns_map("/proc/self/gid_map", gid);
}

static int caa_owned_userns_child(void) { return caa_owned_userns_child_full(NULL); }
