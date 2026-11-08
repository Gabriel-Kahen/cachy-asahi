#define OLD_ONLY "/usr/lib/cachy-asahi/security-maintenance-v1/payload-pins.json"
#define NEW_ONLY "/usr/lib/cachy-asahi/security-maintenance-v2/payload-pins.json"
/* SPDX-License-Identifier: MIT
 * Future interruption role only: block at the exact first UPGRADE checkpoint. */
#define _GNU_SOURCE
#include <alpm.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/sysmacros.h>
_Static_assert(ALPM_PROGRESS_UPGRADE_START == 1, "pinned libalpm16 progress ABI");
static alpm_handle_t *bound;
static alpm_cb_progress original;
static void *original_ctx;
static unsigned registrations, hits, errors;
static int observed_fd = -1;
static int eligible(void) {
    char exe[128];
    const char *fd = getenv("CACHY_SECURITY_OBSERVER_FD");
    const char *owner = getenv("CACHY_SECURITY_OBSERVER_OWNER");
    if(!fd || !owner || !*fd || !*owner) return 0;
    char *end;
    long value = strtol(fd, &end, 10);
    if(*end || value < 3 || value > 127) return 0;
    long parent = strtol(owner, &end, 10);
    if(*end || parent != getppid() || parent <= 1) return 0;
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if(n <= 0 || n >= (ssize_t)sizeof(exe)-1) return 0;
    exe[n] = 0;
    if(strcmp(exe, "/usr/bin/pacman")) return 0;
    struct stat s;
    if(fstat((int)value, &s) || !S_ISREG(s.st_mode) || (s.st_mode & 0777) != 0600 ||
       s.st_uid || s.st_gid || s.st_nlink != 1 || s.st_size > 16384) return 0;
    observed_fd = (int)value;
    return 1;
}

struct observer_load {
    unsigned long long base, pc, start, end, offset, inode;
    unsigned dev_major, dev_minor;
    struct stat object;
};
static int observer_object(void *pc, struct observer_load *value) {
    const char *text = getenv("CACHY_SECURITY_OBSERVER_OBJECT_FD");
    if(!text || !*text) return 0;
    char *end;
    long number = strtol(text, &end, 10);
    if(*end || number < 3 || number > 127 || number == observed_fd) return 0;
    int flags = fcntl((int)number, F_GETFL);
    struct stat file, named;
    Dl_info self;
    if(flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat((int)number, &file) ||
       !S_ISREG(file.st_mode) || (file.st_mode & 0777) != 0500 || file.st_uid || file.st_gid ||
       file.st_nlink != 1 || file.st_size <= 0 || file.st_size > 1048576 ||
       !dladdr(pc, &self) || !self.dli_fname || !self.dli_fbase ||
       lstat(self.dli_fname, &named) || !S_ISREG(named.st_mode) ||
       named.st_dev != file.st_dev || named.st_ino != file.st_ino) return 0;
    int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if(maps < 0) return 0;
    char data[65537];
    size_t used = 0;
    while(used < sizeof(data)) {
        ssize_t got = read(maps, data + used, sizeof(data) - used);
        if(got < 0 && errno == EINTR) continue;
        if(got < 0) { close(maps); return 0; }
        if(!got) break;
        used += (size_t)got;
    }
    close(maps);
    if(!used || used > 65536 || data[used - 1] != '\n') return 0;
    data[used] = 0;
    unsigned matches = 0;
    for(char *line = data; *line;) {
        char *next = strchr(line, '\n');
        if(!next) return 0;
        *next = 0;
        unsigned long long start, finish, offset, inode;
        unsigned dev_major, dev_minor;
        char permissions[5];
        if(sscanf(line, "%llx-%llx %4s %llx %x:%x %llu", &start, &finish,
                  permissions, &offset, &dev_major, &dev_minor, &inode) == 7 &&
           (unsigned long long)(uintptr_t)pc >= start && (unsigned long long)(uintptr_t)pc < finish) {
            if(strcmp(permissions, "r-xp") || makedev(dev_major, dev_minor) != file.st_dev ||
               inode != (unsigned long long)file.st_ino || offset >= (unsigned long long)file.st_size) return 0;
            value->base = (unsigned long long)(uintptr_t)self.dli_fbase;
            value->pc = (unsigned long long)(uintptr_t)pc;
            value->start = start; value->end = finish; value->offset = offset;
            value->dev_major = dev_major; value->dev_minor = dev_minor; value->inode = inode;
            value->object = file;
            matches++;
        }
        line = next + 1;
    }
    return matches == 1;
}

static int missing(const char *path) {
    struct stat s;
    return lstat(path, &s) == 0 ? 0 : errno;
}
static void emit(const char *text, int n) {
    if(!eligible() || n <= 0 || n >= 4096) { errors++; return; }
    struct stat s;
    if(fstat(observed_fd, &s) || s.st_size + n > 16384) { errors++; return; }
    ssize_t written;
    do { written = write(observed_fd, text, (size_t)n); } while(written < 0 && errno == EINTR);
    if(written != n) errors++;
}

/* A missing or failed control channel is a failed episode, never a recovery
 * authorization. Only the owned parent can produce the positive SIGKILL proof. */
static void recovery_block(void) {
    const char *text = getenv("CACHY_SECURITY_RECOVERY_FD");
    const char *nonce = getenv("CACHY_SECURITY_RECOVERY_NONCE");
    char *end;
    if(!text || !*text || !nonce || strlen(nonce) != 32 || errors) _exit(92);
    for(unsigned i = 0; i < 32; i++)
        if(!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) _exit(92);
    long number = strtol(text, &end, 10);
    if(*end || number < 3 || number > 127 || number == observed_fd) _exit(92);
    struct stat st;
    struct ucred peer;
    socklen_t size = sizeof(peer);
    int type;
    socklen_t type_size = sizeof(type);
    if(fstat((int)number, &st) || !S_ISSOCK(st.st_mode) || st.st_uid || st.st_gid ||
       (st.st_mode & 0777) != 0600 ||
       getsockopt((int)number, SOL_SOCKET, SO_TYPE, &type, &type_size) || type != SOCK_SEQPACKET ||
       getsockopt((int)number, SOL_SOCKET, SO_PEERCRED, &peer, &size) || size != sizeof(peer) ||
       peer.pid != getppid() || peer.uid || peer.gid || fsync(observed_fd)) _exit(92);
    char ready[80];
    int count = snprintf(ready, sizeof(ready), "RECOVERY_BLOCK_V1:%s", nonce);
    if(count <= 0 || count >= (int)sizeof(ready) ||
       send((int)number, ready, (size_t)count, MSG_NOSIGNAL) != count) _exit(93);
    struct timespec start, now;
    if(clock_gettime(CLOCK_MONOTONIC, &start)) _exit(94);
    for(;;) {
        if(clock_gettime(CLOCK_MONOTONIC, &now)) _exit(94);
        long long elapsed = ((long long)now.tv_sec - start.tv_sec) * 1000 +
                            ((long long)now.tv_nsec - start.tv_nsec) / 1000000;
        if(elapsed < 0 || elapsed >= 30000) _exit(94);
        struct pollfd wait = { .fd = (int)number, .events = POLLIN };
        int status = poll(&wait, 1, (int)(30000 - elapsed));
        if(status < 0 && errno == EINTR) continue;
        /* Any input, hangup, timeout or failure is not the parent's owned kill. */
        _exit(94);
    }
}

static void observe(void *ctx, alpm_progress_t event, const char *pkg,
                    int percent, size_t howmany, size_t current) {
    int saved_errno = errno;
    (void)ctx;
    if(!hits && eligible() && event == ALPM_PROGRESS_UPGRADE_START && pkg &&
       !strcmp(pkg, "cachy-asahi-security-maintenance") && percent == 0 && howmany == 1 && current == 1) {
        hits++;
        struct stat lock, exe, lib;
        struct observer_load object;
        int le = lstat("/var/lib/pacman/db.lck", &lock);
        int pe = stat("/proc/self/exe", &exe);
        int ae = stat("/usr/lib/libalpm.so.16.0.1", &lib);
        char row[4096];
        if(le || pe || ae || !observer_object((void *)observe, &object)) errors++;
        else {
            int n = snprintf(row, sizeof(row),
              "{\"type\":\"FIRST_UPGRADE_ZERO\",\"pid\":%ld,\"ppid\":%ld,\"event\":1,\"percent\":0,\"howmany\":1,\"current\":1,"
              "\"old_only_errno\":%d,\"new_only_errno\":%d,\"old_desc_errno\":%d,\"new_desc_errno\":%d,"
              "\"lock\":{\"dev\":%llu,\"ino\":%llu,\"mode\":%u,\"uid\":%u,\"gid\":%u,\"nlink\":%llu,\"bytes\":%lld},"
              "\"symbol_object_verified\":1,\"pacman_inode\":[%llu,%llu],\"libalpm_inode\":[%llu,%llu],"
              "\"observer_inode\":[%llu,%llu],\"observer_fd_inode\":[%llu,%llu],"
              "\"observer_load\":{\"base\":%llu,\"pc\":%llu,\"start\":%llu,\"end\":%llu,\"offset\":%llu,\"dev_major\":%u,\"dev_minor\":%u,\"inode\":%llu}}\n",
              (long)getpid(), (long)getppid(), missing(OLD_ONLY), missing(NEW_ONLY),
              missing("/var/lib/pacman/local/cachy-asahi-security-maintenance-0.1.0-1/desc"),
              missing("/var/lib/pacman/local/cachy-asahi-security-maintenance-0.1.0-2/desc"),
              (unsigned long long)lock.st_dev, (unsigned long long)lock.st_ino, (unsigned)lock.st_mode,
              (unsigned)lock.st_uid, (unsigned)lock.st_gid, (unsigned long long)lock.st_nlink, (long long)lock.st_size,
              (unsigned long long)exe.st_dev, (unsigned long long)exe.st_ino,
              (unsigned long long)lib.st_dev, (unsigned long long)lib.st_ino,
              (unsigned long long)object.object.st_dev, (unsigned long long)object.object.st_ino,
              (unsigned long long)object.object.st_dev, (unsigned long long)object.object.st_ino,
              object.base, object.pc, object.start, object.end, object.offset,
              object.dev_major, object.dev_minor, object.inode);
            emit(row, n);
            recovery_block();
        }
    }
    errno = saved_errno;
    if(original) original(original_ctx, event, pkg, percent, howmany, current);
}
int alpm_option_set_progresscb(alpm_handle_t *h, alpm_cb_progress cb, void *ctx) {
    int saved_errno = errno;
    typedef int (*setter)(alpm_handle_t *, alpm_cb_progress, void *);
    setter real = (setter)dlsym(RTLD_NEXT, "alpm_option_set_progresscb");
    if(!real) return -1;
    if(!eligible()) { errno = saved_errno; return real(h, cb, ctx); }
    if(!cb) {
        errno = saved_errno;
        int result = real(h, cb, ctx);
        if(result == 0 && h == bound) { bound = NULL; original = NULL; original_ctx = NULL; }
        return result;
    }
    if(bound && bound != h) { errors++; errno = saved_errno; return real(h, cb, ctx); }
    Dl_info object;
    struct stat actual_object, approved_object;
    if(!dladdr((void *)real, &object) || !object.dli_fname ||
       stat(object.dli_fname, &actual_object) || stat("/usr/lib/libalpm.so.16.0.1", &approved_object) ||
       actual_object.st_dev != approved_object.st_dev || actual_object.st_ino != approved_object.st_ino) {
        errors++; errno = saved_errno; return real(h, cb, ctx);
    }
    errno = saved_errno;
    int result = real(h, observe, NULL);
    if(result == 0) { bound = h; original = cb; original_ctx = ctx; registrations++; }
    return result;
}
alpm_cb_progress alpm_option_get_progresscb(alpm_handle_t *h) {
    int saved_errno = errno;
    typedef alpm_cb_progress (*getter)(alpm_handle_t *);
    getter real = (getter)dlsym(RTLD_NEXT, "alpm_option_get_progresscb");
    errno = saved_errno;
    return h == bound && bound ? original : (real ? real(h) : NULL);
}
void *alpm_option_get_progresscb_ctx(alpm_handle_t *h) {
    int saved_errno = errno;
    typedef void *(*getter)(alpm_handle_t *);
    getter real = (getter)dlsym(RTLD_NEXT, "alpm_option_get_progresscb_ctx");
    errno = saved_errno;
    return h == bound && bound ? original_ctx : (real ? real(h) : NULL);
}
__attribute__((destructor)) static void finish(void) {
    if(eligible()) {
        char row[256];
        int n = snprintf(row, sizeof(row), "{\"type\":\"END\",\"pid\":%ld,\"registrations\":%u,\"hits\":%u,\"errors\":%u}\n",
                         (long)getpid(), registrations, hits, errors);
        emit(row, n);
    }
}
