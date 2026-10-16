/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE 1
#include <features.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <dlfcn.h>
#include <locale.h>
#include <langinfo.h>
#include <iconv.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <linux/mount.h>
#include <sys/auxv.h>
#include <linux/types.h>
#include <gnu/libc-version.h>
#if __GLIBC__ != 2 || __GLIBC_MINOR__ != 43
#error Candidate GNU 2.43 headers required
#endif
_Static_assert(OPEN_TREE_CLONE == 1, "preserved mount clone flag");
_Static_assert(OPEN_TREE_CLOEXEC == O_CLOEXEC, "preserved mount close-on-exec flag");
_Static_assert(sizeof(void *) == 8 && sizeof(ssize_t) == 8, "aarch64 LP64 headers");
_Static_assert(sizeof(pthread_t) == 8, "aarch64 pthread handle");
void candidate_header_probe(void) {
    void *(*allocator)(size_t) = malloc;
    int (*thread)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = pthread_create;
    iconv_t (*conversion)(const char *, const char *) = iconv_open;
    void (*sized_free)(void *, size_t) = free_sized;
    (void)allocator; (void)thread; (void)conversion; (void)sized_free;
}
