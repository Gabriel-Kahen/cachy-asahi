/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors */
#define _GNU_SOURCE
#include "probe.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <iconv.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

extern char **environ;
static _Thread_local unsigned thread_cell = 0x1234;
static uint64_t *(*plugin_tls)(void);
static uint64_t (*plugin_transform)(uint64_t);
static pthread_key_t key;
static pthread_barrier_t barrier;
static _Atomic unsigned destructors;
typedef struct { unsigned slot; uintptr_t local, plugin; } Task;

static void allocation(void)
{
    unsigned char *zero = calloc(4096, 1); probe_require(zero != NULL, "calloc");
    for (size_t n = 0; n < 4096; n++) probe_require(zero[n] == 0, "calloc-zero");
    free(zero);
    unsigned char *data = malloc(257); probe_require(data != NULL, "malloc");
    for (size_t n = 0; n < 257; n++) data[n] = (unsigned char)(n ^ 0xa5);
    data = realloc(data, 16384); probe_require(data != NULL, "realloc-grow");
    for (size_t n = 0; n < 257; n++) probe_require(data[n] == (unsigned char)(n ^ 0xa5), "realloc-preserve");
    data = realloc(data, 128); probe_require(data != NULL, "realloc-shrink");
    for (size_t n = 0; n < 128; n++) probe_require(data[n] == (unsigned char)(n ^ 0xa5), "realloc-shrink-preserve");
    free(data);
    void *aligned = NULL;
    probe_require(posix_memalign(&aligned, 64, 8192) == 0 && (uintptr_t)aligned % 64 == 0, "aligned-allocation");
    memset(aligned, 0x7b, 8192); free(aligned); probe_test("parent", "allocation");
}

static void destructor(void *value) { free(value); atomic_fetch_add(&destructors, 1); }

static void *worker(void *opaque)
{
    Task *task = opaque; probe_require(thread_cell == 0x1234, "thread-local-initialization");
    thread_cell = 100 + task->slot; task->local = (uintptr_t)&thread_cell;
    uint64_t *cell = plugin_tls(); task->plugin = (uintptr_t)cell;
    probe_require(*cell == UINT64_C(0x1020304050607080), "plugin-tls-initialization");
    *cell = task->slot + 7;
    unsigned *specific = malloc(sizeof(*specific)); probe_require(specific != NULL, "thread-specific-allocation");
    *specific = task->slot;
    probe_require(pthread_setspecific(key, specific) == 0 && pthread_getspecific(key) == specific, "thread-specific-storage");
    uint64_t value = task->slot + 29;
    probe_require(plugin_transform(value) == (value ^ UINT64_C(0x55aa55aa55aa55aa)) + *cell, "plugin-thread-transform");
    int code = pthread_barrier_wait(&barrier);
    probe_require(code == 0 || code == PTHREAD_BARRIER_SERIAL_THREAD, "thread-barrier");
    probe_require(thread_cell == 100 + task->slot && *plugin_tls() == task->slot + 7, "thread-tls-isolation");
    return task;
}

static void threads(void)
{
    Task tasks[4]; pthread_t ids[4];
    probe_require(pthread_key_create(&key, destructor) == 0 && pthread_barrier_init(&barrier, NULL, 5) == 0, "pthread-setup");
    thread_cell = 909; *plugin_tls() = 999;
    for (unsigned n = 0; n < 4; n++) {
        tasks[n] = (Task){.slot = n}; probe_require(pthread_create(&ids[n], NULL, worker, &tasks[n]) == 0, "pthread-create");
    }
    int code = pthread_barrier_wait(&barrier);
    probe_require(code == 0 || code == PTHREAD_BARRIER_SERIAL_THREAD, "parent-barrier");
    for (unsigned n = 0; n < 4; n++) {
        void *result = NULL;
        probe_require(pthread_join(ids[n], &result) == 0 && result == &tasks[n], "pthread-join");
        for (unsigned m = 0; m < n; m++)
            probe_require(tasks[n].local != tasks[m].local && tasks[n].plugin != tasks[m].plugin, "distinct-thread-tls-addresses");
    }
    probe_require(thread_cell == 909 && *plugin_tls() == 999 && atomic_load(&destructors) == 4, "parent-tls-and-destructors");
    probe_require(pthread_key_delete(key) == 0 && pthread_barrier_destroy(&barrier) == 0, "pthread-retirement");
    probe_test("parent", "pthread_tls_join");
}

static iconv_t unicode(void)
{
    probe_require(setlocale(LC_ALL, "C.UTF-8") || setlocale(LC_ALL, "C.utf8"), "candidate-utf8-locale");
    probe_require(MB_CUR_MAX >= 4, "utf8-locale-width");
    mbstate_t state = {0}; wchar_t code;
    probe_require(mbrtowc(&code, "\xe2\x82\xac", 3, &state) == 3 && code == 0x20ac, "utf8-decode");
    char encoded[MB_LEN_MAX]; memset(&state, 0, sizeof(state));
    probe_require(wcrtomb(encoded, code, &state) == 3 && memcmp(encoded, "\xe2\x82\xac", 3) == 0, "utf8-encode");
    memset(&state, 0, sizeof(state)); errno = 0;
    probe_require(mbrtowc(&code, "\xc0\xaf", 2, &state) == (size_t)-1 && errno == EILSEQ, "invalid-utf8");
    iconv_t converter = iconv_open("UTF-8", "ISO-8859-1");
    probe_require(converter != (iconv_t)-1, "candidate-iconv-module");
    char input[] = {'A', (char)0xe9}, output[16] = {0}; char *from = input, *to = output;
    size_t input_left = sizeof(input), output_left = sizeof(output);
    probe_require(iconv(converter, &from, &input_left, &to, &output_left) == 0 && input_left == 0 &&
                  to - output == 3 && memcmp(output, "A\xc3\xa9", 3) == 0, "iconv-transcode");
    probe_test("parent", "utf8_iconv_locale"); return converter;
}

static void numeric(void)
{
    probe_require(setlocale(LC_NUMERIC, "C") != NULL, "numeric-locale");
    char buffer[128];
    probe_require(snprintf(buffer, sizeof(buffer), "%.6f %.3e %a", 0.125, 12340.0, 1.5) > 0 &&
                  strcmp(buffer, "0.125000 1.234e+04 0x1.8p+0") == 0, "numeric-formatting");
    char *end; errno = 0;
    probe_require(strtod("0x1.8p+1", &end) == 3.0 && *end == '\0' && errno == 0, "numeric-parsing");
    errno = 0; long value = strtol("999999999999999999999999999999999999999", &end, 10);
    probe_require(value == LONG_MAX && errno == ERANGE && *end == '\0', "numeric-overflow");
    volatile double x = 0.5;
    double a = sin(x), b = cos(x), c = sqrt(2.0);
    probe_require(fabs(a * a + b * b - 1.0) < 1e-14 && fabs(c * c - 2.0) < 1e-14 &&
                  fabs(log(exp(0.25)) - 0.25) < 1e-14, "libm-identities");
    probe_test("parent", "numeric_math");
}

static void file_clock_random(int directory)
{
    int file = openat(directory, "fd-probe", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    const char initial[] = "owned-libc-fd"; char expected[sizeof(initial)], observed[sizeof(initial)] = {0};
    memcpy(expected, initial, sizeof(initial)); memcpy(expected + 6, "ABI", 3);
    probe_require(file >= 0 && write(file, initial, sizeof(initial) - 1) == (ssize_t)sizeof(initial) - 1 &&
                  pwrite(file, "ABI", 3, 6) == 3 && fsync(file) == 0, "fd-write");
    int duplicate = fcntl(file, F_DUPFD_CLOEXEC, 3);
    probe_require(duplicate >= 0 && pread(duplicate, observed, sizeof(initial) - 1, 0) == (ssize_t)sizeof(initial) - 1 &&
                  memcmp(observed, expected, sizeof(initial) - 1) == 0, "fd-read-duplicate");
    struct stat a, b;
    probe_require(fstat(file, &a) == 0 && fstatat(directory, "fd-probe", &b, AT_SYMLINK_NOFOLLOW) == 0 &&
                  S_ISREG(a.st_mode) && a.st_uid == getuid() && a.st_ino == b.st_ino && a.st_dev == b.st_dev &&
                  a.st_size == (off_t)sizeof(initial) - 1 && (a.st_mode & 0777) == 0600, "fd-stat");
    probe_require(close(duplicate) == 0 && close(file) == 0 && unlinkat(directory, "fd-probe", 0) == 0, "fd-close-unlink");
    struct timespec before, after, resolution, pause = {.tv_nsec = 1000000};
    probe_require(clock_gettime(CLOCK_MONOTONIC, &before) == 0 && clock_getres(CLOCK_MONOTONIC, &resolution) == 0 &&
                  (resolution.tv_sec > 0 || resolution.tv_nsec > 0) && nanosleep(&pause, NULL) == 0 &&
                  clock_gettime(CLOCK_MONOTONIC, &after) == 0 &&
                  (after.tv_sec > before.tv_sec || (after.tv_sec == before.tv_sec && after.tv_nsec >= before.tv_nsec)), "clock");
    unsigned char random[32]; size_t done = 0;
    while (done < sizeof(random)) {
        ssize_t bytes = getrandom(random + done, sizeof(random) - done, 0);
        if (bytes < 0 && errno == EINTR) continue;
        probe_require(bytes > 0, "getrandom"); done += (size_t)bytes;
    }
    probe_test("parent", "fd_stat_clock_random");
}

static void numeric_lookup(void)
{
    const char *hosts[] = {"127.0.0.1", "::1"}; int families[] = {AF_INET, AF_INET6};
    for (unsigned n = 0; n < 2; n++) {
        struct addrinfo hints = {.ai_family = families[n], .ai_socktype = SOCK_STREAM, .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV};
        struct addrinfo *result = NULL;
        probe_require(getaddrinfo(hosts[n], "443", &hints, &result) == 0 && result && result->ai_next == NULL, "numeric-getaddrinfo");
        char host[NI_MAXHOST], service[NI_MAXSERV];
        probe_require(getnameinfo(result->ai_addr, result->ai_addrlen, host, sizeof(host), service, sizeof(service),
                      NI_NUMERICHOST | NI_NUMERICSERV) == 0 && strcmp(host, hosts[n]) == 0 && strcmp(service, "443") == 0, "numeric-getnameinfo");
        freeaddrinfo(result);
    }
    probe_test("parent", "numeric_address_lookup");
}

static void child_exec(int directory, const char *loader, const char *libraries, const char *child, const char *work)
{
    int inherited = openat(directory, "exec-inherit", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600), pipefd[2];
    probe_require(inherited >= 3 && pipe2(pipefd, O_CLOEXEC) == 0, "fork-pipe");
    char fd[32]; snprintf(fd, sizeof(fd), "%d", inherited); fflush(stdout);
    pid_t pid = fork(); probe_require(pid >= 0, "fork");
    if (pid == 0) {
        close(pipefd[0]); probe_require(dup2(pipefd[1], STDOUT_FILENO) == STDOUT_FILENO, "child-stdout"); close(pipefd[1]);
        (void)loader; (void)libraries;
        char *arguments[] = {(char *)child, (char *)work, fd, NULL};
        execve(child, arguments, environ); probe_require(0, "exec-system-interpreter");
    }
    close(pipefd[1]); char output[262144]; size_t size = 0;
    for (;;) {
        probe_require(size < sizeof(output), "child-output-bound");
        ssize_t bytes = read(pipefd[0], output + size, sizeof(output) - size);
        if (bytes < 0 && errno == EINTR) continue;
        probe_require(bytes >= 0, "child-pipe-read"); if (bytes == 0) break; size += (size_t)bytes;
    }
    probe_require(close(pipefd[0]) == 0 && close(inherited) == 0, "parent-fd-close");
    int status; probe_require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "exec-wait");
    probe_require(fwrite(output, 1, size, stdout) == size && unlinkat(directory, "exec-inherit", 0) == 0, "child-output");
    char text[32] = {0}; int data = openat(directory, "exec-child-data", O_RDONLY | O_CLOEXEC);
    probe_require(data >= 0 && read(data, text, sizeof(text)) == 11 && strcmp(text, "child-data\n") == 0 &&
                  close(data) == 0 && unlinkat(directory, "exec-child-data", 0) == 0, "exec-file-result");
    probe_test("parent", "fork_exec_wait");
}

int main(int argc, char **argv)
{
    probe_require(argc == 6, "arguments");
    probe_require(chdir(argv[5]) == 0, "private-workspace");
    int directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); probe_require(directory >= 0, "private-directory");
    allocation();
    void *plugin = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL); probe_require(plugin != NULL, "dlopen-plugin");
    int (*abi)(void) = (int (*)(void))dlsym(plugin, "smoke_plugin_abi");
    plugin_tls = (uint64_t *(*)(void))dlsym(plugin, "smoke_plugin_tls");
    plugin_transform = (uint64_t (*)(uint64_t))dlsym(plugin, "smoke_plugin_transform");
    probe_require(abi && plugin_tls && plugin_transform && abi() == 1, "dlsym-plugin");
    probe_test("parent", "dlopen_dlsym"); threads();
    iconv_t converter = unicode(); numeric(); file_clock_random(directory); numeric_lookup();
    child_exec(directory, argv[1], argv[2], argv[4], argv[5]);
    probe_identity("parent", argv[0]);
    probe_require(iconv_close(converter) == 0 && dlclose(plugin) == 0 && close(directory) == 0, "runtime-resource-close");
    printf("{\"kind\":\"result\",\"status\":\"PASS\",\"cases\":8,\"page_size\":%ld,\"glibc_version\":\"%s\"}\n", sysconf(_SC_PAGESIZE), gnu_get_libc_version());
    return 0;
}
