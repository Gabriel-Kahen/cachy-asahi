/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors */
#define _GNU_SOURCE
#include "probe.h"
#include <dlfcn.h>
#include <elf.h>
#include <limits.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

typedef struct {
    unsigned long long start, end, inode;
    unsigned device_major, device_minor;
    char path[PATH_MAX];
} Mapping;
typedef struct { Mapping maps[128]; size_t count; const char *program; int first; } Identity;

static void string(const char *text)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

void probe_require(int condition, const char *name)
{
    if (condition) return;
    fputs("{\"kind\":\"failure\",\"check\":", stdout); string(name); puts("}");
    fflush(stdout); _exit(1);
}

void probe_test(const char *process, const char *name)
{
    fputs("{\"kind\":\"test\",\"process\":", stdout); string(process);
    fputs(",\"name\":", stdout); string(name); puts(",\"status\":\"PASS\"}");
}

static void mapping(const Mapping *map)
{
    char resolved[PATH_MAX]; struct stat info;
    probe_require(realpath(map->path, resolved) != NULL && stat(resolved, &info) == 0, "mapped-file-readable");
    probe_require((unsigned long long)info.st_ino == map->inode && major(info.st_dev) == map->device_major &&
                  minor(info.st_dev) == map->device_minor && S_ISREG(info.st_mode), "mapped-file-inode-device");
    fputs("{\"path\":", stdout); string(resolved);
    printf(",\"inode\":%llu,\"device_major\":%u,\"device_minor\":%u}", map->inode, map->device_major, map->device_minor);
}

static int object(struct dl_phdr_info *info, size_t size, void *opaque)
{
    (void)size; Identity *identity = opaque;
    const char *name = *info->dlpi_name ? info->dlpi_name : identity->program;
    if (strstr(name, "linux-vdso") || strstr(name, "linux-gate")) return 0;
    uintptr_t address = 0; int found = 0;
    for (ElfW(Half) n = 0; n < info->dlpi_phnum; n++) {
        if (info->dlpi_phdr[n].p_type == PT_LOAD && info->dlpi_phdr[n].p_filesz) {
            address = (uintptr_t)info->dlpi_addr + info->dlpi_phdr[n].p_vaddr; found = 1; break;
        }
    }
    probe_require(found, "object-file-load");
    for (size_t n = 0; n < identity->count; n++) {
        Mapping *map = &identity->maps[n];
        if (address >= map->start && address < map->end) {
            char resolved[PATH_MAX]; struct stat file;
            probe_require(realpath(name, resolved) != NULL && stat(resolved, &file) == 0 &&
                (unsigned long long)file.st_ino == map->inode && major(file.st_dev) == map->device_major &&
                minor(file.st_dev) == map->device_minor, "object-map-identity");
            if (!identity->first) putchar(',');
            identity->first = 0;
            mapping(map); return 0;
        }
    }
    probe_require(0, "object-mapping-missing"); return 1;
}

void probe_identity(const char *process, const char *program)
{
    Identity *identity = calloc(1, sizeof(*identity)); probe_require(identity != NULL, "identity-allocation");
    identity->program = program; identity->first = 1;
    FILE *maps = fopen("/proc/self/maps", "re"); probe_require(maps != NULL, "proc-maps");
    char line[PATH_MAX + 256];
    while (fgets(line, sizeof(line), maps)) {
        Mapping row = {0}; unsigned long long offset; char permissions[5]; int position = 0;
        if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &row.start, &row.end, permissions,
                   &offset, &row.device_major, &row.device_minor, &row.inode, &position) != 7) continue;
        char *path = line + position; while (*path == ' ' || *path == '\t') path++;
        path[strcspn(path, "\n")] = '\0';
        if (*path != '/' || row.inode == 0) continue;
        probe_require(identity->count < 128 && strlen(path) < sizeof(row.path), "mapped-file-bound");
        strcpy(row.path, path); identity->maps[identity->count++] = row;
    }
    probe_require(!ferror(maps) && fclose(maps) == 0, "proc-maps-complete");
    char executable[PATH_MAX]; ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    probe_require(length > 0, "proc-executable"); executable[length] = '\0';
    fputs("{\"kind\":\"identity\",\"process\":", stdout); string(process);
    fputs(",\"executable\":", stdout); string(executable);
    fputs(",\"objects\":[", stdout); dl_iterate_phdr(object, identity);
    fputs("],\"mapped_files\":[", stdout);
    int first = 1;
    for (size_t n = 0; n < identity->count; n++) {
        int duplicate = 0;
        for (size_t prior = 0; prior < n; prior++) {
            Mapping *a = &identity->maps[prior], *b = &identity->maps[n];
            if (a->inode == b->inode && a->device_major == b->device_major && a->device_minor == b->device_minor &&
                strcmp(a->path, b->path) == 0) duplicate = 1;
        }
        if (duplicate) continue;
        if (!first) putchar(',');
        first = 0; mapping(&identity->maps[n]);
    }
    fputs("],\"providers\":[", stdout);
    const char *symbols[] = {"malloc", "pthread_create", "iconv_open", "snprintf", "getaddrinfo", "clock_gettime", "getrandom", "cos"};
    for (size_t n = 0; n < sizeof(symbols) / sizeof(*symbols); n++) {
        Dl_info provider; void *symbol = dlsym(RTLD_DEFAULT, symbols[n]); char resolved[PATH_MAX];
        probe_require(symbol != NULL && dladdr(symbol, &provider) && realpath(provider.dli_fname, resolved), "symbol-provider");
        if (n) putchar(',');
        fputs("{\"symbol\":", stdout); string(symbols[n]);
        fputs(",\"path\":", stdout); string(resolved); putchar('}');
    }
    puts("]}"); fflush(stdout); free(identity);
}
