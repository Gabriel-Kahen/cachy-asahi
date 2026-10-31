/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 cachy-asahi contributors
 * Finite functional probe; linked with this package's local static libz.a.
 */
#define _XOPEN_SOURCE 700
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zlib.h"
#ifndef EXPERIMENT_VARIANT
#error EXPERIMENT_VARIANT is required
#endif
#ifndef EXPERIMENT_PREFIX
#error EXPERIMENT_PREFIX is required
#endif
int main(int argc, char **argv) {
    static const size_t sizes[] = {0, 1, 16383, 16384, 16385, 65537, 1048576};
    static const int levels[] = {1, 6, 9};
    unsigned char *input = NULL, *packed = NULL, *output = NULL;
    char resolved[PATH_MAX];
    size_t n, i, k;
    unsigned cases = 0;
    int status = 1;
    if (argc != 2 || (strcmp(argv[1], "--build-check") && strcmp(argv[1], "--installed-check"))) {
        fputs("usage: probe --build-check|--installed-check\n", stderr); return 2;
    }
    if (!strcmp(argv[1], "--installed-check") &&
        (!realpath("/proc/self/exe", resolved) || strcmp(resolved, EXPERIMENT_PREFIX "/bin/probe"))) {
        fputs("probe: installed prefix differs\n", stderr); return 2;
    }
    if (strcmp(zlibVersion(), "1.3.2") || strcmp(ZLIB_VERSION, zlibVersion())) {
        fputs("probe: header/library version differs\n", stderr); return 1;
    }
    input = malloc(1048576); packed = malloc(compressBound(1048576)); output = malloc(1048576);
    if (!input || !packed || !output) goto done;
    for (i = 0; i < 1048576; ++i) input[i] = (unsigned char)((i * 13U + i / 257U) & 255U);
    for (n = 0; n < sizeof(sizes)/sizeof(sizes[0]); ++n) {
        for (k = 0; k < sizeof(levels)/sizeof(levels[0]); ++k) {
            uLongf bytes = compressBound((uLong)sizes[n]), decoded = 1048576;
            if (compress2(packed, &bytes, input, (uLong)sizes[n], levels[k]) != Z_OK || bytes < 6) goto done;
            if (uncompress(output, &decoded, packed, bytes) != Z_OK || decoded != sizes[n] ||
                memcmp(input, output, sizes[n])) goto done;
            decoded = 1048576;
            if (uncompress(output, &decoded, packed, bytes - 1) == Z_OK) goto done;
            packed[bytes - 1] ^= 1U; decoded = 1048576;
            if (uncompress(output, &decoded, packed, bytes) == Z_OK) goto done;
            ++cases;
        }
    }
    printf("{\"status\":\"PASS\",\"variant\":\"%s\",\"prefix\":\"%s\","
           "\"zlib\":\"%s\",\"source_sha256\":\"bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16\","
           "\"roundtrips\":%u,\"negative_checks\":%u}\n",
           EXPERIMENT_VARIANT, EXPERIMENT_PREFIX, zlibVersion(), cases, cases * 2U);
    status = 0;
done:
    free(input); free(packed); free(output);
    if (status) fputs("probe: finite correctness check failed\n", stderr);
    return status;
}
