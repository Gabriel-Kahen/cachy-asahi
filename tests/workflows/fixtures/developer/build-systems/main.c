/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
#include "greeting.h"
int main(int argc, char **argv) {
    if (argc == 1) return fputs(greeting(), stdout) < 0;
    if (argc != 3 || strcmp(argv[1], "--self-test")) return 2;
    FILE *file = fopen(argv[2], "rb");
    char expected[128] = {0};
    if (!file) return 3;
    size_t count = fread(expected, 1, sizeof(expected) - 1, file);
    int bad = ferror(file) || !feof(file);
    if (fclose(file)) return 4;
    if (bad || count != strlen(greeting()) || memcmp(expected, greeting(), count)) {
        fputs("INTENTIONAL_TEST_MISMATCH\n", stderr);
        return 5;
    }
    return fputs("DEVELOPER_TEST_OK\n", stdout) < 0;
}
