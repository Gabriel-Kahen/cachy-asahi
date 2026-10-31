// SPDX-License-Identifier: MIT
// Copyright (c) 2026 cachy-asahi contributors
#include <stdio.h>
#include <string.h>

static const char message[] = "Project version one";

int main(int argc, char **argv) {
    if (argc == 1)
        return puts(message) < 0;
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        if (!strlen(message) || strchr(message, '\n'))
            return 2;
        return printf("PROJECT_TEST_OK:%s\n", message) < 0;
    }
    return 2;
}
