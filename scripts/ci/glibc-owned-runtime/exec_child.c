/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "probe.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    probe_require(argc == 3, "child-arguments");
    char *end; long closed = strtol(argv[2], &end, 10);
    probe_require(*end == '\0' && closed >= 3 && closed <= 1024, "child-fd-argument");
    errno = 0; probe_require(fcntl((int)closed, F_GETFD) == -1 && errno == EBADF, "exec-cloexec");
    probe_require(chdir(argv[1]) == 0, "child-private-directory");
    int file = open("exec-child-data", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    const char data[] = "child-data\n";
    probe_require(file >= 0 && write(file, data, sizeof(data) - 1) == (ssize_t)sizeof(data) - 1 && close(file) == 0, "child-file");
    probe_identity("child", argv[0]); probe_test("child", "exec_child");
    return 0;
}
