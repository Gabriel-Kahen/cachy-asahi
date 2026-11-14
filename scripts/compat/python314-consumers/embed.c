// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <Python.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if PY_VERSION_HEX != 0x030e08f0
#error This consumer requires the selected Python 3.14.8 headers
#endif

int main(int argc, char **argv) {
    if (argc != 5) return 40;
    /* Refuse a system-library fallback before initializing Python. */
    Dl_info info;
    char loaded[PATH_MAX], expected[PATH_MAX];
    if (!dladdr((void *)Py_GetVersion, &info) ||
        !realpath(info.dli_fname, loaded) || !realpath(argv[4], expected) ||
        strcmp(loaded, expected) || strncmp(Py_GetVersion(), "3.14.8 ", 7)) {
        fputs("consumer-library-identity-refused\n", stderr);
        return 41;
    }
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.site_import = 0;
    config.write_bytecode = 0;
    config.parse_argv = 0;
    PyStatus status = PyConfig_SetBytesString(&config, &config.home, argv[2]);
    if (!PyStatus_Exception(status))
        status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (!PyStatus_Exception(status)) status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        fputs("consumer-initialization-refused\n", stderr);
        return 42;
    }
    int result = PyRun_SimpleString(
        "import runpy, sys\n"
        "sys._consumer_embedding = True\n"
        "runpy.run_path(sys.argv[1], run_name='__main__')\n");
    int finalized = Py_FinalizeEx();
    return result || finalized < 0 ? 43 : 0;
}
