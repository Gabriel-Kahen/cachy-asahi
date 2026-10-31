/* SPDX-License-Identifier: MIT */
#ifndef CACHY_GLIBC_PROBE_H
#define CACHY_GLIBC_PROBE_H
void probe_require(int condition, const char *name);
void probe_test(const char *process, const char *name);
void probe_identity(const char *process, const char *program);
#endif
