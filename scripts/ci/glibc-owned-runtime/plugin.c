/* SPDX-License-Identifier: MIT */
#include <stdint.h>
static _Thread_local uint64_t cell = UINT64_C(0x1020304050607080);
int smoke_plugin_abi(void) { return 1; }
uint64_t *smoke_plugin_tls(void) { return &cell; }
uint64_t smoke_plugin_transform(uint64_t value) { return (value ^ UINT64_C(0x55aa55aa55aa55aa)) + cell; }
