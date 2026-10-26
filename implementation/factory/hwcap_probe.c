/* SPDX-License-Identifier: MIT */
#include <asm/hwcap.h>
#include <sys/auxv.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
_Static_assert(HWCAP2_MOPS == (1UL << 43), "exact Linux aarch64 MOPS bit");
int main(void) {
    errno = 0;
    unsigned long value = getauxval(AT_HWCAP2);
    if (errno || getauxval(AT_PAGESZ) != 16384) return 2;
    int enabled = (value & HWCAP2_MOPS) != 0;
    printf("{\"schema_version\":1,\"hwcap2\":%lu,\"mops_mask\":%lu,\"mops\":%s,\"page_size\":16384,\"uid\":%lu}\n",
           value, HWCAP2_MOPS, enabled ? "true" : "false", (unsigned long)getuid());
    return enabled ? 1 : 0;
}
