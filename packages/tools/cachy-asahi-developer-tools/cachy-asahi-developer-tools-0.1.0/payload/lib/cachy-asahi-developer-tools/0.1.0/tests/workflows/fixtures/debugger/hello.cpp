// SPDX-License-Identifier: MIT
// Copyright (c) 2026 cachy-asahi contributors
#include <cstdio>

static int workflow_step(int seed)
{
    volatile int known_local = seed + 7;
    return known_local; /* WORKFLOW_BREAKPOINT */
}

int main()
{
    int result = workflow_step(10);
    std::printf("Debugger version one: %d\n", result);
    return result == 17 ? 0 : 1;
}
