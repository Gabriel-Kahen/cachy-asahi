/* SPDX-License-Identifier: MIT */
extern int puts(const char *);
typedef unsigned __int128 wide;
static volatile unsigned long long divisor = 3;
__attribute__((noinline)) static wide divide(wide a, wide b) { return a / b; }
int main(void) {
  wide value = ((wide)1 << 100) + 17;
  if (divide(value, divisor) * 3 != value) return 2;
  return puts("LLVM23_C_OK") < 0;
}
