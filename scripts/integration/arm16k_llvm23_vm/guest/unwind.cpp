// SPDX-License-Identifier: MIT
extern "C" int puts(const char *);
static volatile unsigned unwound;
struct Guard {
  unsigned mark;
  ~Guard() { unwound = unwound * 10 + mark; }
};
__attribute__((noinline)) static void raise_exception() {
  Guard inner{1};
  throw 23;
}
__attribute__((noinline)) static void cross_frame() {
  Guard outer{2};
  raise_exception();
}
int main() {
  try { cross_frame(); return 2; }
  catch (int value) { if (value != 23 || unwound != 12) return 3; }
  catch (...) { return 4; }
  return puts("LLVM23_UNWIND_OK") < 0;
}
