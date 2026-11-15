// SPDX-License-Identifier: MIT
extern "C" int puts(const char *);
int main() {
  try { throw 23; }
  catch (int value) { return value != 23 || puts("LLVM23_UNWIND_OK") < 0; }
}
