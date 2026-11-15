#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
prefix=/opt/cachy-asahi/llvm23-source-reference
triple=aarch64-unknown-linux-gnu
link='-Wl,-z,max-page-size=16384'
common=(-G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix"
  -DCMAKE_INSTALL_LIBDIR=lib -DLLVM_LIBDIR_SUFFIX= '-DCMAKE_INSTALL_RPATH=$ORIGIN/../lib;$ORIGIN'
  -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=OFF -DCMAKE_BUILD_WITH_INSTALL_RPATH=OFF
  -DCMAKE_EXE_LINKER_FLAGS="$link" -DCMAKE_SHARED_LINKER_FLAGS="$link"
  -DCMAKE_MODULE_LINKER_FLAGS="$link" -DCMAKE_C_FLAGS=-O2 -DCMAKE_CXX_FLAGS=-O2
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
  -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF)
case "${1:-}" in
  probe)
    [[ $(uname -m) == aarch64 ]]
    [[ $(gcc -dumpmachine) == aarch64-*-linux-gnu || $(gcc -dumpmachine) == aarch64-linux-gnu ]]
    gcc --version
    cmake --version
    ninja --version
    ;;
  tools)
    cmake -S /source/llvm -B /work/tools "${common[@]}" \
      -DCMAKE_C_COMPILER=/usr/bin/gcc -DCMAKE_CXX_COMPILER=/usr/bin/g++ \
      -DCMAKE_AR=/usr/bin/gcc-ar -DCMAKE_RANLIB=/usr/bin/gcc-ranlib \
      -DLLVM_ENABLE_PROJECTS='clang;lld' -DLLVM_ENABLE_RUNTIMES= \
      -DLLVM_TARGETS_TO_BUILD=AArch64 -DLLVM_DEFAULT_TARGET_TRIPLE="$triple" \
      -DLLVM_HOST_TRIPLE="$triple" -DLLVM_ENABLE_LTO=OFF -DLLVM_ENABLE_RTTI=ON \
      -DLLVM_BUILD_LLVM_DYLIB=ON -DLLVM_LINK_LLVM_DYLIB=ON \
      -DLLVM_ENABLE_ASSERTIONS=OFF -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_BUILD_DOCS=OFF \
      -DLLVM_ENABLE_BINDINGS=OFF -DLLVM_ENABLE_ZLIB=FORCE_ON -DLLVM_ENABLE_ZSTD=FORCE_ON \
      -DLLVM_ENABLE_LIBXML2=OFF -DLLVM_ENABLE_CURL=OFF -DLLVM_ENABLE_LIBEDIT=OFF \
      -DLLVM_ENABLE_FFI=OFF -DLLVM_ENABLE_TERMINFO=OFF \
      -DLLVM_PARALLEL_COMPILE_JOBS=2 -DLLVM_PARALLEL_LINK_JOBS=1 \
      -DLLVM_PARALLEL_TABLEGEN_JOBS=1 -DCLANG_DEFAULT_CXX_STDLIB=libstdc++ \
      -DCLANG_DEFAULT_RTLIB=libgcc -DCLANG_DEFAULT_UNWINDLIB=libgcc \
      -DCLANG_DEFAULT_LINKER= -DCLANG_INCLUDE_TESTS=OFF -DLLD_INCLUDE_TESTS=OFF
    cmake --build /work/tools --parallel 2
    DESTDIR=/work/dest cmake --install /work/tools
    ;;
  runtimes)
    cmake -S /source/runtimes -B /work/runtimes "${common[@]}" \
      -DCMAKE_C_COMPILER="$prefix/bin/clang" -DCMAKE_CXX_COMPILER="$prefix/bin/clang++" \
      -DCMAKE_ASM_COMPILER="$prefix/bin/clang" -DCMAKE_AR="$prefix/bin/llvm-ar" \
      -DCMAKE_RANLIB="$prefix/bin/llvm-ranlib" -DCMAKE_C_COMPILER_TARGET="$triple" \
      -DCMAKE_CXX_COMPILER_TARGET="$triple" -DLLVM_DEFAULT_TARGET_TRIPLE="$triple" \
      -DLLVM_CONFIG_PATH="$prefix/bin/llvm-config" -DLLVM_DIR="$prefix/lib/cmake/llvm" \
      -DLLVM_ENABLE_RUNTIMES='compiler-rt;libunwind' \
      -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON -DCOMPILER_RT_BUILD_BUILTINS=ON \
      -DCOMPILER_RT_BUILD_PROFILE=ON -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
      -DCOMPILER_RT_BUILD_XRAY=OFF -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
      -DCOMPILER_RT_BUILD_ORC=OFF -DCOMPILER_RT_INCLUDE_TESTS=OFF \
      -DCOMPILER_RT_INSTALL_PATH="$prefix/lib/clang/23" \
      -DLIBUNWIND_ENABLE_SHARED=ON -DLIBUNWIND_ENABLE_STATIC=ON \
      -DLIBUNWIND_INCLUDE_TESTS=OFF -DLIBUNWIND_USE_COMPILER_RT=OFF \
      -DLIBUNWIND_INSTALL_LIBRARY_DIR=lib
    cmake --build /work/runtimes --parallel 2
    DESTDIR=/work/dest cmake --install /work/runtimes
    ;;
  check)
    [[ $("$prefix/bin/llvm-config" --version) == 23.1.1 ]]
    [[ $("$prefix/bin/llvm-config" --targets-built) == AArch64 ]]
    [[ $("$prefix/bin/clang" -dumpmachine) == "$triple" ]]
    "$prefix/bin/clang" --version
    "$prefix/bin/ld.lld" --version | /usr/bin/grep -F '23.1.1'
    # Actual compile/link/runtime probes are part of a future admitted build.
    printf '%s\n' 'int main(void) { return 0; }' > /work/smoke.c
    "$prefix/bin/clang" /work/smoke.c -fuse-ld=lld --rtlib=compiler-rt "$link" -o /work/smoke
    /work/smoke
    "$prefix/bin/clang" /work/smoke.c -fuse-ld=lld -fprofile-instr-generate "$link" -o /work/profile-smoke
    LLVM_PROFILE_FILE=/work/profile.profraw /work/profile-smoke
    [[ -s /work/profile.profraw ]]
    printf '%s\n' 'int main() { try { throw 7; } catch (int n) { return n == 7 ? 0 : 1; } }' > /work/unwind.cpp
    "$prefix/bin/clang++" /work/unwind.cpp -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind \
      -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" "$link" -o /work/unwind-smoke
    /work/unwind-smoke
    ;;
  *) printf '%s\n' 'REFUSED: fixed probe/tools/runtimes/check operation required' >&2; exit 2 ;;
esac
