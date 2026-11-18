#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Runs only as the ordinary builder in the disposable AArch64 guest.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC
export MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 MAKEFLAGS=-j1 SOURCE_DATE_EPOCH=1792021458
unset CC CXX CFLAGS CXXFLAGS CPPFLAGS LDFLAGS MAKEPKG_CONF BUILDDIR PKGDEST
unset CMAKE_PREFIX_PATH CMAKE_TOOLCHAIN_FILE CMAKE_GENERATOR CMAKE_MODULE_PATH
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR PKG_CONFIG_SYSROOT_DIR PYTHONPATH PYTHONHOME
unset LD_PRELOAD LD_LIBRARY_PATH

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ $# == 2 ]] || fail "usage: configure.sh <recipe-working-dir> <absolute-evidence-dir>"
[[ $EUID != 0 && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]] ||
    fail "Expected an ordinary-user AArch64 process with 16384-byte pages"
recipe=$1
evidence=$2
for directory in "$recipe" "$evidence"; do
    [[ $directory == /* && -d $directory && -w $directory && $directory == "$(realpath -e -- "$directory")" ]] ||
        fail "Expected an ordinary writable absolute directory: $directory"
done
[[ $recipe != "$evidence" && $evidence != "$recipe/"* && $recipe != "$evidence/"* ]] ||
    fail "The recipe and evidence directories must be disjoint"
[[ -r /etc/pacman.conf && -f $recipe/PKGBUILD && ! -e $recipe/src && ! -L $recipe/src ]] ||
    fail "Expected an ordinary readable pacman config and a fresh recipe tree"

capture() {
    local name=$1
    shift
    # Keep partial diagnostics and fail on overflow. A failed producer never
    # yields a successful stage even if its diagnostic stream is well formed.
    "$@" 2>&1 | /usr/bin/python -I -B -c '
import sys

limit = 4 * 1024**2
with open(sys.argv[1], "xb") as output:
    while chunk := sys.stdin.buffer.read(65536):
        remaining = limit - output.tell()
        output.write(chunk[:remaining])
        if len(chunk) > remaining:
            raise SystemExit("Evidence exceeded 4 MiB")
' "$evidence/$name"
}

export HOME=$recipe/.home XDG_CONFIG_HOME=$recipe/.home/.config SRCDEST=$recipe/srcdest
export TMPDIR=$recipe/.tmp
mkdir -m 700 -- "$HOME" "$TMPDIR"
cd -- "$recipe"
archive=qtbase-everywhere-src-6.12.0.tar.xz
[[ -d $SRCDEST && ! -L $SRCDEST && -w $SRCDEST && -f $SRCDEST/$archive && ! -L $SRCDEST/$archive ]] ||
    fail "Expected the preseeded offline Qt source archive"
source_pin() {
    printf '%s  %s\n' a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307 \
        "$SRCDEST/$archive" | sha256sum --check --
}
capture configure-source-pin.log source_pin

mapfile -t dependencies < /qtmedia/configure-dependencies.list
[[ ${#dependencies[@]} -gt 0 && ${#dependencies[@]} -le 128 ]] || fail "Invalid dependency count"
for dependency in "${dependencies[@]}"; do
    [[ $dependency =~ ^[A-Za-z0-9@._+-]+([\<\>\=]{1,2}[A-Za-z0-9@._+:-]+)?$ ]] ||
        fail "Invalid configure dependency: $dependency"
done
capture configure-dependencies.log /usr/bin/pacman -T "${dependencies[@]}"
[[ ! -s $evidence/configure-dependencies.log ]] || fail "Normal dependency check produced output"

probe_md4c() {
    local version location file owner
    version=$(/usr/bin/pkg-config --modversion md4c) || return
    location=$(/usr/bin/pkg-config --variable=pcfiledir md4c) || return
    [[ $version == 0.5.3 && $location == /usr/lib/pkgconfig ]] ||
        fail "Unexpected md4c pkg-config selection"
    printf 'pkg-config version=%s pcfiledir=%s\n' "$version" "$location"
    /usr/bin/pkg-config --cflags --libs md4c || return
    [[ $(/usr/bin/pacman -Q md4c) == 'md4c 0.5.3-1' ]] || fail "Unexpected installed md4c package"
    for file in "$location/md4c.pc" /usr/lib/cmake/md4c/md4cConfig.cmake \
        /usr/lib/cmake/md4c/md4cConfig-release.cmake /usr/lib/libmd4c.so.0.5.3; do
        [[ -f $file && ! -L $file ]] || fail "Missing ordinary md4c asset: $file"
        owner=$(/usr/bin/pacman -Qqo "$file") || return
        [[ $owner == md4c ]] || fail "Unexpected ALPM owner for $file"
        printf 'alpm-owner=%s path=%s\n' "$owner" "$file"
    done
    [[ $(realpath -e -- /usr/lib/libmd4c.so.0) == /usr/lib/libmd4c.so.0.5.3 ]] ||
        fail "Unexpected loader target for libmd4c.so.0"
    /usr/bin/python -I -B -c '
import ctypes

lib = ctypes.CDLL("/usr/lib/libmd4c.so.0")
if not lib.md_parse:
    raise SystemExit("Expected md_parse in the loaded md4c shared library")
print("dlopen=PASS md_parse=present")
'
}
capture md4c-pkg-config-and-loader.log probe_md4c

capture configure-prepare.log /usr/bin/makepkg --nobuild --noconfirm
srcdir=$recipe/src
[[ -d $srcdir/qtbase-everywhere-src-6.12.0 && ! -L $srcdir/qtbase-everywhere-src-6.12.0 &&
   ! -e $srcdir/build && ! -L $srcdir/build ]] || fail "The prepared Qt source/build boundary differs"
capture configure-cmake.log /usr/bin/cmake -DCMAKE_AUTOGEN_PARALLEL:STRING=1 \
    -C "$srcdir/configure.cmake" -S "$srcdir/qtbase-everywhere-src-6.12.0" \
    -B "$srcdir/build" -G Ninja -DCMAKE_PROJECT_QtBase_INCLUDE="$srcdir/SERVER_DEPENDENCY_GUARD.cmake"
capture configure-profile.json /usr/bin/python -I -B "$srcdir/source.py" configuration \
    --build "$srcdir/build" --profile "$srcdir/configure.cmake"

prove_cmake_md4c() {
    local md4c_dir feature header
    md4c_dir=$(grep -x 'md4c_DIR:PATH=/usr/lib/cmake/md4c' "$srcdir/build/CMakeCache.txt") || return
    feature=$(grep -x 'QT_FEATURE_system_textmarkdownreader:INTERNAL=ON' "$srcdir/build/CMakeCache.txt") || return
    header=$(grep -E '^#define QT_FEATURE_system_textmarkdownreader[[:space:]]+1[[:space:]]*$' \
        "$srcdir/build/src/gui/qtgui-config.h") || return
    printf '%s\n' "$md4c_dir" "$feature" "$header"
}
capture md4c-cmake-selection.log prove_cmake_md4c

capture configure-result.json printf '%s\n' \
    '{"status":"PASS_QT612_CONFIGURE_ONLY","architecture":"aarch64","page_size":16384,"md4c":"0.5.3-1","full_build":"NOT_RUN"}'
