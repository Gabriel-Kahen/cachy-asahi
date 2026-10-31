#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Executed only by the explicit native disposable-container owner.
set -euo pipefail
[[ ${CACHY_ASAHI_GLIBC_BUILD:-} == 1 && $(uname -m) == aarch64 && $(id -u) != 0 ]]
[[ -d /inputs && -d /work && -r /expected-packages.lock && -d /runner ]]
export HOME=/work/home TMPDIR=/tmp LANG=C LC_ALL=C TZ=UTC
mkdir -p "$HOME" /work/evidence /work/artifacts /work/recipe
pacman -Q | LC_ALL=C sort > /work/evidence/packages-before.lock
diff -u /expected-packages.lock /work/evidence/packages-before.lock
{
  uname -a; getconf PAGESIZE; gcc -v; ld --version; make --version
  sha256sum /usr/bin/gcc /usr/bin/ld /usr/lib/libc.so.6 /usr/lib/ld-linux-aarch64.so.1
} > /work/evidence/toolchain.txt 2>&1
cp -R /inputs/. /work/recipe/
cd /work/recipe
export PKGDEST=/work/artifacts SRCDEST=/work/recipe CACHY_ASAHI_GLIBC_BUILD=1
cat > /work/makepkg.conf <<'CONF'
CARCH=aarch64
CHOST=aarch64-unknown-linux-gnu
CFLAGS='-O2 -g'
CXXFLAGS='-O2 -g'
LDFLAGS=''
MAKEFLAGS='-j4'
BUILDENV=(!distcc !color !ccache check !sign)
OPTIONS=(staticlibs !strip !debug !lto)
PACKAGER='cachy-asahi project-owned rebuild <build@cachy-asahi.invalid>'
INTEGRITY_CHECK=(sha256)
PKGEXT=.pkg.tar.xz
SRCEXT=.src.tar.xz
COMPRESSXZ=(xz -c -T1 -6)
CONF
export MAKEPKG_CONF=/work/makepkg.conf
makepkg --config /work/makepkg.conf --printsrcinfo > /work/evidence/generated.SRCINFO
makepkg --config /work/makepkg.conf --verifysource --noconfirm
status=0
makepkg --config /work/makepkg.conf --cleanbuild --force --log --noconfirm || status=$?
printf '%s\n' "$status" > /work/evidence/makepkg-exit
pacman -Q | LC_ALL=C sort > /work/evidence/packages-after.lock
diff -u /expected-packages.lock /work/evidence/packages-after.lock
exit "$status"
