#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
export HOME=/work/home XDG_CONFIG_HOME=/work/home/.config TMPDIR=/work/tmp
export PATH=/usr/bin LC_ALL=C.UTF-8 MAKEFLAGS=-j2 SOURCE_DATE_EPOCH=1791748800
export PKGDEST=/work/output
unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS PYTHONPATH PYTHONHOME
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$TMPDIR" "$PKGDEST" /work/recipe
cp /inputs/* /work/recipe/
cd /work/recipe
cp /opt/python-tk-host/{packages.txt,pacman.conf,acquired-sha256.txt} "$PKGDEST/"
set +e
makepkg --ignorearch --cleanbuild --nosign --noconfirm > "$PKGDEST/makepkg.log" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$PKGDEST/makepkg-exit.txt"
if (( result != 0 )); then exit "$result"; fi
stage=/work/recipe/pkg/python
LD_LIBRARY_PATH="$stage/usr/lib" "$stage/usr/bin/python3.14" -I /inputs/tk_headless.py \
  > "$PKGDEST/tk-headless.json" 2> "$PKGDEST/tk-headless.stderr"
bsdtar -xOf "$PKGDEST/python-3.14.8-1.1-x86_64.pkg.tar.zst" .PKGINFO > "$PKGDEST/PKGINFO"
bsdtar -xOf "$PKGDEST/python-3.14.8-1.1-x86_64.pkg.tar.zst" .BUILDINFO > "$PKGDEST/BUILDINFO"
sha256sum "$PKGDEST/python-3.14.8-1.1-x86_64.pkg.tar.zst"
