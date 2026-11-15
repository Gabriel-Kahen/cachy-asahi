#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
export HOME=/work/build/home TMPDIR=/work/build/tmp PATH=/usr/bin:/bin LC_ALL=C.UTF-8 MAKEFLAGS=-j2
export PKGDEST=/work/build/output
mkdir -p "$HOME" "$TMPDIR" "$PKGDEST" /work/build/recipe
cp /inputs/recipe/* /work/build/recipe/
cp /inputs/recipe/.SRCINFO /work/build/recipe/
cd /work/build/recipe
set +e
makepkg --noconfirm > "$PKGDEST/makepkg.log" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$PKGDEST/makepkg-exit.txt"
exit "$result"
