#!/usr/bin/env bash
# Runs only inside the explicit isolated OCI builder. Never run this on the host.
set -euo pipefail
compare_srcinfo() {
  local reviewed generated
  # Drop only full comment/blank lines; retain every field, value and order.
  # Capture sed status directly: process-substitution failures must not pass diff.
  reviewed=$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$1") || return
  generated=$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$2") || return
  diff -u <(printf '%s\n' "$reviewed") <(printf '%s\n' "$generated")
}
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && -f /inputs/PKGBUILD && -d /out ]] || {
  echo 'Missing isolated-builder contract' >&2; exit 2;
}
[[ $(id -u) != 0 ]] || { echo 'makepkg must run as a non-root account' >&2; exit 2; }
[[ $(uname -m) == aarch64 ]] || { echo 'Expected aarch64 runtime' >&2; exit 2; }
export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC
mkdir -p "$HOME" /tmp/work
cp -R /inputs/. /tmp/work/
cd /tmp/work
{
  uname -a
  getconf PAGESIZE
  makepkg --version
  pacman -Q
} > /out/environment.txt
pacman -Q | LC_ALL=C sort > /out/packages.lock
diff -u /expected-packages.lock /out/packages.lock
sha256sum /etc/makepkg.conf /etc/pacman.conf > /out/config.sha256
cp /etc/makepkg.conf /etc/pacman.conf /out/
makepkg --printsrcinfo > /out/generated.SRCINFO
if [[ -f .SRCINFO ]]; then
  compare_srcinfo .SRCINFO /out/generated.SRCINFO
fi
# No -s, -i, sudo or host mounts: the pinned image must already contain dependencies.
makepkg --verifysource --noconfirm
makepkg --cleanbuild --clean --force --log --noconfirm
shopt -s nullglob
artifacts=(*.pkg.tar.*)
[[ ${#artifacts[@]} -gt 0 ]] || { echo 'No package artifacts' >&2; exit 2; }
cp -- "${artifacts[@]}" /out/
logs=(*.log)
if [[ ${#logs[@]} -gt 0 ]]; then cp -- "${logs[@]}" /out/; fi
