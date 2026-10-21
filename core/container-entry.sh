#!/usr/bin/env bash
# Run only inside the selected disposable OCI builder, never directly on host.
set -euo pipefail
[[ ${CACHY_ASAHI_CORE_CONTAINER:-} == 1 && -f /profile/profile.json && -d /out ]] || exit 2
[[ $(id -u) != 0 && $(uname -m) == aarch64 ]] || exit 2
case ${CORE_RECIPE:-} in systemd|pacman) ;; *) exit 2;; esac
export HOME=/tmp/core-home LC_ALL=C.UTF-8 TZ=UTC
unset BASH_ENV ENV MAKEPKG_CONF PACMAN GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM MESON_EXTRA_CONFIGURE_OPTIONS
mkdir -m700 "$HOME" /tmp/work
cp -R "/profile/$CORE_RECIPE/." /tmp/work/
cd /tmp/work
pacman -Q | LC_ALL=C sort > /out/packages.lock
cmp /expected-packages.lock /out/packages.lock
pacman -Qi > /out/installed-descriptions.txt
{
 uname -a
 getconf PAGESIZE
 makepkg --version
} > /out/environment.txt
sha256sum /etc/makepkg.conf /etc/pacman.conf > /out/config.sha256
cmp /expected-config.sha256 /out/config.sha256
cp /etc/makepkg.conf /out/image-makepkg.conf
cp /etc/pacman.conf /out/image-pacman.conf
cp /etc/makepkg.conf /tmp/core-makepkg.conf
# Explicit local output and project identity. No -s/-i/sudo, no trust bootstrap,
# package installation, signing, repository update or network actor in this entry.
cat >> /tmp/core-makepkg.conf <<'CONF'
CARCH=aarch64
CHOST=aarch64-unknown-linux-gnu
PACKAGER='Cachy-Asahi Experimental Core Builder'
PKGEXT='.pkg.tar.xz'
SRCDEST=/tmp/work
PKGDEST=/tmp/work
LOGDEST=/tmp/work
BUILDDIR=/tmp/work
BUILDENV=(!distcc color !ccache check !sign)
OPTIONS+=( '!debug' )
CONF
cp /tmp/core-makepkg.conf /out/effective-makepkg.conf
python3 -I -B /contract.py /profile "$CORE_RECIPE"
makepkg --config /tmp/core-makepkg.conf --printsrcinfo > /out/generated.SRCINFO
python3 -I -B /contract.py /profile "$CORE_RECIPE" --generated /out/generated.SRCINFO
# Native makepkg/pacman checks version and soname relations; no guessed resolver grant.
python3 -I -B /contract.py /profile "$CORE_RECIPE" --deps > /out/required-dependencies.txt
mapfile -t dependencies < /out/required-dependencies.txt
# Split outputs do not need to preexist; build dependencies do. Runtime relations
# for sibling outputs are bound later by full generated metadata/archives.
python3 -I -B /build-deps.py /profile "$CORE_RECIPE" > /out/build-dependencies.txt
mapfile -t builddeps < /out/build-dependencies.txt
pacman -T "${builddeps[@]}" > /out/missing-dependencies.txt
[[ ! -s /out/missing-dependencies.txt ]] || exit 2
makepkg --config /tmp/core-makepkg.conf --verifysource --noconfirm
makepkg --config /tmp/core-makepkg.conf --cleanbuild --clean --force --log --noconfirm
shopt -s nullglob
packages=(*.pkg.tar.xz)
[[ ${#packages[@]} -gt 0 ]] || exit 2
cp -- "${packages[@]}" /out/
logs=(*.log)
if [[ ${#logs[@]} -gt 0 ]]; then cp -- "${logs[@]}" /out/; fi
# No package payload or package install script is executed here.
