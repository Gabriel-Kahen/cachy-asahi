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
seed_offline_sources() {
  # makepkg requires writable SRCDEST. Seed tmpfs from the immutable host mount.
  local material_dir=$1 destination=$2
  [[ -d $material_dir && ! -L $material_dir ]] || return 2
  mkdir -m 700 -- "$destination" || return
  cp -- "$material_dir/"* "$destination/" || return
  chmod u+w -- "$destination/"* || return
  export SRCDEST=$destination
}
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && -f /inputs/PKGBUILD && -d /out ]] || {
  echo 'Missing isolated-builder contract' >&2; exit 2;
}
[[ $(id -u) != 0 ]] || { echo 'makepkg must run as a non-root account' >&2; exit 2; }
[[ $(uname -m) == aarch64 ]] || { echo 'Expected aarch64 runtime' >&2; exit 2; }
export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC CMAKE_BUILD_PARALLEL_LEVEL=1 MAKEFLAGS=-j1 MAX_JOBS=1
mkdir -p "$HOME" /tmp/work
cp -R /inputs/. /tmp/work/
cd /tmp/work
if [[ ${CACHY_ASAHI_OFFLINE_SOURCES:-} == 1 ]]; then
  seed_offline_sources /offline-sources /tmp/offline-sources
fi
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
requirements=(brotli dbus double-conversion fontconfig freetype2 glib2 glibc harfbuzz icu libb2 libgcc libgl libice libjpeg-turbo libpng libsm libstdc++ libx11 libxcb libxkbcommon libxkbcommon-x11 'md4c>=0.5.3' 'md4c<0.6' openssl pcre2 shared-mime-info sqlite xcb-util-cursor xcb-util-image xcb-util-keysyms xcb-util-renderutil xcb-util-wm xdg-utils zlib zstd libdrm libglvnd mesa 'wayland>=1.15' libwayland-server.so=0-64 gcc 'cmake>=3.25' ninja pkgconf python perl patch)
set +e
pacman -T "${requirements[@]}" > /out/family-dependencies.missing
dependency_status=$?
set -e
[[ $dependency_status == 0 && ! -s /out/family-dependencies.missing ]] || { echo "Normal Qt612 dependencies missing" >&2; exit 2; }
# No -s, -i, sudo or host mounts: the pinned image must already contain dependencies.
makepkg --verifysource --noconfirm
# makepkg --clean removes phase logs from its working directory on success.
# Write them directly to the retained output, including partial logs on failure.
LOGDEST=/out makepkg --cleanbuild --force --log --noconfirm
# Retain source/configuration/stage proof before natural --rm destroys tmpfs.
cp -- src/stage-contract.json /out/family-stage.json
python /inputs/source.py configuration --build src/build --profile /inputs/configure.cmake > /out/family-configuration.json
python /inputs/source.py verify --root src/qtbase-everywhere-src-6.12.0 --policy /inputs/source-notices.json  > /out/family-notices.json
python /family/proof.py capture --component gui_server --build src/build --contract /inputs/family-contract.json > /out/family-build-proof.json
shopt -s nullglob
artifacts=(*.pkg.tar.*)
[[ ${#artifacts[@]} -gt 0 ]] || { echo 'No package artifacts' >&2; exit 2; }
cp -- "${artifacts[@]}" /out/
logs=(*.log)
if [[ ${#logs[@]} -gt 0 ]]; then cp -- "${logs[@]}" /out/; fi
