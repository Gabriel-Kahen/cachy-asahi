#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
export HOME=/work/home XDG_CONFIG_HOME=/work/home/.config TMPDIR=/work/tmp
export PATH=/usr/bin LC_ALL=C TZ=UTC MAKEFLAGS=-j2 SOURCE_DATE_EPOCH=1785628800
export CACHY_ASAHI_PERL_BUILD=1 PKGDEST=/work/output
unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS PERL5LIB PERL5OPT
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$TMPDIR" "$PKGDEST" /work/recipe
cp -a /inputs/recipe/. /work/recipe/
cp /inputs/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz /work/recipe/
chmod -R u+w /work/recipe
cp /opt/perl-host/* "$PKGDEST/"
cd /work/recipe
set +e
makepkg --cleanbuild --nosign --noconfirm --log > "$PKGDEST/makepkg.log" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$PKGDEST/makepkg-exit.txt"
cp -a ./*.log "$PKGDEST/" 2>/dev/null || true
python -I -B /inputs/provenance.py --exit "$result"
if (( result != 0 )); then exit "$result"; fi
stage=/work/recipe/pkg/perl
LD_LIBRARY_PATH="$stage/usr/lib/perl5/5.42/core_perl/CORE" \
  "$stage/usr/bin/perl" -I"$stage/usr/lib/perl5/5.42/core_perl" \
  -I"$stage/usr/share/perl5/core_perl" /inputs/staged_smoke.pl "$stage" \
  > "$PKGDEST/staged-smoke.json"
archive="$PKGDEST/perl-5.42.3-1.3-x86_64.pkg.tar.zst"
bsdtar -xOf "$archive" .PKGINFO > "$PKGDEST/PKGINFO"
bsdtar -xOf "$archive" .BUILDINFO > "$PKGDEST/BUILDINFO"
sha256sum "$archive"
cp /work/recipe/src/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603/config.over "$PKGDEST/source-config.over"
LD_LIBRARY_PATH="$stage/usr/lib/perl5/5.42/core_perl/CORE" \
  "$stage/usr/bin/perl" -I"$stage/usr/lib/perl5/5.42/core_perl" \
  -MConfig -e 'print "$Config{cf_time}\n"' > "$PKGDEST/staged-cf-time.txt"
