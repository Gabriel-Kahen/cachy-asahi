#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
export LC_ALL=C
for repo in core extra; do
  curl --fail --silent --show-error --max-time 90 \
    "https://archive.archlinux.org/repos/2026/11/09/$repo/os/x86_64/$repo.db" \
    --output "/tmp/$repo.db"
done
printf '%s\n' \
  'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae  /tmp/core.db' \
  '1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d  /tmp/extra.db' \
  | sha256sum --check --strict
cat > /tmp/perl-host-pacman.conf <<'EOF'
[options]
Architecture = x86_64
SigLevel = Required DatabaseOptional
DownloadUser = alpm
DisableSandboxFilesystem
DisableDownloadTimeout
ParallelDownloads = 1
[core]
Server = https://archive.archlinux.org/repos/2026/11/09/$repo/os/$arch
[extra]
Server = https://archive.archlinux.org/repos/2026/11/09/$repo/os/$arch
EOF
install -Dm644 /tmp/core.db /var/lib/pacman/sync/core.db
install -Dm644 /tmp/extra.db /var/lib/pacman/sync/extra.db
# This entire phase runs in one owned disposable image. Preserve signature and
# dependency checking; no package manager runs on the host or in the build actor.
pacman --config /tmp/perl-host-pacman.conf --noconfirm -S --needed \
  base-devel gcc binutils make patch fakeroot python procps-ng perl \
  glibc gdbm db5.3 libxcrypt bzip2 zlib
install -d /opt/perl-host
pacman -Q > /opt/perl-host/packages.txt
cp /tmp/perl-host-pacman.conf /opt/perl-host/pacman.conf
cp /tmp/{core,extra}.db /opt/perl-host/
sha256sum /var/cache/pacman/pkg/*.pkg.tar.* > /opt/perl-host/acquired-sha256.txt
sha256sum /usr/bin/{gcc,ld,make,patch,python,perl,pacman,fakeroot} > /opt/perl-host/tools-sha256.txt
useradd --uid 1000 --user-group --create-home builder
