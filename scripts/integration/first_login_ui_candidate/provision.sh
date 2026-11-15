#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
export LC_ALL=C
for repo in core extra; do
  curl --fail --silent --show-error --max-time 90 \
    "https://archive.archlinux.org/repos/2026/11/09/$repo/os/x86_64/$repo.db" -o "/tmp/$repo.db"
done
printf '%s\n' \
 'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae  /tmp/core.db' \
 '1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d  /tmp/extra.db' | sha256sum --check --strict
install -d /opt/ui-integration
cat > /opt/ui-integration/pacman.conf <<'EOF'
[options]
Architecture = x86_64
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Required TrustedOnly
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
# No optional bubblewrap/Hyprland installation to mask missing checks.
pacman --config /opt/ui-integration/pacman.conf --noconfirm -S --needed \
  base-devel python python-gobject gtk4 gnupg fish zsh xorg-server-xvfb xorg-xauth dbus
# Local network-none owners have no download/user-switch operation. Preserve
# Required TrustedOnly while omitting acquisition-only DownloadUser/chown.
sed '/^DownloadUser = /d; /^DisableSandboxFilesystem$/d; /^DisableDownloadTimeout$/d; /^ParallelDownloads = /d' \
  /opt/ui-integration/pacman.conf > /opt/ui-integration/local-pacman.conf
pacman -Q > /opt/ui-integration/baseline-packages.txt
useradd --uid 1000 --create-home builder
