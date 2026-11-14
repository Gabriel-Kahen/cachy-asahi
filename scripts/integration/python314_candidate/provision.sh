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
 '1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d  /tmp/extra.db' | sha256sum --check --strict
cat > /tmp/python314-frozen.conf <<'EOF'
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
pacman --config /tmp/python314-frozen.conf --noconfirm -S --needed \
 python gcc tk sqlite mpdecimal bzip2 expat gdbm libffi openssl zlib tzdata \
 zstd xz readline ncurses util-linux-libs
install -d /opt/python314-inputs/baseline
cp /var/cache/pacman/pkg/python-3.14.9-1-x86_64.pkg.tar.zst{,.sig} /opt/python314-inputs/baseline/
printf '%s\n' \
 'e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55  /opt/python314-inputs/baseline/python-3.14.9-1-x86_64.pkg.tar.zst' \
 '9261278f2a855d6ae8f7b148ef84300030a120d11ddcf66e93835f705656925d  /opt/python314-inputs/baseline/python-3.14.9-1-x86_64.pkg.tar.zst.sig' | sha256sum --check --strict
# Recheck the retained upstream signature against only the disposable image's
# Arch keyring. Lifecycle package transactions later use private TEST trust.
pacman-key --verify /opt/python314-inputs/baseline/python-3.14.9-1-x86_64.pkg.tar.zst.sig
pacman -Q > /opt/python314-inputs/baseline-packages.txt
cp /tmp/python314-frozen.conf /opt/python314-inputs/frozen.conf
