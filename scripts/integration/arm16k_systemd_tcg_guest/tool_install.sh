#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
mkdir -p /tmp/masked-hooks /opt/arm16k
for path in /usr/share/libalpm/hooks/*.hook /etc/pacman.d/hooks/*.hook; do
  if test -f "$path"; then ln -s /dev/null /tmp/masked-hooks/"$(basename "$path")"; fi
done
cp /opt/tool-provenance.json /opt/arm16k/parent-x86-tool-provenance.json
pacman --config /setup/install.conf --hookdir /tmp/masked-hooks --noscriptlet --noconfirm -U /packages/*.pkg.tar.zst
cp /setup/package-refs.json /opt/package-refs.json
python3 -I /setup/source/frozen/record_tool_inputs.py /packages
cp /setup/source/*.py /setup/source/guest-proof.sh /opt/arm16k/
cp /setup/source/vm_actor.py /opt/vm_actor.py
cp /setup/source/frozen/owned_process.py /opt/owned_process.py
rm -rf /tmp/masked-hooks
