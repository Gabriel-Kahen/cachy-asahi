#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
bash /driver/borrowed/provision.sh
install -d /opt/ui-integration/python-provider
cp /var/cache/pacman/pkg/python-3.14.9-1-x86_64.pkg.tar.zst{,.sig} /opt/ui-integration/python-provider/
cd /opt/ui-integration/python-provider
printf '%s\n' \
 'e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55  python-3.14.9-1-x86_64.pkg.tar.zst' \
 '9261278f2a855d6ae8f7b148ef84300030a120d11ddcf66e93835f705656925d  python-3.14.9-1-x86_64.pkg.tar.zst.sig' | sha256sum --check --strict
pacman-key --verify python-3.14.9-1-x86_64.pkg.tar.zst.sig
