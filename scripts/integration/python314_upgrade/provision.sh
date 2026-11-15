#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
# Existing pinned provisioning installs only inside this disposable image from
# hash-frozen repos with mandatory upstream package signatures.
bash /opt/python314-inputs/base_provision.sh
cd /opt/python314-inputs
printf '%s\n' \
 '8a350ce53aae01ae687f043b301931e411bf06333ba480b42b3b5432a0e6c79b  python-3.14.7-1-x86_64.pkg.tar.zst' \
 'ff4000fab52654e77a2de73ff242ea809b0b4fd2e17951a8375f575180c1ecae  python-3.14.7-1-x86_64.pkg.tar.zst.sig' | sha256sum --check --strict
# This public-package signature gate precedes every private TEST key/signature.
pacman-key --verify python-3.14.7-1-x86_64.pkg.tar.zst.sig > public-signature-3147.txt 2>&1
cat public-signature-3147.txt
# No dependency waiver, extra provider substitution or closure search is allowed.
if ! pacman -T bzip2 expat gdbm libffi libnsl libxcrypt openssl zlib tzdata mpdecimal zstd > closure-3147.txt; then
  cat closure-3147.txt
  echo 'HOLD exact historical baseline dependency closure unavailable' >&2
  exit 2
fi
printf '%s\n' 'PASS public Arch signature and declared dependency closure for exact python3.14.7-1' > historical-gates.txt
