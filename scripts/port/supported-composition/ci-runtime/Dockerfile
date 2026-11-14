# SPDX-License-Identifier: MIT
# Host x86_64 metadata tests only; never a native ARM builder or target image.
FROM docker.io/library/archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae

# A fixed official snapshot and checked DB pin supply Python's finite core-only
# prerequisites. Package signatures remain Required under the image's keyring.
RUN curl --fail --silent --show-error --max-time 60 \
      https://archive.archlinux.org/repos/2026/11/09/core/os/x86_64/core.db \
      --output /tmp/core.db \
 && printf '%s\n' 'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae  /tmp/core.db' | sha256sum --check --strict \
 && printf '%s\n' '[options]' 'Architecture = x86_64' \
      'SigLevel = Required DatabaseOptional' 'DownloadUser = alpm' \
      'DisableSandboxFilesystem' '[core]' \
      'Server = https://archive.archlinux.org/repos/2026/11/09/$repo/os/$arch' \
      > /tmp/composition-pacman.conf \
 && install -Dm644 /tmp/core.db /var/lib/pacman/sync/core.db \
 && pacman --config /tmp/composition-pacman.conf --noconfirm -S python=3.14.9-1 mpdecimal=4.0.1-3 \
 && python3 -I -c 'import ctypes; a=ctypes.CDLL("libalpm.so.16"); a.alpm_version.restype=ctypes.c_char_p; assert a.alpm_version()==b"16.0.1"' \
 && pacman --config /tmp/composition-pacman.conf -Q > /opt/composition-runtime-packages.txt

WORKDIR /work
USER 65534:65534
ENTRYPOINT ["/usr/bin/python3", "-I", "-B", "scripts/port/supported-composition/ci-runtime/run.py"]
