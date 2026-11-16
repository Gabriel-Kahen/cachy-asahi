# SPDX-License-Identifier: MIT
# Host x86_64 metadata tests only; never a native ARM builder or target image.
FROM docker.io/library/archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae

# The host acquires the complete exact snapshot input set through its verified
# cache. No archive connection is made from the image build's bridge network.
COPY inputs/ /opt/composition-inputs/
COPY inputs.lock /opt/composition-inputs/inputs.lock
RUN --network=none set -eu; \
    printf '%s\n' '9e5ac7bd49ca8dc35c8e8531d5ad1c1464d1719a7c501e2e8ff5836ae61ea152  /opt/composition-inputs/inputs.lock' | sha256sum --check --strict; \
    while read -r bytes digest name source; do \
      test "$(wc -c < "/opt/composition-inputs/$name")" -eq "$bytes"; \
      printf '%s  %s\n' "$digest" "/opt/composition-inputs/$name" | sha256sum --check --strict; \
    done < /opt/composition-inputs/inputs.lock; \
    printf '%s\n' '[options]' 'Architecture = x86_64' \
      'SigLevel = Required DatabaseOptional' 'DownloadUser = alpm' \
      'DisableSandboxFilesystem' '[core]' \
      'Server = file:///opt/composition-inputs' > /tmp/composition-pacman.conf; \
    install -Dm644 /opt/composition-inputs/core.db /var/lib/pacman/sync/core.db; \
    pacman --config /tmp/composition-pacman.conf --noconfirm -S python=3.14.9-1 mpdecimal=4.0.1-3; \
    test "$(pacman --config /tmp/composition-pacman.conf -Q python)" = 'python 3.14.9-1'; \
    test "$(pacman --config /tmp/composition-pacman.conf -Q mpdecimal)" = 'mpdecimal 4.0.1-3'; \
    python3 -I -c 'import ctypes; a=ctypes.CDLL("libalpm.so.16"); a.alpm_version.restype=ctypes.c_char_p; assert a.alpm_version()==b"16.0.1"'; \
    pacman --config /tmp/composition-pacman.conf -Q > /opt/composition-runtime-packages.txt

WORKDIR /work
USER 65534:65534
ENTRYPOINT ["/usr/bin/python3", "-I", "-B", "scripts/port/supported-composition/ci-runtime/run.py"]
