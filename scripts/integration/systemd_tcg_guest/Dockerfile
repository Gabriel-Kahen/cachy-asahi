# SPDX-License-Identifier: MIT
FROM docker.io/library/archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae AS guest-base
RUN bsdtar --zstd -cpf /guest-base.tar.zst --exclude etc/hosts --exclude etc/hostname --exclude etc/resolv.conf --exclude etc/pacman.d/gnupg --exclude var/cache/pacman/pkg -C / usr etc var bin sbin lib lib64
FROM docker.io/library/archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae
COPY install.conf /opt/install.conf
COPY package-refs.json record_inputs.py assemble.py vm_actor.py owned_process.py guest-proof.sh /opt/
RUN --mount=type=bind,source=packages,target=/packages,ro mkdir /tmp/masked-hooks && for p in /usr/share/libalpm/hooks/*.hook /etc/pacman.d/hooks/*.hook; do if test -f "$p"; then ln -sf /dev/null /tmp/masked-hooks/"$(basename "$p")"; fi; done && pacman --config /opt/install.conf --hookdir /tmp/masked-hooks --noscriptlet --noconfirm -U /packages/*.pkg.tar.zst && python3 -I /opt/record_inputs.py /packages && rm -rf /tmp/masked-hooks
COPY --from=guest-base /guest-base.tar.zst /opt/guest-base.tar.zst
