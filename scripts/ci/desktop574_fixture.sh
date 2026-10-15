#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Invoked only in the disposable ARM fixture container by desktop574_runtime.py.
set -euo pipefail
[[ ${CACHY_DESKTOP574_FIXTURE:-} == 1 && -f /.dockerenv && $(uname -m) == aarch64 && $(id -u) == 0 ]]
[[ ! -e /out/staged && ! -e /out/guest.raw ]]
root=/out/staged
mkdir "$root"
cp -a --no-preserve=xattr --reflink=never /usr /etc /var /boot "$root/"
# The container has separate /bin and library compatibility links outside /usr.
for path in bin sbin lib lib64; do
  if [[ -L /$path ]]; then cp -a "/$path" "$root/"; fi
done
# The disposable package transaction masks hooks; materialize its GSettings cache here.
glib-compile-schemas --strict "$root/usr/share/glib-2.0/schemas"
[[ -f "$root/usr/share/glib-2.0/schemas/gschemas.compiled" && -s "$root/usr/share/glib-2.0/schemas/gschemas.compiled" ]]
chmod 0644 "$root/usr/share/glib-2.0/schemas/gschemas.compiled"
mkdir -p "$root"/{dev,proc,sys,run,tmp,home/desktop574,usr/local/bin,usr/local/share/desktop574}
chmod 1777 "$root/tmp"
! awk -F: '$1 == "desktop574" || $3 == 23001 {found=1} END {exit !found}' "$root/etc/passwd"
! awk -F: '$1 == "desktop574" || $3 == 23001 {found=1} END {exit !found}' "$root/etc/group"
printf '%s\n' 'desktop574:x:23001:23001:Disposable ARM desktop:/home/desktop574:/bin/bash' >> "$root/etc/passwd"
printf '%s\n' 'desktop574:x:23001:' >> "$root/etc/group"
printf '%s\n' 'desktop574:!:20000:0:99999:7:::' >> "$root/etc/shadow"
chown 23001:23001 "$root/home/desktop574"
chmod 700 "$root/home/desktop574"
cp /runner/desktop574_guest.py "$root/usr/local/share/desktop574/guest.py"
cp /runtime-packages.lock "$root/usr/local/share/desktop574/expected.lock"
printf '%s\n' 'hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })' > "$root/usr/local/share/desktop574/minimal.lua"
cc -std=c11 -O2 -Wall -Wextra -Werror /source/scripts/virtual/gbm_probe.c -o "$root/usr/local/bin/gbm-probe" $(pkg-config --cflags --libs egl gbm glesv2 libdrm)
printf '%s\n' '/dev/vda / ext4 defaults 0 0' > "$root/etc/fstab"
printf '%s\n' 'desktop574-generic' > "$root/etc/hostname"
printf '%s\n' '127.0.0.1 localhost' '::1 localhost' > "$root/etc/hosts"
: > "$root/etc/machine-id"
rm -rf "$root/etc/pacman.d/gnupg" "$root/var/lib/gnupg" "$root/var/cache/pacman/pkg"
mkdir -p "$root/var/cache/pacman/pkg"
cat > "$root/etc/systemd/system/desktop574.service" <<'UNIT'
[Unit]
Description=Disposable generic ARM desktop runtime
Requires=basic.target systemd-udevd.service systemd-udev-trigger.service
After=basic.target systemd-udev-trigger.service
[Service]
Type=oneshot
Environment=CACHY_ASAHI_VIRTUAL_GUEST=1
ExecStartPre=/usr/bin/modprobe virtio_console
ExecStartPre=/usr/bin/udevadm wait --timeout=20 --initialized=yes /dev/virtio-ports/desktop574.events
ExecStart=/usr/bin/python3 -I -B /usr/local/share/desktop574/guest.py boot
TimeoutStartSec=650
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyAMA0
UNIT
cat > "$root/etc/systemd/system/desktop574.target" <<'UNIT'
[Unit]
Description=Disposable ARM desktop test
Requires=desktop574.service
After=desktop574.service
AllowIsolate=yes
UNIT
depmod -b "$root" 7.2.10-1-aarch64-ARCH
cp /boot/Image /out/Image
printf '%s\n' '92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a  /out/Image' | sha256sum -c -
allocated=$(du -sx --block-size=1 "$root" | cut -f1)
available=$(df --output=avail --block-size=1 /out | tail -1)
# Stage plus a fully allocated worst-case populated disk, and 1 GiB margin.
(( available > allocated + 1073741824 ))
size=$(( allocated + 2147483648 ))
truncate -s "$size" /out/guest.raw
mkfs.ext4 -F -m 0 -L DESKTOP574 -d "$root" /out/guest.raw
rm -rf "$root"
