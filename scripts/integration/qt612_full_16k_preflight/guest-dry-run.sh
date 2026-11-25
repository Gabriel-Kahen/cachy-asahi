#!/bin/bash
# SPDX-License-Identifier: MIT
# Inspect the QtGui checkpoint through a disposable 16 KiB guest overlay.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

readonly UUID=ed56022f-4e82-f6e3-fbde-502489347154
readonly ROOT=/qtwork/root
phase=boot
nonce=unknown
result=HOLD

emit() {
    local name=$1 file=/run/qtprobe/$1
    [[ -s $file && -f $file && ! -L $file && $(stat -c %s "$file") -le 4194304 ]]
    printf 'QTBASE_DRY_RUN_FILE %s %s ' "$nonce" "$name"
    guest /usr/bin/zstd -q -c < "$file" | base64 -w0
    printf '\n'
}

finish() {
    trap - EXIT HUP INT TERM
    set +e
    if mountpoint -q /qtwork && ! umount -n /qtwork; then
        phase=cleanup result=HOLD
    fi
    printf 'QTBASE_DRY_RUN_TERMINAL %s %s %s\n' "$nonce" "$result" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 1; done
}

guest() (
    ulimit -f 4096
    exec timeout --kill-after=5s 75s chroot --userspec=1000:1000 "$ROOT" /usr/bin/env -i \
        PATH=/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC HOME=/qt-recipe/.home \
        XDG_CONFIG_HOME=/qt-recipe/.home/.config TMPDIR=/qt-recipe/.tmp \
        NINJA_STATUS='[%f/%t] ' /usr/bin/bash -ec 'cd /qt-recipe/src/build && exec "$@"' qtbase-dry-run "$@"
)

checkpoint_pins() (
    cd "$ROOT"
    sha256sum --check --strict --quiet <<'PINS'
cef51ef9f4a7fce92141f3b31d446da5ada824347da5ec713ead1f800858439a  qt-recipe/src/build/build.ninja
b71df9759d13435ec44b87f1adf866c5ec8aebd44b4a6d41e78ee4ff4bf014cb  qt-recipe/src/build/CMakeFiles/rules.ninja
8ff1dbfd5b753b464f64e240eeb13206f0f231ea1e7acb3fd0f446f8b0c73e58  qt-recipe/src/build/.ninja_log
50f2365b3238ccbc4f70b19d4fb0ec9a24462e0cd752a862030e3ed002877558  qt-recipe/src/build/lib/libQt6Core.so.6.12.0
c64174251bacb101fe466b3f07a00a9b82c628e054a3a6447ab8af735852ebe6  qt-recipe/src/build/lib/libQt6DBus.so.6.12.0
bc73b419fcc9f2e8d07d8454d867e5e2dad34beae4e3d32f29c601dfec767ad8  qt-recipe/src/build/lib/libQt6Gui.so.6.12.0
d7754699fec7db8e53a7813547b4c1c0cfdde079ae09128401c379ec034bdef2  usr/lib/libmd4c.so.0.5.3
PINS
)

check_inventory() {
    guest /usr/bin/pacman -Q < /dev/null | sort > /run/qtprobe/inventory
    printf '%s  %s\n' e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9 \
        /run/qtprobe/inventory | sha256sum --check --strict --quiet
}

main() {
    [[ $# == 0 && $$ == 1 && $EUID == 0 ]]
    trap finish EXIT
    trap 'exit 1' HUP INT TERM
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    local -a words
    local word scratch attempt boot_partition scratch_node
    read -r -a words < /proc/cmdline
    for word in "${words[@]}"; do
        if [[ $word == qtbase_dry_run_nonce=* ]]; then
            [[ $nonce == unknown && ${word#*=} =~ ^[0-9a-f]{32}$ ]]
            nonce=${word#*=}
        fi
    done
    [[ $nonce != unknown && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    findmnt -n -o VFS-OPTIONS / | grep -qw ro
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    [[ $(ls -1 /sys/class/net) == lo ]]
    mount -n -t tmpfs -o mode=0700,nosuid,nodev,noexec,size=16m tmpfs /run
    mkdir /run/qtprobe

    phase=storage
    for ((attempt=0; attempt<50; attempt++)); do
        if scratch=$(blkid -c /dev/null -t "UUID=$UUID" -o device); then break; fi
        sleep 0.2
    done
    [[ $attempt -lt 50 && $scratch =~ ^/dev/vd[a-z]$ && -b $scratch && ! -L $scratch ]]
    scratch_node=$(readlink -e "/sys/class/block/${scratch#/dev/}")
    boot_partition=$(readlink -e "/sys/dev/block/$(findmnt -nro MAJ:MIN /)")
    [[ $scratch_node == /sys/devices/*/block/"${scratch#/dev/}" && ! -e $scratch_node/partition &&
       -r $boot_partition/partition && $scratch_node != "${boot_partition%/*}" &&
       $(readlink -e "${scratch_node%/block/*}/driver") == /sys/bus/virtio/drivers/virtio_blk ]]
    [[ $(blockdev --getsize64 "$scratch") == 17179869184 && $(blockdev --getro "$scratch") == 0 ]]
    [[ $(blkid -p -s LABEL -o value "$scratch") == QT16K_WORK ]]
    # Ninja -n may create directories for generated outputs. Only this new
    # capped child is writable. Its three original backing nodes are read-only.
    mount -n -t ext4 -o rw,nosuid,nodev,noatime "$scratch" /qtwork
    [[ -d $ROOT && ! -L $ROOT ]]

    phase=checkpoint
    checkpoint_pins
    local stem lib="$ROOT/qt-recipe/src/build/lib"
    for stem in libQt6Core libQt6DBus libQt6Gui; do
        [[ $(readlink "$lib/$stem.so") == "$stem.so.6" &&
            $(readlink "$lib/$stem.so.6") == "$stem.so.6.12.0" ]]
    done
    check_inventory
    guest /usr/bin/ninja -t commands all < /dev/null > /run/qtprobe/all.commands
    printf '%s  %s\n' e9bdd7b241d2c28d035e3a084ca7fbeefd7d90f64748e0c0c356e1ea9baff628 \
        /run/qtprobe/all.commands | sha256sum --check --strict --quiet

    phase=ninja
    guest /usr/bin/ninja -n -v lib/libQt6Gui.so < /dev/null > /run/qtprobe/gui.log
    guest /usr/bin/ninja -n -v all < /dev/null > /run/qtprobe/all.log
    checkpoint_pins
    check_inventory
    stat -f -c '%S %a' /qtwork > /run/qtprobe/free-blocks
    for word in gui.log all.log free-blocks; do emit "$word"; done
    phase=complete result=PASS
}

main "$@"
