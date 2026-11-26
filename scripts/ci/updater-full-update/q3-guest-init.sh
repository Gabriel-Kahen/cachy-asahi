#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for a separately admitted disposable updater guest.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
base=/run/updater-q3
root=$base/work/root
code=/updater-q3-v2
nonce=unknown phase=boot result=HOLD

finish() {
    trap - EXIT HUP INT TERM
    set +e
    if mountpoint -q "$root/updater-trust"; then
        for home in /updater-trust /run/updater-bootstrap/official /run/updater-bootstrap/alpm; do
            if [[ -d $root$home ]] &&
               ! timeout --kill-after=5s 15s chroot "$root" /usr/bin/gpgconf --homedir "$home" --kill all >/dev/null 2>&1; then
                phase=cleanup result=HOLD
            fi
        done
    fi
    for target in "$root/usr/bin/sudo" "$root/updater-trust" "$root/updater-code" "$root/updater-input" \
            "$root/tmp" "$root/run" "$root/sys" "$root/proc" "$root/dev" "$base/input" "$base/work"; do
        if mountpoint -q -- "$target" && ! umount -n -- "$target"; then
            phase=cleanup result=HOLD
        fi
    done
    printf 'UPDATER_Q3_TERMINAL %s %s %s\n' "$nonce" "$result" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

selection() {
    local -a words
    local word
    read -r -a words </proc/cmdline
    pin=
    for word in "${words[@]}"; do
        case "$word" in
            cachy_updater16k_nonce=*) [[ $nonce == unknown ]]; nonce=${word#*=} ;;
            cachy_updater16k=*) [[ -z $pin ]]; pin=${word#*=} ;;
        esac
    done
    read -r sealed_nonce input_uuid <"$code/boot-identity"
    [[ $nonce =~ ^[0-9a-f]{32}$ && $nonce == "$sealed_nonce" && $pin =~ ^[0-9a-f]{64}$ ]]
    [[ $input_uuid =~ ^[0-9a-f-]{36}$ ]]
}

disk() {
    local uuid=$1 label=$2 size=$3 read_only=$4 path node boot
    path=$(blkid -c /dev/null -t "UUID=$uuid" -o device)
    [[ $path =~ ^/dev/vd[a-z]$ && -b $path && ! -L $path ]] || return 1
    node=$(readlink -e "/sys/class/block/${path#/dev/}")
    boot=$(readlink -e "/sys/dev/block/$(findmnt -nro MAJ:MIN /)")
    [[ $node == /sys/devices/*/block/"${path#/dev/}" && ! -e $node/partition &&
       -r $boot/partition && $node != "${boot%/*}" &&
       $(readlink -e "${node%/block/*}/driver") == /sys/bus/virtio/drivers/virtio_blk &&
       $(blockdev --getro "$path") == "$read_only" && $(blockdev --getsize64 "$path") == "$size" &&
       $(blkid -p -s LABEL -o value "$path") == "$label" ]] || return 1
    printf '%s\n' "$path"
}

verify_boot() {
    local partition parent
    partition=$(readlink -e "/sys/dev/block/$(findmnt -nro MAJ:MIN /)")
    [[ -r $partition/partition ]]
    parent=${partition%/*}
    [[ $parent =~ ^/sys/devices/.*/block/vd[a-z]$ ]]
    [[ $(readlink -e "${parent%/block/*}/driver") == /sys/bus/virtio/drivers/virtio_blk ]]
    [[ $(blockdev --getro "/dev/${parent##*/}") == 1 ]]
}

[[ $$ == 1 && $EUID == 0 && $# == 0 ]]
trap finish EXIT
trap 'exit 1' HUP INT TERM
mount -n -t proc -o nosuid,nodev,noexec proc /proc
selection
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
findmnt -n -o VFS-OPTIONS / | grep -qw ro
mountpoint -q /dev || mount -n -t devtmpfs -o nosuid devtmpfs /dev
mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
mount -n -t tmpfs -o mode=0700,nosuid,nodev,noexec,size=16m tmpfs /run
[[ $(ls -A /sys/class/net) == lo ]]
phase=clock
D=$base/clock
mkdir -p -m 700 "$D"
source "$code/rtc-clock.sh"
rtc_clock_guard
printf 'UPDATER_Q3_CLOCK %s\n' "$nonce"
cat "$D/rtc-clock.env"

phase=storage
verify_boot
mkdir -m 755 "$base/work" "$base/input"
for ((attempt=0; attempt<50; attempt++)); do
    if work=$(disk ed56022f-4e82-f6e3-fbde-502489347154 QT16K_WORK 17179869184 0) &&
       input=$(disk "$input_uuid" UPDATER16K 134217728 1); then break; fi
    sleep 0.2
done
[[ $attempt -lt 50 && $work != "$input" ]]
mount -n -t ext4 -o rw,nosuid,nodev,noatime "$work" "$base/work"
mount -n -t ext4 -o ro,noload,nosuid,nodev,noexec "$input" "$base/input"
[[ $(stat -c %a "$base/input") == 755 ]]
printf '%s  %s\n' "$pin" "$base/input/plan.json" | sha256sum --check --strict --quiet
for target in "$root" "$root/dev" "$root/proc" "$root/sys" "$root/run" "$root/tmp" "$root/etc" "$root/usr/bin"; do
    [[ -d $target && $(realpath -e -- "$target") == "$target" ]]
done
mkdir -m 755 "$root/updater-code" "$root/updater-input"
mkdir -m 700 "$root/updater-trust"
mount -n -t tmpfs -o mode=0700,nosuid,nodev,noexec,size=16m tmpfs "$root/updater-trust"
mount -n -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs "$root/dev"
for spec in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9' 'tty 5 0'; do
    read -r name major minor <<<"$spec"
    mknod -m 666 "$root/dev/$name" c "$major" "$minor"
done
ln -s /proc/self/fd "$root/dev/fd"
mount -n -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"
mount -n --bind /sys "$root/sys"
mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/sys"
mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=32m tmpfs "$root/run"
mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=32m tmpfs "$root/tmp"
mount -n --bind "$base/input" "$root/updater-input"
mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/updater-input"
mount -n --bind "$code" "$root/updater-code"
mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/updater-code"

phase=bootstrap
timeout --signal=TERM --kill-after=20s 600s chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
    /usr/bin/python -I -B /updater-code/q3-setup.py </dev/null >"$base/setup.json"
[[ $(cat "$base/setup.json") == '{"before_packages": 362, "q3_bootstrap": "PASS"}' ]]
printf 'UPDATER_Q3_BOOTSTRAP %s ' "$nonce"
cat "$base/setup.json"
phase=sudo
sudo=$root/usr/bin/sudo
[[ -f $sudo && ! -L $sudo && $(stat -c '%u:%g:%a:%h' "$sudo") == 0:0:4755:1 ]]
printf '%s  %s\n' 02d73255dabb4e7c477b499ecce56086ff26f1b66a9e0f52ac3a5614068c5e26 "$sudo" |
    sha256sum --check --strict --quiet
mount -n --bind "$sudo" "$sudo"
mount -n -o remount,bind,ro,suid,nodev,exec "$sudo"
sudo_options=$(findmnt -nro VFS-OPTIONS --mountpoint "$sudo")
[[ ,$sudo_options, == *,ro,* && ,$sudo_options, == *,nodev,* &&
   ,$sudo_options, != *,nosuid,* && ,$sudo_options, != *,noexec,* ]]
work_options=$(findmnt -nro VFS-OPTIONS --mountpoint "$base/work")
input_options=$(findmnt -nro VFS-OPTIONS --mountpoint "$root/updater-input")
[[ ,$work_options, == *,nosuid,* && ,$input_options, == *,ro,* && $(blockdev --getro "$input") == 1 ]]
printf 'UPDATER_Q3_MOUNTS %s {"boot_ro":true,"media_ro":true,"scratch_nosuid":true,"sudo_single_file":true}\n' "$nonce"
phase=worker
set +e
timeout --signal=TERM --kill-after=20s 600s chroot "$root" /usr/bin/env -i \
    PATH=/usr/bin:/bin LC_ALL=C TZ=UTC /usr/bin/python -I -B /updater-code/guest.py \
    </dev/null >"$base/report.json" 2>/dev/null
rc=$?
set -e
[[ -s $base/report.json && $(stat -c %s "$base/report.json") -le 16384 &&
   $(wc -l <"$base/report.json") == 1 ]]
printf 'UPDATER_Q3_REPORT %s ' "$nonce"
cat "$base/report.json"
[[ $rc == 0 ]]
phase=complete result=PASS
