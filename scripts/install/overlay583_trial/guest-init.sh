#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for the disposable offline 16 KiB package transaction.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C

phase=bootstrap
nonce=unknown

poweroff_guest() {
    /usr/bin/systemctl --force --force poweroff || :
    # The owner times out and retires QEMU if the shutdown syscall returns.
    while :; do sleep 60; done
}

hold() {
    trap - ERR HUP INT TERM
    set +e
    printf 'OVERLAY583 %s HOLD %s\n' "$nonce" "$1"
    for at in /trial-export /trial-work /trial-scratch /trial-code /trial-inputs /trial-media; do
        if mountpoint -q "$at"; then umount -n -- "$at"; fi
    done
    poweroff_guest
}

trap 'hold "$phase"' ERR
trap 'hold interrupted' HUP INT TERM

boot_selection() {
    local -a args
    local term got_nonce= got_plan= got_worker=
    local nonces=0 plans=0 workers=0
    read -r -a args < /proc/cmdline
    for term in "${args[@]}"; do
        case "$term" in
            cachy_overlay583_nonce=*) got_nonce=${term#*=}; nonces=$((nonces+1)) ;;
            cachy_overlay583_plan=*) got_plan=${term#*=}; plans=$((plans+1)) ;;
            cachy_overlay583_worker=*) got_worker=${term#*=}; workers=$((workers+1)) ;;
        esac
    done
    [[ $nonces == 1 && $got_nonce =~ ^[0-9a-f]{32}$ ]]
    nonce=$got_nonce
    [[ $plans == 1 && $got_plan =~ ^[0-9a-f]{64}$ ]]
    [[ $workers == 1 && $got_worker =~ ^[0-9a-f]{64}$ ]]
    plan=$got_plan worker=$got_worker
}

root_mount_is_readonly() {
    local -a fields
    local separator roots=0 options
    while read -r -a fields; do
        [[ ${fields[4]-} == / ]] || continue
        roots=$((roots+1))
        options=,${fields[5]-},
        [[ $options == *,ro,* && $options != *,rw,* ]] || return 1
        separator=6
        while [[ ${fields[separator]-} && ${fields[separator]} != - ]]; do
            separator=$((separator+1))
        done
        [[ ${fields[separator]-} == - && ${fields[separator+1]-} == ext4 &&
           -n ${fields[separator+2]-} && -n ${fields[separator+3]-} ]] || return 1
    done
    [[ $roots == 1 ]]
}

select_disks() {
    local attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if input=$(/usr/bin/blkid -c /dev/null -L OV583_INPUT) &&
           scratch=$(/usr/bin/blkid -c /dev/null -L OV583_WORK) &&
           result=$(/usr/bin/blkid -c /dev/null -L OV583_RESULT); then
            break
        fi
        sleep 0.2
    done
    [[ $attempt -lt 50 && $input != "$scratch" && $input != "$result" && $scratch != "$result" ]]
    local disk
    for disk in "$input" "$scratch" "$result"; do
        [[ $disk =~ ^/dev/vd[a-z]+$ && -b $disk && ! -L $disk ]]
    done
    [[ $(blockdev --getro "$input") == 1 && $(blockdev --getsize64 "$input") == 2147483648 ]]
    [[ $(blockdev --getro "$scratch") == 0 && $(blockdev --getsize64 "$scratch") == 17179869184 ]]
    [[ $(blockdev --getro "$result") == 0 && $(blockdev --getsize64 "$result") == 67108864 ]]
}

export_evidence() {
    local source=$1 dest=$2
    local name file metadata links bytes total=0
    [[ -d $source && ! -L $source && -f $source/result.json ]] || return 1
    shopt -s nullglob dotglob
    local -a actual=("$source"/*)
    [[ ${#actual[@]} -le 48 ]] || return 1
    mkdir -m 0700 "$dest" || return 1
    for file in "${actual[@]}"; do
        name=${file##*/}
        case "$name" in
            installed.lock|removed.lock|refused.lock|reinstalled.lock|without-setup.lock|before-upgrade.lock|after-upgrade.lock|first-login.json|refusal-db-before.json|refusal-db-after.json|result.json|pacman.log) ;;
            *.stdout|*.stderr)
                case "${name%.*}" in
                    import-[012]|ownertrust|refresh|resolve|install|query|check|remove-plan|remove|query-base|check-base|signature-refusal|query-refused|check-refused|reinstall-plan|reinstall|query-restored|check-restored) ;;
                    import-predecessor|trust-predecessor|resolve-base-and-shells|install-base-and-shells|query-without-setup|check-without-setup|predecessor-plan|install-predecessor|query-before|check-before|upgrade-plan|upgrade|query-after|check-after) ;;
                    *) return 1 ;;
                esac ;;
            *) return 1 ;;
        esac
        [[ -f $file && ! -L $file ]] || return 1
        metadata=$(stat -c '%d %i %h %s %y %z' -- "$file") || return 1
        read -r _ _ links bytes _ <<< "$metadata" || return 1
        [[ $links == 1 && $bytes =~ ^(0|[1-9][0-9]{0,7})$ && $bytes -le 8388608 ]] || return 1
        total=$((total+bytes))
        [[ $total -le 33554432 ]] || return 1
        head -c "$((bytes+1))" -- "$file" > "$dest/$name" || return 1
        [[ $(stat -c '%s' -- "$dest/$name") == "$bytes" ]] || return 1
        [[ $(stat -c '%d %i %h %s %y %z' -- "$file") == "$metadata" ]] || return 1
    done
}

[[ $$ == 1 && $# == 0 && $EUID == 0 ]]
mount -n -t proc -o nosuid,nodev,noexec proc /proc
boot_selection
phase=platform
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
root_mount_is_readonly < /proc/self/mountinfo
if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp

phase=storage
select_disks
mount -n -t ext4 -o ro,noload,nosuid,nodev "$input" /trial-media
for tree in inputs code; do
    [[ -d /trial-media/$tree && ! -L /trial-media/$tree ]]
    mount -n --bind "/trial-media/$tree" "/trial-$tree"
    mount -n -o remount,bind,ro,nosuid,nodev,noexec "/trial-$tree"
done
mount -n -t ext4 -o rw,nosuid,nodev "$scratch" /trial-scratch
mkdir -m 0700 /trial-scratch/work
mount -n --bind /trial-scratch/work /trial-work

phase=transaction
outcome='PASS 16384'
LD_LIBRARY_PATH=/trial-media/runtime/usr/lib \
    /trial-media/runtime/usr/bin/python3.14 -I -B /trial-code/trial.py guest "$plan" "$worker" || {
        [[ $? == 75 ]]
        outcome='HOLD lifecycle'
    }

phase=export
mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" /trial-export
export_evidence /trial-work/evidence /trial-export/evidence
phase=retirement
sync
umount -n /trial-export /trial-work /trial-scratch /trial-code /trial-inputs /trial-media
printf 'OVERLAY583 %s %s\n' "$nonce" "$outcome"
poweroff_guest
