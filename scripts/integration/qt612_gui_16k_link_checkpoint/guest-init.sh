#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for the sealed QtGui continuation on the private top of the QEMU chain.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

parse_cmdline() {
    local word key value
    declare -A fields=()
    for word in "$@"; do
        case "$word" in
            cachy_qt_gui_*=*)
                key=${word%%=*}
                value=${word#*=}
                case "$key" in
                    cachy_qt_gui_nonce|cachy_qt_gui_manifest|cachy_qt_gui_guest_plan|cachy_qt_gui_scratch_uuid|\
                    cachy_qt_gui_result_uuid|cachy_qt_gui_result_bytes|cachy_qt_gui_guest_deadline) ;;
                    *) return 1 ;;
                esac
                [[ ! -v fields[$key] ]] || return 1
                fields[$key]=$value ;;
            cachy_qt_gui_*) return 1 ;;
        esac
    done
    [[ ${#fields[@]} == 7 ]] || return 1
    nonce=${fields[cachy_qt_gui_nonce]}
    manifest=${fields[cachy_qt_gui_manifest]}
    guest_plan=${fields[cachy_qt_gui_guest_plan]}
    scratch_uuid=${fields[cachy_qt_gui_scratch_uuid]}
    result_uuid=${fields[cachy_qt_gui_result_uuid]}
    result_bytes=${fields[cachy_qt_gui_result_bytes]}
    guest_deadline=${fields[cachy_qt_gui_guest_deadline]}
    [[ $nonce =~ ^[0-9a-f]{32}$ && $manifest =~ ^[0-9a-f]{64}$ && $guest_plan =~ ^[0-9a-f]{64}$
       && $scratch_uuid == ed56022f-4e82-f6e3-fbde-502489347154 && $scratch_uuid != "$result_uuid"
       && $result_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
       && $result_bytes =~ ^[1-9][0-9]{7,9}$ && $guest_deadline =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    (( result_bytes >= 67108864 && result_bytes <= 4294967296 && result_bytes % 4096 == 0
       && guest_deadline <= 90000 ))
}

verify_payload() {
    local leaf
    for leaf in GUI-GUEST-PLAN.json guest-init.sh guest_link.py MANIFEST.sha256; do
        [[ -s $leaf && -f $leaf && ! -L $leaf && $(stat -c %h -- "$leaf") == 1 ]] || return 1
    done
    [[ $(stat -c %s -- GUI-GUEST-PLAN.json) -le 4096 && $(stat -c %s -- MANIFEST.sha256) -le 512
       && $(stat -c %s -- guest-init.sh) -le 131072 && $(stat -c %s -- guest_link.py) -le 131072 ]] || return 1
    printf '%s  %s\n' "$manifest" MANIFEST.sha256 "$guest_plan" GUI-GUEST-PLAN.json |
        sha256sum --strict -c - >/dev/null || return 1
    local reconstructed
    reconstructed=$(sha256sum -- GUI-GUEST-PLAN.json guest-init.sh guest_link.py | sha256sum) || return 1
    [[ $reconstructed == "$manifest  -" ]]
}

whole_virtio() {
    local disk=$1 node path virtio
    [[ $disk =~ ^/dev/[a-z0-9][a-z0-9._-]{0,63}$ && -b $disk && ! -L $disk ]] || return 1
    node=${disk#/dev/}
    path=$(readlink -e -- "/sys/class/block/$node") || return 1
    [[ $path == /sys/devices/*/block/"$node" && ! -e $path/partition && -r $path/dev ]] || return 1
    virtio=${path%/block/*}
    [[ $(readlink -e -- "$virtio/driver") == /sys/bus/virtio/drivers/virtio_blk
       && $(stat -c '%Hr:%Lr' -- "$disk") == "$(<"$path/dev")" ]] || return 1
    printf '%s\n' "$path"
}

flat_whole() {
    local partition
    for partition in "$1"/*/partition; do
        [[ ! -e $partition ]] || return 1
    done
}

storage_error() {
    printf 'QTGUI_LINK_STORAGE %s %s\n' "$nonce" "$1"
    return 1
}

verify_boot() {
    local number partition parent
    number=$(findmnt -nro MAJ:MIN /) || return 1
    [[ $number =~ ^[0-9]+:[0-9]+$ ]] || return 1
    partition=$(readlink -e -- "/sys/dev/block/$number") || return 1
    [[ -r $partition/partition ]] || return 1
    parent=${partition%/*}
    [[ $(whole_virtio "/dev/${parent##*/}") == "$parent"
       && $(blockdev --getro "/dev/${parent##*/}") == 1 ]]
}

select_storage() {
    local scratch target scratch_path target_path disk expected_uuid expected_label attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if scratch=$(blkid -c /dev/null -t "UUID=$scratch_uuid" -o device) &&
           target=$(blkid -c /dev/null -t "UUID=$result_uuid" -o device); then
            break
        fi
        sleep 0.2
    done
    [[ $attempt -lt 50 ]] || { storage_error UUID_LOOKUP; return 1; }
    scratch_path=$(whole_virtio "$scratch") && target_path=$(whole_virtio "$target") ||
        { storage_error WHOLE_VIRTIO; return 1; }
    [[ $scratch_path != "$target_path" ]] || { storage_error DISK_ALIAS; return 1; }
    flat_whole "$scratch_path" && flat_whole "$target_path" || { storage_error FLAT_DISK; return 1; }
    for disk in "$scratch" "$target"; do
        if [[ $disk == "$scratch" ]]; then
            expected_uuid=$scratch_uuid expected_label=QT16K_WORK
        else
            expected_uuid=$result_uuid expected_label=QT16K_GUI
        fi
        [[ $(blkid -c /dev/null -t "LABEL=$expected_label" -o device) == "$disk"
           && $(blkid -p -s UUID -o value "$disk") == "$expected_uuid"
           && $(blkid -p -s LABEL -o value "$disk") == "$expected_label"
           && $(blkid -p -s TYPE -o value "$disk") == ext4 ]] || { storage_error FILESYSTEM_ID; return 1; }
    done
    [[ $(blockdev --getsize64 "$scratch") == 17179869184
       && $(blockdev --getsize64 "$target") == "$result_bytes" ]] || { storage_error GEOMETRY; return 1; }
    [[ $(blockdev --getro "$scratch") == 0 && $(blockdev --getro "$target") == 0 ]] ||
        { storage_error WRITE_STATE; return 1; }
    work=$scratch result=$target
}

worker_contract() {
    # The pinned chroot already supplies this Python; the minimal boot root need not.
    chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python -I -B -Werror - \
        "$guest_plan" "$nonce" "$1" <<'PY'
from pathlib import Path
import runpy
import sys

digest, nonce, mode = sys.argv[1:]
worker = runpy.run_path("/qtmedia/guest_link.py")
plan = worker["read_plan"](Path("/qtmedia/GUI-GUEST-PLAN.json"), digest)
if plan["nonce"] != nonce:
    sys.exit("Guest plan nonce differs from the boot identity")
if mode == "limits":
    limits = plan["limits"]
    print(limits["guest_build_seconds"], limits["build_log_bytes"], limits["artifact_bytes"])
elif mode == "pass":
    _, _, original = worker["file_data"](Path("/qtgui-evidence/result.json"), 4096, collect=True)
    import json
    expected = dict(kind="QTGUI_LINK_GUEST_RESULT_V1", status="PASS", phase="complete", nonce=nonce,
                    plan_sha256=digest, core=plan["core"], target=plan["target"])
    if original != (json.dumps(expected, sort_keys=True, indent=2) + "\n").encode():
        sys.exit("Exact original successful guest outcome required")
else:
    sys.exit("Unknown PID1 contract mode")
PY
}

builder_absent() {
    local receipt
    for receipt in /proc/[0-9]*/status; do
        if grep -Eq '^Uid:[[:space:]]+1000[[:space:]]' "$receipt" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

retain() (
    local source=$1 target=$2 state=$3 file leaf size limit artifact_total=0 problem=0 count=0
    local -a required=(inventory.before inventory.after core.commands gui.commands gui.link-command
                       core-dry-run.log gui-dry-run.log build.log metrics.json aliases.txt
                       libQt6Gui.so.6.12.0 libQt6DBus.so.6.12.0 libmd4c.so.0.5.3 result.json)
    shopt -s dotglob nullglob
    for file in "$source"/*; do
        leaf=${file##*/}
        count=$((count+1))
        (( count <= 32 )) || return 1
        case "$leaf" in
            inventory.before|inventory.after) limit=6925 ;;
            inventory.before.raw|inventory.after.raw) limit=16384; [[ $state == HOLD ]] || problem=1 ;;
            core.commands) limit=671480 ;;
            gui.commands) limit=1373001 ;;
            gui.commands.after) limit=1373001; [[ $state == HOLD ]] || problem=1 ;;
            gui.link-command) limit=15466 ;;
            core-dry-run.log|metrics.json|aliases.txt|result.json) limit=4096 ;;
            gui-dry-run.log) limit=1438537 ;;
            build.log) limit=$log_cap ;;
            libQt6Gui.so.6.12.0|libQt6DBus.so.6.12.0|libmd4c.so.0.5.3) limit=$artifact_cap ;;
            *) problem=1; continue ;;
        esac
        if [[ ! -f $file || -L $file || $(stat -c %h -- "$file") != 1 ]] ||
           ! size=$(stat -c %s -- "$file") || [[ ! $size =~ ^[0-9]{1,10}$ ]] || (( size > limit )); then
            problem=1
            continue
        fi
        case "$leaf" in
            libQt6Gui.so.6.12.0|libQt6DBus.so.6.12.0|libmd4c.so.0.5.3)
                artifact_total=$((artifact_total+size))
                if (( artifact_total > artifact_cap )); then
                    problem=1
                    continue
                fi ;;
        esac
        install -m 600 -- "$file" "$target/$leaf" || problem=1
    done
    if [[ $state == PASS ]]; then
        for leaf in "${required[@]}"; do
            [[ -s $target/$leaf ]] || problem=1
        done
    fi
    (( problem == 0 ))
)

finish() {
    trap - ERR HUP INT TERM
    set +e
    local state=$1 file export_mounted=0
    if [[ -n $result && -d $evidence && ! -L $evidence ]] && builder_absent; then
        if mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" /qtexport; then
            export_mounted=1
            if ! mkdir -m 700 /qtexport/evidence || ! retain "$evidence" /qtexport/evidence "$state"; then
                state=HOLD phase=retain
            fi
            if ! sync -f /qtexport; then
                state=HOLD phase=retain
            fi
        else
            state=HOLD phase=retain
        fi
    elif [[ $state == PASS ]]; then
        state=HOLD phase=retain
    fi
    for file in "$root/qtmedia" "$root/sys" "$root/proc" "$root/dev" /qtwork; do
        if mountpoint -q -- "$file"; then
            umount -n -- "$file" || { state=HOLD phase=cleanup; }
        fi
    done
    if (( export_mounted )) && ! umount -n /qtexport; then
        state=HOLD phase=cleanup
    fi
    printf 'QTGUI_LINK_TERMINAL %s %s %s\n' "$nonce" "$state" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

main() {
    [[ $# == 0 && $$ == 1 && $EUID == 0 ]]
    root=/qtwork/root
    volume=/qtgui-link
    evidence=$root/qtgui-evidence
    phase=boot nonce=unknown manifest=unknown result= log_cap=0 artifact_cap=0
    trap 'finish HOLD' ERR HUP INT TERM
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    local -a cmdline
    read -r -a cmdline < /proc/cmdline
    parse_cmdline "${cmdline[@]}"
    [[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    findmnt -n -o VFS-OPTIONS / | grep -qw ro
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
    mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp
    [[ $(ls -1 /sys/class/net) == lo ]]
    verify_boot
    cd "$volume"
    verify_payload

    phase=storage
    select_storage || finish HOLD
    mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
    local path device leaf major minor limits build_seconds rest
    for path in "$root" "$root/dev" "$root/proc" "$root/sys" "$root/qtmedia" /qtexport; do
        [[ -d $path && ! -L $path ]]
    done
    mount -n -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs "$root/dev"
    for device in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
        read -r leaf major minor <<<"$device"
        mknod -m 666 "$root/dev/$leaf" c "$major" "$minor"
    done
    ln -s /proc/self/fd "$root/dev/fd"
    mount -n -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"
    mount -n --bind /sys "$root/sys"
    mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/sys"
    mount -n --bind "$volume" "$root/qtmedia"
    mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/qtmedia"
    limits=$(worker_contract limits)
    read -r build_seconds log_cap artifact_cap rest <<<"$limits"
    [[ $build_seconds =~ ^[1-9][0-9]{0,4}$ && $log_cap =~ ^[1-9][0-9]{0,7}$
       && $artifact_cap =~ ^[1-9][0-9]{0,9}$ && -z $rest ]]
    (( guest_deadline >= build_seconds && result_bytes >= artifact_cap + log_cap + 8388608 ))
    [[ ! -e $evidence && ! -L $evidence ]]
    install -d -o 1000 -g 1000 -m 700 "$evidence"

    phase=link
    timeout --kill-after=20s "$guest_deadline" chroot --userspec=1000:1000 --groups=1000 "$root" \
        /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/python -I -B -Werror /qtmedia/guest_link.py \
        --plan /qtmedia/GUI-GUEST-PLAN.json --plan-sha256 "$guest_plan" --evidence /qtgui-evidence </dev/null
    worker_contract pass
    phase=complete
    finish PASS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
