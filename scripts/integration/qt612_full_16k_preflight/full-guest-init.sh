#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for the sealed Qtbase all-target continuation in the disposable guest.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

readonly ROOT=/qtwork/root VOLUME=/qtbase-full EXPORT=/qtexport
readonly EVIDENCE=/qtbase-full-evidence PLAN=/qtmedia/FULL-GUEST-PLAN.json
readonly SCRATCH_UUID=ed56022f-4e82-f6e3-fbde-502489347154 EXPORT_RESERVE=8388608
readonly WORKER_HELPER_SECONDS=560
declare -A caps=()

parse_cmdline() {
    local word key value
    local -A fields=()
    for word in "$@"; do
        case "$word" in
            cachy_qt_full_*=*)
                key=${word%%=*}
                key=${key#cachy_qt_full_}
                value=${word#*=}
                case "$key" in
                    nonce|manifest|guest_plan|scratch_uuid|result_uuid|result_bytes|guest_deadline) ;;
                    *) return 1 ;;
                esac
                [[ ! -v fields[$key] ]] || return 1
                fields[$key]=$value ;;
            cachy_qt_full_*) return 1 ;;
        esac
    done
    [[ ${#fields[@]} == 7 ]] || return 1
    nonce=${fields[nonce]} manifest=${fields[manifest]} guest_plan=${fields[guest_plan]}
    scratch_uuid=${fields[scratch_uuid]} result_uuid=${fields[result_uuid]}
    result_bytes=${fields[result_bytes]} guest_deadline=${fields[guest_deadline]}
    [[ $nonce =~ ^[0-9a-f]{32}$ && $manifest =~ ^[0-9a-f]{64}$ && $guest_plan =~ ^[0-9a-f]{64}$
       && $scratch_uuid == "$SCRATCH_UUID" && $scratch_uuid != "$result_uuid"
       && $result_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$
       && $result_bytes =~ ^[1-9][0-9]{7,9}$ && $guest_deadline =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    (( result_bytes >= 67108864 && result_bytes <= 4294967296 && result_bytes % 4096 == 0
       && guest_deadline <= 90000 ))
}

verify_payload() (
    local leaf reconstructed
    local -a expected=(FULL-GUEST-PLAN.json full_guest.py guest-init.sh guest_link.py)
    shopt -s dotglob nullglob
    local -a actual=(*)
    [[ ${#actual[@]} == 5 ]] || return 1
    for leaf in "${expected[@]}" MANIFEST.sha256; do
        [[ -s $leaf && -f $leaf && ! -L $leaf && $(stat -c %h -- "$leaf") == 1
           && $(stat -c %s -- "$leaf") -le 131072 ]] || return 1
    done
    [[ $(stat -c %s -- FULL-GUEST-PLAN.json) -le 4096
       && $(stat -c %s -- MANIFEST.sha256) -le 512 ]] || return 1
    printf '%s  %s\n' "$manifest" MANIFEST.sha256 "$guest_plan" FULL-GUEST-PLAN.json |
        sha256sum --strict -c - >/dev/null || return 1
    reconstructed=$(sha256sum -- "${expected[@]}" | sha256sum) || return 1
    [[ $reconstructed == "$manifest  -" ]]
)

whole_virtio() {
    local disk=$1 node path bus
    [[ $disk =~ ^/dev/[a-z0-9][a-z0-9._-]{0,63}$ && -b $disk && ! -L $disk ]] || return 1
    node=${disk#/dev/}
    path=$(readlink -e -- "/sys/class/block/$node") || return 1
    [[ $path == /sys/devices/*/block/"$node" && ! -e $path/partition && -r $path/dev ]] || return 1
    bus=${path%/block/*}
    [[ $(readlink -e -- "$bus/driver") == /sys/bus/virtio/drivers/virtio_blk
       && $(stat -c '%Hr:%Lr' -- "$disk") == "$(<"$path/dev")" ]] || return 1
    printf '%s\n' "$path"
}

verify_boot() {
    local number partition disk
    number=$(findmnt -nro MAJ:MIN /) || return 1
    [[ $number =~ ^[0-9]+:[0-9]+$ && $(findmnt -nro FSTYPE /) == ext4 ]] || return 1
    partition=$(readlink -e -- "/sys/dev/block/$number") || return 1
    [[ -r $partition/partition && $(<"$partition/partition") == 1 ]] || return 1
    boot_path=${partition%/*}
    disk=/dev/${boot_path##*/}
    [[ $(whole_virtio "$disk") == "$boot_path" && $(blockdev --getro "$disk") == 1
       && $(blkid -c /dev/null -t "PARTUUID=${nonce:0:8}-01" -o device) == "/dev/${partition##*/}" ]]
}

verify_volume() {
    local disk=$1 path=$2 uuid=$3 label=$4 bytes=$5 partition
    for partition in "$path"/*/partition; do
        [[ ! -e $partition ]] || return 1
    done
    [[ $(blkid -c /dev/null -t "LABEL=$label" -o device) == "$disk"
       && $(blkid -p -s UUID -o value "$disk") == "$uuid"
       && $(blkid -p -s LABEL -o value "$disk") == "$label"
       && $(blkid -p -s TYPE -o value "$disk") == ext4
       && $(blockdev --getsize64 "$disk") == "$bytes" && $(blockdev --getro "$disk") == 0 ]]
}

select_storage() {
    local scratch target scratch_path target_path attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if scratch=$(blkid -c /dev/null -t "UUID=$scratch_uuid" -o device) &&
           target=$(blkid -c /dev/null -t "UUID=$result_uuid" -o device); then
            break
        fi
        sleep 0.2
    done
    (( attempt < 50 )) || return 1
    scratch_path=$(whole_virtio "$scratch") && target_path=$(whole_virtio "$target") || return 1
    [[ $scratch_path != "$target_path" && $scratch_path != "$boot_path" && $target_path != "$boot_path" ]] || return 1
    verify_volume "$scratch" "$scratch_path" "$scratch_uuid" QT16K_WORK 17179869184 &&
        verify_volume "$target" "$target_path" "$result_uuid" QT16K_FULL "$result_bytes" || return 1
    work=$scratch result=$target
}

guest() {
    local deadline=$1
    shift
    timeout --kill-after=20s "$deadline" chroot --userspec=1000:1000 --groups=1000 "$ROOT" \
        /usr/bin/env -i PATH=/usr/bin:/bin "$@"
}

worker_contract() {
    guest 30 /usr/bin/python -I -B -Werror - "$guest_plan" "$nonce" "$1" "$PLAN" "$EVIDENCE" 2>/dev/null <<'PY'
from pathlib import Path
import runpy
import sys

digest, nonce, mode, path, evidence = sys.argv[1:]
worker = runpy.run_path("/qtmedia/full_guest.py")
plan = worker["read_plan"](Path(path), digest)
if plan["nonce"] != nonce:
    sys.exit(1)
if mode == "caps":
    limits = plan["limits"]
    print(limits["guest_build_seconds"], limits["build_log_bytes"], limits["artifact_bytes"])
    for name, size in sorted(worker["evidence_caps"](plan).items()):
        print(name, size)
elif mode == "pass":
    expected = dict(kind="QTBASE_FULL16K_GUEST_RESULT_V1", status="PASS", phase="complete", nonce=nonce,
                    plan_sha256=digest, target=plan["target"])
    expected_raw = worker["wire_evidence"](expected)
    if worker["read_leaf"](Path(evidence) / "result.json", len(expected_raw)) != expected_raw:
        sys.exit(1)
else:
    sys.exit(1)
PY
}

parse_caps() {
    local lines=$1 build_seconds log_cap rest leaf limit
    {
        read -r build_seconds log_cap artifact_cap rest || return 1
        [[ $build_seconds =~ ^[1-9][0-9]{0,4}$ && $log_cap =~ ^[1-9][0-9]{0,8}$
           && $artifact_cap =~ ^[1-9][0-9]{0,9}$ && -z $rest ]] || return 1
        (( guest_deadline >= build_seconds && result_bytes >= artifact_cap + log_cap + EXPORT_RESERVE )) || return 1
        while read -r leaf limit rest; do
            [[ $leaf =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ && $limit =~ ^[1-9][0-9]{0,9}$ && -z $rest ]] ||
                return 1
            [[ ! -v caps[$leaf] && ${#caps[@]} -lt 64 ]] && (( limit <= result_bytes - EXPORT_RESERVE )) ||
                return 1
            caps[$leaf]=$limit
        done
    } <<<"$lines"
    [[ -v caps[result.json] && -v caps[build.log] && ${caps[build.log]} == "$log_cap" ]] || return 1
    build_cap=$build_seconds
}

worker_timeout() {
    local uptime=$1 elapsed remaining
    [[ $uptime =~ ^([0-9]{1,8})\.[0-9]{2}$ ]] || return 1
    elapsed=$(( 10#${BASH_REMATCH[1]} + 1 ))
    remaining=$(( guest_deadline - elapsed ))
    (( remaining >= build_cap + WORKER_HELPER_SECONDS )) || return 1
    printf '%d\n' "$remaining"
}

builder_absent() {
    local receipt
    [[ -r /proc/self/status ]] || return 1
    for receipt in /proc/[0-9]*/status; do
        if grep -Eq '^Uid:([[:space:]]+[0-9]+){0,3}[[:space:]]+1000([[:space:]]|$)' "$receipt" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

fresh_result_root() (
    shopt -s dotglob nullglob
    local -a entries=("$1"/*)
    (( ${#entries[@]} == 0 )) && return 0
    [[ ${#entries[@]} == 1 && ${entries[0]} == "$1/lost+found" &&
       -d ${entries[0]} && ! -L ${entries[0]} && $(stat -c %u:%g:%a -- "${entries[0]}") == 0:0:700 ]] ||
        return 1
    entries=("$1/lost+found/"*)
    (( ${#entries[@]} == 0 ))
)

retain() (
    local source=$1 target=$2 state=$3 file leaf size total=0 artifacts=0 problem=0 count=0
    shopt -s dotglob nullglob
    for file in "$source"/*; do
        leaf=${file##*/}
        count=$((count+1))
        (( count <= 64 )) || return 1
        if [[ ! $leaf =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ || ! -v caps[$leaf]
              || ! -f $file || -L $file || $(stat -c %h -- "$file") != 1 ]] ||
           ! size=$(stat -c %s -- "$file") || (( size > caps[$leaf] )); then
            problem=1
            continue
        fi
        if (( total + size > result_bytes - EXPORT_RESERVE )); then
            problem=1
            continue
        fi
        case "$leaf" in
            libQt6*.so.6.12.0)
                if (( artifacts + size > artifact_cap )); then
                    problem=1
                    continue
                fi
                artifacts=$((artifacts+size)) ;;
        esac
        total=$((total+size))
        install -m 600 -- "$file" "$target/$leaf" || problem=1
    done
    if [[ $state == PASS ]]; then
        for leaf in "${!caps[@]}"; do
            [[ -s $target/$leaf ]] || problem=1
        done
    fi
    (( problem == 0 ))
)

finish() {
    trap - ERR HUP INT TERM
    set +e
    local state=$1 path
    if [[ -n $result && -d $ROOT$EVIDENCE && ! -L $ROOT$EVIDENCE ]] && builder_absent; then
        if mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" "$EXPORT"; then
            if fresh_result_root "$EXPORT" && mkdir -m 700 "$EXPORT/evidence"; then
                retain "$ROOT$EVIDENCE" "$EXPORT/evidence" "$state" || { state=HOLD phase=retain; }
                sync -f "$EXPORT" || { state=HOLD phase=retain; }
            else
                state=HOLD phase=retain
            fi
        else
            state=HOLD phase=retain
        fi
    elif [[ $state == PASS ]]; then
        state=HOLD phase=retain
    fi
    for path in "$EXPORT" "$ROOT/qtmedia" "$ROOT/sys" "$ROOT/proc" "$ROOT/dev" /qtwork; do
        if mountpoint -q -- "$path"; then
            umount -n -- "$path" || { state=HOLD phase=cleanup; }
        fi
    done
    printf 'QTBASE_FULL16K_TERMINAL %s %s %s\n' "$nonce" "$state" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

main() {
    [[ $# == 0 && $$ == 1 && $EUID == 0 ]]
    phase=boot nonce=unknown result=
    trap 'finish HOLD' ERR HUP INT TERM
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    local -a cmdline
    read -r -a cmdline < /proc/cmdline
    parse_cmdline "${cmdline[@]}"
    [[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    [[ ,$(findmnt -nro VFS-OPTIONS /), == *,ro,* ]]
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
    mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp
    [[ $(ls -1 /sys/class/net) == lo ]]
    verify_boot
    [[ -d $VOLUME && ! -L $VOLUME ]]
    (cd "$VOLUME" && verify_payload)

    phase=storage
    select_storage
    mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
    local path device leaf major minor lines uptime ignored worker_seconds
    for path in "$ROOT" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/qtmedia" "$EXPORT"; do
        [[ -d $path && ! -L $path ]]
    done
    mount -n -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs "$ROOT/dev"
    for device in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
        read -r leaf major minor <<<"$device"
        mknod -m 666 "$ROOT/dev/$leaf" c "$major" "$minor"
    done
    ln -s /proc/self/fd "$ROOT/dev/fd"
    mount -n -t proc -o ro,nosuid,nodev,noexec proc "$ROOT/proc"
    for path in sys qtmedia; do
        device=/$path
        if [[ $path == qtmedia ]]; then device=$VOLUME; fi
        mount -n --bind "$device" "$ROOT/$path"
        mount -n -o remount,bind,ro,nosuid,nodev,noexec "$ROOT/$path"
    done
    lines=$(worker_contract caps)
    parse_caps "$lines"
    [[ ! -e $ROOT$EVIDENCE && ! -L $ROOT$EVIDENCE ]]
    install -d -o 1000 -g 1000 -m 700 "$ROOT$EVIDENCE"

    phase=build
    read -r uptime ignored < /proc/uptime
    worker_seconds=$(worker_timeout "$uptime")
    guest "$worker_seconds" /usr/bin/python -I -B -Werror /qtmedia/full_guest.py \
        --plan "$PLAN" --plan-sha256 "$guest_plan" --evidence "$EVIDENCE" \
        --worker-deadline-uptime "$guest_deadline" </dev/null >/dev/null 2>&1
    builder_absent
    worker_contract pass
    phase=complete
    finish PASS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
