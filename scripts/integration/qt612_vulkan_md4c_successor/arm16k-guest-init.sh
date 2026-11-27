#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for the disposable, offline ARM64 Qtbase successor.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

readonly MEDIA=/qt-successor ROOT=/qtwork/root EXPORT=/qtexport
readonly WORK_UUID=ed56022f-4e82-f6e3-fbde-502489347154
readonly EVIDENCE=/qt-successor-evidence ARCHIVE=qtbase-everywhere-src-6.12.0.tar.xz
readonly PACKAGE=cachy-asahi-qt612-gui-server-source-reference-6.12.0-3-aarch64.pkg.tar.xz
readonly -a SETUP_FILES=(before.lock after.lock gpgv.log alpm.log package-check.log)
readonly -a BUILD_FILES=(build.log dependencies.log features.txt profile.json graph.sha256 CMakeCache.txt build.ninja rules.ninja)
readonly -a FULL_FILES=(stage-contract.json vulkan-md4c-elf.json archive.sha256 "$PACKAGE")
phase=boot nonce=unknown mode=unknown result= work= result_ready=0

parse_selection() {
    local term key
    local -A fields=()
    local -a terms
    read -r -a terms < /proc/cmdline
    for term in "${terms[@]}"; do
        [[ $term == cachy_qt_successor_* ]] || continue
        key=${term%%=*}
        key=${key#cachy_qt_successor_}
        case $key in
            nonce|manifest|result_uuid|result_bytes|deadline|mode) ;;
            *) return 1 ;;
        esac
        [[ $term == *=* && ! -v fields[$key] ]] || return 1
        fields[$key]=${term#*=}
    done
    [[ ${#fields[@]} == 6 ]] || return 1
    nonce=${fields[nonce]} manifest=${fields[manifest]} mode=${fields[mode]}
    result_uuid=${fields[result_uuid]} result_bytes=${fields[result_bytes]} deadline=${fields[deadline]}
    [[ $nonce =~ ^[0-9a-f]{32}$ && $manifest =~ ^[0-9a-f]{64}$ && $mode =~ ^(configure|full)$ &&
       $result_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ &&
       $result_uuid != "$WORK_UUID" && $result_bytes =~ ^[1-9][0-9]{7,9}$ && $deadline =~ ^[1-9][0-9]{2,4}$ ]] || return 1
    (( result_bytes >= 134217728 && result_bytes <= 4294967296 && result_bytes % 4096 == 0 &&
       deadline >= 420 && deadline <= 90000 ))
}

whole_virtio() {
    local disk=$1 node path bus
    [[ $disk =~ ^/dev/vd[a-z]+$ && -b $disk && ! -L $disk ]] || return 1
    node=${disk#/dev/}
    path=$(readlink -e -- "/sys/class/block/$node") || return 1
    bus=${path%/block/*}
    [[ $path == /sys/devices/*/block/"$node" && ! -e $path/partition &&
       $(readlink -e -- "$bus/driver") == /sys/bus/virtio/drivers/virtio_blk &&
       $(stat -c '%Hr:%Lr' -- "$disk") == "$(<"$path/dev")" ]] || return 1
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
    [[ $(whole_virtio "$disk") == "$boot_path" && $(blockdev --getro "$disk") == 1 &&
       $(blkid -c /dev/null -t "PARTUUID=${nonce:0:8}-01" -o device) == "/dev/${partition##*/}" ]]
}

verify_volume() {
    local disk=$1 path=$2 uuid=$3 label=$4 bytes=$5 partition
    for partition in "$path"/*/partition; do
        [[ ! -e $partition ]] || return 1
    done
    [[ $(blkid -p -s UUID -o value "$disk") == "$uuid" &&
       $(blkid -p -s LABEL -o value "$disk") == "$label" &&
       $(blkid -p -s TYPE -o value "$disk") == ext4 &&
       $(blockdev --getsize64 "$disk") == "$bytes" && $(blockdev --getro "$disk") == 0 ]]
}

select_storage() {
    local source target source_path target_path attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if source=$(blkid -c /dev/null -t "UUID=$WORK_UUID" -o device) &&
           target=$(blkid -c /dev/null -t "UUID=$result_uuid" -o device); then
            break
        fi
        sleep 0.2
    done
    (( attempt < 50 )) || return 1
    source_path=$(whole_virtio "$source") && target_path=$(whole_virtio "$target") || return 1
    [[ $source_path != "$target_path" && $source_path != "$boot_path" && $target_path != "$boot_path" ]] || return 1
    verify_volume "$source" "$source_path" "$WORK_UUID" QT16K_WORK 17179869184 &&
        verify_volume "$target" "$target_path" "$result_uuid" QT16K_SUCC "$result_bytes" || return 1
    work=$source result=$target
}

bind_ro() {
    mount -n --bind "$1" "$2"
    mount -n -o remount,bind,ro,nosuid,nodev,noexec "$2"
}

chroot_setup() {
    local leaf major minor path
    for path in "$ROOT" "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/run" "$ROOT/qtmedia" "$EXPORT"; do
        [[ -d $path && ! -L $path ]]
    done
    mount -n -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs "$ROOT/dev"
    while read -r leaf major minor; do
        mknod -m 666 "$ROOT/dev/$leaf" c "$major" "$minor"
    done <<'DEVICES'
null 1 3
zero 1 5
random 1 8
urandom 1 9
DEVICES
    ln -s /proc/self/fd "$ROOT/dev/fd"
    for leaf in 'stdin 0' 'stdout 1' 'stderr 2'; do
        read -r path minor <<< "$leaf"
        ln -s "/proc/self/fd/$minor" "$ROOT/dev/$path"
    done
    mkdir -m 1777 "$ROOT/dev/shm"
    mount -n -t proc -o ro,nosuid,nodev,noexec proc "$ROOT/proc"
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=32m tmpfs "$ROOT/run"
    bind_ro /sys "$ROOT/sys"
    bind_ro "$MEDIA" "$ROOT/qtmedia"
    [[ ! -e "$ROOT$EVIDENCE" && ! -L "$ROOT$EVIDENCE" &&
       ! -e "$ROOT/qt-successor" && ! -L "$ROOT/qt-successor" ]]
    mkdir -m 755 "$ROOT$EVIDENCE"
    mkdir -m 700 "$ROOT$EVIDENCE/setup"
    install -d -o 1000 -g 1000 -m 700 "$ROOT$EVIDENCE/build" "$ROOT/qt-successor" "$ROOT/qt-successor/srcdest"
    cp -R -- "$MEDIA/recipe/." "$ROOT/qt-successor/"
    install -o 1000 -g 1000 -m 600 -- "$MEDIA/$ARCHIVE" "$ROOT/qt-successor/srcdest/$ARCHIVE"
    chown -R 1000:1000 "$ROOT/qt-successor"
    chmod -R u+rwX "$ROOT/qt-successor"
}

builder_absent() {
    local receipt
    for receipt in /proc/[0-9]*/status; do
        if grep -Eq '^Uid:([[:space:]]+[0-9]+){0,3}[[:space:]]+1000([[:space:]]|$)' "$receipt" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}

retain() {
    local phase_dir=$1 state=$2 name src dst size cap problem=0
    shift 2
    for name in "$@"; do
        src=$ROOT$EVIDENCE/$phase_dir/$name dst=$EXPORT/evidence/$name
        if [[ ! -f $src || -L $src || $(stat -c %h -- "$src") != 1 ]]; then
            if [[ $state == PASS ]]; then problem=1; fi
            continue
        fi
        cap=16777216
        case $name in
            build.log) cap=67108864 ;;
            "$PACKAGE") cap=536870912 ;;
        esac
        if ! size=$(stat -c %s -- "$src") || (( size > cap )); then
            problem=1
            continue
        fi
        if (( size == 0 )); then
            if [[ $state == PASS ]]; then problem=1; fi
            continue
        fi
        if [[ -e $dst || -L $dst ]]; then
            [[ -f $dst && ! -L $dst ]] && cmp -s -- "$src" "$dst" || problem=1
        else
            install -m 600 -- "$src" "$dst" || problem=1
        fi
    done
    (( problem == 0 ))
}

open_result() {
    local -a entries
    if ! mountpoint -q "$EXPORT"; then
        mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" "$EXPORT" || return 1
    fi
    if (( ! result_ready )); then
        shopt -s nullglob dotglob
        entries=("$EXPORT/"*)
        shopt -u nullglob dotglob
        [[ ${#entries[@]} == 1 && ${entries[0]} == "$EXPORT/lost+found" &&
           -d ${entries[0]} && ! -L ${entries[0]} && $(stat -c %u:%g:%a -- "${entries[0]}") == 0:0:700 &&
           -z $(ls -A -- "${entries[0]}") ]] || return 1
        mkdir -m 700 -- "$EXPORT/evidence" || return 1
        result_ready=1
    fi
    [[ -d $EXPORT/evidence && ! -L $EXPORT/evidence && $(stat -c %u:%g:%a -- "$EXPORT/evidence") == 0:0:700 ]]
}

finish() {
    trap - ERR HUP INT TERM
    set +e
    local state=$1 path opens=0
    if [[ -n $result && -d $ROOT$EVIDENCE && ! -L $ROOT$EVIDENCE ]] && builder_absent && open_result; then
        opens=1
        retain setup "$state" "${SETUP_FILES[@]}" || { state=HOLD; phase=retain; }
        retain build "$state" "${BUILD_FILES[@]}" || { state=HOLD; phase=retain; }
        if [[ $state == PASS && $mode == full ]]; then
            retain build PASS "${FULL_FILES[@]}" || { state=HOLD; phase=retain; }
        fi
    elif [[ $state == PASS ]]; then
        state=HOLD
        phase=retain
    fi
    for path in "$ROOT/qtmedia" "$ROOT/sys" "$ROOT/proc" "$ROOT/run" "$ROOT/dev" /qtwork; do
        if mountpoint -q -- "$path"; then
            umount -n -- "$path" || { state=HOLD; phase=cleanup; }
        fi
    done
    if (( opens )); then
        printf '{"status":"%s","phase":"%s","nonce":"%s","mode":"%s","architecture":"aarch64","page_size":16384}\n' \
            "$state" "$phase" "$nonce" "$mode" > "$EXPORT/evidence/result.json" &&
            sync -f "$EXPORT" || { state=HOLD; phase=retain; }
    fi
    if mountpoint -q -- "$EXPORT"; then
        umount -n -- "$EXPORT" || { state=HOLD; phase=cleanup; }
    fi
    printf 'QTBASE_SUCCESSOR16K_TERMINAL %s %s %s\n' "$nonce" "$state" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

main() {
    [[ $# == 0 && $$ == 1 && $EUID == 0 ]]
    trap 'printf "QTBASE_SUCCESSOR16K_ERROR phase=%s line=%d exit=%d\n" "$phase" "$LINENO" "$?" >&2; finish HOLD' ERR
    trap 'finish HOLD' HUP INT TERM
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    parse_selection
    [[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    [[ ,$(findmnt -nro VFS-OPTIONS /), == *,ro,* ]]
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
    [[ $(ls -A /sys/class/net) == lo ]]
    verify_boot
    (
        cd "$MEDIA"
        printf '%s  manifest.sha256\n' "$manifest" | sha256sum --strict -c - >/dev/null
        sha256sum --strict -c manifest.sha256 >/dev/null
    )
    phase=storage
    select_storage
    mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
    [[ $(df -B1 --output=avail /qtwork | tail -n 1) -ge 6442450944 ]]
    chroot_setup
    open_result
    umount -n "$EXPORT"

    phase=setup
    timeout --kill-after=15s 900 chroot "$ROOT" /usr/bin/env -i PATH=/usr/bin:/bin HOME=/root \
        /usr/bin/bash /qtmedia/arm16k-build.sh setup </dev/null
    open_result
    retain setup PASS "${SETUP_FILES[@]}"
    sync -f "$EXPORT"
    umount -n "$EXPORT"
    printf 'QTBASE_SUCCESSOR16K_SETUP %s\n' "$nonce"

    phase=build
    local uptime elapsed remaining
    read -r uptime _ < /proc/uptime
    [[ $uptime =~ ^([0-9]{1,8})\.[0-9]{2}$ ]]
    elapsed=$((10#${BASH_REMATCH[1]} + 1))
    remaining=$((deadline - elapsed - 120))
    (( remaining >= 300 ))
    timeout --kill-after=15s "$remaining" chroot --userspec=1000:1000 --groups=1000 "$ROOT" \
        /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash /qtmedia/arm16k-build.sh build "$mode" "$nonce" </dev/null
    builder_absent
    timeout 60 chroot "$ROOT" /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/pacman -Q |
        sort | cmp -- "$ROOT$EVIDENCE/setup/after.lock" -
    if [[ $mode == full ]]; then phase=complete; else phase=configured; fi
    finish PASS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
