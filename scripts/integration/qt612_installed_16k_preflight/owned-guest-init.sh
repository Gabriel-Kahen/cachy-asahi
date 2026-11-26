#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for one installed Qtbase trial on a disposable Q3 child.
set -Eeuo pipefail
export PATH=/usr/bin:/bin LC_ALL=C
umask 077

boot=/qtbase-installed
base=/run/qt-installed
root=/qtwork/root
declare -a mounted=()
terminal=HOLD

mount_at() {
    local target=$1
    shift
    mount -n "$@" "$target"
    mounted+=("$target")
}

installed_finish() {
    trap - EXIT ERR HUP INT TERM
    local index
    for ((index=${#mounted[@]}-1; index>=0; index--)); do
        umount -n -- "${mounted[index]}" || terminal=HOLD
    done
    if [[ ${clone:-} =~ ^[a-f0-9]{32}$ ]]; then
        printf 'QTBASE_INSTALLED16K_TERMINAL %s %s\n' "$clone" "$terminal"
    fi
    sync
    poweroff -f
}

read_cmdline() {
    local arg key value
    declare -gA install=()
    for arg in "$@"; do
        [[ $arg == cachy_qt_install_* ]] || continue
        key=${arg%%=*}
        key=${key#cachy_qt_install_}
        case "$key" in
            nonce|clone|case|manifest|plan|selection|signature|data_uuid|result_uuid|deadline) ;;
            *) return 1 ;;
        esac
        [[ $arg == *=* && ! -v install[$key] ]] || return 1
        value=${arg#*=}
        install[$key]=$value
    done
    [[ ${#install[@]} == 10 ]] || return 1
    for key in nonce clone; do [[ ${install[$key]} =~ ^[a-f0-9]{32}$ ]] || return 1; done
    for key in manifest plan selection signature; do [[ ${install[$key]} =~ ^[a-f0-9]{64}$ ]] || return 1; done
    for key in data_uuid result_uuid; do
        [[ ${install[$key]} =~ ^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$ ]] || return 1
    done
    [[ ${install[deadline]} == 3420 ]] || return 1
    clone=${install[clone]}
    case "${install[case]}" in
        main) [[ $clone == "${install[nonce]}" ]] ;;
        tampered_signature|unknown_key) [[ ${clone:0:8} != "${install[nonce]:0:8}" ]] ;;
        *) return 1 ;;
    esac
}

verify_sources() (
    cd "$boot"
    local leaf
    local -a pinned=(guest-init.sh protect.list root-helpers.sh rtc-clock.sh source.sha256)
    shopt -s dotglob nullglob
    local -a actual=(*)
    [[ ${#actual[@]} == 6 ]]
    for leaf in "${pinned[@]}" MANIFEST.sha256; do
        [[ -f $leaf && ! -L $leaf && $(stat -c %h -- "$leaf") == 1
           && $(stat -c %s -- "$leaf") -le 131072 ]]
    done
    [[ $(sha256sum -- MANIFEST.sha256) == "${install[manifest]}  MANIFEST.sha256" ]]
    [[ $(sha256sum -- "${pinned[@]}") == "$(<MANIFEST.sha256)" ]]
)

select_disks() {
    local scratch_link data_link result_link attempt
    scratch_uuid=ed56022f-4e82-f6e3-fbde-502489347154
    for ((attempt=0; attempt<50; attempt++)); do
        if scratch=$(blkid -c /dev/null -t "UUID=$scratch_uuid" -o device) &&
           data=$(blkid -c /dev/null -t "UUID=${install[data_uuid]}" -o device) &&
           result=$(blkid -c /dev/null -t "UUID=${install[result_uuid]}" -o device); then
            break
        fi
        sleep 0.2
    done
    (( attempt < 50 ))
    scratch_link=$(whole_virtio "$scratch")
    data_link=$(whole_virtio "$data")
    result_link=$(whole_virtio "$result")
    [[ $scratch_link != "$data_link" && $scratch_link != "$result_link" && $data_link != "$result_link"
       && $scratch_link != "$boot_path" && $data_link != "$boot_path" && $result_link != "$boot_path" ]]
    verify_volume "$scratch" "$scratch_link" "$scratch_uuid" QT16K_WORK 17179869184
    verify_volume "$result" "$result_link" "${install[result_uuid]}" QT16K_PKG 1073741824
    [[ $(blkid -c /dev/null -t LABEL=QT16K_INST_IN -o device) == "$data"
       && $(blkid -p -s UUID -o value "$data") == "${install[data_uuid]}"
       && $(blkid -p -s TYPE -o value "$data") == ext4
       && $(blockdev --getro "$data") == 1 && $(blockdev --getsize64 "$data") == 1073741824 ]]
}

export_evidence() {
    local evidence=$root/qt-install-work/evidence cursor raw
    local -a paths
    [[ -d $evidence && ! -L $evidence ]] || return 1
    mapfile -d '' -t paths < <(find "$evidence" -mindepth 1 -maxdepth 2 -print0 | head -zc 262145)
    (( ${#paths[@]} > 0 && ${#paths[@]} <= 900 )) || return 1
    mkdir -m 700 "$base/result/evidence" "$base/result/evidence/commands" || return 1
    local total=0
    for cursor in "${paths[@]}"; do
        raw=${cursor#"$evidence/"}
        if [[ $raw == commands && -d $cursor && ! -L $cursor ]]; then continue; fi
        [[ $raw =~ ^(commands/)?[a-z][a-z0-9.-]{0,95}$ && -f $cursor && ! -L $cursor
           && $(stat -c %u:%g:%h -- "$cursor") == 0:0:1 ]] || return 1
        local size limit=134217728
        size=$(stat -c %s -- "$cursor") || return 1
        if [[ $raw == commands/* ]]; then limit=1048576; fi
        (( size <= limit && (total += size) < 768 * 1024 * 1024 )) || return 1
        install -m 600 -- "$cursor" "$base/result/evidence/$raw" || return 1
    done
    install -m 600 -- "$base/rtc-clock.env" "$base/result/rtc-clock.env" || return 1
    [[ -s $base/result/evidence/result.json ]] || return 1
    sync -f "$base/result"
}

main() {
    local -a words
    trap installed_finish EXIT
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    read -r -a words </proc/cmdline
    read_cmdline "${words[@]}"
    trap 'exit 1' HUP INT TERM
    [[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && ,$(findmnt -nro VFS-OPTIONS /), == *,ro,* ]]
    verify_sources
    source "$boot/root-helpers.sh"
    source "$boot/rtc-clock.sh"
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
    [[ $(ls -1 /sys/class/net) == lo ]]
    mkdir -p "$base/input" "$base/result"
    D=$base
    rtc_clock_guard
    nonce=$clone
    verify_boot
    select_disks
    mount_at "$base/input" -t ext4 -o ro,noload,nosuid,nodev,noexec "$data"
    (
        cd "$base/input/source"
        sha256sum --strict -c "$boot/source.sha256" >/dev/null
    )
    mount_at "$base/result" -t ext4 -o rw,nosuid,nodev,noexec "$result"
    mount_at /qtwork -t ext4 -o rw,nosuid,nodev "$scratch"
    mount_at "$root" --bind "$root"
    mount_at "$root/dev" -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs
    for entry in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
        read -r name major minor <<<"$entry"
        mknod -m 666 "$root/dev/$name" c "$major" "$minor"
    done
    ln -s /proc/self/fd "$root/dev/fd"
    mount_at "$root/proc" -t proc -o ro,nosuid,nodev,noexec proc
    mkdir -m 755 "$root/qt-install-source" "$root/qt-install-inputs" "$root/qt-install-work"
    for pair in "/sys:$root/sys" "$base/input/source:$root/qt-install-source" "$base/input/media:$root/qt-install-inputs"; do
        point=${pair#*:}
        mount_at "$point" --bind "${pair%%:*}"
        mount -n -o remount,bind,ro,nosuid,nodev,noexec "$point"
    done
    install -m 444 "$base/input/pacman.conf" "$root/qt-install-work/pacman.conf"
    options=(--plan-sha256 "${install[plan]}" --selection-sha256 "${install[selection]}"
             --deadline-uptime "${install[deadline]}")
    if [[ ${install[case]} == main ]]; then
        mapfile -t protected < "$boot/protect.list"
        (( ${#protected[@]} > 0 && ${#protected[@]} <= 512 ))
        for path in "${protected[@]}"; do options+=(--protect "$path"); done
    else
        options+=(--case "${install[case]}" --clone "$clone" --signature-sha256 "${install[signature]}")
    fi
    if timeout --kill-after=20s 3400 chroot "$root" /usr/bin/env -i PATH=/usr/bin:/bin \
            /usr/bin/python -I -B -Werror /qt-install-source/scripts/integration/qt612_installed_16k_preflight/guest.py \
            "${options[@]}" </dev/null >/dev/null 2>&1; then
        export_evidence
        terminal=PASS
    elif [[ -d $root/qt-install-work/evidence ]]; then
        export_evidence || true
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
