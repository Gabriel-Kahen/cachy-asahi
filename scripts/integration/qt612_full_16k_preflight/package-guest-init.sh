#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for a separately selected Qtbase package-only continuation.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

readonly PACKAGE_VOLUME=/qtbase-package PACKAGE_OUTPUT=/qtbase-packaging-output
readonly COMMON_INIT_SHA=cd7a48f5cd16011501508ff2bf99fd724e1f11ba9725cb2a000fd7bfd87fc9f8
readonly PACKAGE_RESULT_BYTES=1073741824 PACKAGE_DEADLINE=3300
readonly PACKAGE_TERMINAL=QTBASE_PACKAGE16K_TERMINAL
declare -A package_min=() package_max=()

package_cmdline() {
    local word key value
    local -A fields=()
    for word in "$@"; do
        case "$word" in
            cachy_qt_pkg_*=*)
                key=${word%%=*}
                key=${key#cachy_qt_pkg_}
                value=${word#*=}
                case "$key" in
                    nonce|manifest|plan|selection|scratch_uuid|result_uuid|result_bytes|deadline) ;;
                    *) return 1 ;;
                esac
                [[ ! -v fields[$key] ]] || return 1
                fields[$key]=$value ;;
            cachy_qt_pkg_*) return 1 ;;
        esac
    done
    [[ ${#fields[@]} == 8
       && ${fields[nonce]} =~ ^[a-f0-9]{32}$ && ${fields[nonce]:0:8} != 00000000
       && ${fields[manifest]} =~ ^[a-f0-9]{64}$ && ${fields[plan]} =~ ^[a-f0-9]{64}$
       && ${fields[selection]} =~ ^[a-f0-9]{64}$
       && ${fields[scratch_uuid]} == ed56022f-4e82-f6e3-fbde-502489347154
       && ${fields[result_uuid]} =~ ^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$
       && ${fields[scratch_uuid]} != "${fields[result_uuid]}"
       && ${fields[result_bytes]} == "$PACKAGE_RESULT_BYTES" && ${fields[deadline]} == "$PACKAGE_DEADLINE" ]] || return 1
    nonce=${fields[nonce]} manifest=${fields[manifest]} package_plan=${fields[plan]}
    package_selection=${fields[selection]} scratch_uuid=${fields[scratch_uuid]}
    result_uuid=${fields[result_uuid]} result_bytes=${fields[result_bytes]}
}

package_payload() (
    local leaf line hash path previous=''
    cd "$1" || return 1
    shopt -s dotglob nullglob
    local -a top=(*) staged=(packaging/*) recipe=(packaging/recipe/*) expected=()
    [[ ${#top[@]} == 5 && ${#staged[@]} == 10 && ${#recipe[@]} == 15
       && -d packaging && ! -L packaging && -d packaging/recipe && ! -L packaging/recipe ]] || return 1
    for leaf in MANIFEST.sha256 CAPS.tsv guest-init.sh full-guest-init.sh "${staged[@]}" "${recipe[@]}"; do
        if [[ $leaf == packaging/recipe ]]; then continue; fi
        [[ -f $leaf && -s $leaf && ! -L $leaf && $(stat -c %h -- "$leaf") == 1
           && $(stat -c %s -- "$leaf") -le 131072 ]] || return 1
        [[ $leaf == MANIFEST.sha256 ]] || expected+=("$leaf")
    done
    [[ $(stat -c %s MANIFEST.sha256) -le 8192 ]] || return 1
    local -a selected=()
    while IFS= read -r line; do
        [[ $line =~ ^([a-f0-9]{64})\ \ ((CAPS\.tsv|guest-init\.sh|full-guest-init\.sh)|packaging/(recipe/)?[A-Za-z0-9._-]{1,127})$ ]] || return 1
        hash=${BASH_REMATCH[1]} path=${BASH_REMATCH[2]}
        [[ $previous < $path && ${#selected[@]} -lt 27 ]] || return 1
        if [[ $path == full-guest-init.sh ]]; then [[ $hash == "$COMMON_INIT_SHA" ]] || return 1; fi
        selected+=("$path")
        previous=$path
    done < MANIFEST.sha256
    [[ ${#selected[@]} == 27 && ${#selected[@]} == "${#expected[@]}"
       && $(printf '%s\n' "${expected[@]}" | sort) == "$(printf '%s\n' "${selected[@]}")" ]] || return 1
    printf '%s  %s\n' "$manifest" MANIFEST.sha256 "$package_plan" packaging/PACKAGING-PLAN.UNISSUED.json \
        "$package_selection" packaging/PACKAGING-SELECTION.json | sha256sum --strict -c - >/dev/null || return 1
    sha256sum --strict -c MANIFEST.sha256 >/dev/null
)

package_caps() {
    local leaf minimum maximum extra total=0
    while read -r leaf minimum maximum extra; do
        [[ $leaf =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ && ! -v package_max[$leaf] && -z $extra
           && $minimum =~ ^[01]$ && $maximum =~ ^[1-9][0-9]{0,8}$ ]] || return 1
        (( ${#package_max[@]} < 13 && maximum <= 536870912 )) || return 1
        package_min[$leaf]=$minimum
        package_max[$leaf]=$maximum
        total=$((total + maximum))
    done < "$1"
    [[ ${#package_max[@]} == 13 && -v package_max[result.json] && -v package_max[stage-contract.json] ]] &&
        (( total + 8388608 <= PACKAGE_RESULT_BYTES ))
}

package_storage() {
    local scratch target scratch_sys result_sys attempt
    for ((attempt=0; attempt<50; attempt++)); do
        if scratch=$(blkid -c /dev/null -t "UUID=$scratch_uuid" -o device) &&
           target=$(blkid -c /dev/null -t "UUID=$result_uuid" -o device); then
            break
        fi
        sleep 0.2
    done
    (( attempt < 50 )) || return 1
    scratch_sys=$(whole_virtio "$scratch") && result_sys=$(whole_virtio "$target") || return 1
    [[ $scratch_sys != "$result_sys" && $scratch_sys != "$boot_path" && $result_sys != "$boot_path" ]] || return 1
    verify_volume "$scratch" "$scratch_sys" "$scratch_uuid" QT16K_WORK 17179869184 &&
        verify_volume "$target" "$result_sys" "$result_uuid" QT16K_PKG "$result_bytes" || return 1
    work=$scratch result=$target
}

package_retain() (
    local source=$1 target=$2 state=$3 file leaf size total=0 count=0 problem=0
    shopt -s dotglob nullglob
    for file in "$source"/*; do
        count=$((count+1))
        (( count <= 13 )) || return 1
        leaf=${file##*/}
        if [[ ! $leaf =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ || ! -v package_max[$leaf]
              || ! -f $file || -L $file || $(stat -c '%u:%g:%h' -- "$file") != 1000:1000:1 ]] ||
           ! size=$(stat -c %s -- "$file") || (( size > package_max[$leaf] )); then
            problem=1
            continue
        fi
        if (( total + size > PACKAGE_RESULT_BYTES - 8388608 )); then
            problem=1
            continue
        fi
        install -m 600 -- "$file" "$target/$leaf" || problem=1
        total=$((total+size))
    done
    if [[ $state == PASS ]]; then
        for leaf in "${!package_max[@]}"; do
            [[ -f $target/$leaf ]] && (( $(stat -c %s -- "$target/$leaf") >= package_min[$leaf] )) || problem=1
        done
    fi
    (( problem == 0 ))
)

package_shutdown() {
    printf '%s %s %s %s\n' "$PACKAGE_TERMINAL" "$nonce" "$1" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

package_finish() {
    trap - ERR HUP INT TERM
    set +e
    local state=$1 path
    if [[ -n $result && -d $ROOT$PACKAGE_OUTPUT && ! -L $ROOT$PACKAGE_OUTPUT ]] && builder_absent; then
        if mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" "$EXPORT" &&
           fresh_result_root "$EXPORT" && mkdir -m 700 "$EXPORT/evidence"; then
            package_retain "$ROOT$PACKAGE_OUTPUT" "$EXPORT/evidence" "$state" &&
                sync -f "$EXPORT" || { state=HOLD phase=retain; }
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
    package_shutdown "$state"
}

package_main() {
    [[ $# == 0 && $$ == 1 && $EUID == 0 ]]
    local -a cmdline
    local path device leaf major minor uptime ignored elapsed remaining
    phase=boot nonce=unknown result=
    trap 'package_shutdown HOLD' ERR HUP INT TERM
    mount -n -t proc -o nosuid,nodev,noexec proc /proc
    read -r -a cmdline < /proc/cmdline
    package_cmdline "${cmdline[@]}"
    [[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384
       && ,$(findmnt -nro VFS-OPTIONS /), == *,ro,* ]]
    [[ -d $PACKAGE_VOLUME && ! -L $PACKAGE_VOLUME ]]
    package_payload "$PACKAGE_VOLUME"
    source "$PACKAGE_VOLUME/full-guest-init.sh"
    trap 'package_finish HOLD' ERR HUP INT TERM
    package_caps "$PACKAGE_VOLUME/CAPS.tsv"
    if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
    mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
    mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
    mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp
    [[ $(ls -1 /sys/class/net) == lo ]]
    verify_boot
    phase=storage
    package_storage
    mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
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
        if [[ $path == qtmedia ]]; then device=$PACKAGE_VOLUME; fi
        mount -n --bind "$device" "$ROOT/$path"
        mount -n -o remount,bind,ro,nosuid,nodev,noexec "$ROOT/$path"
    done
    [[ ! -e $ROOT$PACKAGE_OUTPUT && ! -L $ROOT$PACKAGE_OUTPUT ]]
    install -d -o 1000 -g 1000 -m 700 "$ROOT$PACKAGE_OUTPUT"
    phase=package
    read -r uptime ignored < /proc/uptime
    [[ $uptime =~ ^([0-9]{1,8})\.[0-9]{2}$ ]]
    elapsed=$((10#${BASH_REMATCH[1]} + 1))
    remaining=$((PACKAGE_DEADLINE - elapsed))
    (( remaining >= 2700 ))
    # Finish after the worker's stream redirections have been restored.
    guest "$remaining" /usr/bin/python -I -B -Werror /qtmedia/packaging/package_guest.py \
        --plan-sha256 "$package_plan" --selection-sha256 "$package_selection" \
        --worker-deadline-uptime "$PACKAGE_DEADLINE" </dev/null >/dev/null 2>&1 || package_finish HOLD
    builder_absent
    phase=complete
    package_finish PASS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    package_main "$@"
fi
