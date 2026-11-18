#!/bin/bash
# SPDX-License-Identifier: MIT
# Continue the sealed Q3 configuration in a private scratch clone.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

if [[ ${1:-} == compile ]]; then
    [[ $# == 1 && $EUID == 1000 && $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    export LC_ALL=C.UTF-8 HOME=/qt-recipe/.home XDG_CONFIG_HOME=/qt-recipe/.home/.config
    export TMPDIR=/qt-recipe/.tmp SOURCE_DATE_EPOCH=1792021458 MAKEFLAGS=-j1
    export CMAKE_BUILD_PARALLEL_LEVEL=1 MAX_JOBS=1
    evidence=/qt-md4c-evidence
    cd /qt-recipe/src/build
    [[ $(pacman -Q md4c) == 'md4c 0.5.3-1' ]]
    [[ $(pacman -Qqo /usr/include/md4c.h) == md4c ]]
    [[ $(pacman -Qqo /usr/lib/libmd4c.so.0.5.3) == md4c ]]
    sha256sum --strict -c /qtmedia/operands.sha256
    grep -Fxq 'QT_FEATURE_system_textmarkdownreader:INTERNAL=ON' CMakeCache.txt
    grep -Eq '^#define QT_FEATURE_system_textmarkdownreader[[:space:]]+1$' src/gui/qtgui-config.h
    pch=src/gui/CMakeFiles/Gui.dir/cmake_pch.hxx.gch
    importer=src/gui/CMakeFiles/Gui.dir/text/qtextmarkdownimporter.cpp.o
    [[ ! -e $pch && ! -L $pch && ! -e $importer && ! -L $importer ]]
    mkdir -p src/tools/syncqt/CMakeFiles/syncqt.dir lib/qt6 "${importer%/*}"
    ulimit -f 524288
    for stage in headers pch importer; do
        local_file=/qtmedia/$stage.commands
        while IFS= read -r command; do
            [[ -n $command ]]
            timeout --kill-after=10s 480 /usr/bin/bash -c "$command" </dev/null
        done < "$local_file"
    done
    test -s "$pch"
    readelf -hW "$importer" > "$evidence/importer.elf"
    readelf -sW "$importer" > "$evidence/importer.symbols"
    grep -Eq 'Class:[[:space:]]+ELF64' "$evidence/importer.elf"
    grep -Eq 'Type:[[:space:]]+REL[[:space:]]' "$evidence/importer.elf"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$evidence/importer.elf"
    awk '$7 == "UND" && $8 == "md_parse" { found = 1 } END { exit !found }' "$evidence/importer.symbols"
    install -m 600 "$importer" "$evidence/importer.o"
    exit
fi

storage_error() {
    printf 'QTMD4C16K_STORAGE %s %s\n' "$nonce" "$1"
    return 1
}

whole_virtio() {
    local disk=$1 node path virtio
    [[ $disk =~ ^/dev/[a-z0-9][a-z0-9._-]{0,63}$ && -b $disk && ! -L $disk ]] || return 1
    node=${disk#/dev/}
    path=$(readlink -e -- "/sys/class/block/$node") || return 1
    [[ $path == /sys/devices/*/block/"$node" && ! -e $path/partition && -r $path/dev ]] || return 1
    virtio=${path%/block/*}
    [[ $(readlink -e -- "$virtio/driver") == /sys/bus/virtio/drivers/virtio_blk &&
       $(stat -c '%Hr:%Lr' -- "$disk") == "$(<"$path/dev")" ]] || return 1
    printf '%s\n' "$path"
}

flat_whole() {
    local partition
    for partition in "$1"/*/partition; do
        [[ ! -e $partition ]] || return 1
    done
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
    [[ $scratch =~ ^/dev/[a-z0-9][a-z0-9._-]{0,63}$ &&
       $target =~ ^/dev/[a-z0-9][a-z0-9._-]{0,63}$ ]] || { storage_error UUID_SELECTION; return 1; }
    scratch_path=$(whole_virtio "$scratch") && target_path=$(whole_virtio "$target") ||
        { storage_error WHOLE_VIRTIO; return 1; }
    [[ $scratch_path != "$target_path" ]] || { storage_error DISK_ALIAS; return 1; }
    # The sealed boot disk is read-only and partitioned. Both data disks are flat ext4.
    flat_whole "$scratch_path" && flat_whole "$target_path" || { storage_error FLAT_DISK; return 1; }
    for disk in "$scratch" "$target"; do
        if [[ $disk == "$scratch" ]]; then
            expected_uuid=$scratch_uuid expected_label=QT16K_WORK
        else
            expected_uuid=$result_uuid expected_label=QT16K_MD4C
        fi
        [[ $(blkid -c /dev/null -t "LABEL=$expected_label" -o device) == "$disk" &&
           $(blkid -p -s UUID -o value "$disk") == "$expected_uuid" &&
           $(blkid -p -s LABEL -o value "$disk") == "$expected_label" &&
           $(blkid -p -s TYPE -o value "$disk") == ext4 ]] || { storage_error FILESYSTEM_ID; return 1; }
    done
    [[ $(blockdev --getsize64 "$scratch") == 17179869184 &&
       $(blockdev --getsize64 "$target") == 67108864 ]] || { storage_error GEOMETRY; return 1; }
    [[ $(blockdev --getro "$scratch") == 0 && $(blockdev --getro "$target") == 0 ]] ||
        { storage_error WRITE_STATE; return 1; }
    work=$scratch result=$target
}

[[ $# == 0 && $$ == 1 && $EUID == 0 ]]
root=/qtwork/root
volume=/qt-md4c-compile
evidence=$root/qt-md4c-evidence
phase=boot nonce=unknown result=

finish() {
    trap - ERR HUP INT TERM
    local state=$1 file leaf
    if [[ -n $result && -d $evidence ]] &&
        mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" /qtexport; then
        if mkdir -m 700 /qtexport/evidence; then
            for leaf in compile.log importer.elf importer.symbols importer.o; do
                file=$evidence/$leaf
                if [[ -f $file && ! -L $file && $(stat -c %s -- "$file") -le 8388608 ]]; then
                    install -m 600 -- "$file" "/qtexport/evidence/$leaf" || state=HOLD
                fi
            done
            if [[ $state == PASS ]]; then
                for leaf in compile.log importer.elf importer.symbols importer.o; do
                    [[ -s /qtexport/evidence/$leaf ]] || state=HOLD
                done
            fi
            printf '{"status":"%s","nonce":"%s","phase":"%s","page_size":16384}\n' \
                "$state" "$nonce" "$phase" > /qtexport/evidence/result.json || state=HOLD
            sync
        else
            state=HOLD
        fi
        umount -n /qtexport || state=HOLD
    else
        state=HOLD
    fi
    for file in "$root/qtmedia" "$root/sys" "$root/proc" "$root/dev" /qtwork; do
        if mountpoint -q -- "$file"; then umount -n -- "$file" || state=HOLD; fi
    done
    printf 'QTMD4C16K %s %s %s\n' "$nonce" "$state" "$phase"
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

trap 'finish HOLD' ERR HUP INT TERM
mount -n -t proc -o nosuid,nodev,noexec proc /proc
read -r -a args < /proc/cmdline
nonces=0 manifests=0 scratch_ids=0 result_ids=0
for term in "${args[@]}"; do
    case "$term" in
        cachy_qt_compile_nonce=*) nonce=${term#*=}; nonces=$((nonces+1)) ;;
        cachy_qt_compile_plan=*) manifest=${term#*=}; manifests=$((manifests+1)) ;;
        cachy_qt_compile_scratch_uuid=*) scratch_uuid=${term#*=}; scratch_ids=$((scratch_ids+1)) ;;
        cachy_qt_compile_result_uuid=*) result_uuid=${term#*=}; result_ids=$((result_ids+1)) ;;
    esac
done
[[ $nonces == 1 && $nonce =~ ^[0-9a-f]{32}$ && $manifests == 1 && $manifest =~ ^[0-9a-f]{64}$ ]]
uuid_re='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
[[ $scratch_ids == 1 && $result_ids == 1 && $scratch_uuid =~ $uuid_re &&
   $result_uuid =~ $uuid_re && $scratch_uuid != "$result_uuid" ]]
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
findmnt -n -o VFS-OPTIONS / | grep -qw ro
if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp
[[ $(ls -1 /sys/class/net) == lo ]]
cd "$volume"
printf '%s  MANIFEST.sha256\n' "$manifest" | sha256sum --strict -c -
sha256sum --strict -c MANIFEST.sha256

phase=storage
select_storage || finish HOLD
mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
for path in "$root" "$root/dev" "$root/proc" "$root/sys" "$root/qtmedia"; do
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
install -d -o 1000 -g 1000 -m 700 "$evidence"

phase=compile
timeout --kill-after=20s 1800 chroot --userspec=1000:1000 --groups=1000 "$root" \
    /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash /qtmedia/guest.sh compile 2>&1 |
    head -c 4194305 > "$evidence/compile.log"
[[ $(stat -c %s -- "$evidence/compile.log") -le 4194304 ]]
phase=complete
finish PASS
