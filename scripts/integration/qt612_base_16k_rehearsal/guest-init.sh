#!/bin/bash
# SPDX-License-Identifier: MIT
# PID 1 for the disposable, offline AArch64 configure rehearsal.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
phase=boot nonce=unknown
root=/qtwork/root
evidence=/qtwork/evidence

poweroff_guest() {
    /usr/bin/systemctl --force --force poweroff || :
    while :; do sleep 60; done
}

export_evidence() {
    local outcome=$1 file name size total=0 count=0
    printf '{"status":"%s","phase":"%s","nonce":"%s","pages":16384,"Qt_build":"NOT_RUN"}\n' \
        "$outcome" "$phase" "$nonce" > "$evidence/result.json"
    mountpoint -q /qtexport || mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" /qtexport
    mkdir -m 700 /qtexport/evidence
    shopt -s nullglob dotglob
    for file in "$evidence/"*; do
        name=${file##*/}
        [[ $name =~ ^(result\.json|rootfs-gpgv\.log|(alpm|configure|md4c)-[A-Za-z0-9._-]+)$ ]]
        [[ -f "$file" && ! -L "$file" && $(stat -c %h -- "$file") == 1 ]]
        size=$(stat -c %s -- "$file")
        count=$((count + 1))
        total=$((total + size))
        [[ $count -le 48 && $size -le 4194304 && $total -le 33554432 ]]
        install -o 0 -g 0 -m 600 -- "$file" "/qtexport/evidence/$name"
    done
    sync
    umount -n /qtexport
}

retire_mounts() {
    local path
    for path in /qtexport "$root/qtmedia" "$root/sys" "$root/proc" "$root/dev" /qtmedia /qtwork; do
        if mountpoint -q "$path"; then umount -n -- "$path" || return; fi
    done
}

hold() {
    trap - ERR HUP INT TERM
    if [[ -d "$evidence" && -n ${result:-} ]]; then export_evidence HOLD || :; fi
    retire_mounts || :
    printf 'QTBASE16K %s HOLD %s\n' "$nonce" "$phase"
    poweroff_guest
}

trap hold ERR HUP INT TERM
[[ $$ == 1 && $EUID == 0 && $# == 0 ]]
mount -n -t proc -o nosuid,nodev,noexec proc /proc
selection() {
    local -a args
    local term got_nonce= got_plan= nonces=0 plans=0
    read -r -a args < /proc/cmdline
    for term in "${args[@]}"; do
        case "$term" in
            cachy_qtbase_nonce=*) got_nonce=${term#*=}; nonces=$((nonces+1)) ;;
            cachy_qtbase_plan=*) got_plan=${term#*=}; plans=$((plans+1)) ;;
        esac
    done
    [[ $nonces == 1 && $got_nonce =~ ^[0-9a-f]{32}$ && $plans == 1 && $got_plan =~ ^[0-9a-f]{64}$ ]]
    nonce=$got_nonce plan=$got_plan
}
selection
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
findmnt -n -o VFS-OPTIONS / | grep -qw ro
if ! mountpoint -q /dev; then mount -n -t devtmpfs -o nosuid devtmpfs /dev; fi
mount -n -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
mount -n -t tmpfs -o mode=0755,nosuid,nodev,noexec,size=64m tmpfs /run
mount -n -t tmpfs -o mode=1777,nosuid,nodev,noexec,size=64m tmpfs /tmp
[[ $(ls -1 /sys/class/net) == lo ]]

phase=storage
for ((attempt=0; attempt<50; attempt++)); do
    if input=$(blkid -c /dev/null -L QT16K_INPUT) &&
       work=$(blkid -c /dev/null -L QT16K_WORK) &&
       result=$(blkid -c /dev/null -L QT16K_RESULT); then break; fi
    sleep 0.2
done
[[ $attempt -lt 50 && $input != "$work" && $input != "$result" && $work != "$result" ]]
for disk in "$input" "$work" "$result"; do
    [[ $disk =~ ^/dev/vd[a-z]+$ && -b $disk && ! -L $disk ]]
done
[[ $(blockdev --getro "$input") == 1 && $(blockdev --getsize64 "$input") == 2147483648 ]]
[[ $(blockdev --getro "$work") == 0 && $(blockdev --getsize64 "$work") == 17179869184 ]]
[[ $(blockdev --getro "$result") == 0 && $(blockdev --getsize64 "$result") == 67108864 ]]
mount -n -t ext4 -o ro,noload,nosuid,nodev,noexec "$input" /qtmedia
mount -n -t ext4 -o rw,nosuid,nodev "$work" /qtwork
mkdir -m 700 "$evidence"
printf '%s  /qtmedia/plan.json\n' "$plan" | sha256sum -c -

phase=signed-rootfs
mkdir -m 700 /run/qtbase-public "$root"
read -r primary </qtmedia/alpm-primary
[[ $primary =~ ^[0-9A-F]{40}$ ]]
official_keyring=/run/qtbase-public/archlinuxarm.gpg
timeout 60 gpg --batch --no-options --homedir /run/qtbase-public --no-tty --no-autostart \
    --no-auto-key-retrieve --output "$official_keyring" --dearmor /qtmedia/official/archlinuxarm.gpg \
    > "$evidence/rootfs-gpgv.log" 2>&1
[[ -s "$official_keyring" ]]
timeout 450 gpgv --homedir /run/qtbase-public --keyring "$official_keyring" \
    --status-fd 1 /qtmedia/rootfs.tar.gz.sig /qtmedia/rootfs.tar.gz >> "$evidence/rootfs-gpgv.log" 2>&1
awk -v fpr="$primary" '
    $1=="[GNUPG:]" && $2=="VALIDSIG" {if(NF!=12 || $3!=fpr || $12!=fpr) exit 1; valid++}
    $1=="[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|NO_PUBKEY|KEYEXPIRED|SIGEXPIRED)$/ {exit 1}
    END {if(valid!=1) exit 1}' "$evidence/rootfs-gpgv.log"
timeout 450 tar --extract --gzip --numeric-owner --same-permissions --xattrs --acls \
    --file /qtmedia/rootfs.tar.gz --directory "$root"
[[ -d "$root/usr/bin" && -x "$root/usr/bin/pacman" && -x "$root/usr/bin/bash" ]]
[[ -d "$root/dev" && ! -L "$root/dev" && -d "$root/proc" && ! -L "$root/proc" && -d "$root/sys" && ! -L "$root/sys" ]]
mkdir -m 755 "$root/qtmedia" "$root/qt-evidence" "$root/qt-recipe"
mount -n -t tmpfs -o mode=0755,nosuid,noexec,size=16m tmpfs "$root/dev"
for name in 'null 1 3' 'zero 1 5' 'random 1 8' 'urandom 1 9'; do
    read -r leaf major minor <<<"$name"
    mknod -m 666 "$root/dev/$leaf" c "$major" "$minor"
done
ln -s /proc/self/fd "$root/dev/fd"
for descriptor in 'stdin 0' 'stdout 1' 'stderr 2'; do
    read -r name fd <<<"$descriptor"
    ln -s "/proc/self/fd/$fd" "$root/dev/$name"
done
mkdir -m 1777 "$root/dev/shm"
mount -n -t proc -o ro,nosuid,nodev,noexec proc "$root/proc"
mount -n --bind /sys "$root/sys"
mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/sys"
mount -n --bind /qtmedia "$root/qtmedia"
mount -n -o remount,bind,ro,nosuid,nodev,noexec "$root/qtmedia"
chmod 755 "$root"

phase=alpm
chmod 700 "$root/qt-evidence"
trap 'mv -- "$root/qt-evidence/"* "$evidence/" 2>/dev/null || :; hold' ERR
timeout 2100 chroot "$root" /usr/bin/bash /qtmedia/alpm.sh /qt-evidence
mv -- "$root/qt-evidence/"* "$evidence/"
grep -Fxq ALPM_EXACT_349_TO_356_PASS "$evidence/alpm-result"
grep -Fxq PRIVATE_ALPM_KEYRINGS_RETIRED "$evidence/alpm-cleanup.log"

phase=configure
cp -R /qtmedia/recipe/. "$root/qt-recipe/"
mkdir -m 700 "$root/qt-recipe/srcdest"
cp /qtmedia/qtbase-everywhere-src-6.12.0.tar.xz "$root/qt-recipe/srcdest/"
chown -R 1000:1000 "$root/qt-recipe" "$root/qt-evidence"
chmod -R u+rwX "$root/qt-recipe"
timeout 1500 chroot --userspec=1000:1000 --groups=1000 "$root" \
    /usr/bin/bash /qtmedia/configure.sh /qt-recipe /qt-evidence
mv -- "$root/qt-evidence/"* "$evidence/"
[[ -f "$evidence/configure-result.json" ]]
trap hold ERR HUP INT TERM

phase=complete
export_evidence PASS
retire_mounts
printf 'QTBASE16K %s PASS 16384\n' "$nonce"
poweroff_guest
