#!/bin/bash
# SPDX-License-Identifier: MIT
# Link one library from the sealed Q3 configuration in private scratch.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC

check_inputs() {
    (
        cd /qt-recipe
        sha256sum --strict -c - <<'PINS'
b8ab08950fc2e5729e00bc066e13897163ae52362105aa90d58569f603e07296  PKGBUILD
eaa27120efac20a30c6c8d256385532aa988af0dee00dd1f8117f24922674350  configure.cmake
77ee32886383da2d2b7c30b03269c7c482a6386237ad7c0bc111dd960579e379  SERVER_DEPENDENCY_GUARD.cmake
efe21d53a77c92ea66997923529b4d6e34635db7f1cb760af99d01774bdb7870  source.py
2848e83fcf21d6819bb3d183a025a02ba944f05f849b3489c850922a9a89f742  src/build/CMakeCache.txt
cef51ef9f4a7fce92141f3b31d446da5ada824347da5ec713ead1f800858439a  src/build/build.ninja
b71df9759d13435ec44b87f1adf866c5ec8aebd44b4a6d41e78ee4ff4bf014cb  src/build/CMakeFiles/rules.ninja
PINS
    )
}

inventory() {
    (ulimit -f 16; /usr/bin/pacman -Q | LC_ALL=C /usr/bin/sort) > "$1"
    [[ $(wc -lc < "$1" | xargs) == '356 6925' ]]
    printf '%s  %s\n' e2a4da7903e6de26b0ee37758ad424439f83196fa6a3b0bdffa501f35a02d0b9 "$1" |
        sha256sum --strict -c -
}

verify_commands() {
    (
        ulimit -f 1024
        cd /qt-recipe/src/build
        /usr/bin/ninja -t commands lib/libQt6Core.so
    ) > "$1"
    [[ $(wc -lc < "$1" | xargs) == '321 671480' ]]
    printf '%s  %s\n' 1836d53ff5aa42d6d115b8c5301938ccccdd8e3d1fffc29e52d524e44a701769 "$1" |
        sha256sum --strict -c -
}

if [[ ${1:-} == link ]]; then
    [[ $# == 1 && $EUID == 1000 && $(id -g) == 1000 &&
       $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
    export LC_ALL=C.UTF-8 HOME=/qt-recipe/.home XDG_CONFIG_HOME=/qt-recipe/.home/.config
    export TMPDIR=/qt-recipe/.tmp SOURCE_DATE_EPOCH=1792021458 MAKEFLAGS=-j1
    export CMAKE_BUILD_PARALLEL_LEVEL=1 MAX_JOBS=1
    evidence=/qtcore-evidence
    cd /qt-recipe
    output=src/build/lib/libQt6Core.so
    shared=$output.6.12.0
    for leaf in "$output" "$output.6" "$shared"; do
        [[ ! -e $leaf && ! -L $leaf ]]
    done
    check_inputs
    inventory "$evidence/inventory.before"
    verify_commands "$evidence/core.commands"

    # Bound the original merged output and retire the child process group on
    # overflow or timeout. The inspected Ninja stream is never evaluated.
    /usr/bin/python -I -B - "$evidence" <<'PYTHON'
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time


def signal_group(child, signum):
    try:
        os.killpg(child.pid, signum)
    except ProcessLookupError:
        return False
    return True


def retire_group(child):
    for signum, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        if not signal_group(child, signum):
            return
        end = time.monotonic() + grace
        while time.monotonic() < end:
            if child.poll() is not None and not signal_group(child, 0):
                return
            time.sleep(0.05)


def interruption(signum, _frame):
    raise InterruptedError(signum)


output = Path(sys.argv[1])
argv = ["/usr/bin/cmake", "--build", "/qt-recipe/src/build", "--parallel", "1",
        "--target", "lib/libQt6Core.so"]
env = {key: os.environ[key] for key in (
    "PATH", "LC_ALL", "TZ", "HOME", "XDG_CONFIG_HOME", "TMPDIR", "SOURCE_DATE_EPOCH",
    "MAKEFLAGS", "CMAKE_BUILD_PARALLEL_LEVEL", "MAX_JOBS")}
file_cap = 512 * 1024**2
resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

log_limit = 8 * 1024**2
started = time.monotonic()
deadline = started + 6900
complete = False
exit_code = 125
for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(signum, interruption)
with (output / "build.log").open("xb") as log:
    child = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
    try:
        with selectors.DefaultSelector() as watch:
            watch.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not watch.select(remaining):
                    exit_code = 124
                    break
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    try:
                        code = child.wait(timeout=max(0, deadline - time.monotonic()))
                        exit_code = code if code >= 0 else 128 - code
                        complete = True
                    except subprocess.TimeoutExpired:
                        exit_code = 124
                    break
                left = log_limit - log.tell()
                log.write(chunk[:left])
                if len(chunk) > left:
                    break
    except OSError as error:
        print(f"QtCore build capture failed: {error}", file=sys.stderr)
    finally:
        child.stdout.close()
        # The original group must retire even if its leader exited early.
        if signal_group(child, 0):
            complete = False
            exit_code = exit_code or 125
            retire_group(child)
        child.poll()

metrics = dict(compile_exit=exit_code, elapsed_ms=round((time.monotonic() - started) * 1000),
               peak_child_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
               log_complete=complete)
with (output / "metrics.json").open("x", encoding="ascii") as report:
    report.write(json.dumps(metrics, sort_keys=True) + "\n")
sys.exit(exit_code)
PYTHON

    check_inputs
    inventory "$evidence/inventory.after"
    cmp -s -- "$evidence/inventory.before" "$evidence/inventory.after"
    verify_commands "$evidence/core.after.commands"
    cmp -s -- "$evidence/core.commands" "$evidence/core.after.commands"
    rm -- "$evidence/core.after.commands"
    [[ -f $shared && ! -L $shared && -s $shared && $(stat -c %h -- "$shared") == 1 &&
       $(stat -c %s -- "$shared") -le 50331648 ]]
    alias_name=$(readlink -- "$output")
    soname=$(readlink -- "$output.6")
    [[ $alias_name == libQt6Core.so.6 && $soname == libQt6Core.so.6.12.0 &&
       $(readlink -e -- "$output") == "/qt-recipe/$shared" ]]
    /usr/bin/readelf -Wh "$shared" | grep -E 'Class:[[:space:]]+ELF64' >/dev/null
    /usr/bin/readelf -Wh "$shared" | grep -E 'Type:[[:space:]]+DYN[[:space:]]' >/dev/null
    /usr/bin/readelf -Wh "$shared" | grep -E 'Machine:[[:space:]]+AArch64' >/dev/null
    /usr/bin/readelf -Wd "$shared" | grep -E '\(SONAME\)[[:space:]]+Library soname: \[libQt6Core\.so\.6\]$' >/dev/null
    printf 'libQt6Core.so -> %s\nlibQt6Core.so.6 -> %s\n' "$alias_name" "$soname" > "$evidence/aliases.txt"
    install -m 600 -- "$shared" "$evidence/libQt6Core.so.6.12.0"
    exit
fi

storage_error() {
    printf 'QTCORE_LINK_STORAGE %s %s\n' "$nonce" "$1"
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
            expected_uuid=$result_uuid expected_label=QT16K_CORE
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
volume=/qtcore-link
evidence=$root/qtcore-evidence
phase=boot nonce=unknown manifest=unknown result=

write_outcome() {
    printf '{"kind":"QTCORE_LINK_RESULT_V1","status":"%s","nonce":"%s","plan_sha256":"%s","phase":"%s",%s}\n' \
        "$1" "$nonce" "$manifest" "$phase" '"architecture":"aarch64","page_size":16384,"uid":1000,"gid":1000' \
        > /qtexport/evidence/result.json
}

finish() {
    trap - ERR HUP INT TERM
    set +e
    local state=$1 file leaf limit export_mounted=0 export_ready=0
    if [[ -n $result && -d $evidence && ! -L $evidence ]] &&
        mount -n -t ext4 -o rw,nosuid,nodev,noexec "$result" /qtexport; then
        export_mounted=1
        if mkdir -m 700 /qtexport/evidence; then
            export_ready=1
            for leaf in build.log core.commands libQt6Core.so.6.12.0 aliases.txt \
                        inventory.before inventory.after metrics.json; do
                case "$leaf" in
                    libQt6Core.so.6.12.0) limit=50331648 ;;
                    build.log) limit=8388608 ;;
                    core.commands) limit=671480 ;;
                    *) limit=8192 ;;
                esac
                file=$evidence/$leaf
                if [[ -f $file && ! -L $file && $(stat -c %h -- "$file") == 1 &&
                      $(stat -c %s -- "$file") -le $limit ]]; then
                    install -m 600 -- "$file" "/qtexport/evidence/$leaf" || state=HOLD
                fi
                [[ -s /qtexport/evidence/$leaf ]] || state=HOLD
            done
        fi
    fi
    (( export_ready )) || state=HOLD
    for file in "$root/qtmedia" "$root/sys" "$root/proc" "$root/dev" /qtwork; do
        if mountpoint -q -- "$file"; then umount -n -- "$file" || state=HOLD; fi
    done
    if (( export_ready )); then
        if ! write_outcome "$state" || ! sync -f /qtexport; then
            state=HOLD
            write_outcome "$state"
            sync -f /qtexport
        fi
    fi
    if (( export_mounted )) && ! umount -n /qtexport; then
        state=HOLD
        if (( export_ready )); then write_outcome "$state"; sync -f /qtexport; fi
        umount -n /qtexport
    fi
    printf 'QTCORE_LINK_TERMINAL %s %s %s\n' "$nonce" "$state" "$phase"
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
[[ $scratch_ids == 1 && $result_ids == 1 && $scratch_uuid == ed56022f-4e82-f6e3-fbde-502489347154 &&
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
[[ $(wc -l < MANIFEST.sha256) == 1 ]]
grep -Ex '[0-9a-f]{64}  guest\.sh' MANIFEST.sha256 >/dev/null
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
[[ ! -e $evidence && ! -L $evidence ]]
install -d -o 1000 -g 1000 -m 700 "$evidence"

phase=link
timeout --kill-after=20s 7030 chroot --userspec=1000:1000 --groups=1000 "$root" \
    /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/bash /qtmedia/guest.sh link </dev/null
phase=complete
finish PASS
