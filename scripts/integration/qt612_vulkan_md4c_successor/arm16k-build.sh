#!/bin/bash
# SPDX-License-Identifier: MIT
# Successor setup and normal makepkg entry inside the disposable ARM64 chroot.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
readonly MEDIA=/qtmedia RECIPE=/qt-successor EVIDENCE=/qt-successor-evidence
readonly OFFICIAL=68B3537F39A313B3E574D06777193F152BDBE6A6
readonly PACKAGE=cachy-asahi-qt612-gui-server-source-reference-6.12.0-4-aarch64.pkg.tar.xz
readonly MD4C=md4c-0.6.0-2-aarch64.pkg.tar.xz VULKAN=vulkan-headers-1:1.4.363.0-1-any.pkg.tar.xz
readonly ARCHIVE=qtbase-everywhere-src-6.12.0.tar.xz

readback() {
    timeout 60 pacman -Q | sort > "$EVIDENCE/setup/$1.lock"
    cmp -- "$EVIDENCE/setup/$1.lock" "$MEDIA/expected$2.lock"
}

verify_pair() {
    local archive=$1 report=$2
    printf '%s\n' "${archive##*/}" >> "$report"
    timeout 45 gpgv --homedir /run/qt-successor-trust --keyring "$MEDIA/alarm-public.gpg" \
        --status-fd 1 -- "$archive.sig" "$archive" | tee -a "$report" | awk -v fp="$OFFICIAL" '
            $1=="[GNUPG:]" && $2=="VALIDSIG" {count++; if (NF!=12 || $3!=fp || $NF!=fp) bad=1}
            $1=="[GNUPG:]" && $2 ~ /^(BADSIG|ERRSIG|EXPKEYSIG|EXPSIG|REVKEYSIG|NO_PUBKEY|KEYEXPIRED|SIGEXPIRED)$/ {bad=1}
            END {exit !(count==1 && !bad)}'
}

selection_probe() {
    local file owner
    pacman -Q md4c vulkan-headers
    [[ $(pkg-config --modversion md4c) == 0.6.0 ]]
    [[ $(pkg-config --variable=pcfiledir md4c) == /usr/lib/pkgconfig ]]
    printf '%s\n' 'md4c-pkg-config=0.6.0'
    [[ $(realpath -e /usr/lib/libmd4c.so.0) == /usr/lib/libmd4c.so.0.6.0 ]]
    for file in /usr/lib/libmd4c.so.0.6.0 /usr/lib/pkgconfig/md4c.pc /usr/lib/cmake/md4c/md4cConfig.cmake \
        /usr/include/vulkan/vulkan.h; do
        owner=md4c
        if [[ $file == /usr/include/vulkan/* ]]; then owner=vulkan-headers; fi
        [[ -f $file && ! -L $file && $(pacman -Qqo -- "$file") == "$owner" ]]
        printf 'owner=%s path=%s\n' "$owner" "$file"
    done
    python -I -B - <<'PY'
import ctypes
library = ctypes.CDLL("/usr/lib/libmd4c.so.0")
assert library.md_parse
print("md4c-dlopen=PASS")
PY
}

setup() (
    local private=/run/qt-successor-trust hook
    local -a archives=("$MEDIA/alpm-add/$MD4C" "$MEDIA/alpm-add/$VULKAN")
    local -a masks=(/usr/share/libalpm/hooks/*.hook /etc/pacman.d/hooks/*.hook)
    [[ $EUID == 0 && -d $EVIDENCE/setup && ! -e $private && ! -L $private ]]
    mkdir -m 700 -- "$private" "$private/keys" "$private/hooks"
    cleanup_private() {
        local code=$?
        timeout 30 gpgconf --homedir "$private/keys" --kill all || code=1
        rm -rf --one-file-system -- "$private" || code=1
        exit "$code"
    }
    trap cleanup_private EXIT
    readback before 356
    for archive in "${archives[@]}"; do
        verify_pair "$archive" "$EVIDENCE/setup/gpgv.log"
    done
    local -a gpg=(gpg --batch --no-tty --no-options --no-auto-key-retrieve --no-autostart --homedir "$private/keys")
    for hook in "${masks[@]}"; do
        [[ -e $hook || -L $hook ]] || continue
        [[ ${hook##*/} =~ ^[A-Za-z0-9_.@+-]+\.hook$ ]]
        ln -sf -- /dev/null "$private/hooks/${hook##*/}"
    done
    [[ -L $private/hooks/20-systemd-sysusers.hook ]]
    printf '%s\n' '[options]' 'Architecture = aarch64' 'SigLevel = Required TrustedOnly' \
        'LocalFileSigLevel = Required TrustedOnly' "GPGDir = $private/keys" "HookDir = $private/hooks" > "$private/pacman.conf"
    {
        timeout 60 "${gpg[@]}" --import "$MEDIA/alarm-public.gpg"
        printf '%s:6:\n' "$OFFICIAL" | timeout 60 "${gpg[@]}" --import-ownertrust
        timeout --kill-after=15s 600 pacman --config "$private/pacman.conf" --logfile "$private/pacman.log" \
            -U --noconfirm --noscriptlet -- "${archives[@]}"
        timeout 60 ldconfig
        timeout 60 pacman --config "$private/pacman.conf" -Dk
        cat -- "$private/pacman.log"
    } >> "$EVIDENCE/setup/alpm.log" 2>&1
    readback after 357
    {
        timeout 60 pacman -Qk md4c vulkan-headers
        selection_probe
    } > "$EVIDENCE/setup/package-check.log" 2>&1
)

capture() {
    local output=$1
    shift
    "$@" 2>&1 | python -I -B -c '
import sys
limit = 64 * 1024**2
with open(sys.argv[1], "ab") as output:
    while chunk := sys.stdin.buffer.read1(64 * 1024):
        remaining = limit - output.tell()
        output.write(chunk[:remaining])
        output.flush()
        if len(chunk) > remaining:
            raise SystemExit("Build transcript exceeded 64 MiB")
' "$output"
}

graph() {
    local build=$RECIPE/src/build output=$1 leaf
    local -a names=(CMakeCache.txt build.ninja rules.ninja)
    grep -E '^(Vulkan_INCLUDE_DIR:PATH=/usr/include|md4c_DIR:PATH=/usr/lib/cmake/md4c|QT_FEATURE_(vulkan|system_textmarkdownreader):INTERNAL=ON|QT_FEATURE_vkkhrdisplay:INTERNAL=OFF)$' \
        "$build/CMakeCache.txt" > "$output/features.txt" || return
    [[ $(wc -l < "$output/features.txt") == 5 ]] || return 1
    grep -Fxq '#define QT_FEATURE_vulkan 1' "$build/src/gui/qtgui-config.h" &&
        grep -Fxq '#define QT_FEATURE_system_textmarkdownreader 1' "$build/src/gui/qtgui-config.h" &&
        grep -Fxq '#define QT_FEATURE_vkkhrdisplay -1' "$build/src/gui/qtgui-config_p.h" || return 1
    python -I -B "$RECIPE/source.py" configuration --build "$build" --profile "$RECIPE/configure.cmake" \
        > "$output/profile.json" || return
    for leaf in "$build/CMakeCache.txt" "$build/build.ninja" "$build/CMakeFiles/rules.ninja"; do
        [[ -f $leaf && ! -L $leaf && $(stat -c %s -- "$leaf") -le 16777216 ]] || return 1
        install -m 600 -- "$leaf" "$output/${leaf##*/}" || return
    done
    (cd "$output" && sha256sum -- "${names[@]}" > graph.sha256)
}

full_build() {
    local nonce=$1 output=$2 pid result=0 configured=0 ticks=0 progress
    capture "$output/build.log" makepkg --noconfirm --nocolor --nosign &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if (( ! configured )) && [[ -s $output/build.log ]] &&
            grep -Fxq -- "-- Build files have been written to: $RECIPE/src/build" "$output/build.log" &&
            graph "$output"; then
            printf 'QTBASE_SUCCESSOR16K_CONFIGURED %s\n' "$nonce"
            configured=1
        fi
        if (( configured && ticks % 12 == 0 )); then
            progress=$(tail -n 500 -- "$output/build.log" | grep -E '^\[[0-9]+/[0-9]+\] ' | tail -n 1 || :)
            if [[ -n $progress ]]; then printf 'QTBASE_SUCCESSOR16K_BUILD %s %.180s\n' "$nonce" "$progress"; fi
        fi
        ticks=$((ticks + 1))
        sleep 5
    done
    wait "$pid" || result=$?
    if (( ! configured )) && graph "$output"; then
        printf 'QTBASE_SUCCESSOR16K_CONFIGURED %s\n' "$nonce"
        configured=1
    fi
    if (( result != 0 )); then
        tail -n 15 "$output/build.log" >&2
        return "$result"
    fi
    (( configured ))
    graph "$output"
    grep -Fxq 'PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY' "$output/build.log"
    [[ -f $output/$PACKAGE && ! -L $output/$PACKAGE && ! -e $output/$PACKAGE.sig ]]
    install -m 600 -- "$RECIPE/src/stage-contract.json" "$output/stage-contract.json"
    install -m 600 -- "$RECIPE/src/vulkan-md4c-elf.json" "$output/vulkan-md4c-elf.json"
    (cd "$output" && sha256sum -- "$PACKAGE" > archive.sha256)
}

build() {
    local mode=$1 nonce=$2 output=$EVIDENCE/build
    local -a deps
    [[ $EUID == 1000 && $nonce =~ ^[0-9a-f]{32}$ && -d $output && ! -e $RECIPE/src ]]
    export LC_ALL=C.UTF-8 HOME=$RECIPE/.home XDG_CONFIG_HOME=$RECIPE/.home/.config
    export SRCDEST=$RECIPE/srcdest PKGDEST=$output TMPDIR=$RECIPE/.tmp
    export MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 MAKEFLAGS=-j1 SOURCE_DATE_EPOCH=1792021458
    export NINJA_STATUS='[%f/%t] '
    mkdir -m 700 -- "$HOME" "$TMPDIR"
    cd "$RECIPE"
    [[ -s $SRCDEST/$ARCHIVE && ! -L $SRCDEST/$ARCHIVE ]]
    makepkg --printsrcinfo | cmp -- .SRCINFO -
    mapfile -t deps < <(awk -F ' = ' '$1 ~ /^\t(makedepends|depends)$/ {print $2}' .SRCINFO | LC_ALL=C sort -u)
    (( ${#deps[@]} > 0 && ${#deps[@]} <= 128 ))
    printf '%s\n' "${deps[@]}" > "$output/dependencies.log"
    timeout 60 pacman -T "${deps[@]}" >> "$output/dependencies.log" 2>&1
    printf 'ALL_BUILD_DEPENDENCIES_PRESENT\n' >> "$output/dependencies.log"
    if [[ $mode == full ]]; then
        full_build "$nonce" "$output"
        return
    fi
    [[ $mode == configure ]]
    capture "$output/build.log" makepkg --nobuild --nosign --noconfirm --nocolor
    capture "$output/build.log" cmake -C "$RECIPE/src/configure.cmake" \
        -S "$RECIPE/src/qtbase-everywhere-src-6.12.0" -B "$RECIPE/src/build" -G Ninja \
        -DCMAKE_PROJECT_QtBase_INCLUDE="$RECIPE/src/SERVER_DEPENDENCY_GUARD.cmake"
    graph "$output"
    printf 'QTBASE_SUCCESSOR16K_CONFIGURED %s\n' "$nonce"
}

[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(ls -A /sys/class/net) == lo ]]
awk '$5 == "/qtmedia" {n++; if ($6 ~ /(^|,)ro(,|$)/) ro++} END {exit !(n==1 && ro==1)}' /proc/self/mountinfo
case "${1:-}" in
    setup) [[ $# == 1 ]]; setup ;;
    build) [[ $# == 3 ]]; build "$2" "$3" ;;
    *) exit 2 ;;
esac
