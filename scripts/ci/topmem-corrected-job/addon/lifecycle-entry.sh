#!/usr/bin/env bash
# Future isolated ARM container only; Root-owned runtime constructs the actor.
set -euo pipefail
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && -e /.dockerenv && $(id -u) == 0 && $(uname -m) == aarch64 ]]
[[ ${TOPMEM_SIGNER_FP:-} =~ ^[A-F0-9]{40}$ ]]
[[ -f /repo/public-key.asc && -f /topmem-smoke.py ]]
work=$(mktemp -d /tmp/topmem-lifecycle.XXXXXXXX)
pacman -Q | LC_ALL=C sort > "$work/before"
! pacman -Q cachy-asahi-topmem >/dev/null 2>&1
[[ ! -e /home/alarm/topmem-sentinel && ! -L /home/alarm/topmem-sentinel ]]
mkdir /home/alarm/topmem-sentinel
printf 'KEEP\n' > /home/alarm/topmem-sentinel/user-state
finish() {
 first=$?; trap - EXIT
 if pacman -Q cachy-asahi-topmem >/dev/null 2>&1; then pacman --noconfirm -R cachy-asahi-topmem >/dev/null || { [[ $first != 0 ]] || first=1; }; fi
 pacman -Q | LC_ALL=C sort > "$work/after" || { [[ $first != 0 ]] || first=1; }
 cmp "$work/before" "$work/after" || { [[ $first != 0 ]] || first=1; }
 [[ $(cat /home/alarm/topmem-sentinel/user-state) == KEEP ]] || { [[ $first != 0 ]] || first=1; }
 exit "$first"
}
trap finish EXIT
pacman-key --add /repo/public-key.asc
pacman-key --finger "${TOPMEM_SIGNER_FP}" > "$work/fingerprint"
pacman-key --lsign-key "${TOPMEM_SIGNER_FP}"
configure() {
 cat > "$work/pacman.conf" <<EOF
[options]
Architecture = aarch64
HookDir = /builder-disabled-hooks
SigLevel = Required DatabaseRequired
LocalFileSigLevel = Required
[topmem]
Server = file:///repo/$1
EOF
}
check_installed() {
 [[ $(pacman -Q cachy-asahi-topmem) == "cachy-asahi-topmem $1" ]]
 [[ $(pacman -Q python) == 'python 3.14.8-1' ]]
 pacman -Qkk cachy-asahi-topmem
 pacman -Qlq cachy-asahi-topmem | grep -v '/$' | LC_ALL=C sort > "$work/owned"
 printf '%s\n' /usr/bin/cachy-asahi-topmem /usr/share/doc/cachy-asahi-topmem/README.md /usr/share/licenses/cachy-asahi-topmem/LICENSE /usr/share/licenses/cachy-asahi-topmem/NOTICE | LC_ALL=C sort > "$work/expected"
 cmp "$work/owned" "$work/expected"
 for path in $(cat "$work/expected"); do [[ $(pacman -Qqo "$path") == cachy-asahi-topmem ]]; done
 su alarm -s /bin/sh -c '/usr/bin/python3 -I -B /topmem-smoke.py'
 [[ $(cat /home/alarm/topmem-sentinel/user-state) == KEEP ]]
}
configure v1
pacman --config "$work/pacman.conf" --cachedir "$work/cache" -Sy --noconfirm cachy-asahi-topmem
check_installed 0.1.0-1
configure v2
pacman --config "$work/pacman.conf" --cachedir "$work/cache" -Sy --noconfirm cachy-asahi-topmem
check_installed 0.1.0-2
pacman --noconfirm -R cachy-asahi-topmem
for path in $(cat "$work/expected"); do [[ ! -e $path && ! -L $path ]]; done
pacman --config "$work/pacman.conf" --cachedir "$work/cache" -S --noconfirm cachy-asahi-topmem
check_installed 0.1.0-2
pacman --noconfirm -R cachy-asahi-topmem
for path in $(cat "$work/expected"); do [[ ! -e $path && ! -L $path ]]; done
printf '%s\n' '{"status":"PROVISIONAL_TOPMEM_PACKAGE_LIFECYCLE","upgrade":"0.1.0-1 to 0.1.0-2 test-only","reinstall_restoration":true,"hardware":"NOT RUN"}'
