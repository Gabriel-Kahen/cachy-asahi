#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Exact fixture-only transaction; no caller-supplied package arguments.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1
D=/var/lib/arm16k-project-lifecycle
O=/run/arm16k-project-lifecycle
phase=tool_presence
failed_line=0;failed_tool=unknown;failed_source=unknown;expected_probes=0
. "$D/guest-runtime.sh"
IFS= read -r nonce < /etc/arm16k-project-lifecycle-nonce
finish() {
 local rc=$?
 trap - ERR EXIT
 if [[ $rc != 0 ]];then
  # Export only fixed phase/source/tool labels and numeric line/status. Never
  # print BASH_COMMAND, arguments, file contents, environment or credentials.
  failure_fields "$rc" >&2
  if [[ -d $O ]];then failure_fields "$rc" > "$O/summary.env";fi
 fi
 if [[ -d $O && -f $O/summary.env && -x /usr/bin/chmod ]];then
  /usr/bin/chmod 644 "$O/summary.env"
  printf '%s\n' "$nonce" > "$O/terminal"
  /usr/bin/chmod 644 "$O/terminal"
 fi
 exit "$rc"
}
trap 'failure_record "$LINENO" "$BASH_COMMAND" "$?" "${BASH_SOURCE[0]}"' ERR
trap finish EXIT
# Create the result directory only with its fixed tool, when available, so a
# missing later tool can still yield a sanitized terminal report.
if [[ -x /usr/bin/install ]];then /usr/bin/install -d -m755 "$O";fi
require_base_tools
phase=guard
[[ $# == 0 && $nonce =~ ^[0-9a-f]{32}$ && $EUID == 0 ]]
grep -qw "arm16k_systemd_nonce=$nonce" /proc/cmdline
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
digest() { sha256sum "$1" | cut -d' ' -f1; }
inventory() { pacman -Q | sort; }
user_snapshot() {
 find /home/builder -xdev -printf '%p\t%m\t%U\t%G\t%y\t%l\0' | sort -z > "$1.meta"
 find /home/builder -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.hash"
}
assert_users() { user_snapshot "$O/user-current";same_bytes "$O/user-before.meta" "$O/user-current.meta";same_bytes "$O/user-before.hash" "$O/user-current.hash"; }
payload_snapshot() {
 pacman -Qlq | sort -u | tr '\n' '\0' > "$1.paths"
 xargs -0 -r stat --printf='%n\0%f\0%u\0%g\0%h\0%N\0' < "$1.paths" > "$1.meta"
 xargs -0 -r getfattr --no-dereference --absolute-names --dump --match='.*' -- < "$1.paths" > "$1.xattr"
 find -P -files0-from "$1.paths" -maxdepth 0 -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.hash"
 find /var/lib/pacman/local -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.db"
}
phase=sentinels
[[ $(id -u builder) == 1000 && $(id -g builder) == 1000 && $(id -G builder) == 1000 ]]
[[ ! -e /home/builder/.config/cachy-asahi/lifecycle-user.conf && ! -e /home/builder/.local/share/cachy-asahi/lifecycle-user.txt ]]
install -d -m700 -o1000 -g1000 /home/builder/.config /home/builder/.config/cachy-asahi /home/builder/.local /home/builder/.local/share /home/builder/.local/share/cachy-asahi
printf 'User configuration retained: %s\n' "$nonce" > /home/builder/.config/cachy-asahi/lifecycle-user.conf
printf 'User data retained: %s\n' "$nonce" > /home/builder/.local/share/cachy-asahi/lifecycle-user.txt
chown 1000:1000 /home/builder/.config/cachy-asahi/lifecycle-user.conf /home/builder/.local/share/cachy-asahi/lifecycle-user.txt
user_snapshot "$O/user-before"
phase=baseline
[[ ! -e "$D/consumed" ]]
(set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed")
inventory > "$O/baseline.lock";same_bytes "$D/expected111.lock" "$O/baseline.lock"
[[ $(wc -l < "$O/baseline.lock") == 111 ]]
payload_snapshot "$O/before"
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_}
 [[ ! -L $path ]]
 if pacman -Qo -- "$path" > /dev/null 2>&1;then false;fi
 if [[ -f $path ]]; then cp -a "$path" "$O/$name.saved"; else touch "$O/$name.absent";fi
done
[[ -d /var/cache/ldconfig ]] || touch "$O/ldconfig-directory.absent"
phase=trust
cd "$D/materials"
sha256sum -c "$D/materials.sha256" > "$O/input-hashes.log"
install -d -m700 "$D/trust" "$D/cache"
gpg --no-options --batch --no-autostart --no-auto-key-retrieve --homedir "$D/trust" --import TEST-public.asc > "$O/trust-import.log" 2>&1
printf '28883796E039C3CC08603F3EFD56E30AF1115613:6:\n' | gpg --no-options --batch --homedir "$D/trust" --import-ownertrust >> "$O/trust-import.log" 2>&1
for name in cachy-asahi-zlib-baseline-1.3.2-1-aarch64.pkg.tar.xz cachy-asahi-zlib-lto-1.3.2-1-aarch64.pkg.tar.xz;do
 gpg --no-options --batch --no-autostart --no-auto-key-retrieve --homedir "$D/trust" --status-fd 1 --verify "$name.sig" "$name" > "$O/$name.signature" 2>&1
 [[ $(grep -c '^\[GNUPG:\] VALIDSIG 28883796E039C3CC08603F3EFD56E30AF1115613 ' "$O/$name.signature") == 1 ]]
done
phase=install
timeout --signal=TERM --kill-after=3s 90 pacman --config "$D/pacman.conf" --noconfirm -U "$D/materials/cachy-asahi-zlib-baseline-1.3.2-1-aarch64.pkg.tar.xz" "$D/materials/cachy-asahi-zlib-lto-1.3.2-1-aarch64.pkg.tar.xz" > "$O/install.log" 2>&1
inventory > "$O/installed.lock";same_bytes "$D/expected113.lock" "$O/installed.lock"
pacman -T glibc > "$O/dependencies.log"
sha256sum -c "$D/project-payload.sha256" > "$O/project-hashes.log"
while read -r expected path; do [[ $(stat --printf='%a:%u:%g' "/$path") == "$expected" ]];pacman -Qo "/$path";done < "$D/project-metadata.lock" > "$O/project-ownership.log"
pacman -Qlq cachy-asahi-zlib-baseline cachy-asahi-zlib-lto | sort -u > "$O/added.paths"
assert_users
phase=unprivileged-probes
as_builder() { runuser -u builder -- env -i HOME=/home/builder USER=builder LOGNAME=builder PATH=/usr/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 "$@"; }
[[ $(as_builder id -u) == 1000 ]]
timeout --signal=TERM --kill-after=3s 180 runuser -u builder -- env -i HOME=/home/builder USER=builder LOGNAME=builder PATH=/usr/bin LANG=C LC_ALL=C /usr/bin/bash "$D/guest-workload.sh" > "$O/workload.env" 2> "$O/workload.stderr"
same_bytes "$D/expected-workload.env" "$O/workload.env"
assert_users
phase=remove
timeout --signal=TERM --kill-after=3s 90 pacman --config "$D/pacman.conf" --noconfirm -R cachy-asahi-zlib-baseline cachy-asahi-zlib-lto > "$O/remove.log" 2>&1
inventory > "$O/final.lock";same_bytes "$O/baseline.lock" "$O/final.lock"
comm -23 "$O/added.paths" <(tr '\0' '\n' < "$O/before.paths") > "$O/exclusive.paths"
while IFS= read -r path; do [[ ! -e $path && ! -L $path ]];done < "$O/exclusive.paths"
phase=generated-cache-restoration
# Normal ldconfig hooks have already run. Restore the exact prior unowned cache
# state in this owned guest; do not suppress hooks or touch baseline-owned files.
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_};[[ ! -L $path ]]
 if [[ -e "$O/$name.absent" ]];then rm -f -- "$path";else cp -a "$O/$name.saved" "$path";fi
done
if [[ -e "$O/ldconfig-directory.absent" && -d /var/cache/ldconfig ]];then rmdir /var/cache/ldconfig;fi
phase=restoration
payload_snapshot "$O/after"
for suffix in paths meta hash db xattr; do same_bytes "$O/before.$suffix" "$O/after.$suffix";done
assert_users
gpgconf --homedir "$D/trust" --kill all
rm -rf -- "$D/trust"
phase=complete
{
 printf 'STATUS=PASS\nBASELINE_PACKAGES=111\nINSTALLED_PACKAGES=113\nFINAL_PACKAGES=111\nARCH=aarch64\nPAGESIZE=16384\n'
 cat "$O/workload.env"
 for suffix in meta hash db xattr; do printf 'BASE_%s=%s\nFINAL_%s=%s\n' "$suffix" "$(digest "$O/before.$suffix")" "$suffix" "$(digest "$O/after.$suffix")";done
 printf 'USER_BEFORE=%s\nUSER_FINAL=%s\nEXCLUSIVE_PAYLOAD_ABSENT=yes\nPRIVATE_TEST_TRUST_REMOVED=yes\nORDINARY_HOOKS_SCRIPTLETS=unsuppressed\nPERFORMANCE=NOT_MEASURED\nNATIVE16K=NOT_RUN\nM2=NOT_RUN\n' "$(digest "$O/user-before.hash")" "$(digest "$O/user-current.hash")"
} > "$O/summary.env"
