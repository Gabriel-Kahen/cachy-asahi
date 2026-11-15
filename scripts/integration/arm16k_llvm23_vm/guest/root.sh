#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Disposable guest Root oneshot. Normal ALPM hooks and scriptlets remain enabled.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
D=/var/lib/arm16k-llvm23-vm
O=/run/arm16k-llvm23-vm
S=$O/root
P=/opt/cachy-asahi/llvm23-source-reference
PACKAGE=cachy-asahi-llvm23-source-reference
ARCHIVE=$D/$PACKAGE-23.1.1-1-aarch64.pkg.tar.zst
phase=guard
nonce=INVALID
finish() {
 local rc=$?
 trap - EXIT
 if (( rc != 0 )); then
  if [[ -d $S && ! -L $S ]]; then
   printf 'LLVM23_RESTORED_BEGIN %s\nSTATUS=HOLD\nFAILED_PHASE=%s\nLLVM23_RESTORED_END %s\n' "$nonce" "$phase" "$nonce" > "$S/failure.env"
   cp -- "$S/failure.env" "$O/summary.env";chmod 644 "$O/summary.env"
  fi
 fi
 exit "$rc"
}
trap finish EXIT
[[ $# == 0 && $EUID == 0 && ! -e $O && ! -L $O ]]
install -d -m755 "$O"
install -d -m700 "$S"
. "$D/case.sh"
. "$D/frozen/guest-runtime.sh"
. "$D/frozen/rtc-clock.sh"
case_data
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
grep -qw "arm16k_llvm23_vm_nonce=$nonce" /proc/cmdline
[[ $(id -u builder) == 1000 && $(id -g builder) == 1000 && $(id -G builder) == 1000 ]]
[[ ! -e $D/consumed && ! -L $D/consumed && ! -e $P && ! -L $P ]]
( set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed" )
phase=rtc_clock
rtc_clock_guard
clock_valid
inventory > "$S/base.lock"
same_bytes "$D/expected-base.lock" "$S/base.lock"
! pacman -Q "$PACKAGE" > /dev/null 2>&1

user_snapshot() (
 ulimit -f 16384
 find /home/builder /root -xdev -printf '%p\t%m\t%U\t%G\t%y\t%l\0' | sort -z > "$1.meta"
 find /home/builder /root -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.hash"
)
assert_users() {
 user_snapshot "$S/user-current"
 same_bytes "$S/user-before.meta" "$S/user-current.meta"
 same_bytes "$S/user-before.hash" "$S/user-current.hash"
}
payload_snapshot() (
 ulimit -f 16384
 local stage=$1 suffix size total=0
 procfs_guard
 pacman -Qlq | sort -u | tr '\n' '\0' > "$S/$stage.paths"
 xargs -0 -r stat --printf='%n\0%f\0%u\0%g\0%h\0%N\0' < "$S/$stage.paths" > "$S/$stage.meta"
 xargs -0 -r getfattr --no-dereference --absolute-names --dump --match='.*' -- < "$S/$stage.paths" > "$S/$stage.xattr"
 find -P -files0-from "$S/$stage.paths" -maxdepth 0 -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$S/$stage.hash"
 find /var/lib/pacman/local -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$S/$stage.db"
 find /var/lib/pacman/local -print0 | sort -z | xargs -0 -r stat --printf='%n\0%f\0%u\0%g\0%h\0%N\0' > "$S/$stage.dbmeta"
 find /var/lib/pacman/local -print0 | sort -z | xargs -0 -r getfattr --no-dereference --absolute-names --dump --match='.*' -- > "$S/$stage.dbxattr"
 for suffix in paths meta hash db xattr dbmeta dbxattr; do
  size=$(stat -c '%s' "$S/$stage.$suffix");(( size <= 16777216 ));total=$((total+size))
 done
 (( total <= 33538048 ))
 ( O=$S;metadata_equality_view "$stage" )
)
cache_snapshot() (
 ulimit -f 16384
 local path
 for path in /etc/ld.so.cache /var/cache/ldconfig /var/cache/ldconfig/aux-cache;do
  if [[ -e $path || -L $path ]];then
   stat --printf='%n\0%f\0%u\0%g\0%N\0' -- "$path"
   getfattr --no-dereference --absolute-names --dump --match='.*' -- "$path"
   if [[ -f $path && ! -L $path ]];then sha256sum -- "$path";fi
  else printf 'ABSENT %s\n' "$path";fi
 done
)
phase=sentinels
[[ ! -e /home/builder/.arm16k-llvm23-sentinel && ! -L /home/builder/.arm16k-llvm23-sentinel && ! -e /root/.arm16k-llvm23-sentinel && ! -L /root/.arm16k-llvm23-sentinel ]]
printf 'USER %s\n' "$nonce" > /home/builder/.arm16k-llvm23-sentinel
chown 1000:1000 /home/builder/.arm16k-llvm23-sentinel
printf 'ROOT %s\n' "$nonce" > /root/.arm16k-llvm23-sentinel
user_snapshot "$S/user-before"
phase=baseline
payload_snapshot before
cache_snapshot > "$S/before.cache"
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_};[[ ! -L $path ]]
 ! pacman -Qo -- "$path" > /dev/null 2>&1
 if [[ -f $path ]]; then cp -a -- "$path" "$S/$name.saved";else [[ ! -e $path ]];touch "$S/$name.absent";fi
done
[[ -d /var/cache/ldconfig ]] || touch "$S/ldconfig-directory.absent"
phase=trust
( cd "$D";sha256sum --check --strict --status "$D/materials.sha256" )
[[ -d $D/trust && ! -L $D/trust && $(stat -c '%u:%g:%a' "$D/trust") == 0:0:700 ]]
gpg_fixed() { bounded "$gpg_seconds" "$S/$1.log" gpg --no-options --homedir "$D/trust" --batch --no-tty --no-auto-key-retrieve "${@:2}"; }
gpg_fixed import --import "$D/TEST-public.asc"
gpg_fixed secret --with-colons --list-secret-keys
! grep -Eq '^(sec|ssb):' "$S/secret.log"
gpg_fixed keys --with-colons --fingerprint --list-keys
pubs=0;primary=;want=0
while IFS=: read -r kind a b c d e f g h i rest; do
 case "$kind" in pub) pubs=$((pubs+1));want=1;; fpr) if [[ $want == 1 ]];then primary=$i;want=0;fi;;esac
done < "$S/keys.log"
[[ $pubs == 1 && $primary == "$signer_fingerprint" ]]
printf '%s:6:\n' "$signer_fingerprint" > "$S/ownertrust"
gpg_fixed ownertrust --import-ownertrust "$S/ownertrust"
clock_valid
gpg_fixed signature --status-fd 1 --verify "$ARCHIVE.sig" "$ARCHIVE"
valids=0;trusted=0
while IFS= read -r line; do
 [[ $line == '[GNUPG:] '* ]] || continue
 read -r marker code rest <<< "$line"
 case "$code" in
  VALIDSIG) read -r signing rest <<< "$rest";[[ $signing == "$signer_fingerprint" || ${rest##* } == "$signer_fingerprint" ]];valids=$((valids+1));;
  TRUST_ULTIMATE) trusted=$((trusted+1));;
  NEWSIG|KEY_CONSIDERED|SIG_ID|GOODSIG) ;;
  *) false;;
 esac
done < "$S/signature.log"
[[ $valids == 1 && $trusted == 1 ]]
phase=install
bounded "$install_seconds" "$S/install.log" pacman --config "$D/pacman.conf" --noconfirm -U "$ARCHIVE"
inventory > "$S/installed.lock"
same_bytes "$D/expected-installed.lock" "$S/installed.lock"
[[ $(pacman -Q "$PACKAGE") == "$PACKAGE 23.1.1-1" ]]
bounded "$run_seconds" "$S/database-installed.log" pacman -Dk
sha256sum --check --strict --status "$D/payload.sha256"
verify_paths
while IFS=$'\t' read -r kind mode uid gid path target extra; do
 [[ -z $extra && $mode =~ ^[0-7]{3,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]]
 [[ $path == "$P" || $path == "$P/"* || ( $kind == d && ( $path == /opt || $path == /opt/cachy-asahi ) ) ]]
 [[ $(stat -c '%a:%u:%g' -- "$path") == "$mode:$uid:$gid" ]]
 case "$kind" in f) [[ -f $path && ! -L $path && $target == - ]];;d) [[ -d $path && ! -L $path && $target == - ]];;l) [[ -L $path && $(readlink -- "$path") == "$target" && $(readlink -f -- "$path") == "$P/"* ]];;*) false;;esac
 pacman -Qo -- "$path" > /dev/null
done < "$D/payload-metadata.tsv"
pacman -Qlq "$PACKAGE" | sort -u > "$S/added.paths"
assert_users
install -d -m700 -o1000 -g1000 "$O/user"
printf '%s\n' "$nonce" > "$O/installed";chmod 644 "$O/installed"
phase=probe_wait
end=$((SECONDS+probe_wait_seconds))
while [[ ! -f $O/user/PROBED ]]; do (( SECONDS < end ));sleep 1;done
[[ ! -L $O/user/PROBED && $(stat -c '%u:%g:%a' "$O/user/PROBED") == 1000:1000:600 && $(cat "$O/user/PROBED") == "$nonce" ]]
[[ $(stat -c '%s' "$O/user/PROBED") == 33 ]]
# The finite probe has closed its outputs. Seal the run directory before Root
# hashes/copies them; the later user wait reads only the public Root summary.
chown 0:0 "$O/user";chmod 700 "$O/user"
[[ -f $O/user/smoke && ! -L $O/user/smoke && -f $O/user/unwind && ! -L $O/user/unwind ]]
(cd "$O/user";sha256sum --check --strict --status outputs.sha256)
assert_users
clock_valid
verify_paths
c_sha=$(file_sha "$O/user/smoke");cxx_sha=$(file_sha "$O/user/unwind")
phase=remove
bounded "$remove_seconds" "$S/remove.log" pacman --config "$D/pacman.conf" --noconfirm -R "$PACKAGE"
inventory > "$S/final.lock";same_bytes "$S/base.lock" "$S/final.lock"
bounded "$run_seconds" "$S/database-final.log" pacman -Dk
[[ ! -e $P && ! -L $P ]]
comm -23 "$S/added.paths" <(tr '\0' '\n' < "$S/before.paths") > "$S/exclusive.paths"
while IFS= read -r path;do [[ ! -e $path && ! -L $path ]];done < "$S/exclusive.paths"
phase=cache_restoration
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_};[[ ! -L $path ]]
 if [[ -e $S/$name.absent ]];then rm -f -- "$path";else cp -a -- "$S/$name.saved" "$path";fi
done
if [[ -e $S/ldconfig-directory.absent && -d /var/cache/ldconfig ]];then rmdir /var/cache/ldconfig;fi
cache_snapshot > "$S/after.cache";same_bytes "$S/before.cache" "$S/after.cache"
phase=restoration
payload_snapshot after
for suffix in paths hash db xattr dbmeta dbxattr;do same_bytes "$S/before.$suffix" "$S/after.$suffix";done
same_bytes "$S/before.meta-equality" "$S/after.meta-equality"
assert_users
bounded "$gpg_seconds" "$S/gpg-stop.log" gpgconf --homedir "$D/trust" --kill all
rm -rf -- "$D/trust"
bounded "$sync_seconds" "$S/sync.log" sync -f "$D"
{
 printf 'LLVM23_RESTORED_BEGIN %s\nSTATUS=PASS\nARCH=aarch64\nPAGESIZE=16384\nPACKAGE=%s\nVERSION=23.1.1-1\n' "$nonce" "$PACKAGE"
 printf 'BASE_SHA256=%s\nFINAL_SHA256=%s\n' "$(file_sha "$S/base.lock")" "$(file_sha "$S/final.lock")"
 printf 'C_SHA256=%s\nCXX_SHA256=%s\n' "$c_sha" "$cxx_sha"
 printf 'BASE_PAYLOAD=RESTORED\nBASE_METADATA=RESTORED\nBASE_XATTR=RESTORED\nLOCAL_DB=RESTORED\nUSERS=RESTORED\nUNOWNED_LDCACHE=RESTORED\nPREFIX=ABSENT\nPRIVATE_TRUST=REMOVED\nHOOKS_SCRIPTLETS=UNSUPPRESSED\nGUEST_SYNC=PASS\nELF_GEOMETRY=HOST_CHECK_REQUIRED\n'
 cat "$D/rtc-clock.env"
 printf 'LLVM23_RESTORED_END %s\n' "$nonce"
} > "$S/summary.env"
# /run is tmpfs. Preflight the complete durable DATA output set against Root's
# mandatory certificate cap, then preserve it for passive offline host checks.
printf '%s  smoke\n%s  unwind\n' "$c_sha" "$cxx_sha" > "$S/outputs.sha256"
output_bytes=0
for path in "$O/user/smoke" "$O/user/unwind" "$S/outputs.sha256" "$S/summary.env";do
 [[ -f $path && ! -L $path ]]
 size=$(stat -c '%s' -- "$path");[[ $size =~ ^[0-9]+$ ]]
 output_bytes=$((output_bytes+size));(( output_bytes <= guest_output_cap_bytes ))
done
[[ ! -e $D/results && ! -L $D/results ]]
install -d -m700 "$D/results"
cp -- "$O/user/smoke" "$D/results/smoke"
cp -- "$O/user/unwind" "$D/results/unwind"
cp -- "$S/outputs.sha256" "$S/summary.env" "$D/results/"
chmod 600 "$D/results/"*
[[ $(file_sha "$D/results/smoke") == "$c_sha" && $(file_sha "$D/results/unwind") == "$cxx_sha" ]]
same_bytes "$S/summary.env" "$D/results/summary.env"
cp -- "$S/summary.env" "$D/final-summary.env"
[[ ! -e $D/receipts && ! -L $D/receipts ]]
cp -a -- "$S" "$D/receipts"
bounded "$sync_seconds" "$S/final-sync.log" sync -f "$D"
cp -- "$S/summary.env" "$O/summary.env";chmod 644 "$O/summary.env"
printf '%s\n' "$nonce" > "$O/restored";chmod 644 "$O/restored"
phase=complete
