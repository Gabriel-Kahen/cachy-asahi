#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Disposable guest Root oneshot. Normal ALPM hooks and scriptlets remain enabled.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
D=/var/lib/arm16k-perl5423-vm
O=/run/arm16k-perl5423-vm
S=$O/root
PACKAGE=perl
ARCHIVE=$D/$PACKAGE-5.42.3-1.3-aarch64.pkg.tar.zst
phase=guard
nonce=INVALID
finish() {
 local rc=$?
 trap - EXIT
 if (( rc != 0 )); then
  if [[ -d $S && ! -L $S ]]; then
   printf 'PERL5423_RESTORED_BEGIN %s\nSTATUS=HOLD\nFAILED_PHASE=%s\nPERL5423_RESTORED_END %s\n' "$nonce" "$phase" "$nonce" > "$S/failure.env"
   cp -- "$S/failure.env" "$O/summary.env";chmod 644 "$O/summary.env"
   cp -- "$S/failure.env" "$D/failure.env"
   if [[ -d $D/trust && ! -L $D/trust ]];then timeout --signal=KILL "${gpg_seconds:-5}" gpgconf --homedir "$D/trust" --kill all || :;rm -rf -- "$D/trust";fi
   sync -f "$D" || :
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
grep -qw "arm16k_perl5423_vm_nonce=$nonce" /proc/cmdline
[[ $(id -u builder) == 1000 && $(id -g builder) == 1000 && $(id -G builder) == 1000 ]]
[[ ! -e $D/consumed && ! -L $D/consumed ]]
( set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed" )
phase=rtc_clock
rtc_clock_guard
clock_valid
inventory > "$S/base.lock"
same_bytes "$D/expected-base.lock" "$S/base.lock"
if [[ $recovery_mode == REMOVE ]];then ! pacman -Q "$PACKAGE" > /dev/null 2>&1;else pacman -Q "$PACKAGE" > "$S/old-perl.lock";fi
sha256sum --check --strict --status "$D/baseline-paths.sha256"
# Expected archive facts are checked against this fresh running guest before
# the first mutating ALPM transaction. Readonly -Q ownership queries are allowed.
: > "$S/before-alpm-provider-observation.tsv"
while IFS=$'\t' read -r path bytes hash mode owner version extra;do
 [[ -z $extra && $path == /usr/* && $bytes =~ ^[1-9][0-9]*$ && $hash =~ ^[0-9a-f]{64}$ && $mode =~ ^[0-7]{3,4}$ ]]
 [[ -f $path && ! -L $path && $(readlink -f -- "$path") == "$path" && $(stat -c '%s:%a:%u:%g' -- "$path") == "$bytes:$mode:0:0" && $(file_sha "$path") == "$hash" ]]
 [[ $(pacman -Qoq -- "$path") == "$owner" && $(pacman -Q "$owner") == "$owner $version" ]]
 printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$bytes" "$hash" "$owner" "$version" >> "$S/before-alpm-provider-observation.tsv"
done < "$D/expected-before-alpm-providers.tsv"
while IFS=$'\t' read -r path target owner version extra;do
 [[ -z $extra && -L $path && $(readlink -- "$path") == "$target" && $(stat -c '%a:%u:%g' -- "$path") == 777:0:0 ]]
 [[ $(pacman -Q "$owner") == "$owner $version" ]]
 pacman -Qlq "$owner" | grep -Fx -- "$path" > /dev/null
 printf '%s\t%s\t%s\t%s\n' "$path" "$target" "$owner" "$version" >> "$S/before-alpm-provider-observation.tsv"
done < "$D/expected-before-alpm-aliases.tsv"


user_snapshot() (
 ulimit -f 16384
 find /home/builder /root -xdev -printf '%p\t%m\t%U\t%G\t%y\t%l\0' | sort -z > "$1.meta"
 find /home/builder /root -xdev -print0 | sort -z | xargs -0 -r getfattr --no-dereference --absolute-names --dump --match='.*' -- > "$1.xattr"
 find /home/builder /root -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.hash"
)
assert_users() {
 user_snapshot "$S/user-current"
 same_bytes "$S/user-before.meta" "$S/user-current.meta"
 same_bytes "$S/user-before.hash" "$S/user-current.hash"
 same_bytes "$S/user-before.xattr" "$S/user-current.xattr"
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
 if [[ $recovery_mode == SIGNED_EXACT_OLD_PACKAGE ]];then
  local desc=/var/lib/pacman/local/perl-$baseline_perl_version/desc path hash
  normalized_desc "$desc" "$S/$stage.perl-desc.normalized"
  cp -a -- "$desc" "$S/$stage.perl-desc.raw"
  : > "$S/$stage.db-normalized"
  while IFS= read -r -d '' path;do
   if [[ $path == "$desc" ]];then hash=$(file_sha "$S/$stage.perl-desc.normalized");else hash=$(file_sha "$path");fi
   printf '%s *%s\0' "$hash" "$path" >> "$S/$stage.db-normalized"
  done < <(find /var/lib/pacman/local -type f -print0 | sort -z)
 else cp -- "$S/$stage.db" "$S/$stage.db-normalized";fi
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
phase=users
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
[[ ! -L /var/log/pacman.log ]]
if [[ -f /var/log/pacman.log ]];then cp -a -- /var/log/pacman.log "$S/pacman-log-before";else [[ ! -e /var/log/pacman.log ]];: > "$S/pacman-log-before";fi
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
if [[ $recovery_mode == SIGNED_EXACT_OLD_PACKAGE ]];then
 gpg_fixed rollback-signature --verify "$D/rollback.pkg.tar.zst.sig" "$D/rollback.pkg.tar.zst"
fi
phase=dependency_install
if [[ $dependency_mode == DB53 ]];then
 mapfile -t dependencies < "$D/dependency-requires.txt"
 bounded "$run_seconds" "$S/dependency-requires.log" pacman -T "${dependencies[@]}"
 [[ ! -s $S/dependency-requires.log ]]
 bounded "$install_seconds" "$S/dependency-install.log" pacman --config "$D/dependency-pacman.conf" --noconfirm --asdeps -U "$D/db5.3-5.3.28-7-aarch64.pkg.tar.xz"
 inventory > "$S/dependencies.lock";same_bytes "$D/expected-dependencies.lock" "$S/dependencies.lock"
 sha256sum --check --strict --status "$D/dependency-payload.sha256"
 pacman -Qlq db5.3 | sed 's:/$::' | sort -u > "$S/dependency-added.paths"
 same_bytes "$D/expected-dependency.paths" "$S/dependency-added.paths"
fi
mapfile -t dependencies < "$D/dependencies.txt"
bounded "$run_seconds" "$S/dependencies.log" pacman -T "${dependencies[@]}"
[[ ! -s $S/dependencies.log ]]
phase=install
bounded "$install_seconds" "$S/install.log" pacman --config "$D/pacman.conf" --noconfirm -U "$ARCHIVE"
inventory > "$S/installed.lock"
same_bytes "$D/expected-installed.lock" "$S/installed.lock"
[[ $(pacman -Q "$PACKAGE") == "$PACKAGE 5.42.3-1.3" ]]
bounded "$run_seconds" "$S/database-installed.log" pacman -Dk
sha256sum --check --strict --status "$D/payload.sha256"
verify_paths
while IFS=$'\t' read -r kind mode uid gid path target extra; do
 [[ -z $extra && $mode =~ ^[0-7]{3,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]]
 [[ ( $path == /usr/* || ( $path == /usr && $kind == d ) ) && $path != /usr/local/* ]]
 [[ $(stat -c '%a:%u:%g' -- "$path") == "$mode:$uid:$gid" ]]
 case "$kind" in f) [[ -f $path && ! -L $path && $target == - ]];;d) [[ -d $path && ! -L $path && $target == - ]];;l) [[ -L $path && $(readlink -- "$path") == "$target" && $(readlink -f -- "$path") == /usr/* ]];;*) false;;esac
 pacman -Qoq -- "$path" | grep -qx perl
done < "$D/payload-metadata.tsv"
while IFS=$'\t' read -r path target extra;do
 [[ -z $extra && -f $path && ! -L $path && -f $target && ! -L $target ]]
 [[ $(stat -c '%d:%i' -- "$path") == "$(stat -c '%d:%i' -- "$target")" && $(stat -c '%h' -- "$path") -ge 2 ]]
done < "$D/hardlinks.tsv"
pacman -Qlq "$PACKAGE" | sed 's:/$::' | sort -u > "$S/added.paths"
same_bytes "$D/expected-payload.paths" "$S/added.paths"
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
assert_users
clock_valid
verify_paths
# Seal and retain functional logs and the actual installed ELF bytes before ALPM recovery.
[[ ! -e $D/results && ! -L $D/results ]]
install -d -m700 "$D/results"
for name in version functional corelist json perldoc podtext podcheck prove sha splain paths;do
 [[ -f $O/user/$name.log && ! -L $O/user/$name.log ]]
 cp -- "$O/user/$name.log" "$D/results/$name.log"
done
while IFS=$'\t' read -r name path hash extra;do
 [[ $name =~ ^[0-9]+[.]elf$ && $path == /usr/* && $hash =~ ^[0-9a-f]{64}$ && -z $extra ]]
 [[ -f $path && ! -L $path && $(file_sha "$path") == "$hash" ]]
 cp -- "$path" "$D/results/$name"
done < "$D/elf-paths.tsv"
cp -- "$S/before-alpm-provider-observation.tsv" "$D/results/before-alpm-provider-observation.tsv"
(cd "$D/results";sha256sum -- *.elf *.log *.tsv > outputs.sha256)
functional_sha=$(file_sha "$D/results/functional.log");elf_manifest_sha=$(file_sha "$D/elf-paths.tsv")
phase=recovery
if [[ $recovery_mode == REMOVE ]];then
 bounded "$remove_seconds" "$S/remove.log" pacman --config "$D/pacman.conf" --noconfirm -R "$PACKAGE"
else
 reason=$(cat "$D/recovery-reason")
 case "$reason" in explicit) reason_arg=--asexplicit;;dependency) reason_arg=--asdeps;;*) false;;esac
 bounded "$remove_seconds" "$S/rollback.log" pacman --config "$D/pacman.conf" --noconfirm "$reason_arg" -U "$D/rollback.pkg.tar.zst"
 pacman -Q "$PACKAGE" > "$S/recovered-perl.lock";same_bytes "$S/old-perl.lock" "$S/recovered-perl.lock"
fi
if [[ $dependency_mode == DB53 ]];then
 bounded "$remove_seconds" "$S/dependency-remove.log" pacman --config "$D/dependency-pacman.conf" --noconfirm -R db5.3
 comm -23 "$S/dependency-added.paths" <(tr '\0' '\n' < "$S/before.paths" | sed 's:/$::' | sort -u) > "$S/dependency-exclusive.paths"
 while IFS= read -r path;do [[ ! -e $path && ! -L $path ]];done < "$S/dependency-exclusive.paths"
fi
inventory > "$S/final.lock";same_bytes "$S/base.lock" "$S/final.lock"
bounded "$run_seconds" "$S/database-final.log" pacman -Dk
sha256sum --check --strict --status "$D/baseline-paths.sha256"
comm -23 "$S/added.paths" <(tr '\0' '\n' < "$S/before.paths" | sed 's:/$::' | sort -u) > "$S/exclusive.paths"
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
for suffix in paths hash db-normalized xattr dbmeta dbxattr;do same_bytes "$S/before.$suffix" "$S/after.$suffix";done
same_bytes "$S/before.meta-equality" "$S/after.meta-equality"
assert_users
before_log_bytes=$(stat -c '%s' "$S/pacman-log-before")
head -c "$before_log_bytes" /var/log/pacman.log > "$S/pacman-log-prefix"
same_bytes "$S/pacman-log-before" "$S/pacman-log-prefix"
if [[ $recovery_mode == REMOVE ]];then db_policy=EXACT;else db_policy=NORMAL_INSTALLDATE_AND_TRANSACTION_TIMESTAMPS;fi
bounded "$gpg_seconds" "$S/gpg-stop.log" gpgconf --homedir "$D/trust" --kill all
rm -rf -- "$D/trust"
bounded "$sync_seconds" "$S/sync.log" sync -f "$D"
{
 printf 'PERL5423_RESTORED_BEGIN %s\nSTATUS=PASS\nARCH=aarch64\nPAGESIZE=16384\nPACKAGE=%s\nVERSION=5.42.3-1.3\n' "$nonce" "$PACKAGE"
 printf 'BASE_SHA256=%s\nFINAL_SHA256=%s\n' "$(file_sha "$S/base.lock")" "$(file_sha "$S/final.lock")"
 printf 'DB_POLICY=%s\n' "$db_policy"
 printf 'FUNCTIONAL_SHA256=%s\nELF_MANIFEST_SHA256=%s\n' "$functional_sha" "$elf_manifest_sha"
 printf 'BASE_PAYLOAD=RESTORED\nBASE_METADATA=RESTORED\nBASE_XATTR=RESTORED\nLOCAL_DB=RESTORED\nUSERS=RESTORED\nUNOWNED_LDCACHE=RESTORED\nPERL_BASELINE=RESTORED\nPRIVATE_TRUST=REMOVED\nHOOKS_SCRIPTLETS=UNSUPPRESSED\nGUEST_SYNC=PASS\nELF_GEOMETRY=HOST_CHECK_REQUIRED\n'
 cat "$D/rtc-clock.env"
 printf 'PERL5423_RESTORED_END %s\n' "$nonce"
} > "$S/summary.env"
# Every durable log, ELF and preservation receipt is covered by the output budget.
cp -- "$S/summary.env" "$D/results/summary.env"
chmod 600 "$D/results/"*
[[ ! -e $D/receipts && ! -L $D/receipts ]]
cp -a -- "$S" "$D/receipts"
output_bytes=0
while IFS= read -r -d '' path;do
 size=$(stat -c '%s' -- "$path");output_bytes=$((output_bytes+size));(( output_bytes <= guest_output_cap_bytes ))
done < <(find "$D/results" "$D/receipts" -type f -print0)
bounded "$sync_seconds" "$S/final-sync.log" sync -f "$D"
cp -- "$S/summary.env" "$O/summary.env";chmod 644 "$O/summary.env"
printf '%s\n' "$nonce" > "$O/restored";chmod 644 "$O/restored"
phase=complete
