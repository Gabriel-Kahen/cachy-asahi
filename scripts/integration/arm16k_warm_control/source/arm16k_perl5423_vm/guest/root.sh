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
root_phase_writes=0
root_phase_name() {
 case "$1" in guard|rtc_clock|users|baseline|trust|dependency_install|official_trust|install|installed_payload|installed_metadata|probe_wait|retain_outputs|recovery|cache_restoration|restoration) return 0;;*) return 2;;esac
}
# Fixed metadata only. Atomic rename uses the certified baseline /usr/bin/mv.
# This is best-effort journaled progress, not a durability or success receipt.
write_root_phase() (
 umask 077
 local name=$1 record=$D/root-phase.checkpoint temporary=$D/.root-phase.checkpoint.tmp line bytes old_phase
 [[ $nonce =~ ^[0-9a-f]{32}$ ]] && root_phase_name "$name" || return 2
 [[ -d $D && ! -L $D && $(stat -c '%u:%g:%a' -- "$D") == 0:0:755 ]] || return 2
 if [[ -e $record || -L $record ]];then
  [[ -f $record && ! -L $record && $(stat -c '%u:%g:%h:%a' -- "$record") == 0:0:1:644 ]] || return 2
  bytes=$(stat -c '%s' -- "$record") || return
  (( bytes > 0 && bytes <= 128 )) || return 2
  line=$(head -c 129 -- "$record") || return
  old_phase=${line##* };root_phase_name "$old_phase" || return 2
  [[ $line == "PERL5423_ROOT_PHASE_V1 $nonce $old_phase" && $bytes == $((${#line}+1)) ]] || return 2
 fi
 [[ ! -e $temporary && ! -L $temporary ]] || return 2
 line="PERL5423_ROOT_PHASE_V1 $nonce $name"
 ( set -o noclobber;printf '%s\n' "$line" > "$temporary" ) || return
 if [[ -f $temporary && ! -L $temporary && $(stat -c '%u:%g:%h:%a' -- "$temporary") == 0:0:1:600 ]] &&
    [[ $(stat -c '%s' -- "$temporary") == $((${#line}+1)) && ${#line} -lt 128 ]] &&
    chmod 644 -- "$temporary" && /usr/bin/mv -T -- "$temporary" "$record";then return 0;fi
 if [[ -f $temporary && ! -L $temporary && $(stat -c '%u:%g:%h' -- "$temporary") == 0:0:1 ]];then rm -- "$temporary" || :;fi
 return 2
)
checkpoint_phase() {
 root_phase_name "$1" || return 2
 phase=$1;root_phase_writes=$((root_phase_writes+1))
 if (( root_phase_writes <= 20 ));then write_root_phase "$phase" || :;fi
}
# Fixed failure labels only; the coarse checkpoint and five-field HOLD frame stay exact.
restoration_step() {
 [[ $# == 1 ]] || return 2
 case "$1" in snapshot|paths|hash|db-normalized|xattr|dbmeta|dbxattr|meta_equality|users|log_prefix|log_shape|log_capture|preboot_cleanup|trust_cleanup|root_ssh_cleanup|sync|publish)
  phase=restoration_${1//-/_};;
  *) return 2;;
 esac
}
clear_root_phase() {
 local path metadata bytes line name
 for path in "$D/root-phase.checkpoint" "$D/.root-phase.checkpoint.tmp";do
  if [[ -e $path || -L $path ]];then
   [[ -f $path && ! -L $path ]] || return 2
   metadata=$(stat -c '%u:%g:%h:%a' -- "$path") || return
   [[ $metadata == 0:0:1:644 || $metadata == 0:0:1:600 ]] || return 2
   bytes=$(stat -c '%s' -- "$path") || return
   (( bytes > 0 && bytes <= 128 )) || return 2
   line=$(head -c 129 -- "$path") || return
   name=${line##* };root_phase_name "$name" || return 2
   [[ $line == "PERL5423_ROOT_PHASE_V1 $nonce $name" && $bytes == $((${#line}+1)) ]] || return 2
   rm -- "$path" || return
  fi
 done
 [[ ! -e $D/root-phase.checkpoint && ! -L $D/root-phase.checkpoint && ! -e $D/.root-phase.checkpoint.tmp && ! -L $D/.root-phase.checkpoint.tmp ]]
}
finish() {
 local rc=$?
 trap - EXIT
 if (( rc != 0 )); then
  if [[ -d $S && ! -L $S ]]; then
   local failure_rc=$rc
   printf 'PERL5423_RESTORED_BEGIN %s\nSTATUS=HOLD\nFAILED_PHASE=%s\nEXIT_STATUS=%s\nPERL5423_RESTORED_END %s\n' "$nonce" "$phase" "$rc" "$nonce" > "$S/failure.env" || :
   cp -- "$S/failure.env" "$D/failure.env" && chmod 600 "$D/failure.env" || :
   if declare -F retain_failure_data > /dev/null;then retain_failure_data || :;fi
   local trust_home
   for trust_home in "$D/trust" "$O/official-import" "$O/official-trust";do
    if [[ -d $trust_home && ! -L $trust_home ]];then timeout --signal=KILL "${gpg_seconds:-5}" gpgconf --homedir "$trust_home" --kill all || :;rm -rf -- "$trust_home";fi
   done
   timeout --signal=KILL "${sync_seconds:-5}" sync -f "$D" || :
   # Publish failure to the ordinary probe only after bounded durable capture.
   cp -- "$S/failure.env" "$O/summary.env" && chmod 644 "$O/summary.env" || :
  fi
 fi
 exit "$rc"
}
trap finish EXIT
[[ $# == 0 && $EUID == 0 && ! -e $O && ! -L $O ]]
install -d -m755 "$O"
install -d -m700 "$S"
. "$D/frozen/guest-runtime.sh"
. "$D/case.sh"
. "$D/installed-metadata.sh"
. "$D/root-ssh.sh"
. "$D/official-trust.sh"
. "$D/frozen/rtc-clock.sh"
case_data
checkpoint_phase guard
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
grep -qw "arm16k_perl5423_vm_nonce=$nonce" /proc/cmdline
[[ $(id -u builder) == 1000 && $(id -g builder) == 1000 && $(id -G builder) == 1000 ]]
[[ ! -e $D/consumed && ! -L $D/consumed ]]
( set -o noclobber;printf '%s\n' "$nonce" > "$D/consumed" )
checkpoint_phase rtc_clock
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
 root_ssh_guard
 find /home/builder /root -xdev -path "$root_ssh_target" -prune -o -printf '%p\t%m\t%U\t%G\t%y\t%l\0' | sort -z > "$1.meta"
 root_ssh_guard
 find /home/builder /root -xdev -path "$root_ssh_target" -prune -o -print0 | sort -z | xargs -0 -r getfattr --no-dereference --absolute-names --dump --match='.*' -- > "$1.xattr"
 root_ssh_guard
 find /home/builder /root -xdev -path "$root_ssh_target" -prune -o -type f -print0 | sort -z | xargs -0 -r sha256sum -b -z > "$1.hash"
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
# The normal ldconfig hook can create/remove ld.so.cache and change /etc mtime.
# Restore only certified preboot absence and parent mtime; never normalize atime.
preboot_root=/etc
preboot_parents=(etc etc/audit etc/udev)
preboot_paths=(etc/.pwd.lock etc/.updated etc/audisp etc/audit/plugins.d etc/audit/rules.d etc/ld.so.cache etc/os-release etc/udev/hwdb.bin etc/vconsole.conf)
preboot_kinds=(f f d d d f l f f)
preboot_modes=(600 644 755 750 755 644 777 444 644)
preboot_caps=(0 4096 0 0 0 1048576 4096 16777216 4096)
preboot_parent_index=(0 0 0 1 1 0 0 2 0)
preboot_absolute() { printf '%s%s' "$preboot_root" "${1#etc}"; }
preboot_identity() { stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$1"; }
preboot_parent_check() {
 local i=$1 path
 path=$(preboot_absolute "${preboot_parents[$i]}") || return
 [[ -d $path && ! -L $path && $(readlink -f -- "$path") == "$path" ]] || return 2
 [[ $(stat -c '%d:%i:%f:%u:%g' -- "$path") == "${preboot_parent_identity[$i]}" && $(stat -Lc '%d:%i:%f:%u:%g' -- "/proc/self/fd/${preboot_parent_fd[$i]}") == "${preboot_parent_identity[$i]}" ]]
}
preboot_empty() {
 local found
 found=$(find -P "$1" -xdev -mindepth 1 -maxdepth 1 -printf x -quit) || return
 [[ -z $found ]]
}
preboot_node_view() {
 local i=$1 path kind mode cap size hash metadata attrs
 path=$(preboot_absolute "${preboot_paths[$i]}") || return
 kind=${preboot_kinds[$i]};mode=${preboot_modes[$i]};cap=${preboot_caps[$i]}
 [[ $(stat -c '%u:%g:%h:%a' -- "$path") == "0:0:$([[ $kind == d ]] && printf 2 || printf 1):$mode" ]] || return 2
 size=$(stat -c '%s' -- "$path") || return
 [[ $size =~ ^[0-9]+$ ]] || return 2
 case "$kind" in
  f) [[ -f $path && ! -L $path && $size -le $cap ]] || return 2;hash=$(file_sha "$path") || return;;
  l) [[ -L $path && $size -le $cap ]] || return 2;hash=$(readlink -z -- "$path" | sha256sum) || return;hash=${hash%% *};;
  d) [[ -d $path && ! -L $path && $(readlink -f -- "$path") == "$path" ]] || return 2;preboot_empty "$path" || return;hash=EMPTY;;
  *) return 2;;
 esac
 attrs=$(getfattr --no-dereference --absolute-names --dump --match='.*' -- "$path" | sha256sum) || return
 metadata=$(stat -c '%f:%u:%g:%h:%s:%y' -- "$path") || return
 printf '%s|%s|%s' "$metadata" "${attrs%% *}" "$hash"
}
cache_etc_timestamp_capture() {
 local descriptor=$D/preboot-etc.tsv context=$D/preboot-context.json token selected_hash= count=0 marker observed_nonce context_sha extra line i key inode links seconds nanos path reference fd before after actual added expected owned expected_bytes=0
 local -a boot_arguments
 [[ -f $context && ! -L $context && $(stat -c '%u:%g:%h:%a' -- "$context") == 0:0:1:644 && $(stat -c '%s' -- "$context") -le 4096 ]]
 [[ -f $descriptor && ! -L $descriptor && $(stat -c '%u:%g:%h:%a' -- "$descriptor") == 0:0:1:600 && $(stat -c '%s' -- "$descriptor") -le 4096 ]]
 preboot_context_identity=$(preboot_identity "$context")
 preboot_descriptor_identity=$(preboot_identity "$descriptor")
 read -r -a boot_arguments < /proc/cmdline
 for token in "${boot_arguments[@]}";do
  if [[ $token == arm16k_perl5423_vm_preboot_etc_sha256=* ]];then selected_hash=${token#*=};count=$((count+1));fi
 done
 [[ $count == 1 && $selected_hash =~ ^[0-9a-f]{64}$ && $(file_sha "$descriptor") == "$selected_hash" ]]
 exec {preboot_descriptor_fd}< "$descriptor"
 IFS= read -r line <&"$preboot_descriptor_fd"
 expected_bytes=$((${#line}+1))
 IFS=' ' read -r marker observed_nonce context_sha extra <<< "$line"
 [[ $line == "PERL5423_PREBOOT_ETC_V2 $nonce $context_sha" && $observed_nonce == "$nonce" && $context_sha =~ ^[0-9a-f]{64}$ && -z $extra && $(file_sha "$context") == "$context_sha" ]]
 for i in 0 1 2;do
  IFS= read -r line <&"$preboot_descriptor_fd"
  expected_bytes=$((expected_bytes+${#line}+1))
  IFS=' ' read -r marker key inode links seconds nanos extra <<< "$line"
  [[ $marker == P && $key == "${preboot_parents[$i]}" && -z $extra && $line == "P $key $inode $links $seconds $nanos" ]]
  [[ $inode =~ ^[1-9][0-9]{0,9}$ && $links =~ ^[1-9][0-9]{0,4}$ && $seconds =~ ^(0|[1-9][0-9]{0,9})$ && $nanos =~ ^(0|[1-9][0-9]{0,8})$ ]]
  (( inode <= 4294967295 && links >= 2 && links <= 65535 && seconds <= 8589934591 && nanos <= 999999999 ))
  preboot_certified_inode[$i]=$inode;preboot_certified_links[$i]=$links;preboot_seconds[$i]=$seconds;preboot_nanos[$i]=$nanos
 done
 for i in 0 1 2 3 4 5 6 7 8;do
  IFS= read -r line <&"$preboot_descriptor_fd"
  expected_bytes=$((expected_bytes+${#line}+1))
  [[ $line == "A ${preboot_paths[$i]} ${preboot_kinds[$i]} ${preboot_modes[$i]} ${preboot_caps[$i]}" ]]
 done
 if IFS= read -r extra <&"$preboot_descriptor_fd";then return 2;fi
 [[ -z $extra && $(stat -c '%s' -- "$descriptor") == "$expected_bytes" ]]
 exec {preboot_descriptor_fd}<&-
 [[ $(preboot_identity "$descriptor") == "$preboot_descriptor_identity" && $(preboot_identity "$context") == "$preboot_context_identity" ]]
 [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c '%u:%g:%a' -- "$D/cache") == 0:0:700 ]]
 for i in 0 1 2;do
  path=$(preboot_absolute "${preboot_parents[$i]}")
  [[ -d $path && ! -L $path && $(readlink -f -- "$path") == "$path" && $(stat -c '%i:%u:%g:%a' -- "$path") == "${preboot_certified_inode[$i]}:0:0:755" ]]
  exec {fd}< "$path";preboot_parent_fd[$i]=$fd
  [[ $(stat -Lc '%i:%u:%g:%a:%F' -- "/proc/self/fd/$fd") == "${preboot_certified_inode[$i]}:0:0:755:directory" ]]
  preboot_parent_identity[$i]=$(stat -Lc '%d:%i:%f:%u:%g' -- "/proc/self/fd/$fd")
  preboot_parent_check "$i"
  reference=$D/cache/preboot-parent-$i.reference
  [[ ! -e $reference && ! -L $reference ]]
  (set -o noclobber;: > "$reference")
  [[ $(stat -c '%u:%g:%h:%a:%s' -- "$reference") == 0:0:1:600:0 && ! -L $reference ]]
  touch -m --date="@${preboot_seconds[$i]}.$(printf '%09d' "${preboot_nanos[$i]}")" -- "$reference"
  [[ $(date -u -r "$reference" +%s.%N) == "${preboot_seconds[$i]}.$(printf '%09d' "${preboot_nanos[$i]}")" ]]
  preboot_reference_identity[$i]=$(preboot_identity "$reference")
 done
 # Literal ownership only: pacman -Qo may resolve the os-release symlink target.
 owned=$(pacman -Qlq)
 (( ${#owned} <= 16777216 ))
 owned=$'\n'$owned$'\n'
 # Snapshot only these literal public-system operands before the first ALPM write.
 for i in 0 1 2 3 4 5 6 7 8;do
  path=$(preboot_absolute "${preboot_paths[$i]}")
  preboot_parent_check "${preboot_parent_index[$i]}"
  if [[ ! -e $path && ! -L $path ]];then preboot_present[$i]=0;continue;fi
  [[ $owned != *$'\n'"$path"$'\n'* && $owned != *$'\n'"$path/"$'\n'* ]]
  before=$(preboot_identity "$path")
  preboot_initial_view[$i]=$(preboot_node_view "$i")
  after=$(preboot_identity "$path");[[ $before == "$after" ]]
  preboot_initial_identity[$i]=$before;preboot_present[$i]=1
  if [[ ${preboot_kinds[$i]} != l ]];then
   exec {fd}< "$path";preboot_node_fd[$i]=$fd
   [[ $(stat -Lc '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "/proc/self/fd/$fd") == "$before" ]]
  fi
 done
 # A link delta is accepted only when the exact selected initial directories account for it.
 for i in 0 1 2;do
  added=0
  for key in 2 3 4;do if [[ ${preboot_parent_index[$key]} == "$i" && ${preboot_present[$key]} == 1 ]];then added=$((added+1));fi;done
  expected=$((preboot_certified_links[i]+added))
  [[ $(stat -Lc '%h' -- "/proc/self/fd/${preboot_parent_fd[$i]}") == "$expected" ]]
  preboot_observed_links[$i]=$expected
 done
}
cache_etc_timestamp_restore() {
 local descriptor=$D/preboot-etc.tsv i path reference current before after parent anchored fd atime
 [[ -f $descriptor && ! -L $descriptor && $(preboot_identity "$descriptor") == "$preboot_descriptor_identity" ]]
 [[ -f $D/preboot-context.json && ! -L $D/preboot-context.json && $(preboot_identity "$D/preboot-context.json") == "$preboot_context_identity" ]]
 [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c '%u:%g:%a' -- "$D/cache") == 0:0:700 ]]
 # All references and observed parent links must still join before any deletion.
 for i in 0 1 2;do
  preboot_parent_check "$i";reference=$D/cache/preboot-parent-$i.reference
  [[ -f $reference && ! -L $reference && $(preboot_identity "$reference") == "${preboot_reference_identity[$i]}" && $(stat -Lc '%h' -- "/proc/self/fd/${preboot_parent_fd[$i]}") == "${preboot_observed_links[$i]}" ]]
 done
 # Validate the whole initial nine-path snapshot before deleting any selected node.
 for i in 0 1 2 3 4 5 6 7 8;do
  path=$(preboot_absolute "${preboot_paths[$i]}");parent=${preboot_parent_index[$i]};preboot_parent_check "$parent"
  if [[ ${preboot_present[$i]} == 0 ]];then [[ ! -e $path && ! -L $path ]];continue;fi
  before=$(preboot_identity "$path")
  [[ $(preboot_node_view "$i") == "${preboot_initial_view[$i]}" ]]
  [[ $(preboot_identity "$path") == "$before" ]]
  # Normal ldconfig plus the existing exact cp -a cache recovery can replace only this inode.
  if [[ $i != 5 ]];then [[ $before == "${preboot_initial_identity[$i]}" ]];fi
 done
 for i in 0 1 2 3 4 5 6 7 8;do
  [[ ${preboot_present[$i]} == 1 ]] || continue
  path=$(preboot_absolute "${preboot_paths[$i]}");parent=${preboot_parent_index[$i]};preboot_parent_check "$parent"
  before=$(preboot_identity "$path");[[ $(preboot_node_view "$i") == "${preboot_initial_view[$i]}" && $(preboot_identity "$path") == "$before" ]]
  if [[ $i != 5 ]];then [[ $before == "${preboot_initial_identity[$i]}" ]];fi
  anchored=/proc/self/fd/${preboot_parent_fd[$parent]}/${preboot_paths[$i]##*/}
  [[ $(preboot_identity "$anchored") == "$before" ]]
  if [[ ${preboot_kinds[$i]} == l ]];then
   rm -- "$anchored"
  else
   # Re-pin the currently verified cache inode after its normal ALPM restoration.
   if [[ $i == 5 ]];then exec {fd}< "$path";else fd=${preboot_node_fd[$i]};fi
   [[ $(stat -Lc '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "/proc/self/fd/$fd") == "$before" ]]
   if [[ ${preboot_kinds[$i]} == d ]];then rmdir -- "$anchored";else rm -- "$anchored";fi
   [[ $(stat -Lc '%h' -- "/proc/self/fd/$fd") == 0 ]]
   exec {fd}<&-
  fi
  [[ ! -e $path && ! -L $path ]];preboot_parent_check "$parent"
 done
 for i in 0 1 2;do
  preboot_parent_check "$i";fd=${preboot_parent_fd[$i]};reference=$D/cache/preboot-parent-$i.reference
  [[ $(stat -Lc '%h' -- "/proc/self/fd/$fd") == "${preboot_certified_links[$i]}" && -f $reference && ! -L $reference && $(preboot_identity "$reference") == "${preboot_reference_identity[$i]}" ]]
  atime=$(stat -Lc '%x' -- "/proc/self/fd/$fd")
  touch -m --reference="$reference" -- "/proc/self/fd/$fd"
  [[ $(stat -Lc '%x' -- "/proc/self/fd/$fd") == "$atime" && $(stat -Lc '%y' -- "/proc/self/fd/$fd") == "$(stat -c '%y' -- "$reference")" ]]
  preboot_parent_check "$i"
  [[ $(preboot_identity "$reference") == "${preboot_reference_identity[$i]}" ]]
  rm -- "$reference";[[ ! -e $reference && ! -L $reference ]]
  exec {fd}<&-
 done
 # The original cache FD may have become unlinked during the normal ldconfig hook.
 fd=${preboot_node_fd[5]:-};if [[ -n $fd ]];then exec {fd}<&-;fi
}
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
checkpoint_phase users
root_ssh_capture
user_snapshot "$S/user-before"
checkpoint_phase baseline
payload_snapshot before
cache_snapshot > "$S/before.cache"
cache_etc_timestamp_capture
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_};[[ ! -L $path ]]
 ! pacman -Qo -- "$path" > /dev/null 2>&1
 if [[ -f $path ]]; then cp -a -- "$path" "$S/$name.saved";else [[ ! -e $path ]];touch "$S/$name.absent";fi
done
[[ -d /var/cache/ldconfig ]] || touch "$S/ldconfig-directory.absent"
[[ ! -L /var/log/pacman.log ]]
if [[ -f /var/log/pacman.log ]];then cp -a -- /var/log/pacman.log "$S/pacman-log-before";else [[ ! -e /var/log/pacman.log ]];: > "$S/pacman-log-before";touch "$S/pacman-log-before.absent";fi
checkpoint_phase trust
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
checkpoint_phase dependency_install
if [[ $dependency_mode == DB53 ]];then
 checkpoint_phase official_trust
 official_init
 checkpoint_phase dependency_install
 mapfile -t dependencies < "$D/dependency-requires.txt"
 bounded "$run_seconds" "$S/dependency-requires.log" pacman --config "$D/dependency-pacman.conf" -T "${dependencies[@]}"
 [[ ! -s $S/dependency-requires.log ]]
 bounded "$install_seconds" "$S/dependency-install.log" pacman --config "$D/dependency-pacman.conf" --noconfirm --asdeps -U "$D/db5.3-5.3.28-7-aarch64.pkg.tar.xz"
 inventory > "$S/dependencies.lock";same_bytes "$D/expected-dependencies.lock" "$S/dependencies.lock"
 sha256sum --check --strict --status "$D/dependency-payload.sha256"
 pacman -Qlq db5.3 | sed 's:/$::' | sort -u > "$S/dependency-added.paths"
 same_bytes "$D/expected-dependency.paths" "$S/dependency-added.paths"
fi
mapfile -t dependencies < "$D/dependencies.txt"
bounded "$run_seconds" "$S/dependencies.log" pacman --config "$D/pacman.conf" -T "${dependencies[@]}"
[[ ! -s $S/dependencies.log ]]
checkpoint_phase install
bounded "$install_seconds" "$S/install.log" pacman --config "$D/pacman.conf" --noconfirm -U "$ARCHIVE"
checkpoint_phase installed_payload
inventory > "$S/installed.lock"
same_bytes "$D/expected-installed.lock" "$S/installed.lock"
[[ $(pacman -Q "$PACKAGE") == "$PACKAGE 5.42.3-1.3" ]]
bounded "$run_seconds" "$S/database-installed.log" pacman -Dk
sha256sum --check --strict --status "$D/payload.sha256"
verify_paths
checkpoint_phase installed_metadata
# Keep temporary metadata streams out of the exact durable receipt allowlist.
[[ ! -e $O/installed-metadata && ! -L $O/installed-metadata ]]
install -d -m700 "$O/installed-metadata"
verify_installed_metadata "$D" "$O/installed-metadata"
cp -- "$O/installed-metadata/added.paths" "$S/added.paths"
rm -r -- "$O/installed-metadata"
assert_users
install -d -m700 -o1000 -g1000 "$O/user"
printf '%s\n' "$nonce" > "$O/installed";chmod 644 "$O/installed"
checkpoint_phase probe_wait
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
checkpoint_phase retain_outputs
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
checkpoint_phase recovery
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
checkpoint_phase cache_restoration
for path in /etc/ld.so.cache /var/cache/ldconfig/aux-cache; do
 name=${path//\//_};[[ ! -L $path ]]
 if [[ -e $S/$name.absent ]];then rm -f -- "$path";else cp -a -- "$S/$name.saved" "$path";fi
done
if [[ -e $S/ldconfig-directory.absent && -d /var/cache/ldconfig ]];then rmdir /var/cache/ldconfig;fi
cache_snapshot > "$S/after.cache";same_bytes "$S/before.cache" "$S/after.cache"
checkpoint_phase restoration
restoration_step snapshot
payload_snapshot after
for suffix in paths hash db-normalized xattr dbmeta dbxattr;do
 restoration_step "$suffix"
 same_bytes "$S/before.$suffix" "$S/after.$suffix"
done
restoration_step meta_equality
same_bytes "$S/before.meta-equality" "$S/after.meta-equality"
restoration_step users
assert_users
restoration_step log_prefix
before_log_bytes=$(stat -c '%s' "$S/pacman-log-before")
head -c "$before_log_bytes" /var/log/pacman.log > "$S/pacman-log-prefix"
same_bytes "$S/pacman-log-before" "$S/pacman-log-prefix"
restoration_step log_shape
[[ -f /var/log/pacman.log && ! -L /var/log/pacman.log && $(stat -c '%u:%g' /var/log/pacman.log) == 0:0 ]]
after_log_bytes=$(stat -c '%s' /var/log/pacman.log)
(( after_log_bytes >= before_log_bytes && after_log_bytes-before_log_bytes <= log_bytes ))
restoration_step log_capture
cp -- /var/log/pacman.log "$S/pacman-log-after"
chmod 600 "$S/pacman-log-after"
if [[ -f $S/pacman-log-before.absent ]];then rm -- /var/log/pacman.log;[[ ! -e /var/log/pacman.log && ! -L /var/log/pacman.log ]];fi
if [[ $recovery_mode == REMOVE ]];then db_policy=EXACT;else db_policy=NORMAL_INSTALLDATE_AND_TRANSACTION_TIMESTAMPS;fi
# Compare the recovered running state first: certified preboot cleanup changes parent nlinks.
# Final preboot absence/identity/mtime remains subject to the unchanged host preserve gate.
restoration_step preboot_cleanup
cache_etc_timestamp_restore
restoration_step trust_cleanup
bounded "$gpg_seconds" "$S/gpg-stop.log" gpgconf --homedir "$D/trust" --kill all
rm -rf -- "$D/trust"
if [[ $dependency_mode == DB53 ]];then official_finish;fi
restoration_step root_ssh_cleanup
root_ssh_restore
clear_root_phase
restoration_step sync
bounded "$sync_seconds" "$S/sync.log" sync -f "$D"
restoration_step publish
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
