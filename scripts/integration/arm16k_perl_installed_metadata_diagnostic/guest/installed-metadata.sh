# SPDX-License-Identifier: MIT
# Fixed serial observations only; no pathname, command, value or private body.
# Direct console output is outside every unchanged PASS/HOLD protocol frame.
_im_diagnostic() {
 [[ $# == 2 ]] || return 0
 case "$1:$2" in
  PREDICATE:1|PREDICATE:2|PREDICATE:3|PREDICATE:4|COMMAND:5|PREDICATE:6|PREDICATE:7|PREDICATE:8|PREDICATE:9|PREDICATE:10|PREDICATE:11|PREDICATE:12|PREDICATE:13|PREDICATE:14|PREDICATE:15|PREDICATE:16|PREDICATE:17|PREDICATE:18|PREDICATE:19|PREDICATE:20|COMMAND:21|COMMAND:22|PREDICATE:23|COMMAND:24|COMMAND:25|PREDICATE:26|COMMAND:27|COMMAND:28|COMMAND:29|COMMAND:30|PREDICATE:31|PREDICATE:32|PREDICATE:33|PREDICATE:34|PREDICATE:35|PREDICATE:36|PREDICATE:37|PREDICATE:38|PREDICATE:39|PREDICATE:40|PREDICATE:41|PREDICATE:42|PREDICATE:43|PREDICATE:44|PREDICATE:45|PREDICATE:46|PREDICATE:47|COMMAND:48|COMMAND:49|COMMAND:50|COMMAND:51|COMMAND:52|COMMAND:53|COMMAND:54|COMMAND:55|STAGE:1|STAGE:2|STAGE:3|STAGE:4|STAGE:5|STAGE:6|STAGE:7|STAGE:8|STAGE:9|STAGE:10|STAGE:11|STAGE:12|STAGE:13|STAGE:14) :;;
  *) return 0;;
 esac
 { builtin printf '\nPERL5423_INSTALLED_METADATA_DIAGNOSTIC_V1 CATEGORY=%s ORDINAL=%s\n' "$1" "$2" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
_im_diagnostic STAGE 1
#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Readonly installed-node verification. Source after case.sh; caller must retain
# its exact installed inventory/version, pacman -Dk, payload SHA and verify_paths
# gates. No transaction, alternative owner, runtime language or new tool is used.
verify_installed_metadata() (
 _im_diagnostic STAGE 2
 set -Eeuo pipefail
 export LC_ALL=C
 umask 077
 local prefix=/usr
 local packet=$1 output=$2 path target extra kind mode uid gid line owner member key parent canonical field hex dev inode links actual_mode actual_uid actual_gid
 local count=0 global_count=0 batch_bytes=0 hard_count=0
 local -a paths=() parents=() symlinks=() batch=()
 local -A kinds=() modes=() uids=() gids=() targets=() seen_parent=() owners=() entries=() canonical_parents=() stat_dev=() stat_inode=() stat_links=()
 _im_diagnostic STAGE 3
 [[ $# == 2 && -d $packet && ! -L $packet && -d $output && ! -L $output ]] || { _im_diagnostic PREDICATE 1;return 2; }
 declare -F same_bytes > /dev/null || { _im_diagnostic PREDICATE 2;return 2; }
 local metadata=$packet/payload-metadata.tsv hardlinks=$packet/hardlinks.tsv expected=$packet/expected-payload.paths
 local stats_after=$output/installed-metadata.after-stat0 rawlinks_after=$output/installed-metadata.after-links0 resolvedlinks_after=$output/installed-metadata.after-link-targets0
 local stats=$output/installed-metadata.stat0 resolved=$output/installed-metadata.parents0 rawlinks=$output/installed-metadata.links0 resolvedlinks=$output/installed-metadata.link-targets0 global=$output/installed-metadata.owners inventory=$output/added.paths listed=$output/installed-metadata.paths
 # Existing case caps are16MiB/file. All output is fresh; a repeat refuses.
 ulimit -f 16384
 set -o noclobber
 for path in "$metadata" "$hardlinks" "$expected";do
  [[ -f $path && ! -L $path && $(stat -c %s -- "$path") -le 4194304 ]] || { _im_diagnostic PREDICATE 3;return 2; }
 done
 for path in "$stats" "$resolved" "$rawlinks" "$resolvedlinks" "$global" "$inventory" "$listed" "$stats_after" "$rawlinks_after" "$resolvedlinks_after";do
  [[ ! -e $path && ! -L $path ]] || { _im_diagnostic PREDICATE 4;return 2; }
 done
 # Keep the exact complete Perl inventory predicate. Its database is not a
 # replacement for file-owner queries: query lookup canonicalizes the parent.
 # One global ALPM ownership projection, including shared directory owners.
 # The caller's preceding -Dk remains mandatory. No per-node -Qo/-Qoq call.
 _im_diagnostic STAGE 4
 pacman -Ql > "$global" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 5;return "$_im_diagnostic_rc"; }
 [[ $(stat -c %s -- "$global") -le 16777216 ]] || { _im_diagnostic PREDICATE 6;return 2; }
 while IFS= read -r line;do
  global_count=$((global_count+1));(( global_count <= 131072 )) || { _im_diagnostic PREDICATE 7;return 2; }
  [[ $line == *' '* ]] || { _im_diagnostic PREDICATE 8;return 2; }
  owner=${line%% *};member=${line#* }
  [[ $owner =~ ^[A-Za-z0-9@._+:-]+$ && $member == /* && $member != *$'\t'* && $member != *$'\r'* ]] || { _im_diagnostic PREDICATE 9;return 2; }
  [[ $member == / ]] || member=${member%/}
  key=$owner$'\t'$member
  [[ ! ${entries["$key"]+present} ]] || { _im_diagnostic PREDICATE 10;return 2; }
  entries["$key"]=1;owners["$member"]+=${owner}$'\n'
 done < "$global"
 (( global_count > 0 )) || { _im_diagnostic PREDICATE 11;return 2; }
 _im_diagnostic STAGE 5
 while IFS=$'\t' read -r kind mode uid gid path target extra;do
  count=$((count+1));(( count <= 65536 )) || { _im_diagnostic PREDICATE 12;return 2; }
  [[ -z $extra && $mode =~ ^[0-7]{3,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && ${#path} -le 4096 ]] || { _im_diagnostic PREDICATE 13;return 2; }
  [[ $path =~ ^/[A-Za-z0-9._+/@:~-]+$ && ( $path == "$prefix/"* || ( $path == "$prefix" && $kind == d ) ) && $path != "$prefix/local/"* ]] || { _im_diagnostic PREDICATE 14;return 2; }
  [[ $path != *'//'* && $path != */./* && $path != */../* && $path != */. && $path != */.. && ! ${kinds["$path"]+present} ]] || { _im_diagnostic PREDICATE 15;return 2; }
  case "$kind" in
   f) [[ -f $path && ! -L $path && $target == - ]] || { _im_diagnostic PREDICATE 16;return 1; };;
   d) [[ -d $path && ! -L $path && $target == - ]] || { _im_diagnostic PREDICATE 17;return 1; };;
   l) [[ -L $path && $target =~ ^[A-Za-z0-9._+/-]+$ && ${#target} -le 4096 ]] || { _im_diagnostic PREDICATE 18;return 1; };symlinks+=("$path");;
   *) { _im_diagnostic PREDICATE 19;return 2; };;
  esac
  paths+=("$path");kinds["$path"]=$kind;modes["$path"]=$mode;uids["$path"]=$uid;gids["$path"]=$gid;targets["$path"]=$target
  parent=${path%/*};[[ -n $parent ]] || parent=/
  if [[ ! ${seen_parent["$parent"]+present} ]];then parents+=("$parent");seen_parent["$parent"]=1;fi
 done < "$metadata"
 (( count > 0 )) || { _im_diagnostic PREDICATE 20;return 2; }
 printf '%s\n' "${paths[@]}" | sort -u > "$listed" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 21;return "$_im_diagnostic_rc"; }
 same_bytes "$expected" "$listed" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 22;return "$_im_diagnostic_rc"; }
 # GNU coreutils record boundaries are NUL, independent of locale/path quoting.
 # At most128 operands and16KiB path bytes per exec; never ARG_MAX-sized argv.
 im_batches() {
  local action=$1 destination=$2 value bytes;shift 2
  batch=();batch_bytes=0
  for value in "$@";do
   bytes=$((${#value}+1));(( bytes <= 4097 )) || { _im_diagnostic PREDICATE 23;return 2; }
   if (( ${#batch[@]} >= 128 || batch_bytes+bytes > 16384 ));then im_flush "$action" "$destination" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 24;return "$_im_diagnostic_rc"; };batch=();batch_bytes=0;fi
   batch+=("$value");batch_bytes=$((batch_bytes+bytes))
  done
  if (( ${#batch[@]} ));then im_flush "$action" "$destination" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 25;return "$_im_diagnostic_rc"; };fi
 }
 im_flush() {
  case "$1" in
   stat) stat --printf='%n\0%a\0%u\0%g\0%f\0%d\0%i\0%h\0' -- "${batch[@]}" >> "$2";;
   canonical) readlink -f -z -- "${batch[@]}" >> "$2";;
   link) readlink -z -- "${batch[@]}" >> "$2";;
   *) { _im_diagnostic PREDICATE 26;return 2; };;
  esac
 }
 _im_diagnostic STAGE 6
 : > "$stats";: > "$resolved";: > "$rawlinks";: > "$resolvedlinks"
 im_batches stat "$stats" "${paths[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 27;return "$_im_diagnostic_rc"; }
 im_batches canonical "$resolved" "${parents[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 28;return "$_im_diagnostic_rc"; }
 im_batches link "$rawlinks" "${symlinks[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 29;return "$_im_diagnostic_rc"; }
 im_batches canonical "$resolvedlinks" "${symlinks[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 30;return "$_im_diagnostic_rc"; }
 # Parse exactly one record for every requested operand, with no surplus data.
 _im_diagnostic STAGE 7
 exec 7< "$stats"
 for path in "${paths[@]}";do
  IFS= read -r -d '' field <&7 && [[ $field == "$path" ]] || { _im_diagnostic PREDICATE 31;return 2; }
  IFS= read -r -d '' actual_mode <&7 && IFS= read -r -d '' actual_uid <&7 && IFS= read -r -d '' actual_gid <&7 && IFS= read -r -d '' hex <&7 && IFS= read -r -d '' dev <&7 && IFS= read -r -d '' inode <&7 && IFS= read -r -d '' links <&7 || { _im_diagnostic PREDICATE 32;return 2; }
  [[ $actual_mode == "${modes["$path"]}" && $actual_uid == "${uids["$path"]}" && $actual_gid == "${gids["$path"]}" && $hex =~ ^[0-9a-f]{1,8}$ && $dev =~ ^[0-9]+$ && $inode =~ ^[0-9]+$ && $links =~ ^[0-9]+$ ]] || { _im_diagnostic PREDICATE 33;return 1; }
  kind=$((16#$hex & 0170000))
  case ${kinds["$path"]} in f) (( kind == 0100000 )) || { _im_diagnostic PREDICATE 34;return 1; };;d) (( kind == 0040000 )) || { _im_diagnostic PREDICATE 35;return 1; };;l) (( kind == 0120000 )) || { _im_diagnostic PREDICATE 36;return 1; };;esac
  stat_dev["$path"]=$dev;stat_inode["$path"]=$inode;stat_links["$path"]=$links
 done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then { _im_diagnostic PREDICATE 37;return 2; };fi
 exec 7<&-
 _im_diagnostic STAGE 8
 exec 7< "$resolved"
 for parent in "${parents[@]}";do IFS= read -r -d '' canonical <&7 && [[ $canonical == /* && ${#canonical} -le 4096 ]] || { _im_diagnostic PREDICATE 38;return 2; };canonical_parents["$parent"]=$canonical;done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then { _im_diagnostic PREDICATE 39;return 2; };fi
 exec 7<&-
 _im_diagnostic STAGE 9
 exec 7< "$rawlinks" 8< "$resolvedlinks"
 for path in "${symlinks[@]}";do
  IFS= read -r -d '' target <&7 && IFS= read -r -d '' canonical <&8 || { _im_diagnostic PREDICATE 40;return 2; }
  [[ $target == "${targets["$path"]}" && $canonical == "$prefix/"* ]] || { _im_diagnostic PREDICATE 41;return 1; }
 done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then { _im_diagnostic PREDICATE 42;return 2; };fi
 field=;if IFS= read -r -d '' field <&8 || [[ -n $field ]];then { _im_diagnostic PREDICATE 43;return 2; };fi
 exec 7<&- 8<&-
 _im_diagnostic STAGE 10
 for path in "${paths[@]}";do
  parent=${path%/*};[[ -n $parent ]] || parent=/
  canonical=${canonical_parents["$parent"]%/}/${path##*/}
  # Existential Perl ownership, just like `-Qoq path | grep -qx perl`.
  # Shared directory owners are preserved; parent aliases cannot counterfeit it.
  [[ $'\n'${owners["$canonical"]-} == *$'\nperl\n'* ]] || { _im_diagnostic PREDICATE 44;return 1; }
 done
 _im_diagnostic STAGE 11
 while IFS=$'\t' read -r path target extra;do
  hard_count=$((hard_count+1));(( hard_count <= 65536 )) || { _im_diagnostic PREDICATE 45;return 2; }
  [[ -z $extra && ${kinds["$path"]-} == f && ${kinds["$target"]-} == f && -f $path && ! -L $path && -f $target && ! -L $target ]] || { _im_diagnostic PREDICATE 46;return 1; }
  [[ ${stat_dev["$path"]}:${stat_inode["$path"]} == "${stat_dev["$target"]}:${stat_inode["$target"]}" && ${stat_links["$path"]} -ge 2 ]] || { _im_diagnostic PREDICATE 47;return 1; }
 done < "$hardlinks"
 # Recheck the complete collected node/link facts before the original final
 # Perl inventory gate. Missing/replaced nodes during collection cannot hide
 # behind the earlier global DB projection. This is still bounded batching.
 _im_diagnostic STAGE 12
 : > "$stats_after";: > "$rawlinks_after";: > "$resolvedlinks_after"
 im_batches stat "$stats_after" "${paths[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 48;return "$_im_diagnostic_rc"; }
 im_batches link "$rawlinks_after" "${symlinks[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 49;return "$_im_diagnostic_rc"; }
 im_batches canonical "$resolvedlinks_after" "${symlinks[@]}" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 50;return "$_im_diagnostic_rc"; }
 same_bytes "$stats" "$stats_after" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 51;return "$_im_diagnostic_rc"; }
 same_bytes "$rawlinks" "$rawlinks_after" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 52;return "$_im_diagnostic_rc"; }
 same_bytes "$resolvedlinks" "$resolvedlinks_after" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 53;return "$_im_diagnostic_rc"; }
 _im_diagnostic STAGE 13
 pacman -Qlq perl | sed 's:/$::' | sort -u > "$inventory" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 54;return "$_im_diagnostic_rc"; }
 same_bytes "$expected" "$inventory" || { local _im_diagnostic_rc=$?;_im_diagnostic COMMAND 55;return "$_im_diagnostic_rc"; }
 _im_diagnostic STAGE 14
 printf 'PASS_INSTALLED_METADATA_DATA_ONLY nodes=%s global_records=%s\n' "$count" "$global_count"
)
