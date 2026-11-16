#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Readonly installed-node verification. Source after case.sh; caller must retain
# its exact installed inventory/version, pacman -Dk, payload SHA and verify_paths
# gates. No transaction, alternative owner, runtime language or new tool is used.
verify_installed_metadata() (
 set -Eeuo pipefail
 export LC_ALL=C
 umask 077
 local prefix=/usr
 local packet=$1 output=$2 path target extra kind mode uid gid line owner member key parent canonical field hex dev inode links actual_mode actual_uid actual_gid
 local count=0 global_count=0 batch_bytes=0 hard_count=0
 local -a paths=() parents=() symlinks=() batch=()
 local -A kinds=() modes=() uids=() gids=() targets=() seen_parent=() owners=() entries=() canonical_parents=() stat_dev=() stat_inode=() stat_links=()
 [[ $# == 2 && -d $packet && ! -L $packet && -d $output && ! -L $output ]] || return 2
 declare -F same_bytes > /dev/null || return 2
 local metadata=$packet/payload-metadata.tsv hardlinks=$packet/hardlinks.tsv expected=$packet/expected-payload.paths
 local stats_after=$output/installed-metadata.after-stat0 rawlinks_after=$output/installed-metadata.after-links0 resolvedlinks_after=$output/installed-metadata.after-link-targets0
 local stats=$output/installed-metadata.stat0 resolved=$output/installed-metadata.parents0 rawlinks=$output/installed-metadata.links0 resolvedlinks=$output/installed-metadata.link-targets0 global=$output/installed-metadata.owners inventory=$output/added.paths listed=$output/installed-metadata.paths
 # Existing case caps are16MiB/file. All output is fresh; a repeat refuses.
 ulimit -f 16384
 set -o noclobber
 for path in "$metadata" "$hardlinks" "$expected";do
  [[ -f $path && ! -L $path && $(stat -c %s -- "$path") -le 4194304 ]] || return 2
 done
 for path in "$stats" "$resolved" "$rawlinks" "$resolvedlinks" "$global" "$inventory" "$listed" "$stats_after" "$rawlinks_after" "$resolvedlinks_after";do
  [[ ! -e $path && ! -L $path ]] || return 2
 done
 # Keep the exact complete Perl inventory predicate. Its database is not a
 # replacement for file-owner queries: query lookup canonicalizes the parent.
 # One global ALPM ownership projection, including shared directory owners.
 # The caller's preceding -Dk remains mandatory. No per-node -Qo/-Qoq call.
 pacman -Ql > "$global" || return
 [[ $(stat -c %s -- "$global") -le 16777216 ]] || return 2
 while IFS= read -r line;do
  global_count=$((global_count+1));(( global_count <= 131072 )) || return 2
  [[ $line == *' '* ]] || return 2
  owner=${line%% *};member=${line#* }
  [[ $owner =~ ^[A-Za-z0-9@._+:-]+$ && $member == /* && $member != *$'\t'* && $member != *$'\r'* ]] || return 2
  [[ $member == / ]] || member=${member%/}
  key=$owner$'\t'$member
  [[ ! ${entries["$key"]+present} ]] || return 2
  entries["$key"]=1;owners["$member"]+=${owner}$'\n'
 done < "$global"
 (( global_count > 0 )) || return 2
 while IFS=$'\t' read -r kind mode uid gid path target extra;do
  count=$((count+1));(( count <= 65536 )) || return 2
  [[ -z $extra && $mode =~ ^[0-7]{3,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && ${#path} -le 4096 ]] || return 2
  [[ $path =~ ^/[A-Za-z0-9._+/@:~-]+$ && ( $path == "$prefix/"* || ( $path == "$prefix" && $kind == d ) ) && $path != "$prefix/local/"* ]] || return 2
  [[ $path != *'//'* && $path != */./* && $path != */../* && $path != */. && $path != */.. && ! ${kinds["$path"]+present} ]] || return 2
  case "$kind" in
   f) [[ -f $path && ! -L $path && $target == - ]] || return 1;;
   d) [[ -d $path && ! -L $path && $target == - ]] || return 1;;
   l) [[ -L $path && $target =~ ^[A-Za-z0-9._+/-]+$ && ${#target} -le 4096 ]] || return 1;symlinks+=("$path");;
   *) return 2;;
  esac
  paths+=("$path");kinds["$path"]=$kind;modes["$path"]=$mode;uids["$path"]=$uid;gids["$path"]=$gid;targets["$path"]=$target
  parent=${path%/*};[[ -n $parent ]] || parent=/
  if [[ ! ${seen_parent["$parent"]+present} ]];then parents+=("$parent");seen_parent["$parent"]=1;fi
 done < "$metadata"
 (( count > 0 )) || return 2
 printf '%s\n' "${paths[@]}" | sort -u > "$listed" || return
 same_bytes "$expected" "$listed" || return
 # GNU coreutils record boundaries are NUL, independent of locale/path quoting.
 # At most128 operands and16KiB path bytes per exec; never ARG_MAX-sized argv.
 im_batches() {
  local action=$1 destination=$2 value bytes;shift 2
  batch=();batch_bytes=0
  for value in "$@";do
   bytes=$((${#value}+1));(( bytes <= 4097 )) || return 2
   if (( ${#batch[@]} >= 128 || batch_bytes+bytes > 16384 ));then im_flush "$action" "$destination" || return;batch=();batch_bytes=0;fi
   batch+=("$value");batch_bytes=$((batch_bytes+bytes))
  done
  if (( ${#batch[@]} ));then im_flush "$action" "$destination" || return;fi
 }
 im_flush() {
  case "$1" in
   stat) stat --printf='%n\0%a\0%u\0%g\0%f\0%d\0%i\0%h\0' -- "${batch[@]}" >> "$2";;
   canonical) readlink -f -z -- "${batch[@]}" >> "$2";;
   link) readlink -z -- "${batch[@]}" >> "$2";;
   *) return 2;;
  esac
 }
 : > "$stats";: > "$resolved";: > "$rawlinks";: > "$resolvedlinks"
 im_batches stat "$stats" "${paths[@]}" || return
 im_batches canonical "$resolved" "${parents[@]}" || return
 im_batches link "$rawlinks" "${symlinks[@]}" || return
 im_batches canonical "$resolvedlinks" "${symlinks[@]}" || return
 # Parse exactly one record for every requested operand, with no surplus data.
 exec 7< "$stats"
 for path in "${paths[@]}";do
  IFS= read -r -d '' field <&7 && [[ $field == "$path" ]] || return 2
  IFS= read -r -d '' actual_mode <&7 && IFS= read -r -d '' actual_uid <&7 && IFS= read -r -d '' actual_gid <&7 && IFS= read -r -d '' hex <&7 && IFS= read -r -d '' dev <&7 && IFS= read -r -d '' inode <&7 && IFS= read -r -d '' links <&7 || return 2
  [[ $actual_mode == "${modes["$path"]}" && $actual_uid == "${uids["$path"]}" && $actual_gid == "${gids["$path"]}" && $hex =~ ^[0-9a-f]{1,8}$ && $dev =~ ^[0-9]+$ && $inode =~ ^[0-9]+$ && $links =~ ^[0-9]+$ ]] || return 1
  kind=$((16#$hex & 0170000))
  case ${kinds["$path"]} in f) (( kind == 0100000 )) || return 1;;d) (( kind == 0040000 )) || return 1;;l) (( kind == 0120000 )) || return 1;;esac
  stat_dev["$path"]=$dev;stat_inode["$path"]=$inode;stat_links["$path"]=$links
 done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then return 2;fi
 exec 7<&-
 exec 7< "$resolved"
 for parent in "${parents[@]}";do IFS= read -r -d '' canonical <&7 && [[ $canonical == /* && ${#canonical} -le 4096 ]] || return 2;canonical_parents["$parent"]=$canonical;done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then return 2;fi
 exec 7<&-
 exec 7< "$rawlinks" 8< "$resolvedlinks"
 for path in "${symlinks[@]}";do
  IFS= read -r -d '' target <&7 && IFS= read -r -d '' canonical <&8 || return 2
  [[ $target == "${targets["$path"]}" && $canonical == "$prefix/"* ]] || return 1
 done
 field=;if IFS= read -r -d '' field <&7 || [[ -n $field ]];then return 2;fi
 field=;if IFS= read -r -d '' field <&8 || [[ -n $field ]];then return 2;fi
 exec 7<&- 8<&-
 for path in "${paths[@]}";do
  parent=${path%/*};[[ -n $parent ]] || parent=/
  canonical=${canonical_parents["$parent"]%/}/${path##*/}
  # Existential Perl ownership, just like `-Qoq path | grep -qx perl`.
  # Shared directory owners are preserved; parent aliases cannot counterfeit it.
  [[ $'\n'${owners["$canonical"]-} == *$'\nperl\n'* ]] || return 1
 done
 while IFS=$'\t' read -r path target extra;do
  hard_count=$((hard_count+1));(( hard_count <= 65536 )) || return 2
  [[ -z $extra && ${kinds["$path"]-} == f && ${kinds["$target"]-} == f && -f $path && ! -L $path && -f $target && ! -L $target ]] || return 1
  [[ ${stat_dev["$path"]}:${stat_inode["$path"]} == "${stat_dev["$target"]}:${stat_inode["$target"]}" && ${stat_links["$path"]} -ge 2 ]] || return 1
 done < "$hardlinks"
 # Recheck the complete collected node/link facts before the original final
 # Perl inventory gate. Missing/replaced nodes during collection cannot hide
 # behind the earlier global DB projection. This is still bounded batching.
 : > "$stats_after";: > "$rawlinks_after";: > "$resolvedlinks_after"
 im_batches stat "$stats_after" "${paths[@]}" || return
 im_batches link "$rawlinks_after" "${symlinks[@]}" || return
 im_batches canonical "$resolvedlinks_after" "${symlinks[@]}" || return
 same_bytes "$stats" "$stats_after" || return
 same_bytes "$rawlinks" "$rawlinks_after" || return
 same_bytes "$resolvedlinks" "$resolvedlinks_after" || return
 pacman -Qlq perl | sed 's:/$::' | sort -u > "$inventory" || return
 same_bytes "$expected" "$inventory" || return
 printf 'PASS_INSTALLED_METADATA_DATA_ONLY nodes=%s global_records=%s\n' "$count" "$global_count"
)
