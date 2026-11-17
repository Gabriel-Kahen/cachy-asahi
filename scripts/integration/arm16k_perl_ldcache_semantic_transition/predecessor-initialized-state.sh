# SPDX-License-Identifier: MIT
# Public fixed check/index and substage observations only, outside all frames.
_ig_diagnostic() {
 [[ $# == 2 ]] || return 0
 case "$1" in I0|E0|R1|R2|R3|R4|R5|R6|R7|R8|R9|R10|R11|R12|R13|R14|R15|R16|R17|R18|R19|R20|R21|R22|R23|R24|R25|R26|R27|R28|R29|R30|R31|R32|R33|R34|R35|R36|R37|R38|R39|R40|R41) :;;*) return 0;;esac
 case "$2" in 0|1|2|3|4|5|6|7|8|9|10|11|12|13|14) :;;*) return 0;;esac
 { builtin printf '\nPERL5423_INITIALIZED_GUARD_DIAGNOSTIC_V1 CHECK=%s INDEX=%s\n' "$1" "$2" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
_ig_substage() {
 [[ $# == 1 ]] || return 0
 case "$1" in METADATA_RETURNED|COPY_DONE|REMOVE_DONE|ASSERT_USERS_ENTER|ASSERT_USERS_DONE|USER_DIR_DONE|INSTALLED_MARKER_DONE|SNAPSHOT_ENTER|SNAPSHOT_GUARD1_DONE|SNAPSHOT_META_DONE|SNAPSHOT_GUARD2_DONE|SNAPSHOT_XATTR_DONE|SNAPSHOT_GUARD3_DONE|SNAPSHOT_HASH_DONE|USERS_SNAPSHOT_DONE|USERS_META_MATCHED|USERS_HASH_MATCHED|USERS_XATTR_MATCHED) :;;*) return 0;;esac
 { builtin printf '\nPERL5423_POST_METADATA_DIAGNOSTIC_V1 STAGE=%s\n' "$1" >> /dev/ttyAMA0; } 2>/dev/null || :
 return 0
}
# SPDX-License-Identifier: MIT
# Initialized-state equality only: no deletion, cache copy or timestamp repair.
root_ssh_target=/root/.ssh
initialized_paths=(etc/.pwd.lock etc/.updated etc/audisp etc/audit/plugins.d etc/audit/rules.d etc/ld.so.cache etc/os-release etc/udev/hwdb.bin etc/vconsole.conf etc etc/audit etc/udev root root/.ssh)
initialized_kinds=(f f d d d f l f f d d d d d)
initialized_modes=(600 644 755 750 755 644 777 444 644 755 755 755 700 700)
_initialized_sha() { local v;v=$(sha256sum -- "$1") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R1 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };printf '%s' "${v%% *}"; }
_initialized_identity() { stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$1" || { local _ig_diagnostic_rc=$?;_ig_diagnostic I0 "${i:-14}";return "$_ig_diagnostic_rc"; }; }
_initialized_empty() {
 local path=$1 before found
 [[ -d $path && ! -L $path ]] || { _ig_diagnostic R2 "13";return 2; }
 before=$(_initialized_identity "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R3 "13";fi;return "$_ig_diagnostic_rc"; }
 # Only a fixed presence bit is captured. No child body or name is emitted.
 found=$(find -P "$path" -xdev -mindepth 1 -maxdepth 1 -printf x -quit 2>/dev/null) || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R4 "13";fi;return "$_ig_diagnostic_rc"; }
 [[ -z $found && $(_initialized_identity "$path") == "$before" ]] || { _ig_diagnostic E0 13;return 1; }
}
_initialized_view() {
 local i=$1 path=${initialized_prefix}/${initialized_paths[$1]} kind=${initialized_kinds[$1]} payload=- seconds stamp nanos before after
 before=$(_initialized_identity "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R5 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
 case "$kind" in
  f) [[ -f $path && ! -L $path ]] || { _ig_diagnostic R6 "${i:-14}";return 2; };payload=$(_initialized_sha "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R7 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };;
  d) [[ -d $path && ! -L $path ]] || { _ig_diagnostic R8 "${i:-14}";return 2; };;
  l) [[ -L $path ]] || { _ig_diagnostic R9 "${i:-14}";return 2; };payload=$(set -o pipefail;readlink -n -- "$path" | base64 -w0) || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R10 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };;
  *) { _ig_diagnostic R11 "${i:-14}";return 2; };;
 esac
 stamp=$(stat -c '%Y:%y' -- "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R12 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };seconds=${stamp%%:*};nanos=${stamp#*.};nanos=${nanos%% *}
 [[ $seconds =~ ^-?[0-9]+$ && $nanos =~ ^[0-9]{9}$ ]] || { _ig_diagnostic R13 "${i:-14}";return 2; }
 after=$(_initialized_identity "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R14 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };[[ $before == "$after" ]] || { _ig_diagnostic R15 "${i:-14}";return 2; }
 printf 'N %s %s %s %s %s\n' "${initialized_paths[$i]}" "$(stat -c '%i %h' -- "$path")" "$kind" "$(stat -c '%a %u %g %s' -- "$path")" "$seconds.$nanos $payload"
}
_initialized_attrs() { local value;value=$(set -o pipefail;getfattr --no-dereference --absolute-names --dump --match='.*' -- "$1" | sha256sum) || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R16 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };printf '%s' "${value%% *}"; }
_initialized_guard() {
 local i path before attrs
 [[ ${initialized_captured:-0} == 1 ]] || { _ig_diagnostic R17 "${i:-14}";return 2; }
 [[ $(_initialized_identity "$D/initialized-state.tsv") == "$initialized_descriptor_identity" && $(_initialized_identity "$D/preboot-context.json") == "$initialized_context_identity" ]] || { _ig_diagnostic R18 "${i:-14}";return 2; }
 _initialized_empty "$initialized_prefix/root/.ssh" || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R19 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
 for i in "${!initialized_paths[@]}";do
  path=$initialized_prefix/${initialized_paths[$i]};before=$(_initialized_identity "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R20 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
  [[ $(_initialized_view "$i") == "${initialized_expected[$i]}" ]] || { _ig_diagnostic R21 "${i:-14}";return 2; }
  attrs=$(_initialized_attrs "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R22 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
  [[ $attrs == "${initialized_attrs[$i]}" && $(_initialized_identity "$path") == "$before" ]] || { _ig_diagnostic R23 "${i:-14}";return 2; }
 done
 _initialized_empty "$initialized_prefix/root/.ssh"
}
_initialized_capture() {
 # Internal arguments are for ordinary temporary-filesystem controls only.
 # The public actor entry below fixes /, uid0 and the literal kernel selector.
 local prefix=$1 owner=$2 selected=$3 descriptor=$D/initialized-state.tsv context=$D/preboot-context.json line marker observed_nonce context_sha extra i path bytes=0 before attrs
 [[ ${initialized_captured:-0} == 0 ]] || { _initialized_guard;{ local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R24 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }; }
 [[ -f $descriptor && ! -L $descriptor && $(stat -c '%u:%g:%h:%a' -- "$descriptor") == "$owner:$owner:1:600" && $(stat -c '%s' -- "$descriptor") -le 8192 ]] || { _ig_diagnostic R25 "${i:-14}";return 2; }
 [[ -f $context && ! -L $context && $(stat -c '%u:%g:%h:%a' -- "$context") == "$owner:$owner:1:644" && $(stat -c '%s' -- "$context") -le 4096 ]] || { _ig_diagnostic R26 "${i:-14}";return 2; }
 [[ $selected =~ ^[0-9a-f]{64}$ && $(_initialized_sha "$descriptor") == "$selected" ]] || { _ig_diagnostic R27 "${i:-14}";return 2; }
 initialized_descriptor_identity=$(_initialized_identity "$descriptor");initialized_context_identity=$(_initialized_identity "$context");initialized_prefix=$prefix
 exec {initialized_descriptor_fd}< "$descriptor" || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R28 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
 IFS= read -r line <&"$initialized_descriptor_fd" || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R29 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };bytes=$((${#line}+1));IFS=' ' read -r marker observed_nonce context_sha extra <<< "$line"
 [[ $line == "PERL5423_INITIALIZED_STATE_V1 $nonce $context_sha" && $nonce =~ ^[0-9a-f]{32}$ && $observed_nonce == "$nonce" && $context_sha =~ ^[0-9a-f]{64}$ && -z $extra && $(_initialized_sha "$context") == "$context_sha" ]] || { _ig_diagnostic R30 "${i:-14}";return 2; }
 _initialized_empty "$prefix/root/.ssh" || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R31 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
 initialized_expected=();initialized_attrs=()
 for i in "${!initialized_paths[@]}";do
  IFS= read -r line <&"$initialized_descriptor_fd" || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R32 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };bytes=$((bytes+${#line}+1));(( bytes <= 8192 )) || { _ig_diagnostic R33 "${i:-14}";return 2; }
  path=$prefix/${initialized_paths[$i]};before=$(_initialized_identity "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R34 "${i:-14}";fi;return "$_ig_diagnostic_rc"; }
  [[ $(stat -c '%u:%g:%a' -- "$path") == "$owner:$owner:${initialized_modes[$i]}" && $(_initialized_view "$i") == "$line" ]] || { _ig_diagnostic R35 "${i:-14}";return 2; }
  initialized_expected[$i]=$line;attrs=$(_initialized_attrs "$path") || { local _ig_diagnostic_rc=$?;if (( _ig_diagnostic_rc != 0 ));then _ig_diagnostic R36 "${i:-14}";fi;return "$_ig_diagnostic_rc"; };initialized_attrs[$i]=$attrs
  [[ $(_initialized_identity "$path") == "$before" ]] || { _ig_diagnostic R37 "${i:-14}";return 2; }
 done
 if IFS= read -r extra <&"$initialized_descriptor_fd";then { _ig_diagnostic R38 "${i:-14}";return 2; };fi
 [[ -z $extra && $(stat -c '%s' -- "$descriptor") == "$bytes" && $(_initialized_identity "$descriptor") == "$initialized_descriptor_identity" && $(_initialized_identity "$context") == "$initialized_context_identity" ]] || { _ig_diagnostic R39 "${i:-14}";return 2; }
 exec {initialized_descriptor_fd}<&-
 initialized_captured=1;_initialized_guard
}
initialized_capture() {
 [[ $# == 0 ]] || { _ig_diagnostic R40 "${i:-14}";return 2; }
 local token selected= count=0;local -a args
 read -r -a args < /proc/cmdline
 for token in "${args[@]}";do
  if [[ $token == arm16k_perl5423_vm_preboot_etc_sha256=* ]];then selected=${token#*=};count=$((count+1));fi
 done
 [[ $count == 1 ]] || { _ig_diagnostic R41 "${i:-14}";return 2; }
 _initialized_capture '' 0 "$selected"
}
initialized_guard() { [[ $# == 0 ]] && _initialized_guard; }
root_ssh_capture() { initialized_capture "$@"; }
root_ssh_guard() { initialized_guard "$@"; }
root_ssh_restore() { initialized_guard "$@"; }
cache_etc_timestamp_capture() { initialized_capture "$@"; }
cache_etc_timestamp_restore() { initialized_guard "$@"; }
