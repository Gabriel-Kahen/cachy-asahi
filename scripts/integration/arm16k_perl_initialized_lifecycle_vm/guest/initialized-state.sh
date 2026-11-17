# SPDX-License-Identifier: MIT
# Initialized-state equality only: no deletion, cache copy or timestamp repair.
root_ssh_target=/root/.ssh
initialized_paths=(etc/.pwd.lock etc/.updated etc/audisp etc/audit/plugins.d etc/audit/rules.d etc/ld.so.cache etc/os-release etc/udev/hwdb.bin etc/vconsole.conf etc etc/audit etc/udev root root/.ssh)
initialized_kinds=(f f d d d f l f f d d d d d)
initialized_modes=(600 644 755 750 755 644 777 444 644 755 755 755 700 700)
_initialized_sha() { local v;v=$(sha256sum -- "$1") || return;printf '%s' "${v%% *}"; }
_initialized_identity() { stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$1"; }
_initialized_empty() {
 local path=$1 before found
 [[ -d $path && ! -L $path ]] || return 2
 before=$(_initialized_identity "$path") || return
 # Only a fixed presence bit is captured. No child body or name is emitted.
 found=$(find -P "$path" -xdev -mindepth 1 -maxdepth 1 -printf x -quit 2>/dev/null) || return
 [[ -z $found && $(_initialized_identity "$path") == "$before" ]]
}
_initialized_view() {
 local i=$1 path=${initialized_prefix}/${initialized_paths[$1]} kind=${initialized_kinds[$1]} payload=- seconds stamp nanos before after
 before=$(_initialized_identity "$path") || return
 case "$kind" in
  f) [[ -f $path && ! -L $path ]] || return 2;payload=$(_initialized_sha "$path") || return;;
  d) [[ -d $path && ! -L $path ]] || return 2;;
  l) [[ -L $path ]] || return 2;payload=$(set -o pipefail;readlink -n -- "$path" | base64 -w0) || return;;
  *) return 2;;
 esac
 stamp=$(stat -c '%Y:%y' -- "$path") || return;seconds=${stamp%%:*};nanos=${stamp#*.};nanos=${nanos%% *}
 [[ $seconds =~ ^-?[0-9]+$ && $nanos =~ ^[0-9]{9}$ ]] || return 2
 after=$(_initialized_identity "$path") || return;[[ $before == "$after" ]] || return 2
 printf 'N %s %s %s %s %s\n' "${initialized_paths[$i]}" "$(stat -c '%i %h' -- "$path")" "$kind" "$(stat -c '%a %u %g %s' -- "$path")" "$seconds.$nanos $payload"
}
_initialized_attrs() { local value;value=$(set -o pipefail;getfattr --no-dereference --absolute-names --dump --match='.*' -- "$1" | sha256sum) || return;printf '%s' "${value%% *}"; }
_initialized_guard() {
 local i path before attrs
 [[ ${initialized_captured:-0} == 1 ]] || return 2
 [[ $(_initialized_identity "$D/initialized-state.tsv") == "$initialized_descriptor_identity" && $(_initialized_identity "$D/preboot-context.json") == "$initialized_context_identity" ]] || return 2
 _initialized_empty "$initialized_prefix/root/.ssh" || return
 for i in "${!initialized_paths[@]}";do
  path=$initialized_prefix/${initialized_paths[$i]};before=$(_initialized_identity "$path") || return
  [[ $(_initialized_view "$i") == "${initialized_expected[$i]}" ]] || return 2
  attrs=$(_initialized_attrs "$path") || return
  [[ $attrs == "${initialized_attrs[$i]}" && $(_initialized_identity "$path") == "$before" ]] || return 2
 done
 _initialized_empty "$initialized_prefix/root/.ssh"
}
_initialized_capture() {
 # Internal arguments are for ordinary temporary-filesystem controls only.
 # The public actor entry below fixes /, uid0 and the literal kernel selector.
 local prefix=$1 owner=$2 selected=$3 descriptor=$D/initialized-state.tsv context=$D/preboot-context.json line marker observed_nonce context_sha extra i path bytes=0 before attrs
 [[ ${initialized_captured:-0} == 0 ]] || { _initialized_guard;return; }
 [[ -f $descriptor && ! -L $descriptor && $(stat -c '%u:%g:%h:%a' -- "$descriptor") == "$owner:$owner:1:600" && $(stat -c '%s' -- "$descriptor") -le 8192 ]] || return 2
 [[ -f $context && ! -L $context && $(stat -c '%u:%g:%h:%a' -- "$context") == "$owner:$owner:1:644" && $(stat -c '%s' -- "$context") -le 4096 ]] || return 2
 [[ $selected =~ ^[0-9a-f]{64}$ && $(_initialized_sha "$descriptor") == "$selected" ]] || return 2
 initialized_descriptor_identity=$(_initialized_identity "$descriptor");initialized_context_identity=$(_initialized_identity "$context");initialized_prefix=$prefix
 exec {initialized_descriptor_fd}< "$descriptor" || return
 IFS= read -r line <&"$initialized_descriptor_fd" || return;bytes=$((${#line}+1));IFS=' ' read -r marker observed_nonce context_sha extra <<< "$line"
 [[ $line == "PERL5423_INITIALIZED_STATE_V1 $nonce $context_sha" && $nonce =~ ^[0-9a-f]{32}$ && $observed_nonce == "$nonce" && $context_sha =~ ^[0-9a-f]{64}$ && -z $extra && $(_initialized_sha "$context") == "$context_sha" ]] || return 2
 _initialized_empty "$prefix/root/.ssh" || return
 initialized_expected=();initialized_attrs=()
 for i in "${!initialized_paths[@]}";do
  IFS= read -r line <&"$initialized_descriptor_fd" || return;bytes=$((bytes+${#line}+1));(( bytes <= 8192 )) || return 2
  path=$prefix/${initialized_paths[$i]};before=$(_initialized_identity "$path") || return
  [[ $(stat -c '%u:%g:%a' -- "$path") == "$owner:$owner:${initialized_modes[$i]}" && $(_initialized_view "$i") == "$line" ]] || return 2
  initialized_expected[$i]=$line;attrs=$(_initialized_attrs "$path") || return;initialized_attrs[$i]=$attrs
  [[ $(_initialized_identity "$path") == "$before" ]] || return 2
 done
 if IFS= read -r extra <&"$initialized_descriptor_fd";then return 2;fi
 [[ -z $extra && $(stat -c '%s' -- "$descriptor") == "$bytes" && $(_initialized_identity "$descriptor") == "$initialized_descriptor_identity" && $(_initialized_identity "$context") == "$initialized_context_identity" ]] || return 2
 exec {initialized_descriptor_fd}<&-
 initialized_captured=1;_initialized_guard
}
initialized_capture() {
 [[ $# == 0 ]] || return 2
 local token selected= count=0;local -a args
 read -r -a args < /proc/cmdline
 for token in "${args[@]}";do
  if [[ $token == arm16k_perl5423_vm_preboot_etc_sha256=* ]];then selected=${token#*=};count=$((count+1));fi
 done
 [[ $count == 1 ]] || return 2
 _initialized_capture '' 0 "$selected"
}
initialized_guard() { [[ $# == 0 ]] && _initialized_guard; }
root_ssh_capture() { initialized_capture "$@"; }
root_ssh_guard() { initialized_guard "$@"; }
root_ssh_restore() { initialized_guard "$@"; }
cache_etc_timestamp_capture() { initialized_capture "$@"; }
cache_etc_timestamp_restore() { initialized_guard "$@"; }
