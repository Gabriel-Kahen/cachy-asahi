# SPDX-License-Identifier: MIT
# One certified-absent empty directory only. Never list names or read SSH files.
root_ssh_parent=/root
root_ssh_target=$root_ssh_parent/.ssh
root_ssh_identity() { stat -c '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "$1"; }
root_ssh_parent_check() {
 [[ -d $root_ssh_parent && ! -L $root_ssh_parent && $(readlink -f -- "$root_ssh_parent") == "$root_ssh_parent" ]] || return 2
 [[ $(stat -c '%d:%i:%f:%u:%g' -- "$root_ssh_parent") == "$root_ssh_parent_identity" && $(stat -Lc '%d:%i:%f:%u:%g' -- "/proc/self/fd/$root_ssh_parent_fd") == "$root_ssh_parent_identity" ]]
}
root_ssh_empty_view() {
 local before after found attrs
 [[ -d $root_ssh_target && ! -L $root_ssh_target && $(readlink -f -- "$root_ssh_target") == "$root_ssh_target" && $(stat -c '%u:%g:%h:%a' -- "$root_ssh_target") == 0:0:2:700 ]] || return 2
 before=$(root_ssh_identity "$root_ssh_target") || return
 # Only a presence bit, no child names, metadata dumps or file bodies.
 found=$(find -P "$root_ssh_target" -xdev -mindepth 1 -maxdepth 1 -printf x -quit) || return
 [[ -z $found ]] || return 2
 attrs=$(getfattr --no-dereference --absolute-names --dump --match='.*' -- "$root_ssh_target" | sha256sum) || return
 after=$(root_ssh_identity "$root_ssh_target") || return
 [[ $before == "$after" && -d $root_ssh_target && ! -L $root_ssh_target ]] || return 2
 printf '%s|%s' "$before" "${attrs%% *}"
}
root_ssh_guard() {
 local view present=0
 root_ssh_parent_check || return
 if [[ -e $root_ssh_target || -L $root_ssh_target ]];then
  present=1;view=$(root_ssh_empty_view) || return
  if [[ $root_ssh_initial_present == 1 ]];then
   [[ $view == "$root_ssh_initial_view" && $(stat -Lc '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "/proc/self/fd/$root_ssh_child_fd") == "$root_ssh_initial_identity" ]] || return 2
  fi
 else
  [[ $root_ssh_initial_present == 0 ]] || return 2
 fi
 [[ $(stat -Lc '%h' -- "/proc/self/fd/$root_ssh_parent_fd") == "$((root_ssh_certified_links+present))" ]]
}
root_ssh_capture() {
 local descriptor=$D/root-ssh-preboot.tsv context=$D/preboot-context.json token selected= count=0 line marker observed_nonce context_sha extra inode links seconds nanos bytes=0 reference=$D/cache/root-ssh-parent.reference view attrs
 local -a args
 [[ -f $descriptor && ! -L $descriptor && $(stat -c '%u:%g:%h:%a' -- "$descriptor") == 0:0:1:600 && $(stat -c '%s' -- "$descriptor") -le 1024 ]]
 [[ -f $context && ! -L $context && $(stat -c '%u:%g:%h:%a' -- "$context") == 0:0:1:644 && $(stat -c '%s' -- "$context") -le 4096 ]]
 root_ssh_descriptor_identity=$(root_ssh_identity "$descriptor");root_ssh_context_identity=$(root_ssh_identity "$context")
 read -r -a args < /proc/cmdline
 for token in "${args[@]}";do
  if [[ $token == arm16k_perl5423_vm_root_ssh_sha256=* ]];then selected=${token#*=};count=$((count+1));fi
 done
 [[ $count == 1 && $selected =~ ^[0-9a-f]{64}$ && $(file_sha "$descriptor") == "$selected" ]]
 exec {root_ssh_descriptor_fd}< "$descriptor"
 IFS= read -r line <&"$root_ssh_descriptor_fd";bytes=$((${#line}+1))
 IFS=' ' read -r marker observed_nonce context_sha extra <<< "$line"
 [[ $line == "PERL5423_ROOT_SSH_PREBOOT_V1 $nonce $context_sha" && $observed_nonce == "$nonce" && $context_sha =~ ^[0-9a-f]{64}$ && -z $extra && $(file_sha "$context") == "$context_sha" ]]
 IFS= read -r line <&"$root_ssh_descriptor_fd";bytes=$((bytes+${#line}+1))
 # Fixed parent only; no arbitrary path operands.
 IFS=' ' read -r inode links seconds nanos extra <<< "${line#P root }"
 [[ $line == "P root $inode $links $seconds $nanos" && -z $extra ]]
 [[ $inode =~ ^[1-9][0-9]{0,9}$ && $links =~ ^[1-9][0-9]{0,4}$ && $seconds =~ ^(0|[1-9][0-9]{0,9})$ && $nanos =~ ^(0|[1-9][0-9]{0,8})$ ]]
 (( inode <= 4294967295 && links >= 2 && links <= 65535 && seconds <= 8589934591 && nanos <= 999999999 ))
 root_ssh_certified_inode=$inode;root_ssh_certified_links=$links;root_ssh_seconds=$seconds;root_ssh_nanos=$nanos
 IFS= read -r line <&"$root_ssh_descriptor_fd";bytes=$((bytes+${#line}+1))
 [[ $line == 'A root/.ssh d 700 0' ]]
 if IFS= read -r extra <&"$root_ssh_descriptor_fd";then return 2;fi
 [[ -z $extra && $(stat -c '%s' -- "$descriptor") == "$bytes" ]]
 exec {root_ssh_descriptor_fd}<&-
 [[ $(root_ssh_identity "$descriptor") == "$root_ssh_descriptor_identity" && $(root_ssh_identity "$context") == "$root_ssh_context_identity" ]]
 [[ -d $root_ssh_parent && ! -L $root_ssh_parent && $(readlink -f -- "$root_ssh_parent") == "$root_ssh_parent" && $(stat -c '%i:%u:%g:%a' -- "$root_ssh_parent") == "$inode:0:0:700" ]]
 exec {root_ssh_parent_fd}< "$root_ssh_parent"
 [[ $(stat -Lc '%i:%u:%g:%a:%F' -- "/proc/self/fd/$root_ssh_parent_fd") == "$inode:0:0:700:directory" ]]
 root_ssh_parent_identity=$(stat -Lc '%d:%i:%f:%u:%g' -- "/proc/self/fd/$root_ssh_parent_fd")
 root_ssh_parent_check
 attrs=$(getfattr --no-dereference --absolute-names --dump --match='.*' -- "$root_ssh_parent" | sha256sum);root_ssh_parent_attrs=${attrs%% *}
 root_ssh_initial_present=0
 if [[ -e $root_ssh_target || -L $root_ssh_target ]];then
  view=$(root_ssh_empty_view);root_ssh_initial_view=$view;root_ssh_initial_identity=$(root_ssh_identity "$root_ssh_target")
  exec {root_ssh_child_fd}< "$root_ssh_target"
  [[ $(stat -Lc '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "/proc/self/fd/$root_ssh_child_fd") == "$root_ssh_initial_identity" ]]
  root_ssh_initial_present=1
 fi
 root_ssh_guard
 [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c '%u:%g:%a' -- "$D/cache") == 0:0:700 && ! -e $reference && ! -L $reference ]]
 (set -o noclobber;: > "$reference")
 [[ -f $reference && ! -L $reference && $(stat -c '%u:%g:%h:%a:%s' -- "$reference") == 0:0:1:600:0 ]]
 touch -m --date="@$seconds.$(printf '%09d' "$nanos")" -- "$reference"
 [[ $(date -u -r "$reference" +%s.%N) == "$seconds.$(printf '%09d' "$nanos")" ]]
 root_ssh_reference_identity=$(root_ssh_identity "$reference")
}
root_ssh_restore() {
 local descriptor=$D/root-ssh-preboot.tsv context=$D/preboot-context.json reference=$D/cache/root-ssh-parent.reference view before after attrs atime
 [[ -f $descriptor && ! -L $descriptor && $(root_ssh_identity "$descriptor") == "$root_ssh_descriptor_identity" && -f $context && ! -L $context && $(root_ssh_identity "$context") == "$root_ssh_context_identity" ]]
 [[ -d $D/cache && ! -L $D/cache && $(readlink -f -- "$D/cache") == "$D/cache" && $(stat -c '%u:%g:%a' -- "$D/cache") == 0:0:700 && -f $reference && ! -L $reference && $(root_ssh_identity "$reference") == "$root_ssh_reference_identity" ]]
 root_ssh_guard
 attrs=$(getfattr --no-dereference --absolute-names --dump --match='.*' -- "$root_ssh_parent" | sha256sum)
 [[ ${attrs%% *} == "$root_ssh_parent_attrs" ]]
 if [[ -e $root_ssh_target || -L $root_ssh_target ]];then
  view=$(root_ssh_empty_view);before=$(root_ssh_identity "$root_ssh_target")
  if [[ $root_ssh_initial_present == 1 ]];then
   [[ $view == "$root_ssh_initial_view" && $before == "$root_ssh_initial_identity" ]]
  else
   # The exact certified-absent path may be created late; still only empty root0700.
   exec {root_ssh_child_fd}< "$root_ssh_target"
  fi
  [[ $(stat -Lc '%d:%i:%f:%u:%g:%h:%s:%y:%z' -- "/proc/self/fd/$root_ssh_child_fd") == "$before" && $(root_ssh_empty_view) == "$view" ]]
  root_ssh_parent_check
  [[ $(root_ssh_identity "/proc/self/fd/$root_ssh_parent_fd/.ssh") == "$before" ]]
  rmdir -- "/proc/self/fd/$root_ssh_parent_fd/.ssh"
  [[ $(stat -Lc '%h' -- "/proc/self/fd/$root_ssh_child_fd") == 0 && ! -e $root_ssh_target && ! -L $root_ssh_target ]]
  exec {root_ssh_child_fd}<&-
 fi
 root_ssh_parent_check
 [[ ! -e $root_ssh_target && ! -L $root_ssh_target && $(stat -Lc '%h' -- "/proc/self/fd/$root_ssh_parent_fd") == "$root_ssh_certified_links" && $(root_ssh_identity "$reference") == "$root_ssh_reference_identity" ]]
 atime=$(stat -Lc '%x' -- "/proc/self/fd/$root_ssh_parent_fd")
 touch -m --reference="$reference" -- "/proc/self/fd/$root_ssh_parent_fd"
 [[ $(stat -Lc '%x' -- "/proc/self/fd/$root_ssh_parent_fd") == "$atime" && $(stat -Lc '%y' -- "/proc/self/fd/$root_ssh_parent_fd") == "$(stat -c '%y' -- "$reference")" ]]
 root_ssh_parent_check
 [[ ! -e $root_ssh_target && ! -L $root_ssh_target && $(stat -Lc '%h' -- "/proc/self/fd/$root_ssh_parent_fd") == "$root_ssh_certified_links" ]]
 [[ $(root_ssh_identity "$reference") == "$root_ssh_reference_identity" ]]
 rm -- "$reference";[[ ! -e $reference && ! -L $reference ]]
 exec {root_ssh_parent_fd}<&-
}
