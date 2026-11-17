# SPDX-License-Identifier: MIT
# Fixed public facts only; no predicate suppression or repair.
_cr_emit() { { builtin printf '%s\n' "${1:-}" >> /dev/ttyAMA0; } 2>/dev/null || :;return 0; }
_cr_mark() {
 case "${1:-}" in BASELINE_CAPTURED|RESTORED_ENTER|RESTORED_DONE|GUARD_ENTER|GUARD_DONE|SNAPSHOT_ENTER|SNAPSHOT_DONE|COMPARE_ENTER|COMPARE_DONE) _cr_emit "PERL5423_CACHE_RESTORE_SUBSTAGE_V1 STAGE=$1";;esac
 return 0
}
_cr_public() {
 local when=${1:-} phase label path fields before after sha attrs header mode uid gid inode links size extra stable type
 case "$when" in BASELINE|RESTORED) :;;*) return 0;;esac
 case ${initialized_cache_phase:-} in BASELINE|INSTALLED|RESTORED) phase=$initialized_cache_phase;;'') phase=UNSET;;*) phase=UNKNOWN;;esac
 _cr_emit "PERL5423_CACHE_RESTORE_STATE_V1 WHEN=$when PHASE=$phase"
 # Never follow a replaced public directory into an unreviewed namespace.
 for path in /etc /var /var/cache /var/cache/ldconfig;do
  if [[ -L $path ]];then _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when STATUS=ALIASED_PARENT";return 0;fi
 done
 for label in MAIN AUXDIR AUXFILE;do
  case "$label" in MAIN) path=/etc/ld.so.cache;;AUXDIR) path=/var/cache/ldconfig;;AUXFILE) path=/var/cache/ldconfig/aux-cache;;esac
  if [[ ! -e $path && ! -L $path ]];then _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when NODE=$label TYPE=ABSENT";continue;fi
  if [[ -L $path ]];then _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when NODE=$label TYPE=SYMLINK_UNREAD";continue;fi
  if ! fields=$(stat -c '%a %u %g %i %h %s' -- "$path" 2>/dev/null);then _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when NODE=$label TYPE=STAT_UNOBSERVED";continue;fi
  IFS=' ' read -r mode uid gid inode links size extra <<< "$fields"
  if [[ -n $extra || ! $fields =~ ^[0-7]{3,4}[[:space:]][0-9]+[[:space:]][0-9]+[[:space:]][0-9]+[[:space:]][0-9]+[[:space:]][0-9]+$ || ${#size} -gt 10 ]];then _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when NODE=$label TYPE=METADATA_UNOBSERVED";continue;fi
  before=$(stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' -- "$path" 2>/dev/null) || before=UNOBSERVED
  sha=UNOBSERVED;attrs=UNOBSERVED;header=UNOBSERVED
  if [[ -f $path ]] && (( 10#$size <= 1048576 ));then
   if sha=$(sha256sum -- "$path" 2>/dev/null);then sha=${sha%% *};else sha=UNOBSERVED;fi
   if [[ $label == AUXFILE ]]&&(( 10#$size >= 32 ));then
    if header=$(od -An -tx1 -N32 -- "$path" 2>/dev/null);then header=${header//[[:space:]]/};[[ $header =~ ^[0-9a-f]{64}$ ]]||header=UNOBSERVED;else header=UNOBSERVED;fi
   fi
  fi
  if attrs=$(set -o pipefail;getfattr --no-dereference --absolute-names --dump --match='.*' -- "$path" 2>/dev/null | sha256sum);then attrs=${attrs%% *};else attrs=UNOBSERVED;fi
  [[ $sha =~ ^[0-9a-f]{64}$ ]]||sha=UNOBSERVED;[[ $attrs =~ ^[0-9a-f]{64}$ ]]||attrs=UNOBSERVED
  after=$(stat -c '%d:%i:%f:%u:%g:%h:%s:%Y:%Z' -- "$path" 2>/dev/null) || after=UNOBSERVED
  stable=0;[[ $before != UNOBSERVED && $before == "$after" ]]&&stable=1
  if [[ -f $path ]];then type=FILE;elif [[ -d $path ]];then type=DIRECTORY;else type=OTHER;fi
  _cr_emit "PERL5423_CACHE_RESTORE_PUBLIC_V1 WHEN=$when NODE=$label TYPE=$type MODE=$mode UID=$uid GID=$gid INODE=$inode LINKS=$links SIZE=$size SHA=$sha XATTR_STREAM_SHA=$attrs STABLE=$stable AUX_HEADER_HEX=$header"
 done
 return 0
}
