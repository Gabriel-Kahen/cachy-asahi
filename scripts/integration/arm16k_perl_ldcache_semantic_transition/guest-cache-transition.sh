# SPDX-License-Identifier: MIT
# Finite DB53 installed/restored cache bytes; no repair, deletion or timestamp reset.
# The constructor replaces this token with the hash of its independently derived TSV.
_initialized_cache_manifest() {
 local p=$D/expected-cache-transition.tsv line tag key size hash extra before
 [[ -f $p && ! -L $p && $(stat -c '%u:%g:%h:%a:%s' -- "$p") =~ ^0:0:1:644:[0-9]+$ && $(stat -c '%s' -- "$p") -le 512 ]] || return 2
 before=$(_initialized_identity "$p") || return
 [[ $(_initialized_sha "$p") == '@CACHE_TRANSITION_MANIFEST_SHA256@' ]] || return 2
 mapfile -t initialized_cache_manifest < "$p"
 [[ ${#initialized_cache_manifest[@]} == 4 && ${initialized_cache_manifest[0]} == PERL5423_DB53_CACHE_TRANSITION_V1 ]] || return 2
 initialized_cache_sizes=();initialized_cache_hashes=()
 for tag in BASELINE INSTALLED RESTORED;do
  case "$tag" in BASELINE) line=${initialized_cache_manifest[1]};;INSTALLED) line=${initialized_cache_manifest[2]};;RESTORED) line=${initialized_cache_manifest[3]};;esac
  IFS=' ' read -r key size hash extra <<< "$line"
  [[ $key == "$tag" && $size =~ ^[1-9][0-9]{0,6}$ && $hash =~ ^[0-9a-f]{64}$ && -z $extra && $line == "$tag $size $hash" ]] || return 2
  (( 10#$size <= 1048576 )) || return 2
  initialized_cache_sizes+=("$size");initialized_cache_hashes+=("$hash")
 done
 [[ ${initialized_cache_sizes[0]} == 17551 && ${initialized_cache_sizes[2]} == 17551 && ${initialized_cache_hashes[0]} == 0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215 && ${initialized_cache_hashes[2]} == "${initialized_cache_hashes[0]}" && $(_initialized_identity "$p") == "$before" ]] || return 2
 initialized_cache_manifest_identity=$before
}
_initialized_cache_clock() {
 local value;value=$(date +%s%N) || return
 [[ $value =~ ^[1-9][0-9]{18}$ ]] || return 2
 printf '%s' "$value"
}
initialized_cache_transaction_begin() {
 [[ $# == 0 && ${dependency_mode:-} == DB53 && ${initialized_captured:-0} == 1 && -z ${initialized_cache_phase:-} ]] || return 2
 _initialized_guard || return
 _initialized_cache_manifest || return
 initialized_cache_started_ns=$(_initialized_cache_clock) || return
 initialized_cache_phase=BASELINE
}
_initialized_cache_phase_view() {
 local i=$1 current=$2 expected=$3 n now seconds nanos time_ns index
 local -a a b
 [[ $i == 5 || $i == 9 ]] || return 2
 [[ ${initialized_cache_phase:-} == INSTALLED || ${initialized_cache_phase:-} == RESTORED ]] || return 2
 [[ $(_initialized_identity "$D/expected-cache-transition.tsv") == "$initialized_cache_manifest_identity" ]] || return 2
 IFS=' ' read -r -a a <<< "$expected";IFS=' ' read -r -a b <<< "$current"
 [[ ${#a[@]} == 11 && ${#b[@]} == 11 && ${b[0]} == N && ${b[1]} == "${initialized_paths[$i]}" ]] || return 2
 for n in 2 3 5 6 7 8;do [[ ${a[$n]} =~ ^[0-9]{1,10}$ && ${b[$n]} =~ ^[0-9]{1,10}$ ]] || return 2;done
 # Stable directory identity and all typed fields; only public parent mtime varies.
 if [[ $i == 9 ]];then
  for n in 0 1 2 3 4 5 6 7 8 10;do [[ ${a[$n]} == "${b[$n]}" ]] || return 2;done
  [[ ${b[4]} == d && ${b[5]} == 755 && ${b[6]} == 0 && ${b[7]} == 0 && ${b[10]} == - ]] || return 2
 else
  (( 10#${b[2]} > 0 && 10#${b[2]} <= 4294967295 )) || return 2
  [[ ${b[4]} == f && ${b[3]} == 1 && ${b[5]} == 644 && ${b[6]} == 0 && ${b[7]} == 0 ]] || return 2
  case "$initialized_cache_phase" in INSTALLED) index=1;;RESTORED) index=2;;*) return 2;;esac
  [[ ${b[8]} == "${initialized_cache_sizes[$index]}" && ${b[10]} == "${initialized_cache_hashes[$index]}" ]] || return 2
 fi
 [[ ${b[9]} =~ ^([1-9][0-9]{0,9})[.]([0-9]{9})$ ]] || return 2
 seconds=${BASH_REMATCH[1]};nanos=${BASH_REMATCH[2]};time_ns=$((10#$seconds*1000000000+10#$nanos))
 now=$(_initialized_cache_clock) || return
 (( now >= initialized_cache_started_ns && now-initialized_cache_started_ns <= 1500000000000 && time_ns >= initialized_cache_started_ns && time_ns <= now )) || return 2
}
initialized_cache_transaction_installed() {
 [[ $# == 0 && ${initialized_cache_phase:-} == BASELINE ]] || return 2
 initialized_cache_phase=INSTALLED;_initialized_guard
}
initialized_cache_transaction_restored() {
 [[ $# == 0 && ${initialized_cache_phase:-} == INSTALLED ]] || return 2
 initialized_cache_phase=RESTORED;_initialized_guard
}
