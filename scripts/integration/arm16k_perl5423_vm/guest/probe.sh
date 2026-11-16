#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Entered solely through the ordinary builder PAM login; never runuser/su.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
D=/var/lib/arm16k-perl5423-vm
O=/run/arm16k-perl5423-vm
U=$O/user
status=HOLD
nonce=INVALID
failure_phase=probe_checks
summary_relayed=0
summary_state=ABSENT

# A Root summary is DATA, never shell input. Root publishes by chmod644 only
# after its complete copy. Keep unpublished600 files pending within this wait.
read_root_summary() {
 local path=$O/summary.env before after mode bytes hash again rendered line key value i
 local -A seen=()
 summary_lines=();summary_state=INVALID
 if [[ ! -e $O && ! -L $O ]];then summary_state=ABSENT;return 1;fi
 [[ -d $O && ! -L $O && $(stat -c '%u:%g:%a' -- "$O") == 0:0:755 ]] || return 2
 if [[ ! -e $path && ! -L $path ]];then summary_state=ABSENT;return 1;fi
 [[ -f $path && ! -L $path ]] || return 2
 before=$(stat -c '%u:%g:%h:%a:%s:%d:%i:%y:%z' -- "$path") || return 2
 [[ ${#before} -le 256 && $before =~ ^0:0:1:(600|644):([0-9]+):[0-9]+:[0-9]+:.+$ ]] || return 2
 mode=${BASH_REMATCH[1]};bytes=${BASH_REMATCH[2]}
 (( bytes <= 16384 )) || return 2
 if [[ $mode == 600 ]];then summary_state=UNPUBLISHED;return 1;fi
 (( bytes > 0 )) || return 2
 hash=$(head -c 16385 -- "$path" | sha256sum) || return 2
 mapfile -t -n 67 summary_lines < <(head -c 16385 -- "$path")
 (( ${#summary_lines[@]} >= 3 && ${#summary_lines[@]} <= 66 )) || return 2
 [[ ${summary_lines[0]} == "PERL5423_RESTORED_BEGIN $nonce" && ${summary_lines[-1]} == "PERL5423_RESTORED_END $nonce" ]] || return 2
 for (( i=1;i<${#summary_lines[@]}-1;i++ ));do
  line=${summary_lines[i]};[[ ${#line} -le 321 && $line == *=* ]] || return 2
  key=${line%%=*};value=${line#*=}
  [[ $key =~ ^[A-Z][A-Z0-9_]{0,63}$ && $value =~ ^[\ -~]{1,256}$ ]] || return 2
  [[ ! ${seen[$key]+yes} ]] || return 2
  seen[$key]=1
 done
 case ${summary_lines[1]} in
  STATUS=HOLD)
   (( ${#summary_lines[@]} == 5 )) || return 2
   [[ ${summary_lines[2]} =~ ^FAILED_PHASE=[a-z_]{1,64}$ && ${summary_lines[3]} =~ ^EXIT_STATUS=([1-9][0-9]{0,2})$ ]] || return 2
   (( BASH_REMATCH[1] <= 255 )) || return 2
   summary_state=HOLD;;
  STATUS=PASS) summary_state=PASS;;
  *) return 2;;
 esac
 rendered=$(printf '%s\n' "${summary_lines[@]}" | sha256sum) || return 2
 again=$(head -c 16385 -- "$path" | sha256sum) || return 2
 after=$(stat -c '%u:%g:%h:%a:%s:%d:%i:%y:%z' -- "$path") || return 2
 [[ $before == "$after" && $hash == "$again" && $hash == "$rendered" ]] || { summary_state=INVALID;return 2; }
}
relay_root_summary() {
 [[ $summary_relayed == 0 && ( $summary_state == HOLD || $summary_state == PASS ) ]] || return 2
 summary_relayed=1
 printf '\n' || return
 printf '%s\n' "${summary_lines[@]}"
}
# Report only an observed last checkpoint, outside all PASS/HOLD frames. Never
# infer failure cause from it; missing/unsafe/changing metadata is ignored.
relay_last_root_phase() {
 local path=$D/root-phase.checkpoint before after bytes line name first second rendered
 [[ -d $D && ! -L $D && $(stat -c '%u:%g:%a' -- "$D") == 0:0:755 && -f $path && ! -L $path ]] || return 1
 before=$(stat -c '%u:%g:%h:%a:%s:%d:%i:%y:%z' -- "$path") || return 1
 [[ ${#before} -le 256 && $before =~ ^0:0:1:644:([0-9]+):[0-9]+:[0-9]+:.+$ ]] || return 1
 bytes=${BASH_REMATCH[1]};(( bytes > 0 && bytes <= 128 )) || return 1
 first=$(head -c 129 -- "$path" | sha256sum) || return 1
 line=$(head -c 129 -- "$path") || return 1
 name=${line##* }
 case "$name" in guard|rtc_clock|users|baseline|trust|dependency_install|official_trust|install|installed_payload|installed_metadata|probe_wait|retain_outputs|recovery|cache_restoration|restoration) :;;*) return 1;;esac
 [[ $nonce =~ ^[0-9a-f]{32}$ && $line == "PERL5423_ROOT_PHASE_V1 $nonce $name" && $bytes == $((${#line}+1)) ]] || return 1
 rendered=$(printf '%s\n' "$line" | sha256sum) || return 1
 second=$(head -c 129 -- "$path" | sha256sum) || return 1
 after=$(stat -c '%u:%g:%h:%a:%s:%d:%i:%y:%z' -- "$path") || return 1
 [[ $before == "$after" && $first == "$second" && $first == "$rendered" ]] || return 1
 printf '\nPERL5423_LAST_ROOT_PHASE %s %s\n' "$nonce" "$name"
}
wait_for_case() {
 local kind=$1 end=$((SECONDS+probe_wait_seconds)) rc
 [[ $kind == installed || $kind == restored ]] || return 2
 while :;do
  if read_root_summary;then
   if [[ $summary_state == HOLD ]];then relay_root_summary || return 2;return 1;fi
   if [[ $kind == restored ]];then relay_root_summary;return;fi
   failure_phase=root_summary_unexpected_pass;return 1
  else
   rc=$?;if (( rc != 1 ));then failure_phase=root_summary_invalid;summary_state=INVALID;return 1;fi
  fi
  if [[ $kind == installed && $summary_state == ABSENT && -f $O/installed ]];then return 0;fi
  if (( SECONDS >= end ));then
   if [[ $kind == installed ]];then failure_phase=install_ready_timeout;else failure_phase=restoration_ready_timeout;fi
   relay_last_root_phase || :
   return 1
  fi
  sleep 1 || return
 done
}
finish() {
 local rc=$?
 trap - EXIT
 if [[ ${summary_relayed:-0} == 1 ]];then exit "$rc";fi
 printf '\nPERL5423_PROBE_BEGIN %s\nSTATUS=%s\n' "$nonce" "$status"
 if [[ $status == PASS ]];then
  printf 'ARCH=aarch64\nPAGESIZE=16384\nUID=1000\nGID=1000\nPERL_VERSION=5.42.3\nFUNCTIONAL=PASS\nCOMMANDS=PASS\nELF_GEOMETRY=HOST_CHECK_REQUIRED\n'
 else printf 'FAILURE_SOURCE=PROBE\nFAILED_PHASE=%s\nROOT_SUMMARY_STATE=%s\nEXIT_STATUS=%s\n' "${failure_phase:-probe_checks}" "${summary_state:-ABSENT}" "$rc";fi
 printf 'PERL5423_PROBE_END %s\n' "$nonce"
 exit "$rc"
}
[[ ( $# == 1 || ( $# == 2 && $2 == restored ) ) && $1 =~ ^[0-9a-f]{32}$ ]]
argument=$1
. "$D/case.sh"
case_data
[[ $argument == "$nonce" && $(id -u) == 1000 && $(id -g) == 1000 && $(id -G) == 1000 ]]
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
trap finish EXIT
if [[ ${2:-} == restored ]]; then
 failure_phase=restoration_ready_wait
 wait_for_case restored
 exit 0
fi
failure_phase=install_ready_wait
wait_for_case installed
failure_phase=probe_checks
[[ -f $O/installed && ! -L $O/installed && $(cat "$O/installed") == "$nonce" ]]
[[ $(stat -c '%u:%g:%a' "$O/installed") == 0:0:644 ]]
[[ $(stat -c '%s' "$O/installed") == 33 ]]
[[ -d $U && ! -L $U && $(stat -c '%u:%g:%a' "$U") == 1000:1000:700 ]]
printf 'PERL5423_INSTALLED_BEGIN %s\nSTATUS=PASS\nPACKAGE=perl\nVERSION=5.42.3-1.3\nPERL5423_INSTALLED_END %s\n' "$nonce" "$nonce"
[[ ! -e $U/PROBED && ! -L $U/PROBED ]]
clock_valid
verify_paths
cd "$U"
inventory > before.lock
same_bytes "$D/expected-installed.lock" before.lock
bounded "$run_seconds" version.log /usr/bin/perl -e 'print "$^V\n"'
printf 'v5.42.3\n' > expected-version; same_bytes expected-version version.log
bounded "$run_seconds" functional.log /usr/bin/perl "$D/runtime.pl"
printf 'PERL5423_FUNCTIONAL_OK\nDB_FILE=ROUNDTRIP\nGDBM=ROUNDTRIP\nZLIB=ROUNDTRIP\nBZIP2=ROUNDTRIP\nTHREADS=JOIN_SHARED\nLIBPERL=SHARED\n' > expected-functional; same_bytes expected-functional functional.log
bounded "$run_seconds" corelist.log /usr/bin/corelist -v 5.42.3
grep -F '5.42.3' corelist.log
printf '{"answer":42}\n' > input.json
bounded "$run_seconds" json.log /usr/bin/json_pp -json_opt canonical < input.json
grep -Eq '"answer"[[:space:]]*:[[:space:]]*42' json.log
bounded "$run_seconds" perldoc.log /usr/bin/perldoc -T -t -f print
grep -F 'print' perldoc.log
printf '=head1 NAME\n\nsample - candidate document\n\n=cut\n' > sample.pod
bounded "$run_seconds" podtext.log /usr/bin/pod2text sample.pod
grep -F 'candidate document' podtext.log
bounded "$run_seconds" podcheck.log /usr/bin/podchecker sample.pod
grep -F 'pod syntax OK' podcheck.log
bounded "$run_seconds" prove.log /usr/bin/prove "$D/smoke.t"
grep -F 'Result: PASS' prove.log
printf 'abc' > digest-input
bounded "$run_seconds" sha.log /usr/bin/shasum -a 256 digest-input
printf 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  digest-input\n' > expected-sha; same_bytes expected-sha sha.log
printf 'Use of uninitialized value $x in print at runtime.pl line 1.\n' > diagnostic
bounded "$run_seconds" splain.log /usr/bin/splain < diagnostic
grep -F 'undefined value' splain.log
bounded "$run_seconds" paths.log /usr/bin/perl -MConfig -e 'print "$Config{archlib}/CORE/$Config{libperl}\n"'
printf '/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n' > expected-paths; same_bytes expected-paths paths.log
inventory > after.lock
same_bytes before.lock after.lock
verify_paths
clock_valid
sha256sum -- *.log > probe-outputs.sha256
bounded "$sync_seconds" sync.log sync -f "$U"
# This marker reports completed ordinary-user probes, not Root restoration or
# ELF16K acceptance. Root checks the retained files; the host parses their ELF.
( set -o noclobber;printf '%s\n' "$nonce" > PROBED )
status=PASS
