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
finish() {
 local rc=$?
 trap - EXIT
 printf '\nPERL5423_PROBE_BEGIN %s\nSTATUS=%s\n' "$nonce" "$status"
 if [[ $status == PASS ]];then
  printf 'ARCH=aarch64\nPAGESIZE=16384\nUID=1000\nGID=1000\nPERL_VERSION=5.42.3\nFUNCTIONAL=PASS\nCOMMANDS=PASS\nELF_GEOMETRY=HOST_CHECK_REQUIRED\n'
 else printf 'EXIT_STATUS=%s\n' "$rc";fi
 printf 'PERL5423_PROBE_END %s\n' "$nonce"
 exit "$rc"
}
[[ ( $# == 1 || ( $# == 2 && $2 == restored ) ) && $1 =~ ^[0-9a-f]{32}$ ]]
argument=$1
. "$D/case.sh"
case_data
[[ $argument == "$nonce" && $(id -u) == 1000 && $(id -g) == 1000 && $(id -G) == 1000 ]]
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 && $(cat /proc/1/comm) == systemd ]]
if [[ ${2:-} == restored ]]; then
 end=$((SECONDS+probe_wait_seconds))
 while [[ ! -f $O/summary.env ]];do (( SECONDS < end ));sleep 1;done
 [[ ! -L $O/summary.env && $(stat -c '%u:%g:%a' "$O/summary.env") == 0:0:644 && $(stat -c '%s' "$O/summary.env") -le 16384 ]]
 cat "$O/summary.env"
 exit 0
fi
trap finish EXIT
end=$((SECONDS+probe_wait_seconds))
while [[ ! -f $O/installed ]];do [[ ! -f $O/summary.env ]];(( SECONDS < end ));sleep 1;done
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
