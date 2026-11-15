#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Entered solely through the ordinary builder PAM login; never runuser/su.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
D=/var/lib/arm16k-llvm23-vm
O=/run/arm16k-llvm23-vm
P=/opt/cachy-asahi/llvm23-source-reference
U=$O/user
status=HOLD
nonce=INVALID
finish() {
 local rc=$?
 trap - EXIT
 printf '\nLLVM23_PROBE_BEGIN %s\nSTATUS=%s\nARCH=aarch64\nPAGESIZE=16384\nUID=1000\nGID=1000\nPREFIX=%s\nCLANG_VERSION=23.1.1\nTRIPLE=aarch64-unknown-linux-gnu\nC_STDOUT=LLVM23_C_OK\nCXX_STDOUT=LLVM23_UNWIND_OK\nELF_GEOMETRY=HOST_CHECK_REQUIRED\nLLVM23_PROBE_END %s\n' "$nonce" "$status" "$P" "$nonce"
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
printf 'LLVM23_INSTALLED_BEGIN %s\nSTATUS=PASS\nPACKAGE=cachy-asahi-llvm23-source-reference\nVERSION=23.1.1-1\nLLVM23_INSTALLED_END %s\n' "$nonce" "$nonce"
[[ ! -e $U/PROBED && ! -L $U/PROBED ]]
clock_valid
verify_paths
cd "$U"
inventory > before.lock
cmp -- "$D/expected-installed.lock" before.lock
bounded "$run_seconds" clang-version.log "$P/bin/clang" --version
bounded "$run_seconds" clangxx-version.log "$P/bin/clang++" --version
grep -Eq '^(clang|.* clang) version 23\.1\.1([[:space:]]|$)' clang-version.log
grep -Eq '^(clang|.* clang) version 23\.1\.1([[:space:]]|$)' clangxx-version.log
bounded "$run_seconds" triple.log "$P/bin/clang" -dumpmachine
printf 'aarch64-unknown-linux-gnu\n' | cmp -- - triple.log
bounded "$run_seconds" config-version.log "$P/bin/llvm-config" --version
printf '23.1.1\n' | cmp -- - config-version.log
bounded "$compile_seconds" c-build.log "$P/bin/clang" "$D/smoke.c" -fuse-ld=lld --rtlib=compiler-rt -Wl,-z,max-page-size=16384 -o "$U/smoke"
bounded "$run_seconds" c-run.log "$U/smoke"
printf 'LLVM23_C_OK\n' | cmp -- - c-run.log
bounded "$compile_seconds" cxx-build.log "$P/bin/clang++" "$D/unwind.cpp" -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -L"$P/lib" -Wl,-rpath,"$P/lib" -Wl,-z,max-page-size=16384 -o "$U/unwind"
bounded "$run_seconds" cxx-run.log "$U/unwind"
printf 'LLVM23_UNWIND_OK\n' | cmp -- - cxx-run.log
inventory > after.lock
cmp -- before.lock after.lock
verify_paths
clock_valid
sha256sum -- smoke unwind > outputs.sha256
bounded "$sync_seconds" sync.log sync -f "$U"
# This marker reports completed ordinary-user probes, not Root restoration or
# ELF16K acceptance. Root checks the retained files; the host parses their ELF.
( set -o noclobber;printf '%s\n' "$nonce" > PROBED )
status=PASS
