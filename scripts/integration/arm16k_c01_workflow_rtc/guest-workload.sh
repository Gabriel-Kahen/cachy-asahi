#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# UID1000 only. Fixed installed programs and bounded, pre-generated ordinary DATA.
set -Eeuo pipefail
umask 077
export PATH=/usr/bin LANG=C LC_ALL=C
D=/var/lib/arm16k-project-lifecycle
. "$D/guest-runtime.sh"
[[ $# == 0 && $(id -u) == 1000 && $(id -g) == 1000 && $(id -G) == 1000 ]]
[[ $(uname -m) == aarch64 && $(getconf PAGESIZE) == 16384 ]]
work=$(mktemp -d /tmp/c01-workload.XXXXXXXX)
cleanup() { [[ $work == /tmp/c01-workload.* && -d $work && ! -L $work && $(stat -c %u "$work") == 1000 ]] && rm -rf -- "$work"; }
finish() { local rc=$?;trap - EXIT;if ! cleanup;then rc=1;fi;exit "$rc"; }
trap finish EXIT
encodes=0;cross=0;independent=0;rejects=0
for variant in baseline lto;do
 root=/usr/lib/cachy-asahi/experiments/zlib-$variant
 timeout --signal=TERM --kill-after=1s 15 "$root/bin/probe" --installed-check > "$work/probe"
 same_bytes "$D/probe-$variant.json" "$work/probe"
 for i in 0 1 2 3 4 5 6;do
  for level in 1 6 9;do
   timeout --signal=TERM --kill-after=1s 15 "$root/bin/minigzip" "-$level" < "$D/corpus-$i" > "$work/packed"
   encodes=$((encodes+1))
   timeout --signal=TERM --kill-after=1s 15 /usr/bin/gzip -dc < "$work/packed" > "$work/decoded"
   same_bytes "$D/corpus-$i" "$work/decoded";independent=$((independent+1))
   for consumer in baseline lto;do
    timeout --signal=TERM --kill-after=1s 15 /usr/lib/cachy-asahi/experiments/zlib-$consumer/bin/strict-gzip < "$work/packed" > "$work/decoded"
    same_bytes "$D/corpus-$i" "$work/decoded";cross=$((cross+1))
   done
  done
 done
 for i in 0 1 2;do
  rc=0
  timeout --signal=TERM --kill-after=1s 15 "$root/bin/strict-gzip" < "$D/invalid-$i" > "$work/rejected" 2> "$work/stderr" || rc=$?
  [[ $rc == 2 ]]
  same_bytes "$D/corpus-2" "$work/rejected"
  [[ $(cat "$work/stderr") == 'strict gzip: incomplete or invalid single gzip member' ]]
  rejects=$((rejects+1))
 done
done
[[ $encodes == 42 && $cross == 84 && $independent == 42 && $rejects == 6 ]]
printf 'WORKLOAD_UID=1000\nPROBES=2\nENCODES=42\nCROSS_DECODES=84\nINDEPENDENT_DECODES=42\nSTRICT_REJECTIONS=6\n'
