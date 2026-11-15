#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Isolated local synthetic DATA only. Never invokes GPG, ALPM, VM or network.
set -Eeuo pipefail
export PATH=/usr/bin:/bin LC_ALL=C
HERE=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)
. "$HERE/guest/case.sh"
. "$HERE/guest/official-trust.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
printf '\0\377\nA\0B' > "$scratch/binary-a"
printf '\0\377\nA\0B' > "$scratch/binary-b"
printf '\0\377\nA\0C' > "$scratch/binary-c"
: > "$scratch/empty-a";: > "$scratch/empty-b"
same_bytes "$scratch/binary-a" "$scratch/binary-b"
same_bytes "$scratch/empty-a" "$scratch/empty-b"
! same_bytes "$scratch/binary-a" "$scratch/binary-c"
! same_bytes "$scratch/empty-a" "$scratch/binary-a"
! same_bytes "$scratch/missing" "$scratch/binary-a"
ln -s binary-a "$scratch/alias"
! same_bytes "$scratch/alias" "$scratch/binary-a"
# Command errors must not collapse to equal empty hash strings.
( sha256sum() { return 19; }; ! same_bytes "$scratch/empty-a" "$scratch/empty-b" )
( stat() { return 19; }; ! same_bytes "$scratch/empty-a" "$scratch/empty-b" )
signer=68B3537F39A313B3E574D06777193F152BDBE6A6
printf '# Normal trusted payload\n%s:4:\n' "$signer" > "$scratch/trusted"
: > "$scratch/revoked"
official_policy_file trusted "$scratch/trusted" "$signer"
official_policy_file revoked "$scratch/revoked" "$signer"
printf '%s\n' "$signer" > "$scratch/revoked"
! official_policy_file revoked "$scratch/revoked" "$signer"
printf '%s:3:\n' "$signer" > "$scratch/trusted"
! official_policy_file trusted "$scratch/trusted" "$signer"
printf 'MALFORMED\n' > "$scratch/trusted"
! official_policy_file trusted "$scratch/trusted" "$signer"
printf 'PASS_SYNTHETIC_BINARY_EMPTY_SIZE_SHA_COMPARISONS_AND_PUBLIC_TRUST_POLICY\n'
# Model guest root ownership only; all files remain in this unprivileged scratch.
(
 stat() {
  if [[ $1 == -c && ( $2 == '%u:%g:%h:%a' || $2 == '%u:%g:%a' ) ]];then
   local rest
   if [[ $2 == '%u:%g:%h:%a' ]];then rest=$(command stat -c '%h:%a' -- "$4");else rest=$(command stat -c '%a' -- "$4");fi
   printf '%s:0:%s\n' "${model_owner:-0}" "$rest"
  else command stat "$@";fi
 }
 D=$scratch/diagnostic-case;S=$scratch/diagnostic-root;phase=baseline;failure_rc=19
 mkdir -m700 "$D" "$S"
 printf 'MODEL_HOLD_ONLY\n' > "$D/failure.env";chmod 600 "$D/failure.env"
 head -c 2048 /dev/zero > "$S/import.log";printf 'MODEL_LATER_LOG\n' > "$S/keys.log";chmod 600 "$S/"*
 printf 'MODEL_UNSELECTED_SECRET\n' > "$S/unselected.key"
 log_bytes=1024;guest_output_cap_bytes=1048576
 retain_failure_data
 [[ $(command stat -c '%s' "$D/failure-diagnostics/import.log") == 1024 ]]
 [[ ! -e $D/failure-diagnostics/keys.log && ! -e $D/failure-diagnostics/unselected.key ]]
 grep -F $'2048\t1024\t' "$D/failure-diagnostics/manifest.tsv" > /dev/null
 grep -F $'TRUNCATED\timport.log' "$D/failure-diagnostics/manifest.tsv" > /dev/null
 grep -F $'OMITTED\tkeys.log' "$D/failure-diagnostics/manifest.tsv" > /dev/null
 grep -Fx 'PERL5423_FAILURE_DIAGNOSTICS_END' "$D/failure-diagnostics/manifest.tsv" > /dev/null
 # Existing evidence, unsafe ownership, links and exhausted budgets all refuse.
 ! retain_failure_data
 rm -rf "$D/failure-diagnostics"
 model_owner=1000;! retain_failure_data;[[ ! -e $D/failure-diagnostics ]];model_owner=0
 mv "$S/import.log" "$S/ordinary";ln -s ordinary "$S/import.log"
 ! retain_failure_data;! grep -q 'PERL5423_FAILURE_DIAGNOSTICS_END' "$D/failure-diagnostics/manifest.tsv"
 rm -rf "$D/failure-diagnostics";rm "$S/import.log";mv "$S/ordinary" "$S/import.log"
 ln "$S/import.log" "$S/alias";! retain_failure_data
 rm -rf "$D/failure-diagnostics";rm "$S/alias"
 guest_output_cap_bytes=32768;! retain_failure_data;[[ ! -e $D/failure-diagnostics ]]
 # Exercise the actual Root trap body. Its sync is a local assertion stub;
 # no host sync, GPG, ALPM or guest entry point is executed.
 D=$scratch/trap-case;O=$scratch/trap-run;S=$O/root
 mkdir -m700 "$D" "$O" "$S"
 printf 'MODEL_LOG\n' > "$S/import.log";chmod 600 "$S/import.log"
 if (
  . <(sed -n '/^finish() {/,/^}/p' "$HERE/guest/root.sh")
  phase=baseline;nonce=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  log_bytes=1024;guest_output_cap_bytes=1048576;sync_seconds=2
  timeout() {
   [[ $# == 5 && $1 == --signal=KILL && $2 == 2 && $3 == sync && $4 == -f && $5 == "$D" ]] || return 2
   [[ ! -e $O/summary.env ]] || return 2
   grep -Fx 'PERL5423_FAILURE_DIAGNOSTICS_END' "$D/failure-diagnostics/manifest.tsv" > /dev/null || return 2
   printf 'MODELED_SYNC_AFTER_CAPTURE\n' > "$D/sync-observation"
  }
  trap finish EXIT
  exit 19
 );then false;else [[ $? == 19 ]];fi
 [[ -f $D/sync-observation && -f $O/summary.env ]]
 grep -Fx 'FAILED_PHASE=baseline' "$D/failure.env" > /dev/null
 grep -Fx 'EXIT_STATUS=19' "$D/failure.env" > /dev/null
 # A failed ordinary probe emits no unearned functional/command PASS fields.
 if (
  . <(sed -n '/^finish() {/,/^}/p' "$HERE/guest/probe.sh")
  status=HOLD;nonce=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  trap finish EXIT
  exit 19
 ) > "$scratch/probe-hold";then false;else [[ $? == 19 ]];fi
 grep -Fx 'STATUS=HOLD' "$scratch/probe-hold" > /dev/null
 ! grep -Eq 'FUNCTIONAL=PASS|COMMANDS=PASS' "$scratch/probe-hold"
)
printf 'PASS_SYNTHETIC_BOUNDED_FAILURE_DIAGNOSTICS_AND_REFUSALS\n'
