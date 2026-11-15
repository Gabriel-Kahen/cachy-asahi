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
