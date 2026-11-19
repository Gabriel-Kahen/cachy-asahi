#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SOURCE ONLY, NOT RUN. Future Root-selected isolated ARM container entry.
# No bootstrap, image/repository/signer selection, key generation or downloads.
set -euo pipefail
[[ $# == 4 && $1 == --deadline && $3 == --nonce ]]
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && -f /.dockerenv ]]
[[ ${FISH_SIGNER_FP:-} =~ ^[A-F0-9]{40}$ ]]
[[ $4 =~ ^[a-f0-9]{32}$ ]]
exec /usr/bin/python3 -I -B /fish-history-probe.py --phase lifecycle --root /home/alarm/fish-history-sentinel --deadline "$2" --nonce "$4"
