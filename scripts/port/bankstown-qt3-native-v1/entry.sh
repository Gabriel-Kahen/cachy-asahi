#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
[[ ${CACHY_ASAHI_CONTAINER:-} == 1 && ${BANKSTOWN_NATIVE_TOOLS_PROFILE:-} == /bankstown-qt3-control/profile.json ]] || exit 70
[[ ${BANKSTOWN_NATIVE_TOOLS_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || exit 70
[[ $(id -u) != 0 && $(uname -m) == aarch64 ]] || exit 70
/usr/bin/python3 -I -B /bankstown-qt3-source/scripts/port/bankstown-qt3-native-v1/profile.py verify \
  --admission /bankstown-qt3-control/admission.json \
  --admission-sha256 "$(cat /bankstown-qt3-control/admission.sha256)" \
  --catalog "$(cat /bankstown-qt3-control/catalog.path)" --root / \
  --profile "$BANKSTOWN_NATIVE_TOOLS_PROFILE" --profile-sha256 "$BANKSTOWN_NATIVE_TOOLS_SHA256"
/usr/bin/python3 -I -B /inputs/build_guard.py native-tools \
  --profile "$BANKSTOWN_NATIVE_TOOLS_PROFILE" --sha256 "$BANKSTOWN_NATIVE_TOOLS_SHA256"
exec /bin/bash /bankstown-qt3-source/scripts/build/container-entry.sh
