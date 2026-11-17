#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Binary stdin only. No cache writes, path traversal or interpreter dependency.
set -euo pipefail
[[ $# == 0 ]] || exit 2
export LC_ALL=C
here=${BASH_SOURCE[0]%/*}
# Read at most CAP+1: over-cap input is rejected, never silently truncated.
/usr/bin/head -c 1048577 | /usr/bin/od -An -v -tx1 -w4096 | /usr/bin/gawk -f "$here/canonicalize.awk"
