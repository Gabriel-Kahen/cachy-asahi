#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
/usr/bin/python3 -I -B /inputs/actor/work_check.py
exec /usr/bin/python3 -I -B /inputs/actor/entry.py
