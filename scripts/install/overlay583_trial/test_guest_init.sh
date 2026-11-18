#!/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail

init=${BASH_SOURCE[0]%/*}/guest-init.sh
source_text=$(<"$init")
if [[ $source_text == *'<('* || $source_text == *'>('* || $source_text == *'/dev/fd'* ]]; then
    printf 'guest init must not depend on process-substitution fd paths\n' >&2
    exit 1
fi

# Load the exact parser alone. The boot code, mounts and shutdown stay dormant.
parser=$(sed -n '/^root_mount_is_readonly() {$/,/^}$/p' "$init")
[[ -n $parser ]]
eval "$parser"

root_mount_is_readonly <<'MOUNTS'
18 1 254:49 / / ro,relatime - ext4 /dev/vdd1 ro
19 18 0:4 / /proc rw,nosuid,nodev,noexec - proc proc rw
MOUNTS
root_mount_is_readonly <<< '18 1 254:49 / / ro,nosuid shared:3 master:2 - ext4 /dev/vdd1 rw'

reject() {
    if root_mount_is_readonly <<< "$1"; then
        printf 'incorrectly accepted mountinfo fixture: %s\n' "$1" >&2
        exit 1
    fi
}
reject '18 1 254:49 / / rw - ext4 /dev/vdd1 ro'
reject '18 1 254:49 / / ro,rw - ext4 /dev/vdd1 ro'
reject '18 1 254:49 / / rootcontext - ext4 /dev/vdd1 ro'
reject '18 1 254:49 / / ro - xfs /dev/vdd1 ro'
reject '18 1 254:49 / / ro - ext4'
reject '19 18 0:4 / /proc ro - proc proc ro'
reject $'18 1 254:49 / / ro - ext4 /dev/vdd1 ro\n20 18 254:1 / / ro - ext4 /dev/vda1 ro'
printf 'guest init mountinfo fixture passed (9 cases)\n'

exporter=$(sed -n '/^export_evidence() {$/,/^}$/p' "$init")
[[ -n $exporter ]]
eval "$exporter"
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
mkdir "$temp/original"
printf 'model receipt\n' > "$temp/original/result.json"
printf 'model failed removal\n' > "$temp/original/remove.stderr"
export_evidence "$temp/original" "$temp/held"
cmp "$temp/original/result.json" "$temp/held/result.json"
cmp "$temp/original/remove.stderr" "$temp/held/remove.stderr"
touch "$temp/original/foreign"
if export_evidence "$temp/original" "$temp/foreign"; then
    printf 'incorrectly exported foreign evidence\n' >&2
    exit 1
fi
rm "$temp/original/foreign"
ln "$temp/original/remove.stderr" "$temp/original/reinstall.stderr"
if export_evidence "$temp/original" "$temp/hardlink"; then
    printf 'incorrectly exported hard-linked evidence\n' >&2
    exit 1
fi
printf 'guest init evidence export fixture passed (3 cases)\n'
