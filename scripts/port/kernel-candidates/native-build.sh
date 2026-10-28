#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Future native build only. Not executed during source audit; no install targets.
set -euo pipefail
export PATH=/usr/bin:/bin
if [ "$#" -ne 10 ]; then
  echo 'usage: native-build.sh VARIANT SOURCE NEW_OUTPUT ARCHIVE CONFIG PATCH LOCK LOCK_SHA BUILDER_RECEIPT BUILDER_SHA' >&2
  exit 2
fi
task_variant=$1
task_source=$2
task_output=$3
task_archive=$4
task_config=$5
task_patch=$6
task_lock=$7
task_lock_sha=$8
task_builder=$9
task_builder_sha=${10}
task_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
python3 -B "$task_script_dir/verify_build.py" preflight --variant "$task_variant" --source "$task_source" \
  --build "$task_output" --archive "$task_archive" --config "$task_config" --patch "$task_patch" \
  --lock "$task_lock" --lock-sha256 "$task_lock_sha" --builder "$task_builder" --builder-sha256 "$task_builder_sha"
# Stop before upstream Makefile execution unless24GiB output headroom exists.
python3 -B - "$task_output" <<'PY'
import pathlib, shutil, sys
p = pathlib.Path(sys.argv[1])
while not p.exists():
    p = p.parent
if shutil.disk_usage(p).free < 24 * 1024**3:
    raise SystemExit('24GiB native build output headroom required')
PY
mkdir -m 700 -- "$task_output"
cp -- "$task_config" "$task_output/.config"
export ARCH=arm64 LC_ALL=C TZ=UTC
export KBUILD_BUILD_USER=cachy-asahi-kernel-c01 KBUILD_BUILD_HOST=native-kernel-c01 KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='Sat Sep 19 16:04:41 UTC 2026'
ulimit -v 8388608
task_clean_env=(/usr/bin/env -i PATH=/usr/bin:/bin HOME="$task_output" ARCH=arm64 LC_ALL=C TZ=UTC \
  KBUILD_BUILD_USER="$KBUILD_BUILD_USER" KBUILD_BUILD_HOST="$KBUILD_BUILD_HOST" \
  KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP="$KBUILD_BUILD_TIMESTAMP")
timeout --kill-after=30s 300s "${task_clean_env[@]}" /usr/bin/make -C "$task_source" O="$task_output" ARCH=arm64 \
  CC=/usr/bin/gcc LD=/usr/bin/ld AS=/usr/bin/as RUSTC=/usr/bin/rustc BINDGEN=/usr/bin/bindgen \
  PAHOLE=/usr/bin/pahole DTC=/usr/bin/dtc HOSTCC=/usr/bin/gcc \
  LOCALVERSION=-cachy-asahi-kernel-c01 olddefconfig > "$task_output/configure.log" 2>&1
python3 -B "$task_script_dir/verify_build.py" config --expected "$task_config" --actual "$task_output/.config" \
  > "$task_output/config-verification.json"
timeout --kill-after=30s 7200s "${task_clean_env[@]}" /usr/bin/make -C "$task_source" O="$task_output" ARCH=arm64 \
  CC=/usr/bin/gcc LD=/usr/bin/ld AS=/usr/bin/as RUSTC=/usr/bin/rustc BINDGEN=/usr/bin/bindgen \
  PAHOLE=/usr/bin/pahole DTC=/usr/bin/dtc HOSTCC=/usr/bin/gcc \
  LOCALVERSION=-cachy-asahi-kernel-c01 -j2 Image modules dtbs > "$task_output/build.log" 2>&1
python3 -B "$task_script_dir/verify_build.py" outputs --build "$task_output" > "$task_output/output-verification.json"
