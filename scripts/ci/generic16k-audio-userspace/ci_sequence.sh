#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Future disposable native CI only; no installation, Git mutation or dispatch.
set -euo pipefail
if [ "$#" -ne 5 ]; then
  echo 'usage: ci_sequence.sh SOURCE_ROOT PRODUCT_CHECKOUT DESKTOP_CHECKOUT NEW_OWNER_ROOT NEW_KERNEL_WORK' >&2
  exit 2
fi
task_source=$1
task_product=$2
task_desktop=$3
task_owner=$4
task_work=$5
task_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
: "${AUDIO16K_SOURCE_COMMIT:?explicit frozen Source required}"
: "${AUDIO16K_CANDIDATE_SHA256:?reviewed candidate-files.json SHA required}"
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ARCH:-}" = ARM64
test "${RUNNER_OS:-}" = Linux
python3 -I -B - "$task_source" "$task_dir/candidate-files.json" "$AUDIO16K_CANDIDATE_SHA256" <<'PY'
import hashlib,json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);raw=pathlib.Path(sys.argv[2]).read_bytes()
assert re.fullmatch('[0-9a-f]{64}',sys.argv[3]) and hashlib.sha256(raw).hexdigest()==sys.argv[3]
manifest=json.loads(raw);assert manifest['schema']==1 and len(manifest['files'])<=24
for name,row in manifest['files'].items():
    assert not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/'))
    path=root/name;assert not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
    data=path.read_bytes();assert len(data)==row['bytes']<=262144 and hashlib.sha256(data).hexdigest()==row['sha256']
PY
mkdir -m 700 -- "$task_work"
task_args=(--root "$task_owner" --source "$task_source" --source-commit "$AUDIO16K_SOURCE_COMMIT"
           --product "$task_product" --desktop "$task_desktop")
task_clean_env=(env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$task_work" LANG=C.UTF-8
                TZ=UTC PYTHONDONTWRITEBYTECODE=1)
task_finish() {
  task_status=$?
  trap - EXIT INT TERM
  set +e
  if [ -f "$task_owner/state.json" ]; then
    timeout --kill-after=10s 180s "${task_clean_env[@]}" python3 -I -B "$task_dir/job.py" cleanup "${task_args[@]}" || task_status=1
  fi
  python3 -I -B - "$task_owner/public/result.json" "$task_work" <<'PY'
import base64,hashlib,json,pathlib,sys
result=pathlib.Path(sys.argv[1]);work=pathlib.Path(sys.argv[2])
if result.is_file():
    value=json.loads(result.read_text());rows=[]
    for name in ('kernel-controller.log','kernel-helper/build/configure.log','kernel-helper/build/build.log','kernel-input.json'):
        path=work/name
        if path.is_file():
            assert path.stat().st_size<=16*1024**2
            raw=path.read_bytes();rows.append({'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                                              'tail_base64':base64.b64encode(raw[-8192:]).decode()})
    value['kernel_diagnostics']=rows
    raw=json.dumps(value,sort_keys=True,indent=2)+'\n';assert len(raw.encode())<=128*1024
    result.write_text(raw)
PY
  if [ "$?" -ne 0 ]; then task_status=1; fi
  timeout --kill-after=5s 60s python3 -I -B -c 'import shutil,sys;shutil.rmtree(sys.argv[1])' "$task_work" || task_status=1
  exit "$task_status"
}
trap task_finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
"${task_clean_env[@]}" python3 -I -B "$task_dir/job.py" init "${task_args[@]}"
task_seed=()
for task_key in CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01 CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02 \
                CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01 CACHY_OLD_FOUR_JBIGKIT_01 \
                CACHY_OLD_FOUR_JBIGKIT_02 CACHY_OLD_FOUR_JBIGKIT_SIG_01 CACHY_OLD_FOUR_LIBTIFF_SIG_01; do
  task_seed+=("$task_key=${!task_key:?required retained seed secret}")
done
for task_index in {01..15}; do
  task_key="CACHY_OLD_FOUR_LIBTIFF_$task_index"
  task_seed+=("$task_key=${!task_key:?required retained seed secret}")
done
timeout --kill-after=15s 120s "${task_clean_env[@]}" "${task_seed[@]}" python3 -I -B "$task_dir/job.py" seed "${task_args[@]}"
unset task_seed
timeout --kill-after=30s 2400s "${task_clean_env[@]}" python3 -I -B "$task_dir/job.py" build "${task_args[@]}"
timeout --kill-after=15s 670s "${task_clean_env[@]}" "GH_TOKEN=${GH_TOKEN:?actions-read token required}" \
  python3 -I -B "$task_dir/job.py" retrieve "${task_args[@]}"
# Only the kernel input is acquired here. Guest userspace comes from current574 capture.
timeout --kill-after=10s 320s "${task_clean_env[@]}" python3 -I -B - "$task_dir" "$task_source" "$task_work" <<'PY'
import json,pathlib,shutil,sys,time
sys.path.insert(0,sys.argv[1]);import deps
root=pathlib.Path(sys.argv[2]);work=pathlib.Path(sys.argv[3])
fetch=deps.load(root,'scripts/virtual/generic16k/fetch_inputs.py')
manifest,_=fetch.load_manifest(deps.source(root,'scripts/virtual/generic16k/inputs.json'))
inputs=work/'inputs';inputs.mkdir(mode=0o700)
with fetch.deadline_alarm(300):
    receipt=fetch.fetch_one(manifest['inputs'][0],inputs,time.monotonic()+300)
(work/'kernel-input.json').write_text(json.dumps(receipt,indent=2)+'\n')
helper=work/'kernel-helper';helper.mkdir(mode=0o700)
for name in ('build_kernel.py','kernel.fragment'):
    shutil.copyfile(deps.source(root,'scripts/virtual/generic16k/'+name),helper/name)
PY
timeout --signal=TERM --kill-after=30s 3700s "${task_clean_env[@]}" python3 -I -B \
  "$task_work/kernel-helper/build_kernel.py" --archive "$task_work/inputs/kernel.tar.gz" \
  --output "$task_work/kernel-helper/build" --build --boot-diagnostics > "$task_work/kernel-controller.log" 2>&1
timeout --signal=TERM --kill-after=75s 1350s "${task_clean_env[@]}" \
  "AUDIO16K_KERNEL_RECEIPT=$task_work/kernel-helper/build/build-receipt.json" \
  python3 -I -B "$task_dir/job.py" trial "${task_args[@]}"
