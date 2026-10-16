#!/usr/bin/env bash
# Future disposable native CI only. No dispatch, installation or global cleanup.
set -euo pipefail
test "$#" -eq 4
task_source=$1
task_public_seed=$2
task_work=$3
task_mode=$4
task_dir="$task_source/scripts/ci/maintained574-active-trial"
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ARCH:-}" = ARM64
test "${RUNNER_OS:-}" = Linux
case "$task_mode" in normal|cancel|both) ;; *) exit 2 ;; esac
: "${ACTIVE574_SOURCE_COMMIT:?frozen Source required}"
mkdir -m 700 -- "$task_work"
mkdir -m 700 -- "$task_work/public" "$task_work/home"
task_clean=(env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 HOME="$task_work/home")
task_stage=seed
task_finish() {
  task_status=$?
  trap - EXIT INT TERM
  "${task_clean[@]}" python3 -I -B - "$task_work/public/sequence.json" "$task_stage" "$task_status" "$ACTIVE574_SOURCE_COMMIT" <<'PY'
import json,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({'stage':sys.argv[2],'exit_code':int(sys.argv[3]),
    'source_commit':sys.argv[4],'scope':'DISPOSABLE_OPTIONAL_574_CANCELLATION',
    'hardware':'NOT RUN'},sort_keys=True,indent=2)+'\n')
PY
  exit "$task_status"
}
trap task_finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
# Only the established held seed helper receives the existing 19 old-four +3 bubblewrap values.
task_secrets=()
for task_key in CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01 CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02 \
  CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01 CACHY_OLD_FOUR_JBIGKIT_01 CACHY_OLD_FOUR_JBIGKIT_02 \
  CACHY_OLD_FOUR_JBIGKIT_SIG_01 CACHY_OLD_FOUR_LIBTIFF_SIG_01; do
  task_secrets+=("$task_key=${!task_key:?existing seed secret required}")
done
for task_index in {01..15}; do
  task_key="CACHY_OLD_FOUR_LIBTIFF_$task_index"
  task_secrets+=("$task_key=${!task_key:?existing seed secret required}")
done
timeout --signal=TERM --kill-after=15s 120s "${task_clean[@]}" "${task_secrets[@]}" \
  CACHY_OLD_FOUR_SCHEMA=1 CACHY_OLD_FOUR_SOURCE_EPOCH=1791748800 \
  python3 -I -B "$task_source/scripts/ci/maintained_desktop574.py" seed \
  --inputs "$task_source/scripts/ci/maintained-desktop574-inputs.json" --output "$task_work/base" \
  > "$task_work/secret-seed.log" 2>&1
unset task_secrets
for task_key in ${!CACHY_OLD_FOUR_@} ${!CACHY_RETAINED_BUBBLEWRAP_@}; do unset "$task_key"; done
task_stage=public-seed
timeout --signal=TERM --kill-after=15s 160s "${task_clean[@]}" python3 -I -B "$task_dir/prepare.py" public-seed \
  --source-ci "$task_source/scripts/ci" --base "$task_work/base" --public-inputs "$task_public_seed" \
  --public-output "$task_work/public/public-seed.json" > "$task_work/public-seed-controller.log" 2>&1
task_stage=acquire-context
timeout --signal=TERM --kill-after=15s 1800s "${task_clean[@]}" python3 -I -B "$task_dir/prepare.py" acquire \
  --source-ci "$task_source/scripts/ci" --base "$task_work/base" \
  --public-output "$task_work/public/preparation.json" > "$task_work/preparation-controller.log" 2>&1
# Observer owns termination/reaping. Its process and the owner use distinct sessions.
task_stage=observe
timeout --signal=TERM --kill-after=660s 7900s "${task_clean[@]}" python3 -I -B "$task_dir/observe.py" \
  --source-ci "$task_source/scripts/ci" --prepared-context "$task_work/base/context" \
  --output "$task_work/trial" --public-output "$task_work/public/trial.json" \
  --source-commit "$ACTIVE574_SOURCE_COMMIT" --mode "$task_mode" > "$task_work/observer.log" 2>&1
task_stage=completed
# Private context/logs remain under this disposable job's work directory until teardown.
