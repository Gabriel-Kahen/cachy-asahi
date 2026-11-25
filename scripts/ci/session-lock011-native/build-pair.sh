#!/usr/bin/env bash
# Build the exact helper candidate in two fresh, offline native ARM containers.
set -euo pipefail

if [[ $# != 2 || ! $1 =~ ^sha256:[0-9a-f]{64}$ || $2 != /* ]]; then
    echo 'Usage: build-pair.sh sha256:IMAGE_ID /absolute/fresh-output' >&2
    exit 2
fi

image=$1
output=$2
lane=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$lane/../../.." && pwd -P)
inventory="$root/scripts/ci/session-lock-settings-native-source-v2/fixtures/expected349.lock"
reviewed_inputs="$lane/recipe-inputs.json"
recipe="$root/packages/tools/cachy-asahi-session-lock011"

printf '%s  %s\n' \
    '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453' "$inventory" \
    'c1e2b7a583e56f258e590ba71f4751602da1ebb74e40828641314a2407234c76' "$reviewed_inputs" |
    sha256sum --check --status

mkdir -- "$output"
python3 -B "$root/scripts/ci/native_arm.py" probe --cache "$output" --output "$output/runner"

for slot in a b; do
    python3 -B "$root/scripts/build/build.py" "$recipe" --image "$image" \
        --output "$output/$slot" --mode native --network none --timeout 300 \
        --source-date-epoch 1794667200 --expected-packages "$inventory" \
        --reviewed-inputs "$reviewed_inputs"
    log="$output/$slot/build.log"
    if [[ $(grep -cF 'Starting check()' "$log") != 1 ||
          $(sed -nE 's/^Ran ([0-9]+) tests? in [0-9.]+s$/\1/p' "$log") != $'24\n16\n2' ||
          $(grep -cx 'OK' "$log") != 3 ]] ||
          grep -Eq 'Skipping dependency checks|FAILED|skipped=|expected failures=|unexpected successes=' "$log"; then
        echo "Incomplete helper check() evidence in $log" >&2
        exit 1
    fi
done

python3 -B "$root/scripts/build/compare.py" "$output/a" "$output/b" --require-bytes > "$output/compare.json"

python3 -I -B - "$root/scripts/integration" "$output" > "$output/payload.json" <<'PY'
import json
from pathlib import Path
import runpy
import sys

integration, output = map(Path, sys.argv[1:])
verifier = runpy.run_path(str(integration / "desktop_session_lock.py"))
profile = verifier["load_profile"](
    integration / "profiles/desktop-session-lock011-idle.json",
    "faac805487cb2b6c58a03a844631f5848a7002363d2495364ca368b0927427e0",
)
helper = profile["packages"][verifier["LOCKER"]]
result = {}
for slot in ("a", "b"):
    build = output / slot
    record = json.loads((build / "provenance.json").read_text())
    (name, digest), = record["artifacts"].items()
    files, receipt = verifier["verify_archive"](build / "artifacts" / name, digest, helper)
    result[slot] = {"archive": receipt, "payload_files": sorted(files)}
print(json.dumps(result, indent=2, sort_keys=True))
PY
