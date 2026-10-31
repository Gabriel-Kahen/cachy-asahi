# Exact Repair242 to Repair245 source factory

Reproduce the published private relative-path validation repair from complete
public242 source. The fast path handles canonical strings; uncertain values use
the original validator. Its private installer facade authenticates the original
source and functions. Runtime/root-observation checks and limits remain intact.

```sh
python3 -I -B -Werror scripts/ci/repair-relative-source/prepare.py \
  --source /absolute/public242 --output /absolute/fresh245 --context known
```

The factory treats supplied source as data. `null` emits identical bytes with NULL
revision/ref receipt fields. Actual/native acceptance remains false. Local oracle,
descriptor and mutation controls do not establish a native hotspot, deadline fit
or M2 improvement. The complete published245 VM trial remains separate.

```sh
export REPAIR_RELATIVE_INPUT=/absolute/public242
export REPAIR_RELATIVE_EXPECTED=/absolute/public245
python3 -I -B -Werror scripts/ci/repair-relative-source/test_source.py
python3 -I -B -Werror scripts/ci/repair-relative-source/test_relative.py
```
