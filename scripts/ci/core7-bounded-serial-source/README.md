# Exact Core49 to Core51 source factory

Reproduce the published bounded serial-output repair using only ordinary source files.
Full observer and custody files stay on media. UART carries closed references;
the original validator runs after full file authentication. Original clocks,
the aggregate UART cap, package behavior and boot checks remain mandatory.

```sh
python3 -I -B -Werror scripts/ci/core7-bounded-serial-source/prepare.py \
  --source /absolute/public49 --output /absolute/fresh51 --context known
```

The supplied source must match the complete pinned public49 tree. `null` emits
identical source bytes with NULL revision/ref receipt fields. The factory does
not execute supplied source or run installed/native operations. Both modes have
actual=NULL and native_acceptance=false. These controls grant no M2 or performance
acceptance.

```sh
CORE_SERIAL_INPUT=/absolute/public49 CORE_SERIAL_EXPECTED=/absolute/public51 \
  CORE_SERIAL_VM=/absolute/public-ksm637 \
  python3 -I -B -Werror scripts/ci/core7-bounded-serial-source/test_source.py
```
