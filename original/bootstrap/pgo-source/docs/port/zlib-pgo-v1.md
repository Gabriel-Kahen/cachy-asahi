# Offline zlib PGO candidate v1

This is new candidate source, not admission. Previous installed baseline/LTO
timing remains negative: 1.429444879 s versus 1.4300250785 s medians, below the
frozen 5% useful-gain rule. Baseline remains retained. PGO tests a different
hypothesis: GCC can use training branch/value counts to improve an independent
workload. Benefit is not assumed; training must not select heldout samples or
change thresholds.

The real zlib 1.3.2 archive is 1,502,830 bytes, SHA256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
`inputs/` carries the already acquired cache object, original descriptor/receipt
and Zlib notice. No acquisition is performed. Seeding makes a new private
verification copy, not a new transport attestation. `provenance/` preserves exact
prior generic TCG16K qualification and negative LTO evidence; neither transfers
to this candidate. Original builders and C01/LTO packets remain unchanged.

## Construction

Use a reviewed existing immutable native ARM builder image and its exact package
lock. It must contain gcc/gcov-tool, binutils, make, Python, glibc and makepkg.
No dependency installation is attempted. From the closed source root:

```sh
python3 -B scripts/experiments/zlib_pgo_native_plan.py \
  --image sha256:ROOT_REVIEWED_IMAGE_ID \
  --expected-packages /absolute/reviewed-packages.lock \
  --output /absolute/fresh-preparation
```

This only verifies/stages offline source and emits `native-command.json`. Its
`command` array is the executable versioned `scripts/build/build_v2.py` invocation
for Root's supervised native dispatch. It fixes native mode, network none,
source epoch, reviewed recipe map, source plan/catalog/cache and expected package
inventory. Root must retain complete `artifacts/pgo-v1-evidence/` as well as normal
builder output: the builder's top-level file map alone omits that nested tree.
Existing output directories refuse reuse after partial or complete execution.

The package owns only `/usr/lib/cachy-asahi/experiments/zlib-pgo-v1` and its license
paths. It has no system-zlib provides/conflicts/replaces, install script, global
hooks or platform changes. Zlib/MIT licenses and reviewed sources are retained.
Actual installation/removal belongs to a later disposable Root lane.

The ordinary-user aarch64 isolated pipeline copies makepkg source symlinks into
fresh ordinary files and verifies their hashes. Supervised groups hold their
leaders through cleanup. It performs:

1. Static instrumentation with generic ARMv8, `-O2`, no LTO, existing hardening/
   page-alignment flags and serial GCC profile generation.
2. Removal of feature-probe counters, then four fixed training commands using
   only independent 256 KiB training bytes and pinned upstream example literals.
   Validation never reaches instrumented programs.
3. Native gcov-tool checking of all 17 expected profiles, then a no-replace seal
   binding source/helpers, ten toolchain components, ISA, absolute build/profile/
   prefix paths, training plan/results and both corpus identities.
4. Two clean optimized builds using the same sealed profiles at `/tmp/build` and
   `/tmp/profile`. Baseline configure probes precede exact profile-use Makefile
   flags. Missing-profile/coverage-mismatch warnings are fatal; fallback, changed
   tools, profile bytes or seal refuse. Probe/strict-oracle translation units stay
   unprofiled while linking optimized zlib.
5. Byte comparison of optimized payloads, upstream tests, 48 encodes, 96 strict
   cross-decodes, independent Python decoding, six strict refusals and two finite
   probes. Cases include empty/one-byte and 16383/16384/16385 boundaries plus
   heldout data. Profiles, training outputs, binaries, flags and command records
   survive tmpfs with a complete receipt.

Two optimized builds share one seal. Independently retrained archives are not
promised byte-identical; profile stamps and runtime provenance may vary.

## Subsequent installed and measurement gates

`scripts/experiments/zlib_pgo_guest.py --execute --baseline-manifest FILE
--candidate-manifest FILE --output FRESH` is a read-only installed generic16K gate.
Root supplies actual binary/source/publication/seal identities from accepted
native output and sets `CACHY_ASAHI_PGO_GENERIC16K=1` inside an ordinary-user
aarch64/16384-page guest. It requires 42 encodes, 84 strict cross-decodes,
42 Python decodes, six full-plaintext strict refusals, two installed probes and
unchanged package inventories. It performs no ALPM installation, VM boot or
final VM/container retirement itself.

Corpus policy retains the old measurement design: unchanged 4 MiB heldout bytes
repeated to 16 MiB, four level-6 roundtrips, two correctness slots, four excluded
warmups and twelve measured ABBA/BAAB/ABBA slots, six per variant. Useful gain stays
5%; maximum range/median stays 25%. Empty regression budgets grant no energy,
memory or thermal acceptance. Root must bind a new measurement source to actual
candidate output; this source packet supplies no measured result.

Native instrumentation, optimized builds, reproduction, installed lifecycle,
candidate16K execution, M2, performance, power/thermals and release are **NOT RUN**
by this author task. Generic TCG16K is not physical M2 evidence; ELF alignment is
not execution. Host controls use synthetic profiles/mock runtimes and real
offline archive hashes only.
