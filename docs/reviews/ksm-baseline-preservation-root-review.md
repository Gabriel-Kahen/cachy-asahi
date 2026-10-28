# KSM baseline-preservation source peer review

Review date: 2026-10-12. Scope: the held five-file correction against the adopted 152-file KSM job packet. This review changes only this document and `artifacts/reviews/ksm-baseline-preservation-root-peer-20261012/`.

The new baseline-preservation predicates pass source review and the isolated 255-test suite. One existing startup-budget gap remains: source capture starts a new 180-second clock, and source copying has no caller deadline. The executor rejects the overrun before starting its backend or producer, but this is late rejection, not enforcement of the initial workflow's complete 180-second source-work budget. This gap predates the correction and is recorded separately from its baseline behavior. No corrected native execution or real Docker preservation is established here.

## Reviewed source

Read `AGENTS.md`, `docs/roadmap.md`, the KSM entry in `manifests/packages.toml`, the package README/provenance and the held job workstream. The inventory's earlier native development build pair does not validate this executor correction, installation, management, M2 hardware or performance.

The adopted map remains `65a7ab50f5e9b085278a1f2094771d2f705a2e768ab74300698ce451b858d24e`. The review copied all 152 authenticated rows, allowing exactly the following changes; the other 147 rows retained their declared bytes and modes. Source total: **2,242,023 bytes**. All five changed files have mode `0644`.

| Held correction path | SHA-256 |
| --- | --- |
| `scripts/port/ksm-native-job/executor.py` | `10cc86a56e398cfa789e20292c487d7ef9cd7758a89e15fb80ac64e7f516f145` |
| `scripts/port/ksm-native-job/test_executor.py` | `1313c11fb1bd9206041f76107559db69a44cb0b68b298bb3be4c7e6fcfa0d390` |
| `scripts/port/ksm-native-job/broker.py` | `b1f6383da59a40f3eadd19bd8544b795c738566889f397e544fbcaba90531c27` |
| `scripts/port/ksm-native-job/test_broker.py` | `73ff122615cd7920dfe6054ffb214e2dbca3a626a454114b34cb666b52628360` |
| `docs/workstreams/ksm-native-job.md` | `e23ecf6aec2339616f095f583625b2042717fce3ff8ea3292ebc81c1f4b75d1a` |

The private prospective map is `c7a2fa58b74e0432a614c32f1b17128839289da73d0cf008ae756e2e8617e09c`; it was placed only in the review copy. `snapshot-receipt.json` records every row, old/new changes and source bytes. Final root checks verified all 152 live and copied rows, the unchanged adopted map and zero snapshot bytecode files.

## Baseline and acceptance behavior

Baseline B is twice observed with empty container inventories, bounded image/JSON/reference projections and source/packet/run/attempt/nonce/UID/GID/daemon/CLI/socket bindings. Its separate single-link `0600` journal and private `0700` parent are checked against retained descriptors and named identities. Reference selectors must resolve back to their captured IDs; metadata/reference drift remains failed after restoration.

B does not become owned by the job. Produced IID collision is refused before producer acceptance and broker image ownership. Cleanup rechecks exclusion immediately before deletion, accepts only journaled matching owned identities, and uses `image rm --no-prune <immutable ID>` without force. Inventory differences are not deletion grants. Protected-ID-only cleanup observations cannot establish final preservation PASS.

The executor requires a clean producer return, accepted original receipts, an IID outside B and positive full post-producer preservation before `COMPLETE_ACCEPTED`. Full inventory/reference preservation after owned cleanup is required before constructing public acceptance or exporting it. Unknown actor commitment, cancellation and failed observations remain failed even if a later inventory is empty. Unknown extra images remain unowned and unverified; legacy cache absence is not established. The contract assumes cooperative daemon writers, not exclusive daemon isolation.

The new baseline calls share their caller's absolute phase cutoff. Cleanup stores its first cutoff, bounded by `now + 180` and aggregate end minus 30 seconds. Retries and the final ordinary reference observation use that same cutoff. An expired retry is refused; it cannot renew cleanup time.

## Existing source-budget finding

**P2, pre-existing:** `executor.py:465` invokes `acceptance.capture` without the initial source cutoff. `acceptance.py:258` sets a fresh `monotonic() + 180`; `source_tree` and its validation also lack that caller cutoff. The shared-start check occurs at `executor.py:477`, after capture, copy and launcher preparation.

The independent executor peer exercised copied executor/capture/copy functions with a tiny actual committed private Git tree and an injected clock: initial start 0, capture begins at 179, internal deadline 359, capture reads advance to 181, and two authenticated files are copied at 181. The executor then saves FAIL at `source-clock`; backend creation and producer launch remain uncalled. This demonstrates budget renewal/late checking, not a 181-second wall-clock run or unsafe native mutation. The capture/copy/check order exists in the adopted executor, and `acceptance.py` is unchanged by this correction.

Carry the caller's absolute cutoff through capture, Git acceptance and copying before claiming complete source-phase enforcement. This review does not import a broader kernel timer design or modify implementation.

## Validation and limits

The isolated full command was `python -I -B -S -Werror::ResourceWarning -m unittest discover -s scripts/port/ksm-native-job -p 'test_*.py'`: **255 tests passed in 12.737 seconds**, exit 0. The executor peer independently ran 21 copied executor tests, zero skips, with ResourceWarnings as errors, and exercised two structural cleanup clock schedules. Its receipt distinguishes actual temporary Git from mocked host/backend conditions and injected clocks. The suite also includes real local process/signal fixtures; Docker behavior is supplied by fake backends.

The broker peer separately passed **24 checks**: 18 copied baseline tests plus six independent controls. Those controls verify sticky FAIL after a foreign container disappears, a reference is restored, a journal is restored, backend binding is restored, or cancellation is cleared; the positive control preserves B and an unknown image while disposing only an owned image without pruning. Two retained tests deliver actual self-SIGTERM against fake Docker. All 152 snapshot rows remain unchanged, with zero bytecode files. No new broker or executor blocker was found in the correction.

Receipts are under `artifacts/reviews/ksm-baseline-preservation-root-peer-20261012/`: `root-checks.json`, `executor-peer/receipt.json` and `broker-peer/receipt.json`. The final binding is `final-review.json`; test counts are reported separately because the copied tests overlap the full suite. The executor's existing source-budget finding prevents a claim of complete 180-second source-phase enforcement; it does not turn the new baseline predicates into a failure.

The historical native attempt **38271066975** remains failed at its original baseline gate: its recorded image inventory returned exit 0 and six lines. Six returned lines do not prove six distinct image IDs. The correction has not been run natively, and this review neither changes that historical result nor counts VM teardown as owned cleanup. Package installation/removal, M2 testing, KSM activation and performance remain outside this source review. Root owns shared-map adoption, Git publication and any subsequent native dispatch.
