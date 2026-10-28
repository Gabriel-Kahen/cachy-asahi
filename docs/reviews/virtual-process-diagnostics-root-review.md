# Guest process diagnostics and registration: independent source review

Disposition: **SOURCE-READY**, with no reproduced material blocker in the captured candidate. This is source/fixture acceptance only. New committed Git proof, native guest execution, visual acceptance, hardware compatibility and performance acceptance are **NOT RUN** by this review. Historical guest failures remain failures.

## Authenticated boundary

Author receipt `artifacts/reviews/virtual-process-diagnostics-correction-20261012/receipt.json` is SHA256 `32ea908eb97a95a917f6b85bec06b7b5c182fe480a250f6ed1437f92d30c6ab9`. Its 118 artifact rows were checked for exact bytes, hashes and modes before imports. The four held source files are:

| File | SHA256 |
| --- | --- |
| `scripts/virtual/guest.py` | `f3bd405de20e51b27f7cbb2c18081ef7ed24c44ceb999d42341a95675f47a0a2` |
| `scripts/virtual/test_virtual.py` | `f19c7cf7b17525dc686da4922332dfe889f1ee1f3c04ea5b3913da8fcf8830f1` |
| `scripts/ci/development/virtual_stage.py` | `250e5451ca2067d2d53d8664fafe1b620f049655f6e557e6a2619c8a79d87117` |
| `scripts/ci/development/test_virtual_stage.py` | `89eca60cbc881cb01da3f5766240b4a4db10abe4071bd9133f0bd7f98d92a5dc` |

Root's applied controller is `704402c239e41fb65a80d4a993d1ac72ddd8b61f02aea76a0193ea3acaa29aee`. Reconstructing it from the retained historical controller confirms exactly two substitutions: the guest source pin and the `process_state` event allowlist entry. Proposal patch SHA256 is `5ef4a476e4f292a472c643e32cad556d9b2e2ca2da021cda0c884275088a7096`. The existing common implementation remains `b5099507b27fd9f86259c0096d0128b3a2480c546469312763a84438202fa4c3`.

Root candidate packet SHA256 is `47610163e48bcdfa6f716fa9fea065e7f58e385232ca767bf3301a02865f9935`. All 211 selected files (4,283,719 bytes) were independently captured and checked against their hash and mode rows. Exactly the above four files and controller changed; the other 206 rows match the historical packet. All other packet fields, including the initial 159 source rows, 125 generated fixture rows and seven metadata pins, match the historical candidate. The copied initial lock's source/fixture maps agree exactly with those packet fields. No PYC files are present. A final check reconfirmed the captured 211 rows and the six current held/registration source hashes and modes.

## Verification and causal coverage

Previously completed independent fresh-capture suites passed **178 tests, zero skips**: guest 52, modern receiver 104 and controller 22 using the applied controller. Their receipts and logs were inspected on resumption; these completed suites were not rerun merely to regenerate evidence.

The separate bounded host probes passed eight guest failure schedules and 74 receiver negatives: 47 nested-schema/type cases, 17 ordering/continuation cases, six startup-context cases and four cross-snapshot cases. These use fake processes, clocks, drains and commands plus small owned files; they do not invoke native actors. The guest controls retain the original failure through observation, cancellation, log-finish failure and cleanup. They distinguish a naturally observed exit from an exit observed after cleanup. Failed delivery of the before-cleanup event does not produce an orphan after-cleanup event. Unsupported logger error objects and failed finishing cannot become `logging: ok`.

The receiver requires a valid correlated startup/IPC prefix before accepting these records. It rejects after-only or duplicate observations, unrelated stages, success continuation after a failure snapshot, boolean/unsupported return codes, resurrection of an exited process, changed exit codes and reversal of an observed logger error. A before-only partial observation is valid failure evidence. The successful guest protocol refuses all process-state failure streams.

An additional independent replay authenticated the exact eight saved producer-emitted fixture byte streams and their generation harness, then passed them to the captured receiver using those same immutable bytes. All eight passed diagnostic parsing and were refused as successful guest execution. None contained frame-ready, phase-pass or guest-pass claims. The two broken-event-delivery cases truthfully retain one snapshot (`closed-post`) or none (`closed-pre`); neither gains success from missing observations. This confirms producer/modern-receiver compatibility for the controlled failure paths rather than merely testing hand-written record shapes.

Retained actual event streams from runs 38259350917, 38274341668 and 38283691844 (10, 13 and 35 events) remain readable as historical failure diagnostics and are refused by the success protocol. Their raw bytes were retained unchanged. No newly modeled diagnostic is presented as an observation from those native runs.

## Meaning and limits

The finite client/compositor rows expose only state, a bounded typed return code and a closed logging status. They retain the first failure and separate observations made before cleanup from observations after termination/reaping. The two role observations are sequential; they are not an atomic snapshot or proof of which process exited first. Unknown observations remain unavailable. These records confer no readiness, captured-frame, compositor, guest, native or hardware PASS authority.

No primary source, shared lock, manifest, workflow or Git state was changed by the reviewer. No Docker, QEMU, compositor, compiler, media, physical-device, installation or system operation was executed. The roadmap/package inventory continue to require native execution, actual target transactions and exact-machine hardware evidence separately.

Independent artifacts are under `artifacts/reviews/virtual-process-diagnostics-root-peer-20261012/`: `capture.json`, `registration-check.json`, `tests.json`, the three suite logs, `controls/guest-receipt.json`, `controls/adapter-receipt.json`, `producer-parity.json`, its authenticated eight raw fixtures, and `final-source-check.json`. These support source readiness for this exact candidate; the coordinator owns subsequent committed proof and any native trial.
