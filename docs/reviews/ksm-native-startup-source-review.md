# KSM native startup source review — 2026-10-12

Disposition: **bounded source correction accepted; ready for coordinator source-packet rebinding and committed preflight. Native acceptance remains pending.** No additional blocker was confirmed in this review. Only this review and its private peer evidence were written; implementation, packet, checkpoint, workflow and project Git were not changed.

## Exact held input

| Path | SHA-256 | Bytes | Mode |
| --- | --- | ---: | --- |
| `scripts/port/ksm-native-job/executor.py` | `a0c164abf888ac4b0a642d8edc2ccad8d9c060a376d84c55ed376a46ab9f9667` | 31,262 | 0644 |
| `scripts/port/ksm-native-job/test_executor.py` | `19b28136d8c8ccbd091d363f5551dc3aad0e79e3187f79245e74c931c5723575` | 21,600 | 0644 |
| `docs/workstreams/ksm-native-job.md` | `8b51c6a686dc356f6d5ae6990882d7b57a8105cd8033bb96424d51c7f20776a6` | 18,995 | 0644 |

All 152 source paths were captured into a fresh peer source tree, with actual bytes and modes checked. Exactly the held three differ from historical packet `631df29044c624ef0c6d0d2d0c178e7cff489e2395071a679125a1fa7adb80a5`; the other 149 remain unchanged. The checkpoint's other **37 owned rows** were independently rechecked against their recorded bytes, size and mode. Historical checkpoint `e54715b27d8ff753be0e4a07b3301485f80f3cd1e619205a641732d80b39d099`, its 229-test receipt and the old packet remain historical bindings. The corrected bytes require the coordinator's new packet before actual source acceptance.

## Causal importer correction

The independent probe extracted and executed `stage_module` from the actual historical executor (`ca0699e8ed6df798627dc64f746a7558d9a056c55cb06a2e4f45e782cac94b2f`) against the fresh, actual captured source set. It reproduced **`unbound transitive import: contextlib`**. The corrected function loaded the pinned BASE and CONTRACT from that captured tree and passed the final source-tree check without bytecode caches.

The explicit 26-module allowlist exactly matches the complete import AST closure of held lifecycle stage, BASE, CONTRACT and GUARD, including the explicit parent of `importlib.util`. It adds no foreign helper route. Independent probes refused `executor`, `socket`, `importlib.machinery`, a relative `pathlib` import and a wildcard `hashlib` import. The importer is a source-binding mechanism for trusted pinned code, not a general sandbox.

This proves a deterministic old startup defect and its correction. Run **38262440852** reported generic source-phase `ValueError`; its exact first failed predicate remains **UNPROVEN**. The causal local reproduction does not identify that run's original cause.

## Gates and bounded diagnostics

The original host `need` predicates and empty-image/container query arguments and acceptance predicates are AST-identical to the historical executor. Both baseline queries still require actual exit zero and empty stripped output. Occupied image or container responses and exit 17 refuse startup before broker reservation or producer launch. Transport closure is observed; cleanup remains NOT RUN because no native owner was acquired.

The failing source operation has a finite gate and closed failure-reason label. Baseline observations contain only line counts within the unchanged bounded subprocess output contract and actual integer exit values in −128…255, otherwise null. Additional isolated startup probes covered −15, 255, 256 and a foreign private-text return code. All refused the baseline as appropriate; out-of-range/foreign values became null and no identifier or exception text entered the report. The unchanged public exporter constructs its allowlisted evidence independently and omits all three new source diagnostic fields.

## Independent checks and limits

Four focused tests from the fresh capture passed, **zero failures/errors/skips**, in 3.084 seconds: actual captured nested BASE/CONTRACT imports, isolated CLI-capture tripwire, occupied/failed daemon baselines, and refusal without native authorization/host. The independent historical-function/importer proof and four additional exit-diagnostic cases also passed. The author's complete 232-test PASS is reported evidence; this review did not repeat that complete suite.

Startup fixtures create explicitly test-only temporary Git repositories from all 152 source paths, perform actual capture/fresh-copy acceptance, and run isolated Python (`-I -B -S`). Architecture, tools, filesystem capacity and Docker responses are synthetic; native actors are forbidden tripwires. No real Docker daemon, producer, compilation, signing/install lifecycle, M2/16K execution, management or performance measurement ran. Saved fixture PASS and source review do not advance those gates.

Evidence: `artifacts/reviews/ksm-startup-root-peer-20261012/{capture.json,focused-tests.log,independent-importer-proof.json,independent-diagnostic-cases.json,final-review-receipt.json}`. The final receipt binds evidence hashes and exact held inputs.
