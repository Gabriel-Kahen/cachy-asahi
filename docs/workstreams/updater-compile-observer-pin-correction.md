# Updater compile observer pin correction

**Implemented source-only; fresh models pass. Not registered or native-tested.** Root selected the minimal correction from the [actual updater7 review](../reviews/native-updater-execution-38307993177.md), sealed receipt `147d85b1af33b7bb38fd7cdbe506bc258da14a3b3c9c117507a15c0e9cf0fa99`. Actual run38307993177 remains FAIL/native compilation NOT RUN, scoped cleanup/recovery PASS. Private gate stderr remains unexported; the prior exact-source refusal is a reproduced source blocker, not recovered child error text.

## Exact production delta

Only `worker-metadata.py`'s pin changes in two production locations: `build-gate.py:MODULE_PINS` and `build-policy.json:module_sha256`. Both now require the selected unchanged observer SHA256 `4acc1fa076884b28973cf13b966030081dc6e5b030072332365b7a4485231f48`, replacing `f54226c068f3f8a51556ed9185168b89f793c1c8f2219c81557246f587e0edf2`.

The gate AST is exactly the original except one string literal. The policy JSON and serialized text differ only in that observer-pin value. The observer bytes, closure pin, all evidence/inventory/policy/source/identity/isolation/resource/deadline/output/cleanup/compiler/PASS checks and command sequence are unchanged. No obsolete observer is restored, no dynamic hash acceptance is added, and no diagnostic/public ABI changes.

The original selected recipe authenticated the4acc observer while its gate and policy requiredf542. Exact gate entry refused before observer import. This correction removes that specific source consistency obstruction. It does not establish that real observer, controller, source/vendor, Linux graph, license/script, retention, compilation or ELF checks pass on a future worker.

## Decisive tests and exact source hold

The actual original `test-gate.py` contains19 test methods, not20. All19 original method/helper ASTs are preserved. Five added regressions bring the full gate suite to24:

- Hash the actual shipped observer and closure payloads and require equality with both gate and checked policy pins.
- Run exact gate entry with module-import facades and an explicit sentinel before any real observation.
- Show mutually consistent stale pins still refuse before import.
- Show mutated observer/closure payloads refuse before their own import.
- Show asymmetric gate/policy pin refresh refuses before any import.

The identical final five additions against the original gate/policy and the same selected observer/closure are RED:4 failures/1 error, zero skips. Candidate added5/full24 are PASS with zero skips. The captured positive facade is not a worker observation or compilation acceptance.

The parent captures the exact actual86-source closure and substitutes only the three granted files. Independent isolated Python processes use `-I -B -W error::ResourceWarning` and short owned TMPDIRs. Fresh results are24 gate +14 compile-worker +38 Linux-closure controls, **76 PASS with zero skips**. Compile-worker results use synthetic command/Cargo/ELF records; Linux-closure tests use temporary inert source/metadata fixtures. No query, real worker observation, compiler, Cargo, GPG, Docker, native, namespace, media or host installation actor runs. All fixture roots are empty afterward and no foreign PYC is created.

| Held production file | SHA256 | Bytes/mode |
| --- | --- | --- |
| `build-gate.py` | `f934e4222910dd40c6988445d798da60dea74627d9b2b4e9fa7788acdb2303b1` | 16613/0644 |
| `build-policy.json` | `47e4d58ae2051619a40543588ce1284effbd8ceb424c5aab7f77d01d0efdbf5a` | 1956/0644 |
| `test-gate.py` | `6b1a334bd11270b0116ba8d469be18123f1a7532d119718eee6f149c899c1d82` | 20748/0644 |

Artifacts are held under [`artifacts/reviews/updater-compile-observer-pin-correction-20261012/`](../../artifacts/reviews/updater-compile-observer-pin-correction-20261012/). The test-owner receipt is `997cce6180ed1c8c84e1b52f1f7b53efe5ebcec73805871ce02ace8b528c7d7d`. The first parent source audit looked for the workflow inside source86, but that closure holds the workflow separately. Its failure is retained; the corrected audit compares the exact separately authenticated workflow. No actual source or expected hash was changed to address that harness assumption.

## Root-owned admission and preserved evidence

This worker owns only those three existing files, this new guide and the new artifact namespace. PKGBUILD/.SRCINFO, derived input lock, ready64 map, stage86/source registration, source helper, workflow and its two selected literals are unchanged by this worker. Historical `validation.json` and `recipe-validation.json` are preserved as historical evidence. The original ready map still records the old three file hashes and does not admit the candidate; no stale registration is presented as ready.

Root must rebind current derived recipe/checksum/input-lock/ready/stage/source/workflow identities and obtain independent review before selecting any actual worker/native attempt. The new guide is outside the original86 runtime closure; no new runtime path or dependency is introduced by the correction.

The sealed actual updater7 review and its source/public/model packet remain unchanged. SVG, kernel capability, actual kernel6, KSM and guest4 holds are re-read without promotion of any historical FAIL or unknown cause. Source registration, subsequent gate success, compiler launch, compiled units, package publication, updater lifecycle, M2/16K and performance remain separate unachieved checks.
