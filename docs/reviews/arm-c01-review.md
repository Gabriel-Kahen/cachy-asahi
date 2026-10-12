# ARM-C01 independent review

October 12, 2026. Source/local mocked controller and stage-adapter review;
native execution is NOT RUN. This reviewer owns only this
document. Updated roadmap and package inventory were read. No source, manifest,
CI or Git state was edited; no upstream code, Docker, package tool or native
build was executed.

## Final disposition

**Ready for controlled native source execution at the final freeze; no open
source-review blocker within ARM-C01's documented correctness-only scope.**
Final lock SHA256:
`98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5`.
Native execution, actual native cleanup, 16K execution, both physical M2 Airs and
performance/energy acceptance remain **NOT RUN**. Source readiness is not native
acceptance or completion of R1–R5.

## Resolved fallback-cleanup cancellation/status finding

At candidate lock `729d172a2e52562779d87c41515c59be6329e74d6a11aebd7a84b3714a3a5381`,
`stage.py:337-373` catches ordinary failures around `cleanup_trial()` but omits
`arm.Cancelled` and `KeyboardInterrupt`. `cleanup_trial()` uses `Commands.run()`,
whose cleanup/receipt phase records deferred cancellation and raises
`arm.Cancelled`. That exception can escape the stage's finally block before its
authoritative result and manifest-bound public status are written.

Bounded reproduction `/tmp/arm-c01-cleanup-cancel-review.py` uses the stage
fixture's real finalization path, with subprocess/signal tripwires and a mocked
successful delegate. Injecting `arm.Cancelled` from fallback cleanup leaves:

```text
fallback cleanup cancellation escapes run_stage finally
result.json exists: False
public-status/result.json exists: False
delegated trial result status: PASS
```

This does not execute Docker or prove an actual container leak. It demonstrates
loss of required failure/status diagnostics at an implemented cancellation
boundary; cleanup absence is also not established in this path. Required
correction: preserve/defer cancellation through final cleanup, mark cancellation
and uncertain cleanup as FAIL, and still produce bounded failure projection and
authoritative status. Add a regression injecting cancellation during the
fallback command's cleanup/receipt phase, not only during trial execution or
status export. Caller must continue requiring both exit zero and final stage
PASS; the delegated trial's PASS cannot substitute for final stage acceptance.

The final adapter catches both `arm.Cancelled` and `KeyboardInterrupt` from
launcher/fallback cleanup and continues bounded teardown and diagnostic export.
Fallback command cancellation is recorded; interrupted before/after queries
have one bounded retry, and an interrupted removal still proceeds to the
absence query. Interrupted cleanup always yields stage FAIL/cancelled with
explicit uncertainty, even when subsequent container absence is established.

Independent `/tmp/arm-c01-cancel-freeze-review.py` reran the exact prior
successful-delegate/fallback-cancellation scenario for both exception types.
Both now return exit 1, retain the delegate's distinct PASS record, and produce
authoritative local/final/public-status FAIL records with matching exporter
manifest hashes; safe evidence export succeeds. No container absence is falsely
claimed for the injected whole-cleanup failure. Four further independent mocked
cases cancel the before query, removal, after query and both before queries.
Teardown/recheck continues where possible; the repeated-before case terminates
boundedly with absence unverified. All six checks PASS, with real subprocess and
process-signal tripwires. No Docker cleanup was executed.

The final freeze's six source/test hashes and modes plus the pinned unchanged
text exporter were independently checked against the actual files. Full final
local aggregate: **91 tests PASS**, no skips, 3.309 seconds. The earlier 89-test
recheck below applies to the prior candidate; core controller/corpus hashes are
unchanged by this final cleanup correction.

## Corrected receiver and adapter recheck

All **89 local tests PASS** in this review (3.336 seconds, no skips). The suite
uses temporary fixtures/mocks; Docker/package/upstream/process-signal tripwires
remain in place. Independent final reproduction
`/tmp/arm-c01-final-independent-review.py` established:

- Complete synthetic control: **485 exact ordered commands**, four builds,
  336 cross-decodes and 32 rejection records accepted.
- The original unrelated-command receipt now refuses. An empty source license
  with updated self-hash refuses against pinned source bytes. Substituted
  heldout bytes/role and updated manifests/checks refuse independent source
  derivation. A decoded stdout/checksum contradiction also refuses.
- The complete control went through actual local `project_evidence()` and the
  pinned generic text exporter: PASS. The separate actual local development
  archive contains exactly **38 approved files**; private/input/cache/image
  trees are excluded. This is synthetic exporter execution, not native output.
- Independent read-only **341-package base** and **345-package installed-image**
  controls pass without creating stage output. Missing 345 handoff and a wrong
  READY source commit with refreshed file hashes refuse.

The receiver now checks hash-bound native guard/environment, exact argv/cwd/env/
exit/stream dataflow, tool/inventory records, generated configurations, effective
baseline/LTO flags, retained ELF/load/LTO observations, pinned source notices and
README-derived corpus/roles. It reproduces corpus derivation locally without
executing upstream code. Both variants share per-Make-output-target random seed
control; no native reproducibility or performance result is inferred from it.

The adapter freezes six source/test files and the unchanged text exporter. Its
six-file 345 handoff binds image/commit/inventory, original versions/payloads,
full restored image configuration and prior container removal. Exact base input
authority comes from the caller's accepted hash-bound inventory; cardinality
alone is not architecture/platform acceptance. It delegates to the finite
read-only isolated runner, independently reverifies raw results, queries/removes
only the fresh nonce-owned container and checks absence. Raw/trial/source working
trees stay local. Selected text and the separate development archive have
distinct bounded exports; authoritative final status is exported separately and
late cancellation reseals it. The final cancellation correction above closes
the last reproduced review finding.

The separately reported derived-image verifier alias-device/socket defect is
outside this experiment review. ARM-C01's own guard scans device/socket types
and identities; this review does not conflate the two contracts.

## Resolved historical finding: incomplete receiver evidence could pass

`scripts/experiments/arm_c01.py:303-363` verifies a nonempty collection of
successful command labels and matching log hashes, but does not require the
actual experiment command set, argv, exit codes, source/target links or ordering.
It also does not consume `environment.json`, bind generated configuration files,
verify declared compiler/linker flags, or revalidate the retained ELF/LTO
observations. Those checks occur inside the runner but are not established by
the host's receipt verifier. The current passing receiver test fixture has only
one unrelated synthetic command and no environment/build/LTO/ELF evidence.

An independent temporary reproduction reused the synthetic receiver fixture,
with its subprocess/process-signal tripwires enabled. It set the only command
to `name: not-an-experiment-command`, `argv: [false]`, `exit_code: 42`, retaining
the PASS labels and actual log hash. `verify_result()` returned PASS. The fixture
had no `environment.json`, generated configuration files, ELF observations or
LTO command evidence. No command was executed by this reproduction.

Required correction: define the complete expected command schema/set and bind
each receipt to its operation, exact argv, expected exit behavior and relevant
build/corpus/decoder identity. Require the inventory/tool/build/configuration,
ELF/LTO and all encode/decode/rejection command records. Derive acceptance from
those retained records and their bound bytes, with duplicate/missing/unrelated
commands refused. Validate the environment/guard record and input contract,
expected baseline/LTO flags, generated configuration hashes and retained binary
observations. Source and stage adapter must share this strict verifier; an export
hash alone cannot reconstruct missing execution evidence. Add negative
regressions removing any mandatory record and substituting an unrelated
successful label or contradictory exit code.

## Resolved historical finding: retained input/notice self-assertions

The same receiver requires `LICENSE.txt` to exist as a bounded regular file but
does not bind its bytes to the pinned source license. The reproduction emptied
`baseline-1/LICENSE.txt`; verification still passed. Generated configuration
references in actual build receipts likewise are not consumed by the verifier.

The receiver requires nine corpus filenames and checks their self-declared
sizes/hashes, but does not reproduce corpus bytes from pinned source README and
the hash-bound generator or validate declared roles. The reproduction replaced
`heldout-source.bin` with unrelated bytes, changed its role to `train`, updated
both self-declared corpus manifests and the corresponding decoded hashes, and
again passed. This does not demonstrate a native compiler failure; it shows
that the receipt verifier cannot establish the claimed exact experiment inputs
or future train/held-out separation from those records alone.

Required correction: bind the retained notice and source-derived heldout bytes
to the reviewed source archive; validate or regenerate the expected corpus using
the authenticated generator/runtime contract, including file roles. Verify each
generated configuration reference against its retained bytes. Add explicit
notice/configuration/heldout/role drift regressions. The stage adapter must not
accept these self-consistent substitutions as the reviewed trial.

## Source behavior and executed checks

- The inside runner requests four clean source extractions: baseline and LTO,
  twice each. It runs configure/static build/teststatic, retains the static
  archive/example/minigzip, and compares artifact hashes within each variant.
  Baseline uses `-fno-lto`; the candidate adds `-flto=2` and
  `-Werror=lto-type-mismatch`. Archive section output must contain LTO IR exactly
  for the candidate variant. Readelf checks AArch64 ELF64, 16K-compatible load
  metadata and no writable/executable load segment; 16K execution stays NOT RUN.
- The correctness matrix has 336 positive cross-decoder checks: four encoders,
  seven non-corrupt corpus inputs, three levels and four decoders. There are 32
  corruption-rejection records: two corrupt inputs and four decoder identities
  repeated under each build identity. The receiver checks completeness and
  decoded hashes, but currently fails to link this matrix to actual commands.
- The pinned zlib archive SHA256 was verified by read-only inspection:
  `bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
  Source inspection confirms static/teststatic targets and minigzip's gzread/
  gzclose error checks; truncated gzip input sets Z_BUF_ERROR and gzclose_r
  propagates it. No upstream configure/build/test code was executed locally.
- The host refuses x86/root/set-ID controllers, Docker endpoint overrides,
  unpinned images/input hashes, unsafe output paths and nonnative daemon/image
  architecture. It supplies read-only root/input mounts, private tmpfs, dropped
  capabilities, no-new-privileges and no network. The inside guard checks these
  observed mounts, owner/modes, native architecture, loopback-only interfaces,
  disallowed sockets/devices and the fresh nonce before input/output operations.
- Command groups are tracked, cancellation signals restored before child exec,
  groups terminated/reaped and cleanup outcomes recorded. The controller removes
  the named container after execution/failure and overrides PASS on cleanup or
  deferred cancellation failure. Mock regressions cover these paths. Actual
  native process/container cleanup has not been exercised by this reviewer.
- `python3 -B -m unittest discover -s scripts/experiments -p 'test_*.py' -v`:
  **54 PASS**, all temporary/mocked. Independent reproduction script:
  `/tmp/arm-c01-independent-review.py`; no real subprocess or signal was allowed.

## Snapshot and limits

| Input | SHA256 |
| --- | --- |
| `scripts/experiments/arm_c01.py` | `b725639885740505a04fbdcab2e629e3201afb09cf948ac997c1309d91fe36cf` |
| `scripts/experiments/corpus.py` | `dbaf951adbb91d6769f40f8fb18c13044a42a3b5db11b4ad7d1f44afbed9ad8c` |
| `scripts/experiments/test_arm_c01.py` | `f3cb4674f28691367f1618643ca0cba0ae1f3da52ce294461c80ba9e35d264fc` |
| `scripts/experiments/test_corpus.py` | `c0d60f1006d158e8162a8fc78871be895e9d46e5098733f4a0321d7eac63f5a8` |
| `scripts/experiments/stage.py` | `e6eaf7200d97c0ff65f1d652b85987e2c00a5c60745c870e996cf90fd9b62b70` |
| `scripts/experiments/test_stage.py` | `993e27f82bd742e4a5d5395dd045dc0ee8ee64b640104397115114c14568ae76` |
| `scripts/experiments/stage.lock.json` | `98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5` |

Status: **all reproduced findings resolved; controlled-native source readiness
established at the final freeze**. No native ARM-C01 build or execution, native container cleanup,
physical M2/16K testing, measured optimization gain, release selection or R2/R3
acceptance is established. Command elapsed times are operational receipts; they
cannot support a performance comparison or M2 improvement claim. This remains
a correctness experiment toward mandatory R1–R5, not full-port completion.
