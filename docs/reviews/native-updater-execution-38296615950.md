# Actual updater run 38296615950: independent review

The actual run remains **FAIL**. Its new, bound worker diagnostic establishes the first inner predicate as `entry-guard / unexpected-mount / ValueError`, before controller validation or compiler launch. Cleanup and recovery report PASS independently. No native package build pair, package acceptance, installation, hardware or performance PASS follows from this attempt.

## Source and retained-byte authentication

The reviewed source is committed `4748a5d5f4d2d649c1b397baaa63b087d3658ed0`, retrieved using read-only Git blob queries rather than the current worktree/HEAD. All 86 selected files (4,180,952 bytes) were independently captured with their committed object hashes, SHA256 and executable modes. The 64 package rows, eight root rows, ten stage files, ready map and three supplemental helpers close exactly; no PYC was loaded.

| Binding | SHA256 |
| --- | --- |
| READY | `84eb3a020ed0cca3fe977feabc2b18bcaf6c6ae3811a5df5129c700ed9d8012f` |
| Stage | `3b38a7de9adea343dbc3cc08e3909e23b840ca12f0211e40e38afd7172b92012` |
| Collector | `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb` |
| Workflow | `52320dfb23f192b3d22a1161e58cc0c8fcb65464f29688457461699af2516ba4` |
| Diagnostic helper | `2bde1dc53bc63fc8a536265100ed07ede16d3b96faa37af5054b977984c73048` |

The downloaded logs ZIP is 120,169 bytes, SHA256 `dd3edad0942bcfd0481cbd42faec7b63734a530e866b086f01f8ca8bece34897`. Its ten regular log members expand to 264,353 bytes. Finite size/member bounds, canonical paths, duplicates, encryption/type/mode refusal and full CRC checks passed before interpretation. GitHub ZIP entries have unspecified Unix mode zero; decoding created ordinary reviewer-owned files rather than trusting those attributes.

Three log-delimited base64 bundles were separately checked against their announced lengths and SHA256, then bounded gzip/tar decoding verified 15 regular JSON members total, exact bundle-relative paths, unique names, finite metadata and no links or arbitrary PAX fields. Their hashes are:

| Bundle | Bytes | SHA256 |
| --- | ---: | --- |
| `guarded` | 34,896 | `abdf57ba320a1ab8f7b1a568487fc46f52ccaefa444d1bacdb20c9cf5130f4e5` |
| `terminal-public` | 1,205 | `a76806d139e6f2cd47f7f3fb10966fae33e5c0a058c02f2c2f646cb4e4251da0` |
| `recovery-terminal-public` | 844 | `c63d42e8300b9ca68035076df1919aeab0426080311e449d8552dfbbd57a9d76` |

The logs identify the hosted `ubuntu-24.04-arm` runner and checkout of the exact source commit. The printed bootstrap and native shell bodies match the committed workflow byte-for-byte after removing only timestamp/color framing. The freeze step completed before the native step, which actually returned exit 1. The recorded outer controller SHA agrees with both terminal groups.

## Actual observations and authority

The terminal is finalized FAIL, `failed_phase: native-pair`, `runtime_reason: process-failed`, `runtime_returncode: 1`, `native_compilation: NOT RUN`, and cancellation false. Acquisition reports 527/527 PASS, zero pending/fail. Materialization reports PASS, phase complete and 167 completed registry sources. The exported 354-package inventory reconstitutes its original lock hash exactly and agrees with bootstrap and worker controller input.

Worker 1's parent provenance reports a launched worker, returned client exit 1 and a separately inspected owned container State: exited/code 1, running/paused/restarting/dead/OOM false, no state-error text. Its four-field diagnostic group is BOUND. The 17-field diagnostic has status FAIL, first failure `entry-guard / unexpected-mount / ValueError`, `controller_validated: false`, command null, compiler launch/return/acceptance false and compiler return code null. The source-issued operation identifies the guard boundary; it does not identify the unseen offending mount path.

The captured modern projector binds this diagnostic to the parent's controller, image, entry source and validated State; it equals the nested parent diagnostic exactly. The entry hash matches the committed source. The parent raw-capture SHA is `f52f19ce0b1765b74f37dedc389e9c79ea9ca56f9ee800d3ad65f4c5753819d6`; the 803-byte formatted selector SHA is `e34ff9218ba6ad96f6f496add0bf29b5ec79312ce1a7366c38ad8f3acbe84bfc`. Re-encoding the projected object with the exact committed helper's encoder produces 707 bytes and independently matches the raw-capture hash. The original private file itself was not retained. These two hashes bind distinct serializations and must not be equated.

Worker 1's returned cleanup flags positively attest attempted cleanup, removal, absence verification and completion. The stage reports cleanup PASS, private-data removal true, retention within budget true, and process/Docker/GPG/private cleanup PASS. Daemon disposal remains NOT ATTESTED. Recovery reports PASS with `native_compilation: NOT ATTESTED BY RECOVERY`; it cannot override the initial failure. No worker 2 group, comparison, entry-success, compilation or package proof is present. Their absence grants nothing.

## Independent consumer checks and source defect

Pure function ASTs were extracted from the exact authenticated workflow body (SHA256 `44ebb68d805b6d66bf7b237723b5b60d1f6ba980f9028c5e4dbd8967a2e01af5`) and executed against the captured committed stage/projectors. Actual manifest membership/hash/byte counts, projection metadata, terminal/recovery schemas, finite diagnostics and all present projected receipts passed. The authenticated generic credential guard separately passed all three public groups. This replays the bounded public consumer functions, not the complete native job or its private controller/runtime.

Twelve causal negative controls refuse: actual failed-pair success, foreign diagnostic controller/image/entry, unknown fields or operation/predicate text, boolean return/cancel values, promotion of the failed diagnostic to parent native PASS, partial parent groups, and missing historical groups as modern success. Historical pure FAIL projection remains readable without a modern PASS fallback.

A concrete source compatibility defect is independently reproduced. `worker-metadata.py` excludes `/dev/mqueue` from `PSEUDO`, while the launch uses ordinary private IPC without an override. [Moby v28.0.4 DefaultLinuxSpec](https://github.com/moby/moby/blob/v28.0.4/oci/defaults.go) defines that default mount as `mqueue` with `nosuid,noexec,nodev`. An otherwise accepted bounded source fixture rejects this single additional standard row with exactly `unexpected-mount`. The same source omits the default masks `/proc/timer_stats`, `/proc/sched_debug`, and conditional `cpuN/thermal_throttle`; corresponding finite fixtures reproduce the refusal. These are portable source/API reproductions, not observations of this run's private mount table. The actual offending row and hosted Docker implementation/version remain unexported, so attribution to a particular mount is **UNKNOWN**.

The narrow next correction is to review and admit exact standard runtime rows with explicit filesystem/flag/type/path constraints, preserving nested mounts, root/input/output custody, all capabilities, no-new-privileges, resource bounds and all original build/acceptance gates. Any remaining host-dependent row should receive a finite source-issued subpredicate rather than exported raw paths or blanket allowlisting. No correction was implemented by this review.

## Limits and retained evidence

All four older failed attempts retain their historical FAIL and unestablished inner causes; this newly observed predicate does not diagnose them retrospectively. The private original bundle referenced by the terminal is not the newly repackaged log bundle; no compressed-byte equality between those distinct archives is asserted. Public content/hash/schema validation and the actual source-bound publication path are verified separately.

Reviewer artifacts live under `artifacts/reviews/native-updater-38296615950-root-peer/`: exact Git source capture, bounded decoded logs/bundles, `capture.json`, the extracted consumer, `verification.json`, and `mount-compatibility-probes.json`. Review scripts perform read-only Git capture, bounded local parsing/projecting and inert modeled guard calls. No Docker, native worker, compiler, package/GPG, installer, system mutation, shared source/map/workflow or Git edit was performed.
