# Repository native handoff phase02: independent root review

October 12, 2026. **FINDINGS OPEN: two P2 corrections are required before this
review can clear native adoption.** The fresh suites pass; that does not close
independently reproduced deadline and source-custody gaps. No production source,
shared source map, workflow, authority, Git or dispatch was changed in this review.

The reviewed checkpoint SHA256 is
`7e3d4d5718138987f99bfc2540ef15e8bd59e5fca1b41cf0b33233a9bb1c56ba`.
All twelve referenced artifacts and all nineteen final captured sources match
the checkpoint/capture-map byte hashes and modes. The proposed seven-runtime map
is `9e6aa90e3cf9f6fc65bb8d410ec5acdbdfe2024f0bd1462cd51d52a5479d085e`.
Independent evidence and exact source identities are under
[the review namespace](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/authentication.json).

## Required corrections

1. **P2 — cleanup exceeds the enclosing allowance.**
   [supervisor.py:375](../../scripts/port/repository-native-handoff/supervisor.py#L375)
   starts a fresh `now + cleanup_seconds` cutoff after work, independently of the
   clipped role/job deadline. The declared base330 includes cleanup and the added
   envelope1200 is clipped to the existing job. A real harmless sleeping owned
   child, with an80ms role deadline and120ms enclosing deadline, remained alive
   after the enclosing cutoff when the first kill boundary was given an explicitly
   injected160ms delay. It was subsequently killed and reaped, with cleanup PASS
   and overall FAIL. This proves a deadline-envelope gap, not an expired PASS or
   a production-load measurement. Reserve teardown within the existing allowance,
   or explicitly select a larger external envelope; preserve mandatory cleanup.
   [Reproducer/results](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/supervisor-peer/probe-results.json).
2. **P2 — original source modes are lost at the postexecution boundary.**
   [entry.py:179](../../scripts/port/repository-native-handoff/entry.py#L179)
   compares only returned bytes after the context, although the original159 rows
   include expected modes. Both coordinator and independent peer reproduced a
   same-byte0644-to0755 mutation being accepted with159 inert modeled source files.
   Initial mode drift, later byte drift and a later symlink correctly refuse.
   Recheck the externally authenticated modes alongside bytes under the existing
   verification deadline. This shows missing mode custody, not altered code bytes
   executing. [Coordinator controls](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/parent-probes.json)
   and [independent controls](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/supervisor-peer/entry-custody-results.json).

Standalone supervisor callback grants also contain only module/path/SHA; a mode
change after construction survives its per-role source check. The entry factory
checks all seven modes once, but the returned supervisor does not repeat that
complete mode guard per role. Include this boundary when correcting source
custody; these are trusted captured callbacks, not an untrusted-code sandbox.

## Checked behavior and limits

| Check | Independently observed result |
| --- | --- |
| Fresh exact19-file handoff capture |120 tests PASS, zero skips |
| Fresh frozen provenance capture |24 tests PASS, zero skips |
| Exact seven-source CLI preflight |PASS; actors/native admission NOT RUN |
| Transport probes |14 assertions PASS, zero skips; actual harmless children, pipes and socketpair |
| Supervisor focused suite and controls |37 tests PASS, zero skips; six additional controls, including reproduced gaps |
| Assembly probes and broker rerun |12 probes and17 broker tests PASS, zero skips |

All suites use isolated Python with bytecode disabled and ResourceWarning treated
as errors. Passing probe assertions include detecting the documented gaps; they
do not mean every negative input was refused. The coordinator probe initially
had a Python context-manager syntax error; that failed harness log is retained,
then the corrected unchanged-source probe passed. No PYC or live fixture residue
is retained.

Imports, CLI preflight and constructors start no Docker/native actor. The loader
compiles authenticated captured project bytes, checks exact closure/modes,
no-follow single-link source paths and standard-library origins. The entry
launcher itself still needs external source/mode authentication. Construction
and binding do not contact the daemon. Runtime transport pins the CLI/socket,
private tool-state directories and fixed environment; literal create grammar
limits operations to its registered namespace/CID. Separate finite stdout/stderr,
partial ACK writes, incomplete ACK, third ACK, timeout, cancellation, forced
cooperative-zero refusal and postexecution guard refusal were exercised with
harmless Python children. Producer checkpoints retain ordered canonical frames,
nonce/digest binding and durable private ACK custody.

Role supervision registers the forked leader before callback entry, binds
PID/start/PGID, tracks descendants including setsid escapes, reaps owned children
and restores handlers/subreaper/descriptors. A single-thread parent and no-existing-
children boundary refuse ambiguous ownership before fork. Failure/cancellation
is sticky, outputs/results are finite, and natural zero plus cleanup plus the
postcleanup deadline check are required for PASS. Deadline correction above is
still needed to make the execution envelope match its documentation.

The inspector rejects observed network-host and cgroup-host mutations, matching
its explicit network-none/private-cgroup policy. It accepts12 modeled PID/IPC/
UTS/user-namespace overrides or malformed field values because those fields are
not checked. Literal create argv cannot request those overrides. The workstream
does not separately define those fields, so this is additional custody hardening,
not a demonstrated violation of its explicit namespace grant or a Docker escape.
Before extending the claim, define/enforce expected daemon defaults or explicitly
limit it to the fields checked. [Transport evidence](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/transport-peer/report.md).

## Input and historical custody

Direct `terminal_inputs` controls cover a794-path positive and1025-path refusal,
index/byte tampering, reserved names, cancellation/expired deadlines, links,
private bytes and nonfresh output. Authority remains PENDING for external issuance.
The map counts remain separate: authority793/794, baseline provenance241,
base receiver689 and crypto128. Rehashed historical inputs supply112 public files,
222 original build/recipe bindings,258 projected paths and15 required aliases plus
index. The682 ALPM desc/files,688 observation files and689 receiver total are
source-derived future requirements; these missing actual observations were not
created or recovered. The authority1024-file cap does not permit dropping them
or combining all trees. [Assembly evidence](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/assembly-peer/report.md).

The old checkpoint `2e42f08787c9f07fdf574ba7a2db6263df3bf0af9f5741800befa425834b796e`
and its fifteen bound artifacts, original159 source bytes/modes and49c producer
are unchanged. The original eight clean environments/four baseline comparisons,
341 inventory and four original packages remain historical baseline evidence.
Exact generic policy `ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e`
and MIT license51a352 remain unchanged, with supported_models empty. Initial
historical integration PASS remains distinct from broader FAIL and admission
NOT RUN. [Preservation checks](../../artifacts/reviews/repository-native-handoff-phase02-root-review-20261012/preservation.json).

Current provenance42d18 remains a separately held delta against its older
registered pin; root must adopt its complete collector/successor closure. No old
raw argv, fullCID or checkpoint custody is reconstructed. Complete source
registration, external authority and a new actual same-job packet remain pending.
Actual Docker/GPG/native execution, phase acceptance/restaging, installation,
M2/16K graphics, performance and full-port acceptance were not run or claimed.
