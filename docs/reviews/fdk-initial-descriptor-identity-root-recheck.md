# Independent FDK initial descriptor identity recheck

Result: **PASS for the bounded source correction**. The previously demonstrated
initial-query failure followed by different-inode descriptor reuse no longer
adopts or closes the foreign descriptor. This review establishes no registration,
adoption, native build, package, installation, hardware or performance acceptance.

The reviewed author receipt is
`024d2fc3f585c9261a0754979337c310ef41d5a3962b8c46fe5193cbfaff4eb0`.
Its [guide](../workstreams/fdk-initial-descriptor-identity-correction.md) accurately
describes the narrow correction and remaining limits. The prior blocked root
receipt `c52ad7daa213f7395768c6765e54c1676898b8988d7808ce6cdd433256576bb9`
and its counterexample remain historical evidence; this review does not rewrite
that verdict against the older bytes.

Evidence is in
[`fdk-initial-descriptor-identity-root-recheck-20261012`](../../artifacts/reviews/fdk-initial-descriptor-identity-root-recheck-20261012/).
The authentication and harness are reviewable in `authentication.json` and
`recheck.py`; `tests.json` records the fresh selected suites, and `controls/`
contains the independently captured focused red/green proof and sealed receipt.

## Exact boundary

The held helper is `inner_observation.py` at `a5074240…`, with test
`d62929e72…`. Parent `inner_evidence.py` remains `bdbef4cb…` and its test remains
`7cc9b798…`. Live source pins match the independently copied 136-file graph.
Against the prior root peer's final capture, only the two helper files differ;
the other 134 are unchanged. Only `close_owned` changes its AST; all other
top-level helper function/class definitions are identical.

All 257 records in the new author packet, all 363 in the former author packet,
and all 561 in the prior root review authenticate with their recorded bytes,
modes and SHA-256 values, as regular single-link files. They authenticate again
after the fresh suite replay. Existing source, recipes, maps, workflows and Git
were not edited for this review. The separate KSM code-custody correction remains
held unchanged: receipt `37188259…`, all 360 artifacts, its two source files and
guide reauthenticate. Its adoption is not claimed.

The initial review harness compared against an intermediate former-author
capture whose parent pins predated that author's final packet. It stopped at a
delta assertion before tests. `harness-diagnostic.md` preserves the correction
to the authenticated c52ad7da final capture; no primary source changed.

## Causal result and fresh verification

For a fresh entry, only successful query slot zero establishes identity. Any
other initial acquisition error retains `identity: None`; later successful
queries, including across repeated calls, skip close. EBADF alone can retire
unknown ownership without a close. The existing three query/close slots remain.
Known identity continues to permit matching-query retries and refuses a changed
identity. The same first ordinary error and first control remain recorded, and
existing active business/control exception priority is preserved.

The focused worker independently authenticated and copied old and corrected
sources. Its 22 finite cases pass their expected outcomes: **four RED cases**
reproduce the foreign close against old `dec7eeeb…`, and **18 GREEN cases** pass
against corrected `a5074240…`. Both the exact prior mocked-table reproducer and
actual private different-inode FD reuse cover initial EIO and inert
`KeyboardInterrupt`. Repeated healthy queries against the reused descriptor
leave identity unknown and the foreign FD open. Fixture teardown occurs after
measuring its identity and live contents, rather than being mistaken for the
helper's close.

Positive controls retain known-identity recovery within three slots, changed
identity refusal, unknown EBADF retirement, exact first-error/control identity,
and active exception priority, including retention of both exact ordinary and
control objects with the original business/ordinary cause chain. A failed unknown entry keeps `write_failed`,
cancellation and refusal sticky across fresh recorders while preserving the
first compiler-nonzero fact, return code 7. Later EBADF retirement does not erase
those durable refusal/nonzero facts. These controls use mocks and owned temporary
FDs, with no actual signal, compiler or native actor.

The coordinator's fresh independent 136-file capture passes **142 tests**, with
zero skips and PYC files: helper 25, mocked compiler-call models 24, unchanged
parent reader 26, worker 27, public projection 40. Source hashes are unchanged
before/after. Existing suites include bounded handled self-signals, child Python,
Unix IPC and fake-Docker fixtures; compiler/daemon calls remain fixtures. No
actual native, Docker, compiler, makepkg, GPG, installation, namespace, network
or service actor ran.

The older 44-control replay has **three intentionally changed expectations**:
`query-before`, `control-query`, and `control-over-business` now require retained
unknown identity and zero authorized close. Their former recovery-by-later-query
expectations are obsolete. The authenticated author replay records 41 unchanged
expectations and three revised ones; this recheck freshly runs the selected 142
tests and focused 22 cases, and does not claim a fresh replay of all 44 historical
schedules.

## Remaining work and limits

Persistent faults can retain an open FD; production recovery is not proved.
Same-inode reopening does not authenticate an FD generation. Known-identity
query/close remains non-atomic and requires cooperative ownership. The unmasked
allocation-to-registration interval remains unchanged. The finite causal cases
close the c52ad7da demonstrated schedule, not those broader races.

The held public consumer still calls `validate_workers(workers)` without
`require_complete=True`. The mandatory modern-inner completion gate, recipe's
23 source bindings/checksums, reviewed maps, workflows, dispatch and admission
remain separate coordinator work. This review does not edit or certify them.

Historical actual FDK8 remains **FAIL at exit/attach 4**, with inner
function/compiler invocation cause **UNKNOWN**. No new native execution or cause
attribution follows from this source correction. Native rebuilds and cleanup,
package reproducibility, ABI/AAC integration, lifecycle, Asahi/exact-M2 behavior,
publication terms and measured performance remain unfinished acceptance work.
