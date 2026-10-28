# Held composed parent: independent source review

**Disposition: source revision required before coordinator admission.** The held
parent receipt `4836091ac8978538608735bcf573af51fa59758d329fad549ae461dc3a1c54f2`
and owner deadline receipt
`28863705435d986bce1de4ce4b464e05069d082e6e4c9cd05688e4f2809f75c7`
authenticate. Fresh source-only replay passes parent175 and owner216, but a causal
probe demonstrates an uncovered composed recovery deadline omission. No actual
clock grant, native/crypto acceptance, ARM build, target integration, hardware or
performance acceptance is established by this review.

Evidence is retained under
[`broader-composed-parent-root-peer-20261013`](../../artifacts/reviews/broader-composed-parent-root-peer-20261013/).
This review owns only that directory and this document. The updated outline,
roadmap, package manifest and upstream inventories were consulted. R1–R5 and
M5–M9 remain required; this tooling review completes none of them.

## Finding: forward the captured J through failure recovery

**[P1] `Development.recover_public`, held controller.py:375–394.** Both ordinary
stage failures and KeyboardInterrupt invoke this helper from lines363–369.
Its KSM/ARM branch calls `base_stages.recovery_public(name, output)` at line383
without forwarding `self.deadline`. The final held owner interface is
`recovery_public(stage, output, *, deadline=None)`. Omission therefore selects
its legacy path. That path can inspect JSON, hash/copy/validate package or ARM
material, and retain failure evidence without the composed J checks.

[`recovery_deadline_probe.py`](../../artifacts/reviews/broader-composed-parent-root-peer-20261013/recovery_deadline_probe.py)
first records both KSM and ARM calls receiving None despite a finite captured J.
A second causal check uses the actual held owner implementation with a private
JSON status fixture: directly passing an expired J refuses with
`stage-deadline-exceeded`; the actual parent helper with the same expired J
retains that status. The fixture establishes deadline bypass, not successful
stage or actor authority. No actor, callback grant or native result is created.

The correction should preserve legacy invocation with no added keyword and pass
`deadline=self.deadline` in composed mode. It should check that same J before and
after all recovery selectors and while accepting retained paths, including the
finite virtual/client branches. Virtual `public_paths(output)` has no deadline
keyword and only fixed directory selectors: enforce its parent boundary rather
than pass an unsupported keyword. Do not select a new recovery budget or revive
expired J. On refusal, retain authoritative failure/cancellation and report
failure retention failure. Regression checks should distinguish legacy kwargs,
explicit-J forwarding, expiry before recovery, expiry during selectors, and
first-failure/cancellation preservation.

The shared owner APIs `recovery_public`, `retain`, `finish`, and `cleanup_ksm`
already accept optional absolute deadline. KSM's120-second cleanup phase is
clipped to J; common command cleanup retains its existing grace/10-second caps
within J. Parent ordinary/cancellation recovery is the omission found here.
Client command/read/status operations explicitly receive J. Owner finalization
already uses J and finite first-cause failures. Parent terminal status persistence
is distinct from owner evidence recovery and cannot be construed as a new owner
execution allowance.

## Authentication and selected source

Independent authentication verifies all258 parent source rows in both held-source
and held-snapshot, exact bytes/modes, total5,462,000 bytes and12 metadata pins.
The exact six owned parent files agree with source-files-held.json and receipt.
All six final owner deadline sources are selected byte for byte in that same
parent capture, rather than intermediate implementations:

| Source | Final SHA256 |
| --- | --- |
| common.py | a9fd67f8ca192a5d27f95377fae3804a2ae69f6675440b1104c4411a35dc8a12 |
| test_common.py | a10c674af6608a32f2abe65302173e5bdbd2cacb31048db327e96c89b2a281ca |
| base_stages.py | ce4fb0fea1178b515fade95ea33fd1ab6b380ebc87feb3a70dd4198edd854fb8 |
| test_base_stages.py | 32d8ba27bda35a5d99114a848ab77382b7d7be2fc26f97463f66a96433e64f58 |
| virtual_stage.py | db35ff2fa75a845c141376eb2441b7ac46bb9caeae3a35ae0e66f2dacb566038 |
| test_virtual_stage.py | 6acfd60e5b20a69204f0cbf186f83cd0112ed489a6bc4629a10f15619c49a4c7 |

The owner's47 dependency rows and192 indexed artifacts authenticate, including
historical RED/correction evidence; both guide pins and the parent's historical
175 log authenticate. Historical test-preservation assertions remain their
sealed evidence, separate from this fresh replay.

Actual held `freeze_composed` independently reconstructs prospective packet
`fd525bca07ad18ac14e37b60b8e57f6b8075569cdb8fc082f975a9dda4bd76b6` from the independent
capture. The original159 source/125 fixture maps and recipes4/inputs71 remain
locked. Generic policy bytes retain ff424921…0365e/666 bytes at the future real
policy path. Maps remain the selected7/7/5 source domains; installer4 and future
Zsh consumer5 are unselected, while Zsh package12 are source-only.

The selected capture's unfiltered original scanner sees171 rows and refuses
`initial-source-map-drift`; it intentionally excludes installer4 from the full
checkout. My first scanner control incorrectly expected175 on the selected
capture; its harness diagnostic is retained and corrected. The mutable live
checkout's actual scanner refuses earlier with `source-python-cache-refused`,
so this review does not claim a freshly observed175 live scanner count. Root
must re-establish its cold full-root175 refusal separately, without filtering
it into159. No foreign cache was removed or included in this capture.

## Source authority boundaries inspected

The composed constructor checks external grant/runtime bytes and callback
identities before allocation. It creates captured Sources/Session/RootCallbacks,
binds unchanged19 argv and adapter output, and uses one actual Session.execute
and original native.main. Actual CLI callback namespace must be __main__.
Session's160-file original view has exact directory and file rows, inode/mode/
owner/source bindings, suspended loader context and native/run/execute frame
custody. Original context checks and broad source module/function/code/global/
default identity guards are retained; labels or arbitrary PASS dictionaries do
not create an accepted Session.

The closed12-field clock receipt binds CLOCK_MONOTONIC boot/time namespace,
source/workflow commit, run/attempt, nonce and issuer. Six bootstrap environment
values match six CLI values. J is selected before grant/source/copy work as
`min(workflow_deadline-120, entry+10080)`; active enclosing alarms refuse. The
held `CLOCK_ISSUER_SHA256=None` intentionally prevents actual issuance acceptance.
Root's real reviewed issuer, workflow/bootstrap and committed Git proof remain
unregistered/unverified here. E remains `min(J, broad_return+1200)` with work E-60
and original cleanup30 within60; publication is a separate actor-free120 maximum
clipped to the workflow end. Numeric budgets and blocking operations do not
prove hard real-time completion.

Dedicated phase_public is immutable return-only descriptor bytes after actual
guarded restage, cleanup, durable status and late-cancellation checks. Parent
capture checks actual retained frame/controller/Session identities and status/
grant bindings before bounded exact-map byte custody and archive publication.
Parsed PASS alone is refused. Actual RESULT schema33, lineage15, three distinct
A/B/verifier certificate roles, A7/B8 source lineage and four archive identities
remain structurally checked. Crypto/input authority remains the earlier actual
Session gates; these source fixtures do not independently rerun or prove it.

The generic privacy guard remains unchanged. Exceptions are exactly the closed
empty TEST GPG --passphrase argv shape and source-defined REVOKED, SNAPSHOT_ONLY
and VALID_AT_OBSERVATION semantic slots. Arbitrary credential keys, raw log
exceptions, unknown fields, noncanonical JSON, links, extra files, altered byte
maps and forged return authority refuse. No new generic credential allowlist or
live actor success was supplied.

## Fresh replay and limits

| Frozen-source replay | Result |
| --- | --- |
| Parent controller44 + packet33 + handoff81 + unchanged authority17 | 175 PASS; zero errors/failures/skips |
| Owner common27 + base59 + virtual130 | 216 PASS; zero errors/failures/skips |
| Causal recovery forwarding and actual owner expired-J probe | Omission reproduced; revision required |

Each suite runs in a fresh Python process using project-owned TMPDIR. Audit
hooks allow only private Python fixture launches and Unix IPC; Docker/native/
GPG/package/compiler/image/debugfs/tool/network actors are denied. All258 source
rows reauthenticate after every replay; captured source has no PYC. Counts are
separate rosters; peer subsets and historical runs are not added to them.

The first parent run retains174 passes plus one sandbox EPERM on the existing
harmless socketpair sendall fixture. The exact same capture passes175 with the
same actor/network hooks in the authorized replay outside the sandbox wrapper.
Two read-only tool calls also failed before execution because sandbox synthetic
mount setup had ENOSPC; these diagnostics are retained. Author ENOSPC79+2 and
intermediate runs remain untouched. None of these errors is relabeled as source
acceptance.

No further actionable finding was established within this finite source-only
scope. Correct the recovery seam, recapture/reseal exact sources, rerun causal
and appropriate rosters, and complete Root's shared registration/admission gates
before any actual dispatch. Actual actors, full maintained port acceptance,
both M2 Air sizes, lifecycle/recovery and performance remain outside this result.
