# FDK observer correction: independent root recheck

Disposition: **BLOCKED for source/adoption readiness** on correction seal
`23e58b979fa22c3f826b7f590c0f3730f10e007c7d8e4cc31901e030e581e3c5`.
The three original findings are repaired in their bounded causal controls.
New finite identity-query failures still lose tracking of live descriptors in
both disposal helpers. Persistent close refusal also exhausts local tracking;
refused evidence is not proof of descriptor release. No native PASS bypass is
claimed. Actual FDK8 stays FAIL, historical inner/compiler invocation UNKNOWN.

## Authenticated correction and preservation

Root independently rehashed 175 correction artifacts, 378 original author
artifacts and 235 original root-review evidence rows before importing captured
source. The fresh136-file correction closure retains exact bytes/modes,
including artifact-only recipe overlays and the selected archive. Exactly four
of the original ten owned source rows changed; all six others remain exact in
held and current source. Changed regular mode0644 rows:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `packages/libraries/cachy-asahi-fdk-aac/inner_observation.py` | 21868 | `4e817deb236cabee28c98d8c6ce23d29c16d8978b412a088b4d6be670f546ade` |
| `packages/libraries/cachy-asahi-fdk-aac/test_inner_observation.py` | 17043 | `002efb3a977db9086bdc2b9a8765126f140119cc6009512df2e30d63fa087460` |
| `scripts/port/fdk-native-stage/inner_evidence.py` | 13122 | `eb0457c7bde9a688f224b2c24afc23a749fc5f3433617074b8e11a029d7b51f9` |
| `scripts/port/fdk-native-stage/test_inner_evidence.py` | 18058 | `7d239c1cea537d432587f1657618608406b169fd819f6c8bd2da6278536590c2` |

Compiler adapter3cf179f6, compiler tests4e3b9852, worker1f0af437,
worker tests9e5fbe3c, projection1feb23dc and projection tests8b5c89b4 are unchanged.
The observer's11-stdlib grant, finite parser/schema/issuer and2048-byte bound
are independently checked unchanged. Capture remains bounded4096 bytes, with
restricted pinned-source loading and the original private State/context/source
binding. SPDX/project MIT evidence is retained; no upstream code is executed.

Historical author8515871e, original blocked peerdce2bf78 and its review7f3a296a
remain immutable. FDK8 diagnosis85744489, camera correction peer3cbfd872 and
kernel capability peer9846fb83 remain sealed. This review edits only this new
document and its new artifact namespace. It makes no installer, current source,
primary recipe, shared map, workflow or Git edit. The ongoing installer
successor is outside this review; its old source holds are historical, not a
claim about the successor's current bytes. R1–R5 and full M5–M9 remain required.

## Closure of the original findings

1. **Temporary-cleanup control:** the independent observer reviewer replays
   the same ordinary temporary-write error followed by KeyboardInterrupt during
   temporary unlink. Old e8606e10 preserves stale healthy evidence, leaves its
   refusal lock empty, fails to latch cancellation and leaks two descriptors.
   Corrected4e817deb propagates the same control after cleanup, preserves earlier
   compiler NONZERO7, latches cancellation/write_failed, invalidates stale
   healthy evidence, retains a939-byte refusal marker and has zero live owned
   FDs before reviewer cleanup. A fresh recorder retains the refusal facts.

2. **Parent close interruption:** all four original direct/composed ordinary/
   KeyboardInterrupt before-effect close schedules reproduce old leaks of one
   FD each. Correctedeb0457 retries the still-owned unchanged descriptor and
   leaves zero owned FDs in every original schedule, preserving refusal/control
   outcomes. After-effect/EBADF controls do not retry a released descriptor.
   Distinct-foreign-inode FD reuse remains open and is not closed by a retry.
   The same-inode reoccupation limit is explicitly separate: inode identity
   cannot distinguish malicious reoccupation of the exact same object.

3. **Diagnostic startup before original recipe work:** proposed callbacks now
   run only inside an explicit shell `if`, immediately after the original host/
   architecture guard. Ordinary callback/startup exits continue original work;
   fixed signal-style statuses130/143 return first. Removing these four wrappers
   and restoring original source/checksum declarations reproduces the original
   actual recipe byte-for-byte. Original business commands are outside the new
   conditional, preserving their own ERR/exit behavior.

Root independently executes48 inert shell models: eight callback exits
(0,1,2,7,127,130,143,139), three original-business exits and plain versus an
ERR-trapped function model. Ordinary startup failures invoke the fake original
body and do not trigger its trap; original failures retain their own result/
trap behavior.130/143 prevent original work. Two additional guard models
refuse before callback and work. Only the extracted callback and fake shell
functions/builtins run; no recipe is sourced, and no Python/compiler/makepkg
actor is invoked by these models. The modeled ERR trap maps failures to4;
this does not authenticate installed ARM makepkg or attribute historical exit4.
The wrapper does not classify arbitrary SystemExit or every process termination.
Missing/unhealthy observations must still refuse modern completion.

## Blocking disposal findings

**[P2] Parent cleanup identity query needs bounded recovery/retained ownership.**
At `scripts/port/fdk-native-stage/inner_evidence.py:51`, `release_owned()` returns
immediately when its pre-close `os.fstat(handle)` raises. A single one-shot
OSError at the first cleanup identity query leaves exactly one original owned
descriptor live, with remaining descriptors closed. Capture refuses with the
error, but its local ownership list then expires without retry or retained
ownership. This is a single transient fault, not persistent OS refusal or a
combination of read/close failures. Exact FD liveness is measured before explicit
fixture cleanup in `capture/results-v2.json`, case `one-shot-cleanup-fstat`.
Result SHA256 `a8936fcadf12f9d2856a99324ddd7ee8c82c166595dd62f3a40e9762f47078a0`.

**[P2] Observer conflates unresolved post-close identity with release.**
At `packages/libraries/cachy-asahi-fdk-aac/inner_observation.py:132`, any OSError
from the post-failed-close `fstat` stops disposal. An ordinary before-effect
close EIO followed by one post-close fstat EIO performs only one close attempt
while the exact original FD/dev/ino remains open. EIO proves neither EBADF nor
foreign identity. The close error propagates; this is a live ownership residual,
not silent healthy evidence. Proof: `observer/control-results.json`, case
`post-close-fstat-EIO`, SHA256
`1239c05c5281ac530b348d126046306df153aad912f594f01028e95e971fcfe9`.

Bounded identity-query retry can repair these finite schedules. If identity
remains unresolved, retain/report unknown ownership rather than speculatively
closing a possible foreign FD or abandoning the handle. Distinguish actual
EBADF from unrelated query errors; do not treat refusal as proof of release.
No source fix was made by the reviewer.

**[P2, persistent-fault ownership limit] Local disposal tracking expires.**
Four parent persistent-before-release schedules make three close attempts and
refuse while one measured FD remains live per case. Observer publication and
invalidation each make three attempts, then return with two exact lock FDs
referencing the same inode and no retained ownership registry/next-call guard.
The940-byte refusal marker and healthy-record revocation work. Persistent OS
failure cannot be forced away; this finding requests honest retained ownership
and bounded subsequent behavior, not guaranteed closure under arbitrary faults.
All exact residual FDs were recorded before identity-checked reviewer cleanup.
These fixtures do not demonstrate successful native acceptance.

## Fresh controls and proposal limits

Root's35 captured-source tests pass (observer17 and capture18), zero failures/
errors/skips, ResourceWarnings treated as errors. Existing harmless self-SIGINT
coverage is part of those tests; no native/media/container actor runs. The
author's198 tests and logs are authenticated historical author evidence, not
independent admission or an invented root198-test run.

Observer review: ten independent groups, seven PASS, one expected old red and
two corrected counterexamples. Capture review:21 final control methods with
zero failures/errors/skips,24 close/failure matrix rows and the separate
cleanup-fstat residual. A green reproducer may assert an expected residual;
its passing assertion does not mark disposal repaired. Sixteen prior strict
capture/projection controls replay: once-only bytes/raw digest, normalized
projection,11-field private context, original State/CID/image/name/nonce/outer
result, source grants, bounds, refusal marker/cancellation and artifact-before-
inner-completion ordering. Signal handlers/masks are unchanged in capture
controls. The first same-inode reuse fixture was retained, then corrected to a
distinct inode; production bytes never changed between those fixture runs.

Static recipe checks authenticate23 source/checksum pairs and matching SRCINFO,
24 template files and25 reviewed files. Proposed recipe SHA256 is
`7f0cce6802b9157297a6a98d4fafdcdd0f6b521fde5b1396a4d52900ed21b16c`;
SRCINFO is `de811d33f897c196c5faec587ade150a76bd8544b28745466f01d469b4d8e4af`.
Template and reviewed proposal hashes are respectively `c6e60251…` and `7157dd41…`.
These are artifact proposals, not current primary recipe/input-map admission.

Shared `evidence.py` remains exact
`27d16ce1a89d949075b0fe85072575883de6e9021a4902747c4b8ed44ed71b27`.
Its legacy finalstatus consumer still accepts a synthetic completed legacy
vector; modern `require_complete=True` refuses it. Root must adopt the modern
completion gate, resolve current kernel dependency/registration reconciliation,
and regenerate the source/recipe/template/reviewed/stage/job/ready/workflow
closure before any new PASS/grant. That known coordinator-owned gap is separate
from these four author source files. No actual private FDK8 binding is recovered.

Evidence and final receipt:
`artifacts/reviews/fdk-inner-phase-observation-correction-root-peer-20261012/`.
The final seal rechecks175 correction/378 original artifacts, current four/
unchanged six rows,136 captured files, both independent receipts, original root
proofs and companion holds. Actual compiler/makepkg/Docker/GPG/install/native/
namespace work is NOT RUN; hardware/M2/16K, reproducibility, publication and
performance acceptance remain unestablished. Fix and independently recheck
the finite disposal gaps before combined adoption.
