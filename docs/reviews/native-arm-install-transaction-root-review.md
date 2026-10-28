# Native ARM installer receiver independent source review

Disposition: **BLOCKED for source adoption** at checkpoint
`9c3b1f2d4a130e9b02e0236cdaa1f441a3368713c5cc9885edce891c0ed3cd23`
(10,358 bytes,0644). Independent source controls pass, but the public projection
does not require the completed phase when accepting either PASS status.

The checkpoint's complete evidence rows, source4, unchanged runtime and guide
authenticate by exact bytes/modes/SHA. Guide SHA is
`b2604c77f44b59b85a110b3f44c0c208cf191f20b6c30a29628d8ddb2216e6f7`.
The retained fresh five-file source copy is independently authenticated and has
zero PYC files. The prior95 original-view recheck remains unchanged.

## Blocking finding

**P2: Require `phase == 'complete'` in both public PASS predicates.**
At `scripts/install/native_arm_trial.py:268`, `public` accepts
`PASS_NATIVE_PREFLIGHT_ONLY` when barrier/count/cleanup facts match, regardless of
which allowed phase the record contains. The equivalent matrix predicate has
the same gap. A record with otherwise accepted facts and `phase='inputs'` is
serialized as PASS. Independent controls confirm that each status also accepts
`preflight`, `ABI` and `matrix` phases: eight inconsistent PASS projections total.
The complete-phase contract should reject these records before publication.

The normal `execute` success path writes `phase='complete'`; this finding does
not claim an actual incomplete transaction emitted PASS or that a data Boolean
grants Root execution authority. It is a concrete closed-record validation gap.
Require the completed phase for both PASS variants, with causal negative controls
for every other allowed phase and positive controls for the valid completed
preflight and matrix projections. The source reproducer and exact serialized
records are retained in `controls.py` and `controls.json` below.

## Independent verification

Fresh exact source replay passes **84 unique controls,0 failures/errors/skips**.
An audit hook permits only `/usr/bin/python3 -I -B` source-marker children and
refuses shell and non-null native DLL actors. It observes16 marker children;
no Docker, GPG, package DLL, namespace, mount, package, network or compiler actor
runs. `-B` and `PYTHONDONTWRITEBYTECODE=1` remain enabled. Original runtime8a7,
legacy contract/binary/flags/bounds are unchanged.131 other original test/helper
definitions are AST-identical; the three explicit native binding points are
reported separately rather than claimed unchanged. Production changes comprise
the six original definitions and two added profile/authority helpers recorded
in `authentication.json`.

Additional independent controls establish:

- Exact Config and the two permitted empty Entrypoint/null Labels normalizations
  reach a deliberately stopped pre-proc gate. Nonempty command/entrypoint,
  poisoned Env, root User, unknown Config and integer substitute for ArgsEscaped
  refuse there. These are Config-prefix controls, not full environment or P0 PASS.
- Boolean, expired, NaN, infinite and over60-second P0 deadlines refuse before
  source reading. The existing process reserve, command allowlist, source/function
  code/globals/closure controls remain in the passing selected suites.
- Sampled late cancellation and close failure revoke durable modeled PASS, and
  the original barrier failure remains the first cause after later cancellation.
  Three separately retained pipeline controls exercise these cases. Their
  environment/barrier/process facts are explicit mocks; actual P0 remains NOT RUN.
- The public projection omits private raw diagnostic/path fields and remains
  bounded; unrecognized public causes and incomplete cleanup/count predicates
  still refuse. This privacy check does not cure the phase finding.

Retained metadata is independently inspected without reopening/extracting the
5.211GB archives. Selected profile bytes exactly match the embedded source
profile. Its136 ELF rows agree with the authenticated audit facts and machine183,
including internally invoked gpg-agent. All four embedded header declaration
byte lengths/hashes validate. The retained UAPI declarations support native
audit0xc00000b7, denials203/206/211/269/425–427 and mount_setattr442. Passing typed
BPF models preserve native/foreign architecture decisions and historical x86/x32
behavior; no seccomp/prctl syscall is executed by this review.

The archive audit records5,211,513,344 decoded bytes/122,444 headers and held
same-FD pre/post digest/identity checks. Those are authenticated prior metadata,
not a repeated archive audit. Generic optional Tk remains INCOMPLETE; absent Perl
and the unrelated171,229,352-byte LLVM member remain visible. Selected-role
closure is distinct from whole inventory completeness, renewed GPG authority,
actual ABI16.0.1, runtime execution,16K compatibility and M2 behavior.

## Scope and next action

Correct and re-hold the PASS phase predicates and causal controls, then recheck
before Root registration. The pure fixed Docker constructor provides no actor
grant. It retains ordinary aarch64/user requirements, immutable image selection,
networknone/read-only/cap-dropALL/no-new-privileges and fixed resource limits;
it supplies no privileged/unconfined/SYS_ADMIN fallback. Root's existing controller
must own daemon/CLI/current-job authority, fresh341 image/Config, input/source
custody, deadline execution, owned cleanup and actual container absence.

The source receiver sequences the selected barrier before libalpm ABI and the
26-method matrix. P0's restrictive nested namespace viability and actual barrier
remain **NOT RUN**, as do actual ABI/GPG/native transactions. Matrix mocks cannot
grant those outcomes. The externally selected current03 tiny any/x86 actual26
history and S01f59 source remain separate; this review does not repeat or upgrade
them. Real-four/fullbaseline624 admission remains **NOT RUN**. Both M2 sizes and
16K target behavior remain **NOT RUN**, and R1–R5/M5–M9 remain mandatory/incomplete.

No primary source/shared manifest/map/workflow/Git changes or actual dispatch
were performed. Evidence is under
`artifacts/reviews/native-arm-install-transaction-root-peer-20261012`:
`authentication.json`, `fresh84.log`, `controls.json`, `metadata.json`, retained
source and helper scripts, and sealed `final-receipt.json`.
