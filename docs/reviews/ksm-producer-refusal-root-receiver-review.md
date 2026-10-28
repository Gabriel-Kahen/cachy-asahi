# KSM refusal parent receiver independent source review

Disposition: **BLOCKED for source adoption** at held receipt
`87cc002574329fdc52b86731e26e388aae014f703b57e5d7f8b71b60cf646637`.
The bounded decoder/projection seam otherwise passes source controls, but its
observation markers lack exact scalar checks before comparison.

## Finding

**P2: Reject foreign observation values before any lookup/comparison dispatch.**
`producer_refusal` checks return codes as exact ints, but compares `reaping` to
`COMPLETED` and `before_cleanup.state` to `exited` without first requiring exact
builtin strings. An exact builtin observation dict holding foreign objects with
`__eq__` returning True is accepted as a valid leaf; their equality methods are
invoked with `COMPLETED` and `exited`. A str subclass is also accepted. These
values do not meet the promised closed natural125 observation vector.

Require plain-string marker values and plain-string dict keys before key lookup,
set construction or equality on untrusted diagnostic data. Preserve the existing
typed return codes and require wrong/subclass/hostile values to return None without
foreign method invocation. Add causal controls for both markers and malformed
dictionary keys, with the real builtin-value positive retained. Exact CP class
and dict checks alone do not validate their contents. This is a cooperative source
diagnostic validation defect, not an actual forged actor/source/PASS grant.

The independently retained `controls.py` / `controls.json` reproduces acceptance
and its two foreign equality calls against the immutable source copy. No actual
process observation, backend or natural exit125 is inferred from those fixtures.

## Authentication and controls

All159 indexed artifacts authenticate by exact bytes/modes/SHA. The captured154
selected source rows compare with the approved driver-leaf capture: only Root's
executor/test2 additionally change. Together with approved driver/test2, the
published-source difference is four paths; all other150 are exact. The old154
packet is not silently replaced or registered by this peer. Current working
executor/test2 moved on to a future correction during review; this disposition
and tests remain bound to held87cc, with working drift recorded separately.

All24 prior executor function ASTs remain identical except the six-line optional
observation seam in `pipeline`. All35 original class test/helper definitions and
the top-level snapshot helper remain AST-exact; four test methods and three data
helpers are added. Existing broker diagnostic schema2, runtime cancellation,
workflow, business validation, deadlines/commands and first-cause handling remain
unchanged. The leaf enum matches the captured driver through AST inspection,
without importing the driver to manufacture source authority.

Independent authorized cold-copy replay passes **35 tests,0 failures/errors/
skips** using `-I -B -S -W error::ResourceWarning`. The sandbox35 replay separately
retains one failure caused by the existing private RPC socket refusal; it is not
reported as PASS. Replaying the four new methods against the old receiver fails
with the absent new helper/seam, while the held new receiver passes all four.
The280 enum combinations and missing/non-natural/code-type/CP-subclass/getter,
terminal framing/ASCII/size/duplicate/nonfinite/extra/private-value controls pass.
The new hostile observation-value controls expose the remaining P2 above.

Source inspection and the pipeline controls verify the leaf is sampled only from
the original registered producer command's captured result, after the unchanged
`check_source_tree` succeeds and before the existing `validate_producer` refusal.
No raw child log can self-certify that source check. The optional top-level
`producer_refusal` contains only schema_version/last_source_gate/predicate and
is absent for legacy/unknown/non-natural records. Its source fields grant neither
source acceptance nor transaction/PASS authority. Exact CompletedProcess class
does not prove that a constructed fixture is an actual child outcome.

Observer ValueError/KeyboardInterrupt/SystemExit models are omitted by the new
observational catch; the original producer business exception retains its exact
object, mutationUNCERTAIN and existing diagnostic facts. Actual cancellation
remains the prior runtime-state mechanism; a synthetic observer control is not
a delivered-signal claim. Original RPC first cause and pre-cleanup/return/reap
samples remain distinct. No raw private path/error enters this added projection.

## Bounds and next action

Root should correct/re-hold the typed observation and plain-key guards, then
independently replay the exact P2 controls and original35 suite before adoption.
The current source hold's8MiB stdout/512-byte terminal line, single prefix,
closed typed JSON,8 gates/35 predicates and natural125/fully reaped vector remain
the intended decoder bounds. A future correction must preserve business refusal,
source-check ordering and old diagnostic absence behavior.

KSM6 history remains FAIL/natural125/0RPC/cleanupFAIL/mutationUNCERTAIN/private
causeUNKNOWN. Native7, fresh leaf, Git publication and final packet154 registration
remain **NOT RUN / pending**; no retrospective cause is assigned. Driver-leaf
PASS remains unchanged. No primary source, workflow, packet/map or Git edit was
made by this peer. Only authorized harmless private Python/IPC source fixtures
run; no native/compiler/Docker/GPG/package/network/image/backend actor runs.
R1–R5/M5–M9 remain mandatory and incomplete.

Evidence is sealed in
`artifacts/reviews/ksm-producer-refusal-root-receiver-peer-20261012`:
`authentication.json`, `conservation.json`, sandbox/authorized35 logs,
old/new-four-control logs, `controls.json`, exact source154 and `final-receipt.json`.
