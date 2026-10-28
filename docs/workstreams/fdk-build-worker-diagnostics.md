# FDK build-worker diagnostics

This source correction is pending independent review and coordinator adoption.
It is not an accepted native FDK build, installation, hardware or performance
result. Actual run 38277573107 remains FAIL. Its strict eight-file public
verification passed; the FDK record is schema 1, phase `build-1`, status FAIL,
owned container absence true, native build NOT ACCEPTED. The original producer
and four build pairs were accepted separately. The first FDK worker predicate,
returned worker/container codes and compiler invocation were not exported and
remain unproven. Reaching `build-1` establishes source preparation passed the
controller's checks, not an independent public source-byte receipt.

The new diagnostics make those distinctions reviewable before another trial.
The original builder, broker, runtime, package recipe, source pins, timers,
installation scope and acceptance checks are unchanged.

## Schema 2 public record

The current stage projection always emits integer schema version 2. Its exact
13 keys are `schema_version`, `stage`, `status`, `phase`, `error_code`,
`cancelled`, `owned_container_absence`, `native_build`, `hardware`,
`installation`, `selected_for_release`, `binary_publication`, and
`worker_diagnostics`. The historical twelve fields retain their finite value
sets; hardware/installation/binary publication stay NOT RUN and release selection
stays false. Historical schema-1 receipts and their committed projector remain
unchanged. Missing new fields cannot fall back to a current schema-1 PASS.

`worker_diagnostics` has exactly `build-1`, `build-2`, `compare`. Each row has
exactly `availability`, `exit`, `observation`. Availability is `NOT_RUN`,
`UNAVAILABLE`, `UNVERIFIED`, or `VERIFIED`. Unavailable/unverified observations
are null; VERIFIED requires a valid captured observation. Verified binding
digests must be distinct across actions. An actual returned worker subprocess
code is separate from builder, Docker-command and container State codes.

All typed exits have exactly `kind` and `code`. `NOT_RUN` and `UNOBSERVED`
have null code. `EXIT_ZERO`, `EXIT_NONZERO`, `EXIT_SIGNAL` require respectively
integer zero, 1–255, or -64 through -1. Booleans are refused. UNOBSERVED is used
when a command was attempted without an observed return; signal/timeout codes
are never guessed from exceptions.

## Closed worker observation

The private object has exactly `schema_version` (integer 1), `binding`,
`current_predicate`, `first_failed_predicate`, `failure_reason`, `cancelled`,
`builder`, `commands`, `cleanup`. The public object substitutes only
`binding_sha256` for `binding`. Both objects have a 4,096-byte sorted-key compact
JSON limit and reject unknown keys, nonfinite values and wrong types.

The binding has exactly `source_commit`, `stage_lock_sha256`, `run_id`,
`run_attempt`, `action`, `nonce`, `config_sha256`, `inputs_sha256`,
`inventory_sha256`, `recipe_sha256`, `template_sha256`. Commit and nonce are
40/32 lowercase hex characters; hashes are 64 lowercase hex characters;
run/attempt are null or 1–20 decimal characters. Action is one of the three
worker actions. Input/inventory/recipe/template hashes must equal their frozen
constants, including the accepted canonical selected-source correction.
`config_sha256` hashes the exact captured bytes passed to the worker, binding
its private paths without exporting them. Public binding SHA256 hashes the
canonical compact binding object; raw run/nonce/path values are private.

Predicates are `CONFIG`, `REVIEWED_INPUTS`, `BUILDER_IMPORT`,
`BROKER_INITIALIZE`, `BUILDER_CALL`, `CONTAINER_CREATE`, `CONTAINER_ATTACH`,
`BUILDER_PROVENANCE`, `ARTIFACT_VERIFY`, `COMPARE_INPUTS`, `COMPARE_CALL`,
`COMPARE_VERIFY`, `CLEANUP`, `FINALIZATION`, `COMPLETE`. First failed predicate
adds `NONE` and is sticky across cleanup and late cancellation. Failure reasons
are `NONE`, `CANCELLED`, `DEADLINE`, `TIMEOUT`, `OUTPUT_BOUND`, `IO`,
`INVALID_DATA`, `COMMAND_NONZERO`, `UNKNOWN`; NONE pairs only with first NONE.
Exception messages, paths, credentials, IDs, archive contents and raw output
are never copied into these fields.

`builder` has exactly `exit`, `status`, `reason`, `provenance`, `log`. Exit is
the actual returned in-process `builder.main()` integer, not a Docker exit.
Status is `NOT_RUN`, `UNAVAILABLE`, `UNVERIFIED`, `FAILED`, or `STATIC_PASS`.
STATIC_PASS requires the captured native builder header/input/image/inventory/
entry-script bindings, actual zero return and bounded captured log. It does not
replace the independent artifact/ABI/smoke acceptance. The status is UNVERIFIED
for malformed/binding-mismatched or incomplete provenance. NOT_RUN requires no
builder invocation/digest claims. Builder reasons are `NONE`, `RECIPE_REVIEW`,
`RECIPE_INPUTS`, `INVENTORY`, `IMAGE`, `MODE`, `RECIPE_SNAPSHOT`,
`CONTAINER_EXIT`, `TIMEOUT`, `BUILDER_OUTPUT`, `GENERATED_METADATA`,
`ARTIFACT_VALIDATION`, `UNKNOWN`. Only fixed known messages/narrow frozen
prefixes choose a label; arbitrary or combined messages yield UNKNOWN. A
container-exit label does not establish a compiler invocation.

Provenance and log are null or exactly `{"sha256": <64 hex>, "bytes": <int>}`.
Only fixed `provenance.json` and `build.log` are read; there is no filesystem
walk/export. Provenance capture is limited to 32 MiB and log capture to 8 MiB,
inside the existing bounded worker/parent process calls. Raw bytes remain
private; only their digest and length enter diagnostics.

`commands` has exactly `create`, `attach`, `container`, each a typed exit.
Instance-only pass-through wrappers observe existing exact create and attached
command calls without changing arguments, returns, queries or mutation order.
A returned create/attach code is not a container exit. Container State is
UNOBSERVED unless attach was attempted and the existing broker `_inspect` gate
validated the same captured bytes against name/ID/nonce/image/user/configuration/
resources/mounts. Only exited/dead State with Running false and integer ExitCode
0–255 is projected. Repeated State observations cannot overwrite a different
first code. No new inspection query is introduced. None of these states alone
establishes a compiler or kernel execution.

`cleanup` has exactly `status`, `absence`, `reason`. Status is NOT_RUN/PASS/FAIL;
absence is NOT_RUN/PASS/UNVERIFIED; reason is NONE/CANCELLED/IO/INVALID_DATA/
UNVERIFIED. Positive cleanup uses only existing positive scoped absence proof.
Cancellation, errors or unknown absence retain failure. Build COMPLETE requires
zero observed create/attach returns, STATIC_PASS builder, no known nonzero
container State, existing artifact verification and cleanup PASS. Compare
COMPLETE requires its original comparison checks and no invented builder,
container or cleanup operations. Both require no failure or cancellation.

## Capture, publication and adoption

The stage captures its actual saved config bytes once before launch and passes
that hash to the worker. After a return, it records the actual worker code even
when nonzero, then captures one owned mode-0600 single-link regular receipt.
Missing receipts become UNAVAILABLE; wrong source/config/action/run/nonce,
malformed fields or contradictory cleanup become UNVERIFIED. The receiver
independently captures any declared provenance/log once and matches the worker's
source-bound digest/length/classification. It never replaces a failed capture
with later files. Publication uses only those validated objects.

The optional `verify_attempt(..., record=..., log_bytes=...)` API consumes the
same captured provenance/log, including the captured log's evidence hash and
ABI/smoke parsing. Production build and compare paths pass these captures;
default standalone calls retain the original acceptance checks. Other files,
recipe/package reinspection, inventory bijection, ABI, smoke and paired byte/
payload/metadata comparison remain required.

Current public PASS additionally requires all three VERIFIED observations,
actual zero worker returns, each COMPLETE state, both original artifact
acceptances/comparison, uncancelled state and positive stage/worker cleanup.
Zero return, launch, phase, log digest or a private builder status alone cannot
authorize PASS. Outer original first-failure and actual workflow outcome gates
are coordinator-owned and must remain authoritative.

The one new pure helper `worker_evidence.py` gives expected stage40/job129
closure, before any coordinator choice to add this guide. The coordinator owns
stage/job lock regeneration, packet/source-pin updates, the workflow's literal
128→129 source-count change and strict schema-2 consumer adaptation. No native
retry is accepted before that chain and independent review pass.

FDK `evidence.py` imports the helper lazily inside only its FDK public projection.
All twelve other evidence functions retain exact prior AST, including the
standalone kernel `accepted_base`/inventory/read contract. An isolated import
and accepted-base fixture succeeds with the helper absent from the import path.
The historical kernel trial uses committed a53 FDK evidence; current FDK edits
cannot alter that immutable source. Any future kernel helper rebind remains
separately coordinator-reviewed.

## Source validation limits

Temporary fixtures test returned/nonreturned codes, actual TERM handling,
prebuilder/artifact/cleanup failures, wrong bindings/types/ownership, missing
receipts, immutable captures, unknown-message refusal, strict PASS gates and
the kernel standalone interface. The private fake daemon verifies the original
operation sequence is unchanged, nonce ownership precedes State observation,
and later State drift cannot overwrite a known exit. These are controlled
source/interface checks, not actual native Docker, compiler, package-install,
hardware, release or performance acceptance.

The authenticated consumer entry point is
`worker_evidence.validate_workers(rows, *, require_complete=False)`. It validates
the exact vector/row/projection shapes, role-specific completion and distinct
binding hashes, returning a JSON snapshot. `require_complete=True` additionally
requires every VERIFIED actual-zero COMPLETE worker. Lower pure boundaries are
`validate_worker_row(row, action)`, `validate_public(observation, action)`,
`exit_record(code)`, `no_exit(kind='NOT_RUN')`, and
`worker_row(kind='NOT_RUN')`. These validate claims; the source-bound private
receiver and existing artifact/cleanup checks provide their execution basis.
The outer job may retain finite diagnostics while downgrading an inner successful
stage on its own failure; it must not invent an inner first failure. Current
source fallback records remain FAIL with NOT_RUN/UNAVAILABLE diagnostics.

Final working and fresh copied suites each passed **104 tests, zero skips**
with `python3 -B -Werror::ResourceWarning -m unittest discover`. Existing local
socket/process fixtures used the approved bounded sandbox exception. Source,
test logs and hashes are retained under
`artifacts/reviews/fdk-build-worker-diagnostics-20261012/`. The selected stage
closure contains 40 files/816,117 bytes; shared locks are not adopted by this
implementation. The seven owned Python files are held for independent review.
The outer job must forward `GITHUB_RUN_ATTEMPT` alongside its existing run ID
so the hosted worker config binds both actual fields.
