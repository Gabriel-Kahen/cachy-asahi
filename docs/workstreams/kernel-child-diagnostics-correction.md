# Kernel child diagnostics correction

This is a source correction pending independent review, coordinator source-lock
adoption and a new actual trial. It does not establish kernel compilation,
installation, boot, M2 hardware support or performance. Actual kernel trial
38270726379 remains FAIL at outer `kernel/KERNEL_EXIT`; cleanup FAIL and final
baseline preservation/owned absence UNVERIFIED remain unchanged. Its first
child predicate and compiler invocation are unknown.

The earlier broad cleanup-clock defect inference was withdrawn: the actual
broker renews its 60-second cleanup runner at entry. A direct expired-runner
fixture did not exercise that renewal. This correction changes no broker,
image or runtime timers, the 18,000-second child work ceiling, 240-second outer
child margin, 20,760-second job envelope or workflow outcome gate. Those caps
and reserves are refusal rules; they are not proof of successful cleanup.

## Private child binding and immutable reception

The child adds `stage_lock_sha256`, `nonce` and `diagnostics` to its existing
private report. Existing report limits remain 4 MiB. `diagnostics` is a closed
object limited to 4,096 canonical compact JSON bytes; nonfinite numbers,
unknown keys and wrong types are refused. Its exact keys are `schema_version`
(integer 1), `binding`, `current_predicate`, `first_failed_predicate`,
`failure_category`, `commands` and `cleanup`.

`binding` has exactly these fields:

| Field | Allowed value |
| --- | --- |
| `source_commit` | 40 lowercase hex characters |
| `stage_lock_sha256`, `output_name_sha256` | 64 lowercase hex characters |
| `run_id`, `run_attempt` | Null or 1–20 decimal characters |
| `nonce` | 32 lowercase hex characters |
| `accepted_result_sha256`, `bootstrap_sha256` | 64 lowercase hex characters |
| `inputs_sha256`, `base_inventory_sha256` | Unchanged original 64-hex pins |

The parent freezes expected binding fields from the actual child command and
environment before launch, including the exact supplied input hashes. It does
not replace those expectations with files reread after the child returns. The
child's source-bound nonce must match the private report and every completed
variant on PASS. The output-name digest binds the unique private child output.

The parent captures one bounded JSON byte sequence from an ordinary owned,
mode-0600, single-link regular report, checking file identity around the read.
It validates the exact binding, diagnostic schema, report header and cleanup
agreement. Production terminal, progress and absence receivers reuse the same
validated object. A missing/unbound capture cannot be promoted by a later file
creation or rewrite. Individual progress and scoped absence retain their
existing receipt predicates; capture alone does not prove either.

## Finite predicates, returns and cleanup

`current_predicate` is one of:

`SNAPSHOT`, `ACCEPTED_BASE`, `DEPENDENCY_PACKET`, `PROVISION_INITIALIZE`,
`PROVISION_COMMAND`, `PROVISION_RECEIPT`, `DERIVED_IMAGE`, `BUILD_INITIALIZE`,
`PROBE_COMMAND`, `PROBE_RECEIPT`, `BASELINE_COMMAND`, `BASELINE_RECEIPT`,
`BASELINE_CONFIG`, `CANDIDATE_COMMAND`, `CANDIDATE_RECEIPT`, `PAIR_ACCEPTANCE`,
`CLEANUP`, `FINALIZATION`, `COMPLETE`.

`first_failed_predicate` allows that set plus `NONE`. It records the first
observed failure and remains fixed through cleanup, later I/O or cancellation.
`failure_category` allows `NONE`, `CANCELLED`, `DEADLINE`, `TIMEOUT`,
`OUTPUT_BOUND`, `IO`, `INVALID_DATA`, `COMMAND_NONZERO`, `UNCLASSIFIED`.
`NONE` is paired only with first predicate `NONE`. Classification exports no
exception message, path, daemon ID, command output or raw log text.

`commands` has exactly `provision`, `probe`, `baseline`, `candidate`. Each is
`{"kind": ..., "code": ...}`. `NOT_RUN` means no launch was attempted;
`UNOBSERVED` means no return was observed. Both have null code. `EXIT_ZERO`,
`EXIT_NONZERO`, `EXIT_SIGNAL` require the corresponding actual integer return,
respectively zero, 1–255 or -64 through -1. Booleans are refused. A zero return
does not establish receipt acceptance, successful compilation or an executed
kernel. Command and receipt predicates remain separate.

`cleanup` has exactly `status` (`NOT_RUN`, `PASS`, `FAIL`) and `category`.
Categories allow the failure set plus `ABSENCE_UNVERIFIED` and
`UNCERTAIN_MUTATION`; only FAIL can carry a non-NONE category. Positive cleanup
requires the original positive scoped-absence records. Cancellation, unknown
commit or cleanup I/O cannot become successful cleanup. `COMPLETE` requires
all four observed zero command returns, no first failure and cleanup PASS.

The public child projection replaces raw `binding` with `binding_sha256`,
SHA256 of sorted-key compact JSON binding bytes. It is also limited to 4 KiB.
Child and parent use pure closed validators with cross-schema poison fixtures.

## Outer schema and acceptance

Current outer schema 4 adds only `kernel_child` to the schema-3 25-key record.
`kernel_child` has exactly `availability`, `exit` and `diagnostics`.
Availability is `NOT_RUN`, `UNAVAILABLE`, `UNVERIFIED`, or `VERIFIED`.
NOT_RUN requires a NOT_RUN/null exit. Unavailable/unverified diagnostics are
null, even if an actual nonzero child return is known. Verified diagnostics
require the validated projection; the actual child return remains separate
from each worker return. A killed child may leave a valid pending initial FAIL
receipt with no observed first predicate; the parent does not invent one.

Schema-4 PASS additionally requires VERIFIED diagnostics, actual child
EXIT_ZERO, child COMPLETE, accepted probe/full baseline/full candidate, existing
baseline preservation and absence proof, successful outer cleanup, uncancelled
terminal state and the actual successful workflow outcome. Existing outer
`first_failed_phase`/`failure_reason` remain authoritative and sticky. Missing,
unbound or malformed diagnostics may accompany truthful finite FAIL but cannot
authorize PASS. The current projector preserves historical schema-3 validation
and outcome behavior; old actual receipts are not rewritten.

## Source adoption and validation

The owned correction is eight Python files: stage/evidence and their tests,
job/public and their tests. New evidence/test_evidence add two stage source rows:
expected stage closure 26, expected job closure 117 before any coordinator
choice to include this additional guide. No shared lock, pin, workflow or Git
mutation is performed here. The coordinator must regenerate the stage lock,
update `packet.py`'s `KERNEL_SHA`/`KERNEL_COUNT` to the accepted lock/26, regenerate
the job packet and prove committed bytes/modes before dispatch. The workflow's
source bootstrap has generic bounded rows rather than a literal 115 count.
Unrelated frozen helper drift must receive its own review; it is not silently
adopted as part of these diagnostics.

Local fixtures exercise real owned receipt I/O, actual TERM delivery, returned
nonzero versus unobserved commands, precompile/receipt/pair boundaries, finite
cleanup failures, frozen command-input binding, file mutation/ownership/type
refusal, first-failure preservation and historical projection. Native actors
are inert fixture replacements. Local tests do not establish actual Docker,
compiler, cleanup or ARM execution behavior.

Both the working source and fresh copied source passed 202 job tests and 115
stage tests, zero skips, using `python3 -B -Werror::ResourceWarning -m unittest
discover` in each owned directory. The stage's existing bounded loopback
HTTP/Unix-socket fixtures required the authorized sandbox exception. Its first
copied pass skipped eight BIO tests because the two private pinned data inputs
were absent; after separately capturing those two hash-checked inputs, the
complete 115-test copied suite passed without skips. Those extracted-C tests
run with the host x86 compiler, not an ARM kernel compiler.

The held copy is `/tmp/kernel-child-diagnostics-held-by7_4x4c`; its receipt
records all eight owned source hashes, three guides, 26/117 selected source
counts, and the separately reviewed FDK helper exception. The current projector
reproduces the actual schema-3 status
`cd18c3062c939917b57afbf46f5bf915289e1de47dc55403b44301b1eddae495`
exactly under failure outcome. Broker/image/runtime and their unchanged tests
match source `07450c5fa339ebdb83fa94efc53138405988ced0`. The only non-owned
changed stage row is FDK `evidence.py`
`a53a08c59ec30f8824bb99dcfa374d0c40dcfdecd2bdb1f32064e2c906d1735f`,
whose diff is limited to the independently reviewed template/recipe constants;
its explicit adoption remains coordinator-owned.
