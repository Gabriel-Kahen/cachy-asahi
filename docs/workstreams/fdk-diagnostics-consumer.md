# FDK diagnostic consumers

This is a held source candidate pending coordinator binding and independent
consumer review. Corrected native execution, compiler invocation, installation,
hardware, performance and release acceptance are NOT RUN. Actual 38277573107
remains FAIL with its original schema-1 receipt and historical workflow.

The outer job now receives the current schema-2 stage receipt with exactly
13 fields, including the three-action `worker_diagnostics` vector described in
[the stage contract](fdk-build-worker-diagnostics.md). Current PASS requires
`validate_workers(rows, require_complete=True)`, a typed integer child return
of zero, the existing producer acceptance, uncancelled completion, and actual
owned cleanup proof. Missing, malformed or unbound observations cannot PASS.
The original producer, recipes, builder, brokers, runtimes and timers are unchanged.

## Authenticated validator loading

`job.validator_from_bytes(captured)` takes exactly two byte values keyed by
`evidence.py` and `worker_evidence.py`. It constructs private modules and binds
their mutual imports through private builtins. It does not change `sys.modules`
or replace the outer producer's unrelated module named `evidence`.

Production `authenticated_worker_validator(snapshot, manifest_path, manifest_sha)`
runs after the complete packet/source/Git copy gate. It captures the stage lock
and both dependencies once, verifies their packet hashes, sizes, modes and file
identity, and verifies the dependency rows against the separately pinned stage
lock. The loaded helper exposes `validate_workers(rows, *, require_complete=False)`.

The workflow's always-step `verify_consumers(root, commit, pin, env)` independently
captures the packet, job loader, packet pin literal, stage lock and dependency
bytes. It verifies their committed Git bytes and modes, the dispatched packet
hash and workflow identity, and the nested stage binding before execution. It
extracts only the exact undecorated `validator_from_bytes` function from the
authenticated job source and invokes the same pure vector validator. Unknown
code or an independently rehashed dependency without the nested stage binding
is refused before its code executes. The pinned public encoder remains separately
authenticated; no raw worker logs, paths, exceptions, Docker IDs or keys are added.

## Receipt and publication authority

The job captures the bounded owned stage public receipt once. Acceptance and
publication reuse the validated snapshot; later file replacement cannot promote
an absent or invalid initial capture. An outer failure downgrades public FDK
acceptance while preserving a valid inner vector, without inventing an inner
first failure. Finite fallback rows are NOT_RUN before a stage attempt and
UNAVAILABLE/UNOBSERVED after an attempt without a verified receipt. Fallback
status is always FAIL. The workflow accepts those closed FAIL diagnostics and
rejects legacy schema 1 for current output. Historical evidence is replayed only
through its retained historical guard.

`GITHUB_RUN_ATTEMPT` now accompanies the run ID in the private child environment.
The workflow bootstrap requires 129 source rows. Existing native outcome, source,
producer, publication allowlist, cancellation and owned-absence gates remain.

## Validation and coordinator binding

The separate captured candidate passed 174 job tests with zero skips. Fourteen
loader/bootstrap/public tests cover poisoned global modules, source and mode
drift, nested bindings, captured-byte mutation, malformed vectors, finite FAIL
and actual historical schema-1 replay. A fifteenth added causal regression
refuses boolean child exits; removing that integer gate reproduces acceptance.
Both Python heredocs parse, the existing C++ yaml-cpp harness parses the workflow
and checks its structural contract, and the owned diff passes whitespace checks.
These are source and controlled-fixture results, not native build evidence.

The first copied run had three errors caused by an omitted separately pinned
encoder test input. Its exact bytes were added outside the 129-row packet; the
corrected 173-test run passed, then the final integer-exit change passed all 174.
The eight historical public files are additional test inputs, not newly produced
native evidence. No primary shared lock or packet pin was edited by this author.

The coordinator must adopt the unchanged held seven stage sources plus the new
helper row in the stage40 lock; refresh `packet.py`'s ADAPTER_SHA; and bind the
owned job/test changes into the job129 packet. The prospective copy has stage
SHA `4db538d6292c6580c1eb1cc0d330fc84b9c27ae7b570dbfea5a0cdda6f403e3c`,
packet.py SHA `09bde8c730cbd1b596b2cdc23fd8e2c6d75ded82a6355c3b4fac4ebda058aec0`,
and packet SHA `b91331eb4799718bf0700d8b9a81bbf39c99d5dad4a4f06f777e54d08392ac9d`
(129 rows, 2,141,231 selected bytes). The precise proposed rows and separate
test inputs are retained under `artifacts/reviews/fdk-diagnostics-consumer-20261012/`.
The workflow must be separately reviewed and committed; the new guide is not an
executed packet source. A fresh committed Git/copy proof and independent consumer
review remain required before the next native dispatch.
