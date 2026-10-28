# Same-job repository handoff development adapter

This source implementation composes the existing original native job with the
reviewed repository handoff APIs. It does not register actors or issue authority.
Default CLI execution is BLOCKED without an external grant; CLI preflight uses
`python -I -B -S` and performs source/data checks only. Native, Docker, GPG,
package transactions, restaging, installation and hardware execution are NOT RUN
by the implementation lane.

Ownership is limited to `scripts/ci/development/repository_handoff.py`, its new
test, this guide and the adapter review artifacts. Root owns controller/packet/
workflow wiring, source maps/review locks, live receiver/issuer implementations
and dispatch. Original 159 sources, 125 generated fixtures, producers and recipes
remain unchanged. The historical blocked runtime7 map `9e6aa90e` is usable for
API/inert planning only and is explicitly refused by `Session.execute`; root
must select the independently reviewed corrected runtime before actor use.

## Callable contract

```python
sources = preflight(root, execution_grant_raw, execution_grant_sha256,
                    deadline=existing_source_cutoff)
session = Session(sources, fresh_output,
                  job_deadline=existing_absolute_job_deadline,
                  cancelled=root_cancellation_observer)
result = session.execute(original_native_argv, callbacks, runtime_contract)
```

`runtime_contract` has exactly `cli_sha256`, `endpoint_identity`, and `env`.
Root independently observes and authorizes the pinned actual Docker CLI, fixed
root-owned `/run/docker.sock` identity and curated private environment before
creating the grant. The grant's `actor_contract_sha256` is SHA256 of
`encoded(runtime_contract)`: sorted keys, two-space indentation, no nonfinite
numbers and trailing newline. Dictionary agreement alone does not grant an
actor. The runtime additionally performs its unchanged real CLI/socket/state
checks; construction starts no Docker process.

The externally pinned grant has exactly these keys:

- `schema_version: 1`, `purpose: reviewed-same-job-handoff-execution`,
  `source_peer_preflight: PASS`, `development_only: true`, `added_seconds: 1200`.
- Exact `source_commit`, `recipe_source_commit`, `run_id`, `run_attempt`, and
  `actor_contract_sha256` and `initial_invocation_sha256`. Execute requires actual `GITHUB_SHA`, `GITHUB_RUN_ID`
  and `GITHUB_RUN_ATTEMPT` to match, plus an ordinary nonroot main-thread caller.
- `source_files`: complete root-selected closure, each `{sha256, mode}`;
  8MiB per file/64MiB total and the existing 20,000-file cap are preserved.
  The planning minimum is241 including the explicit policy row; root's final
  actual selection controls its count and adds the receiver/issuer sources.
- `maps`: `runtime`, `collector`, `phase`, each `{path, sha256}`. These maps
  bind respectively seven, seven and five exact source rows to the same full
  closure. Entry bytes/modes and dependencies are authenticated before imports.
- `callbacks`: the three roles below, each `{path, module, qualname}`. Their
  source hash/mode comes from `source_files`. The supplied callable's code must
  equal captured compiled code, use the actual registered module's globals and
  real source filename, and retain those bindings before/after calls. Project
  module/function globals must come from the selected closure; a transplanted
  code object in a fabricated namespace is refused. Root must register the
  authenticated callback module objects before supplying them.
- `policy_path`, `license_path`: mapped bytes pinned to generic policy
  `ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e`
  and MIT license `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7`.

The complete initial lock is pinned to
`d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`.
Its exact159 source rows and125 fixture rows are prerequisites. Frozen original
modules also perform their mode/inode postexecution check through the corrected
runtime loader. Imports execute authenticated source bytes, never PYC.

`initial_invocation_sha256` binds `encoded({'argv': original_native_argv,
'output': absolute_adapter_output})`. Root constructs and authorizes that exact
invocation. The adapter checks it before allocation, callback binding or the
single original native call. Different input/recipe/integration paths or hashes,
an extra argument and output substitution are refused; the actual argv is passed
unchanged. The invocation hash also appears in the finite status and callback
live binding.

The three root-owned live callbacks are:

```python
existing_consumers(original_controller)
public_receiver(original_controller, pending_capture, *, deadline)
authority_provider(candidate_path, candidate_sha256, input_root, *, deadline)
```

The latter two return exactly `{path: absolute_string, sha256: 64_hex}`. Root
implements finite operations under the supplied existing cutoff and separately
reviews their public/input predicates. They must be bound methods on the exact
captured class, with no subclass or foreign `self`. Their captured
`handoff_binding()` method returns exactly:

```text
schema_version=1, purpose=root-repository-handoff-live-binding,
source_commit, run_id, run_attempt, execution_grant_sha256,
initial_invocation_sha256,
actor_contract_sha256, integration_lock_sha256, policy_sha256,
license_sha256, supported_models=[]
```

These values are checked against the actual externally pinned grant and known
pins before/after calls, with exact JSON types. The data-only instance state may
contain owned root Paths, strings/bytes/maps and finite cutoffs. Injected
executable attributes such as a fake verifier are refused; real source/phase
verification must be authenticated and loaded internally by trusted methods.
There is no circular grant hash because the live external grant pin is checked
after the grant bytes have already been authenticated. The broader consumer's
instance report is intentionally mutable and is not this authority state.

Receiver bytes are captured once and
staged privately; later external-file mutation cannot substitute a new receipt.
The staged bytes/hash must still equal that original capture. The provider is
outside the adapter: it must independently verify the complete exact authority
tree, data references, live source/run/attempt/image/nonce, original terminal
results, cleanup, public receiver and typed15-object cryptographic phases before
issuing accepted bytes. The adapter passes a PENDING draft; it cannot grant
acceptance itself. Returned authority must match every draft field/ref/hash/
archive/byte count, permitting only externally issued top-level and crypto
status changes. The existing phase gate then independently verifies that data.
Missing callback/source/grant refuses before any native invocation.

## Ordering, custody and result gates

There is one original `native.main(..., integration_consumers=callback)` under
authenticated `Pending.interpose`. It retains the original eight clean package
builds, all eleven repository cases, all six TEST repositories, typed15 objects,
two durable checkpoint ACKs, source custody and original aggregate/final cleanup.
No second producer or duplicate build sequence is launched.

The wrapper invokes the existing broader consumers first. Immediately after
they return, and before any added raw/public/custody capture, staging, hashing,
collection or authority work, it fixes **E = min(job_deadline, now +1200)**.
The added work cutoff is E−60, reserving60 seconds within E for private teardown.
Role supervisors preserve their own existing smaller cleanup reserves. E never
renews and remains charged across the original job's final cleanup and every
postreturn operation. Observer construction and original checkpoint ACKs remain
under the original/enclosing native budgets and their existing30-second caps.
If final cleanup consumes the remaining added envelope, later roles refuse.

The legacy `broker.run_existing` starts its cutoff before its consumer. Direct
use would incorrectly charge the earlier broad consumers against1200 seconds.
This adapter changes budget composition only: it explicitly retains external
grant checks, one use, scoped observer restoration, source checks before/after,
PENDING-only callback capture, actual typed native exit, original terminal
aggregate/cleanup checks, cancellation and independent authority/restage gates.

After the callback it retains separate exact trees rather than merging them:

| Tree | Exact files | Role |
| --- | ---: | --- |
| Baseline provenance |241| Four original baseline archives, all eight actual build records and source/license components |
| Base receiver |689|341-package actual immutable generic base metadata and independent receiver |
| Crypto inputs |128|Actual original A/B observations and independent phase verification |
| Authority inputs |794|Complete raw/projected/public/source/custody/terminal/crypto inventory |

Missing raw argv, logs, source or custody cannot be reconstructed or silently
omitted to fit caps. Baseline collection and provenance remain PENDING until
original natural exit0, terminal aggregate and cleanup, external public
acceptance and independent authority bind the whole tree. The grant covers only
original four baseline packages and exact341/lock89bdb generic builder with
`supported_models: []`. Fresh TEST restaging requires independent phase
acceptance and bound metadata; it claims no original-B continuity, stable
promotion, production trust, installation or hardware acceptance.

The closed <=4KiB status contains source/run/attempt/execution-grant binding,
`actor_contract_sha256` and `initial_invocation_sha256`,
typed actual initial exit, input-acceptance/restage/cleanup status, cancellation
and a finite error code. No raw exception/path/command/log text enters it. The
first captured failure survives enclosing native failure and cleanup errors.
Transport close and private removal are attempted independently. No-follow
private deletion refuses replacement, links, foreign ownership/type/device and
budget violations. A late failure/cancellation revokes the phase PASS receipt
and removes that directory from eligible public selectors. Status publication
close/check is part of the caught transaction; late cancellation rewrites FAIL.

`public_paths(output)` returns only fixed `status`, plus `phase-public` after
closed successful status with actual exit0/acceptance/restage/cleanup and no
cancel. Phase output must match the successor's exact approved public byte map.
Root must separately admit purpose-specific binary/signature selectors;
there is no generic-export fallback and no arbitrary unknown-path passthrough.

## Coordinator deltas and validation limits

Root must select the new adapter/test and corrected runtime7, collector7 and
phase5 closures; update their externally reviewed maps/dependency literals and
review-lock closures; retain original159/fixture125 untouched; and freeze the
complete primary packet (proposal minimum240 sources/metadata12, minimum241
after explicitly selecting the ff424 policy data row). Actual callback sources
enlarge that count honestly. The existing
8MiB/64MiB source limits are unchanged. Controller wiring replaces its sole
native call with `Session.execute`, supplies its existing `consume` callback
unchanged, provides independently reviewed live receiver/issuer code and actual
execution grant, incorporates the new finite status into the broader aggregate
and registers only reviewed recovery/public selectors. Root owns every shared
map/packet/workflow/Git/dispatch edit and the exact final selected cardinality.

The owned tests exercise real private files, source/mode/inode drift, symlinks/
hardlinks/FIFOs, a harmless Python stdout pipe and local Unix socket pair;
source-bound namespace/code substitution and finite field/privacy refusals;
one native-call/order/restoration/clock/cleanup models; immutable receiver
capture versus external/owned mutation; external authority full-data mutation;
cancel before acceptance; and late successful-status cancellation invalidation.
Broker calls are checked against the actual existing API signatures. The native,
base, crypto and phase gates in orchestration tests are explicitly modeled;
synthetic shapes, counts, identities and PASS values grant no actual admission.

An initial restricted run retained25 passing tests plus the Unix socket EPERM;
an authorized bounded socket/process rerun passed26 with no skips. Later expanded
captures retain their own actual counts and hashes in the adapter artifacts.
An initial clock fixture used an expired synthetic absolute deadline and was
corrected before the captured26 run. An expanded mocked restage used the wrong
positional output index; its failed log and corrected model are retained. The
mistaken synthetic directory was removed after exact fixture-content checking.
No existing source, producer, runtime/collector/phase owner file, shared lock,
manifest, workflow, Git state or actor was changed by this lane.

The earlier working-source suite has41 distinct tests, all PASS with no skips;
`fixture-tests-v10.log` records the bounded authorized socket/process run.
Earlier50-test output contained inherited duplicate source-fixture cases and is
not counted as50 distinct checks. The copied34-test result applies only to its
older explicitly captured source cohort.
The subsequent terminal actor-contract binding control is recorded separately;
every claimed current success requires that hash as well as its grant/invocation
bindings. Candidate-v10 bytes and test output remain immutable historical data.

Source-only composition is not yet signed off. The exact241-file second capture
passed the adapter preflight and original159 module mode/inode checks, but the
runtime's actual legacy collector loader refused `from common import ...` with
`unbound-runtime-import`. No actors were started. Root routed this deterministic
dependency-import defect to its exclusive source owner. The correction must be
held, externally rebound and replayed through the actual collector/phase loaders
before a final adapter source disposition. Moving owner bytes are not accepted
by the old map. Live callback implementation, full source registration, actor
grant, native execution and external authority remain coordinator prerequisites.
