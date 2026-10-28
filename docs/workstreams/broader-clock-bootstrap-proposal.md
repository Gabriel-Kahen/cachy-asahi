# Broader clock bootstrap proposal

Status: source-only proposal, held for Root review and registration. The candidate
issuer passes 31 finite controls and five independent controls. It has not issued
an admitted workflow clock, execution grant or actor PASS. The current parent is
under integration; tests below use a captured reader rather than certify its final
bytes. No existing source, lock, map, workflow or Git registration was edited.

The complete [roadmap](../roadmap.md) and
[development inventory](../../manifests/packages.toml) were read. This proposal
does not complete the Asahi target transaction, either M2 Air validation,
performance measurements or the maintained full-port milestones.

## Proposed first step

The reviewable body is
[`issuer_body.py`](../../artifacts/reviews/broader-clock-bootstrap-proposal-20261013/issuer_body.py),
10,894 bytes, SHA-256
`9e3271b8cb21e7be1940c2aa9f17f84357d0a438ed45a19ad34ae226ec9d4581`.
It imports only the standard library and belongs inline in the reviewed workflow
before checkout. It neither reads nor executes checkout code. The
[`inline specimen`](../../artifacts/reviews/broader-clock-bootstrap-proposal-20261013/bootstrap_inline_model.py)
and [step specimen](../../artifacts/reviews/broader-clock-bootstrap-proposal-20261013/workflow-step-model.yml)
are deliberately inert: their external paths contain `__SOURCE_MODEL_ONLY__`.
Root must substitute its already selected actual grant/runtime references; the
specimens supply no credential flow or execution authorization.

The launcher contains the exact body bytes and a separate literal body SHA. It
hashes those bytes before execution and supplies the verified SHA to the body.
The body excludes that literal, so hashing it does not require a self-hash or a
workflow/commit fixed point. Root registers the same body digest in
`controller.CLOCK_ISSUER_SHA256` and independently reviews the enclosing workflow.
The body digest and a nonce are not cryptographic process attestation; their trust
comes from that registered runner/workflow boundary.

`issue(environment, source_sha256, execution_grant, runtime_contract)` takes the
two external references as `(absolute_path, actual_file_sha256)` pairs. It captures
monotonic issuance once, before domain or file work. It verifies actual source,
workflow and run identities, requires `GITHUB_WORKFLOW_SHA == GITHUB_SHA`, and
retains `end = issued + 10800`. It refuses unavailable clock/domain evidence.
Checks around reads, writes and publication consume this same endpoint.

The issuer exclusively creates an owned mode0700 directory below `RUNNER_TEMP`
outside checkout, then a mode0600 single-link `clock.json` of at most16KiB. It
emits exactly the existing closed12 schema1 fields: schema_version, purpose,
source_commit, run_id, run_attempt, nonce, issued_monotonic, deadline_monotonic,
allowance_seconds, clock_domain, issuer_source_sha256, issuer_workflow_commit.
Purpose is `development-workflow-clock`, nonce is32 lowercase hex characters and
allowance is integer10800. Domain is exactly CLOCK_MONOTONIC, boot UUID, integer
time namespace device>=0 and inode>0. Before/open/after namespace identity and
zero monotonic/boottime offsets must agree.

It reads the selected external grant/runtime files without interpreting or
rewriting them. Their parents must be owned mode0700; files owned mode0600,
regular and single-link, outside checkout, with stable opened/named identities
and exact pins. Limits remain8MiB for grant and16KiB for runtime. No local
`source_peer_preflight=PASS` or new grant field is created.

The same control process appends exactly these six existing bindings to
`GITHUB_ENV`; the controller CLI must use precisely the matching values:

| Environment pair | CLI pair |
| --- | --- |
| DEVELOPMENT_CLOCK_PATH / DEVELOPMENT_CLOCK_SHA256 | --clock / --clock-sha256 |
| DEVELOPMENT_EXECUTION_GRANT_PATH / DEVELOPMENT_EXECUTION_GRANT_SHA256 | --execution-grant / --execution-grant-sha256 |
| DEVELOPMENT_RUNTIME_CONTRACT_PATH / DEVELOPMENT_RUNTIME_CONTRACT_SHA256 | --runtime-contract / --runtime-contract-sha256 |

Use `--composition repository-svg` alongside the existing reviewed metadata and
development pins, output/cache arguments. Do not repeat the issuer for preflight,
tests or execution. A later process recaptures the same private files and pins;
the same boot/time namespace and real run/attempt must still match. A successful
check-only route currently certifies clock/source packet, not grant/runtime.

## Existing authority and runtime construction

The [independent contract audit](../../artifacts/reviews/broader-clock-bootstrap-proposal-20261013/contract-audit/audit.md)
records exact field sets, callback descriptors, map roles and constructor paths.
The execution grant remains schema2/17 fields, original_view8, runtime3,
repository status22 and original live12. Keep original159 sources/view160,
fixtures125, recipes4, inputs71 and one original producer. No new source closure,
callback role, actor budget or credential operation follows from the issuer.

Root must already select the final reviewed source rows/maps, callback identities,
actual source commit/run/attempt and deterministic output/view/argv values when
constructing the external grant. Bind the canonical existing
`encoded({'argv': exact19, 'output': adapter_output})` hash and runtime contract
hash. The generic policy remains the selected666-byte SHA
`ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e` at
`manifests/reviewed/repository-generic-policy.json`; actual registration is Root
work. Test fixture grants cannot provide authority for a real run.

The runtime contract is exactly `cli_sha256`, `endpoint_identity`, `env`.
`scripts/port/repository-native-handoff/entry.py:services` constructs the actual
`transport.py:DockerTransport` without contacting Docker. Its existing checks
bind root-owned single-link mode0755 `/usr/bin/docker` bytes to the external pin;
bind root-owned socket `/run/docker.sock` to the actual six-field identity
`[st_dev, st_ino, st_mode, st_uid, st_gid, st_nlink]`; and require the fixed
allowlisted environment. PATH is `/usr/bin:/bin`, DOCKER_HOST is
`unix:///run/docker.sock`, DOCKER_BUILDKIT is `0`, LC_ALL is `C`.
HOME/DOCKER_CONFIG/TMPDIR name owned mode0700 empty directories. Keep bootstrap
JSON storage separate from tool state. Distinct tool-state directories are a
proposed choice; the existing constructor does not require distinctness.

No `docker info/version/context`, socket connection or credential helper is
needed to observe these facts. Keep existing private alias/GPG references with
their selected producer/broker authority. The proposal creates no aliases or
keys, and refuses missing external contract files instead of inventing defaults.
If those selected contracts cannot exist before checkout, Root must arrange a
separately reviewed handoff retaining this earlier clock; rerunning issuance
after checkout would renew the budget and is unacceptable.

Only the following existing paths need Root coordination for this handoff:

- `.github/workflows/native-arm-development.yml`: insert independently reviewed
  first-step body/launcher; supply selected actual references; retain the same six
  bindings through later composed preflight/execution.
- `scripts/ci/development/controller.py`: register body SHA and finish/review
  clock/J/retention wiring. Its current interfaces provide the reader and flags.
- `scripts/ci/development/packet.py` and the three selected source maps: Root
  reconciles exact committed source rows and final controller hashes.
- `scripts/ci/development/repository_handoff.py` and
  `repository_authority.py`: existing preflight/Session/RootCallbacks consume the
  unchanged grant/runtime schemas; this proposal requests no new schema/API.
- `manifests/reviewed/repository-generic-policy.json`: Root registers the exact
  already selected bytes. No fixture or ignored artifact substitutes for it.

## Controls and limits

31 fresh tests pass with zero skips/errors/failures and no attempted actor launch.
They exercise captured actual controller reader ASTs, fixed J selection/expiry,
unregistered/wrong issuer, body-hash mismatch, source/workflow/run mismatch,
unavailable/domain drift/nonzero offsets, invalid clocks, mode/size/pin/checkout,
symlink/hardlink/ancestor refusals, partial clock writes, delayed references,
environment-file replacement, continued closes/first cause, and foreign private
directory protection. A real read-only host domain observation was available;
it issued no clock or grant. Five independent finite controls separately pass;
they are not added to31. Historical old RED/new GREEN probes and the intermediate
cleanup-refusal finding remain sealed. No native, Docker, compiler, media,
network, GPG, service, package or install actor ran.

The controller selects J once as
`min(trusted_clock_deadline - 120, controller_entry + 10080)` before full source,
grant/runtime interpretation, copies or allocation. Final publication must stay
within the retained workflow endpoint. Relative child clocks remain contained
by J; this is not proof of the same child clock. No self-PASS receipt authenticates
the clock or grant.

First-step `issued + 10800` proves the proposed owning-step envelope. Current
contracts contain no authenticated mapping from the GitHub scheduler's earlier
job start to that monotonic instant. They therefore do not prove equality to the
exact180-minute scheduler cutoff; setup before issuance can make the scheduler
cancel earlier. Root must retain this limit or supply independent timing evidence
without changing the closed schema or renewing time. Source tests cannot supply
that missing authority.

Same-UID interference, blocking syscall/scheduler latency and persistent close
faults remain limits. An environment append is not an atomic transaction with
clock retention: partial append may remain on failure, and cleanup may fail or
leave an identity-moved owned file. Such failure retains its first cause and
never returns successful issuance; it does not claim complete rollback or absence.
Root still owns final parent/owner combined review, registration, external
per-real-run authority and actual dispatch/admission. Hardware and performance
remain unverified.
