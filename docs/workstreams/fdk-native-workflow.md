# Separate hosted FDK workflow

[The workflow](../../.github/workflows/native-arm-fdk.yml) is a finite, manual
`workflow_dispatch` entry for the [128-file native job](fdk-native-job.md).
It uses `ubuntu-24.04-arm`, permits only the public
`Gabriel-Kahen/cachy-asahi` repository, grants `contents: read`, and joins the
existing `native-arm-build` concurrency group with cancellation disabled.
Checkout is pinned to `3d3c42e5aac5ba805825da76410c181273ba90b1`, checks out the
exact `github.sha`, and does not persist credentials. It uses workflow logs
rather than artifact or cache uploads. Registration, Git publication and dispatch
remain coordinator-owned; none was performed in this workflow source task.

The required `packet_sha256` field has no default. Supply the independently
reviewed SHA256 of `scripts/port/fdk-native-job/packet.lock.json`; the accepted
corrected source checkpoint is
`76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449`, committed at
`e3c450cc342e9f5e1f24f195c342d8d9c67e7c72`. It contains 128 files and 1,954,949
source bytes. The accepted 39-file adapter and 22-file recipe template remain
unchanged. The workflow and log encoder are separately reviewed inputs outside
that packet. A source commit must contain every locked file and the workflow
before it can pass preflight. No default-branch registration or dispatch is
implied by having these files locally.

Read-only preflight checks the ordinary nonzero user/group, zero effective and
permitted capabilities, native Linux ARM and hosted runner declarations, Python
3.11+, existing Git/GPG/lscpu/zstd/Docker/Python executables, at least 8 GiB free
space, and a canonical existing `/run/docker.sock`. It hashes the actual canonical
regular `/usr/bin/docker` bytes and passes that hash and the explicit local socket
to the job. It performs no host installation, Docker plugin discovery or daemon
mutation. Missing prerequisites fail visibly; there is no bootstrap install step.
The held broker subsequently binds the CLI, socket and daemon identity.

Before running repository code, inline Python verifies the externally pinned
packet bytes, all 128 row hashes/sizes/0644-or-0755 modes, and their exact Git
blobs/modes at `GITHUB_SHA`. It checks checkout HEAD and the workflow commit when
provided by GitHub. Paths must have ordinary directory parents and single-link
regular files; per-source-file limits are 8 MiB and total source is at most 32 MiB.
The encoder's bytes and 0644 mode must independently match both Git and SHA256
`a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5`.
The workflow itself also matches its exact committed Git bytes/mode.

Execution uses `/usr/bin/python3 -I -B`, the held `job.py --execute-native`
interface, exact source commit/root and packet pin, newly named external
`$RUNNER_TEMP/fdk-native-job-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT`, the pinned Docker
CLI and `unix:///run/docker.sock`. Budgets are 7200 seconds overall work, 3300
producer and 3000 FDK; the job retains its separate shared 180-second cleanup
budget. The workflow timeout is 150 minutes; preflight and publication each have
5-minute step limits. The original producer, accepted adapter, cleanup ownership
limits and private/public separation remain as documented by the held job.

The `always()` publication step independently rechecks encoder hash and exact
Git binding, then accepts only these public paths:

- `status.json`
- `fdk/status.json`
- `producer/producer-summary.json`
- `producer/acquisition.json`
- `producer/signatures.json`
- `producer/inputs.lock.json`
- `producer/recipes.lock.json`
- `producer/export-manifest.json`

Only ordinary owned directories and single-link regular owned files are allowed.
There are at most ten visited entries, 1 MiB per file and 4 MiB total. Every file
must be a JSON object without duplicate keys or nonfinite numbers. The job
receipt has a fixed schema, binds any present commit/packet identities, and
retains installation, hardware and binary publication as `NOT RUN`. FDK status,
producer summary and exact manifest hash set must agree with authoritative job
status. An emitted PASS requires the native step's actual outcome to be success,
all eight public records, complete/noncancelled cleanup, and matching source pins.
Native success without authoritative PASS makes publication fail.

Producer content has finite exact schemas, including every nested row. Summary
records accept only the full producer receipt or the fixed minimal failure
receipt; full summaries constrain the four original package names, hash fields,
fixed counters, booleans, and six audit-receipt names. Acquisition records bind
all 501 names/hash/size pairs to the immutable inputs, recompute exact counters
and state, and accept only fixed PASS/PENDING/FAIL fields and bounded HTTP error
codes. Signatures bind exactly 249 payload names to the immutable signer
fingerprint. Unknown fields, raw response/log/command strings, unexpected names
and incorrectly typed values fail, even if an export manifest was recomputed.
Exported input and recipe bytes must respectively match SHA256
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` and
`20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`
before JSON parsing or snapshot creation. Producer file sets are transactional:
summary/manifest only, or those with acquisition and both immutable maps,
optionally signatures. These partial sets remain valid on authoritative FAIL;
full producer success recorded before an outer job failure stays explicitly
`recorded_native_build: PASS` with summary status FAIL and native build
`NOT ACCEPTED`.

Normal FAIL receipts and partial producer evidence can still be encoded. Missing
public evidence prints only `FDK_PUBLIC_EVIDENCE_NOT_CREATED`; malformed or
inconsistent evidence prints only `FDK_PUBLIC_EVIDENCE_REFUSED` and fails the
publication step. Neither condition creates a fabricated native receipt. The
validated JSON bytes and independently verified encoder are copied into a fresh
temporary snapshot before encoding, avoiding a second read of the live public
tree. The existing encoder additionally caps raw input at 16 MiB and compressed
output at 8 MiB, printing its digest, length and base64 gzip-tar between the
`CACHY_ASAHI_EVIDENCE_BEGIN public` / `CACHY_ASAHI_EVIDENCE_END public` markers.
No private root, cache, context, GPG home, command log, source archive, package or
codec binary is passed to the encoder. Prior native failure remains a job failure;
there is no `continue-on-error`. A cancelled workflow or lost host can prevent
publication entirely, and no missing log is evidence of acceptance.

The initial source task ran no hosted prerequisites, Docker/GPG acquisition,
native builds, registration, dispatch, installation or M2 checks. The
coordinator's later trial is recorded below. Source and fixture checks establish
the workflow's wiring and export boundaries, not native or hardware acceptance.

Historical source validation checkpoint before the first trial:

- Workflow SHA256: `c7b90461edfbc079768a189d0930c0249b1d430174590b9dc3342413796afbbf`.
- Existing encoder SHA256: `a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5`.
- System yaml-cpp parsed the complete YAML and checked dispatch, permissions,
  concurrency, runner, timeouts, checkout and native-outcome wiring. Both inline
  Python blocks compiled; whitespace checks passed. This is local validation,
  not GitHub workflow registration or an actual runner check.
- The coordinator's previous `9382319f...` reproducer exposed acceptance of an
  unknown private field inside acquisition JSON after rebinding its manifest
  hash. The revised actual inline validator accepts the curated control and
  refuses that poison before returning captured bytes or invoking the encoder.
  The adapted reproducer also passes exact 128-file Git/source verification,
  outcome/path refusal and actual pinned-encoder snapshot checks.
- Revised temporary Git/publication fixtures: **24 tests PASS**, 6.750 seconds
  on local replay. Positive controls call the held exporter on its curated
  fixture data. Coherently rehashed unknown fields at top-level and
  nested schemas, forged maps, signature/name/fingerprint drift, counters/types
  and HTTP error mutations fail before an evidence marker is emitted. Complete
  PASS, complete producer receipts under outer FAIL, incomplete producer FAIL,
  and partial acquisition FAIL/PENDING remain publishable. Existing source/Git,
  size-before-blob, path/link/JSON and validated-byte snapshot checks also pass.
- Job source and adapter maps were rechecked with **128/39 entries, zero drift**.
  The native-job checkpoint then was **90 tests PASS, no skips**; no job,
  adapter or template source was edited or native execution performed here.

## Coordinator registration and first actual trial

The reviewed workflow and documentation were committed at
`b939ebff3faaa8f3ffa68d5faf2d77e30b87de5b`. Root checked all 128 committed
source blobs/modes and the exact workflow digest again. Independent closure
of the publication finding is recorded in
[the source review](../reviews/fdk-native-job-review.md).

The one-file [registration PR #2](https://github.com/Gabriel-Kahen/cachy-asahi/pull/2)
was merged at 08:28:14 UTC on October 12, 2026, main merge commit
`cdd5e911fa7c21219dd78d0d77ba7653bc196c55`. It adds only this reviewed workflow,
preserving the user's updated roadmap and other main files. The trial runs the
explicitly selected feature commit above.

[Native run 38223759349](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38223759349)
was created at 08:28:19 UTC. Its actual checkout and committed-packet/host
prerequisite check passed. The job completed at 08:32:20 UTC: **FAIL** in the
original producer phase; FDK did not run. The public acquisition receipt binds
all 501 successful downloads, but no accepted complete signature/build receipt
was published. The private producer's failure cause cannot be established from
the generic public code alone. Do not infer successful authentication or original
builds from acquisition. Verified owned-image absence and bounded public
publication passed.

Root retained the workflow log and decoded the single public bundle under
`artifacts/ci/38223759349/`. It is 85,482 bytes, SHA256
`c4443e045be96e30da10e737ce4934c3f929b40cd7faf48dcc1c1f76bf222d9e`.
Its fixed-schema job receipt records producer FAIL, FDK NOT RUN, no cancellation
and owned-image absence. The reviewed delegate logging correction and fixed
diagnostic codes are documented in [the failure audit](fdk-producer-failure-audit.md);
the exact hosted cause remains unknown and raw private logs remain excluded.
Two local isolated no-agent public-key imports, including the exact delegate,
passed but do not explain or replace the actual Ubuntu ARM failure.

Installation, provider substitution, codec binary publication, M2/16K execution
and performance acceptance remain open.


## Held diagnostic publication correction

The corrected workflow SHA256 is
`6eecc3235b91dfeb326f497f6fe0984ce7525db860739b2c0083b0f8271e37b1`.
This changes only the authoritative FAIL receipt's `error_code` allowlist.
The public job schema still has exactly 14 fields; private `{phase, outcome}`
objects, raw errors and extra/missing fields are not accepted for publication.
PASS still requires `error_code: null` and all existing acceptance conditions.
FAIL accepts the original `fdk-native-job-failed` plus exactly 70 producer codes
from the reviewed `evidence.PRODUCER_FAILURE_CODES` contract.

The finite phases are `preflight`, `base-probe`, `host-probe`, `acquisition`,
`gpg-import`, `gpg-verify`, `bootstrap`, `original-build`, `original-compare` and
`complete`. For each phase, the three `not-run`/`started`/`pass` outcomes project
as `producer-before-PHASE-failed`, `producer-during-PHASE-failed` and
`producer-after-PHASE-failed`. The four failure outcomes project as
`producer-PHASE-command-failed`, `producer-PHASE-delegate-refused`,
`producer-PHASE-runner-failed` or `producer-PHASE-cancelled`. Membership is exact,
with no arbitrary suffix or message string. Last-call PASS is not signature or
build acceptance; before/during/after does not invent a more precise cause.

The coordinator accepted and committed the six reviewed wrapper source/test
corrections and refrozen 128-file packet at
`e3c450cc342e9f5e1f24f195c342d8d9c67e7c72`. Corrected packet SHA256 is
`76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449`; its 128 files
contain 1,954,949 source bytes. The coordinator's workspace and exact copied
source each passed **104 tests, no skips**. Actual Git blob/mode binding and
copied-byte/mode verification passed; the
[corrected source proof](../../artifacts/reviews/fdk-corrected-source-git-proof-20261012.json)
records the source commit, pins and scope.

The former packet
`2e190f75594fe5550770aa567b7729637853a99d6c2ce3b137248ed3954cbe32` and 90-test
checkpoint belong to the historical failed trial. They are not the corrected
source handoff. This publisher task edits neither the accepted six source files
nor the refrozen packet. The workflow correction remains pending final held
review; no corrected dispatch has occurred. The coordinator must bind a later
trial to the new packet and exact committed workflow digest. The original
Ubuntu failure stays FAIL with its cause unknown; installation, provider
substitution and hardware acceptance remain open. Existing checkout/source
checks, encoder pin, finite producer/Fdk schemas, snapshot capture and cleanup
gates are preserved.

Diagnostic publisher validation: **28 fixtures PASS**, 8.571 seconds on local
replay. The workflow phase set and all 70 codes match the reviewed source
contract exactly; every code accepts a valid FAIL receipt, and each of the seven
outcome forms passes through the actual verified snapshot encoder. Unknown,
appended, newline-containing, private or nonstring codes, null FAIL codes,
non-null PASS codes, missing fields and extra private diagnostic fields are
refused before encoding. All existing curated producer schemas, source/Git/mode,
size/link, oversized-blob and captured-byte checks still pass. Full YAML parsing,
workflow contract, both inline Python compilations and whitespace checks pass.
These are local source/fixture results, not a new hosted trial.

## Corrected finite trial dispatched

The coordinator committed the reviewed consumer at
`ee9797812cb454e413b5900d8262f1015fe863f1` and pushed that exact source.
The actual embedded source preflight verified all 128 committed Git blobs/modes,
workflow bytes and encoder pin before dispatch. The corrected finite public ARM
[run 38230760444](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38230760444)
was created at 09:34:25 UTC on 2026-10-12, with packet SHA256
`76e475f63332c66de123481b77c904254c8f0c988bdf73b0787c732d3ae70449`
and workflow SHA256
`6eecc3235b91dfeb326f497f6fe0984ce7525db860739b2c0083b0f8271e37b1`.
It was queued when recorded. No corrected producer or FDK build PASS is yet
claimed; the prior trial remains FAIL. The existing shared native builder
concurrency group serializes this job with other project native trials.
