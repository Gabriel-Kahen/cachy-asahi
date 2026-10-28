# Native repository-client input collector

This is an additive development collector and consumer. It owns no shared CI,
repository, release/client implementation, lock or workflow. Actual native
end-to-end acceptance is **NOT RUN**. Local observation fixtures cannot supply it.

The seven production sources are `entry.py`, `worker.py`, `common.py`, `base.py`,
`provenance.py`, `crypto.py` and `orchestrator.py`. The coordinator must authenticate
the launcher's bytes before executing it, then supply an external SHA-256 for the
complete source byte/mode map. Start Python with `-I -B`; the entry checks those
flags before adjacent standard-library modules can load. It authenticates every
source before compiling source strings and excludes cached bytecode.

```sh
python3 -I -B /absolute/reviewed/entry.py \
  --source-map /absolute/coordinator-source-map.json \
  --source-map-sha256 EXTERNAL_SHA256 \
  collect-base --image sha256:ACTUAL_IMAGE_ID \
  --bootstrap /absolute/bootstrap.json --bootstrap-sha256 EXTERNAL_SHA256 \
  --packages /absolute/packages.lock --packages-sha256 EXTERNAL_SHA256 \
  --inputs /absolute/inputs.lock.json --inputs-sha256 EXTERNAL_SHA256 \
  --output /absolute/new-base-output
```

`base.collect_base(image_id, bootstrap_raw, bootstrap_pin, packages_raw,
packages_pin, source_map, output, *, inputs_raw, inputs_pin)` requires the exact
three-source worker map (`base.py`, `common.py`, `worker.py`). It validates native
daemon/image identity, collects all 341 local ALPM `desc`/`files` pairs in a
read-only worker, cross-checks real `pacman -Q` and `pacman -Ql`, and preserves the
authenticated inputs snapshot ID. Directory ownership is excluded; file/symlink
ownership is retained. It exports raw observations and independently parsed base
metadata only after private cleanup and full name/CID absence proof.

`base.receive_base(output_root, result_raw, result_pin)` independently receives
that export after the coordinator supplies its external result pin. It reparses
all records/queries, checks the exact worker launch and cleanup identities, and
returns a purpose-validated map of exactly 689 approved files (the result plus
688 observations). This is the narrow input for a new CI publication hook; it
does not relax or replace the generic credential guard or approve arbitrary
directories. The recorded architecture and cleanup remain actual observations
that the coordinator must bind to the retained same-job runner authority.

The worker uses no network, all capabilities dropped, read-only source/inputs,
2 GiB memory, 128 PIDs and a private 64 MiB `/tmp`. Commands have 45-second,
1 MiB output and 300-second aggregate budgets; cleanup gets a separate
30-second budget and 10-second commands. `common.run_owned` creates and registers
Docker's full CID before starting the worker, verifies name/image identity,
removes by that CID, and checks both name and ID absence. Uncertain cleanup fails.
Docker must be installed at a reviewed `/usr/bin` or `/bin` path; user PATH
wrappers and inherited remote Docker settings are not used.
Installed tools have a separate 128 MiB streaming hash bound; input/output data
keeps its smaller bounds.

`provenance.consume(input_root, request_raw, request_sha256, base_raw,
base_sha256)` accepts a separately pinned, complete bounded map of the actual
four selected archives, both build evidence trees per package, comparison
receipts, fixture manifest/diffs, build entry source and generator source. It
rechecks all receipt file and recipe snapshots, exact archive bytes/identities,
actual packaged license text, `.BUILDINFO` recipe hashes, generated `.SRCINFO`,
native architecture/image/inventory and distinct recorded build environments.
Native build/container observations remain externally authenticated evidence;
the consumer does not recreate those builds or independently certify their
historical cleanup. Current producer gzip/xz archives are supported; other
compression formats fail explicitly. Decompression is bounded before tar header
parsing; archive data is never extracted or executed.

Baseline records retain `execution=native`. Updated records retain
`execution=synthetic` alongside actual native compilation and generated ancestry.
Generated input hashes refer to retained request-bound evidence; the generator's
Git URL/hash and baseline source origins are separate. `bind_metadata` binds
these components to the exact accepted authority, separately reviewed generic
policy and project license. `supported_models=[]` is mandatory. Generic policy
does not describe the Asahi protected stack.

`crypto.attest(input_root, request_raw, request_sha256, output)` requires an exact
version-2 request and complete public six-repository map. It uses isolated
public-only GPG homes and the real clock. It checks self-signatures/expiry, all
healthy detached signatures, embedded signatures and DB records, exact negative
differences, strict config and signed regular aliases. All fifteen healthy
objects receive snapshot-integrity checks; effective current authorization is
**A REVOKED / B VALID_AT_OBSERVATION**. Earlier native status logs remain explicitly
retained native observations, not reconstructed local trust certifications.
No expired/revoked positive status is accepted and no clock bypass exists.
Temporary key homes are removed before authoritative public receipt publication.

`orchestrator.post_terminal(input_root, authority_raw, authority_pin, crypto_raw,
crypto_pin, metadata_raw, metadata_pin, *, repo_root=ROOT)` is the post-terminal
interface. It requires final initial integration/public acceptance and actual
original container name/CID cleanup. It authenticates the held adapter/gate and
semantic/client dependencies before importing them, then returns **NOT RUN**:
the held gate's unqualified `VALID` schema cannot represent the current A outcome.
[gate-successor-proposal.json](gate-successor-proposal.json) gives the exact
proposed delta. No signer or client launches through this incompatible boundary.

The CLI also provides `attest`, `consume-provenance` and `post-terminal` actions;
run `entry.py --help` with the required isolated flags. Exit 0 means its selected
operation passed, 1 means refusal/failure, and 2 means dependent execution NOT RUN.
Production imports must use the authenticated entry; ordinary module imports in
the test harness operate on explicitly controlled local source.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/port/repository-client-native -p 'test_*.py' -q
```

Tests use real CLI/GPG/repo-add/process signals. Docker control-plane and native
build/admission fixtures are explicitly modeled. They establish source behavior,
not actual native builder acceptance, stable publication, installation or M2/16K
compatibility. See the [workstream](../../../docs/workstreams/repository-client-native.md)
and the local review lock for source pins, counts and integration obligations.

Historical local copied-source checks: **107 tests PASS, zero skips** (35 base,
23 runtime, 24 crypto, 15 provenance and 10 orchestration/CLI). Source bytes were
stable across the copied-packet run; AST/JSON/link/whitespace checks passed. This
review packet is not self-authenticating native authority.

Independent review subsequently reproduced RCN1: TERM delivered during partial
cleanup-handler installation escaped deferral and left an owned child alive.
The correction in `common.py` blocks both INT/TERM while capturing, installing
and restoring the complete handler pair. Transition events are delivered after
restoration; originally blocked pending signals and the prior mask are preserved.
Nested guards relay cancellation through complete disposal. Child signal masks
and ordinary TERM exit after the guard cutoff retain their actual semantics.
Eleven focused signal regressions cover those boundaries, including bounded
restoration retries before/after a modeled setter fault with real dispositions.

The existing `source-map.json` and `review.lock.json` remain the coordinator-held
**historical 107-test packet**. They deliberately do not authenticate the changed
runtime/tests until the coordinator updates them. Current correction checks and
proposed source pins are reported separately; no source adoption or native
acceptance follows from either set of local tests.

Coordinator adoption, October12: the independent RCN1 closure binds corrected
runtime92ca4100/testbe76e126 and the seven-source map50638283. Historical107
maps/lock remain in the review artifacts; the current map and review lock now
bind the corrected source. Full118 local tests and independent34 focused tests
are source evidence. The phase-aware successor and actual native execution are
still required before admission/restaging acceptance.
