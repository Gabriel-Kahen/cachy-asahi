# Repository native authority: held same-job handoff

October 12, 2026. **Initial implementation HELD; native admission NOT RUN.**
Root selected the baseline-first interfaces below. New owned runtime code in
`scripts/port/repository-native-handoff/**` implements source preflight, producer
observation, injected launch supervision, private capture and terminal checks.
Its CLI authenticates sources only. Phase02 adds a real duplex transport and
bounded process supervisor; their native use, shared adoption and dispatch
remain root-owned prerequisites. The initial proposal is
preserved under implementation-review artifacts.

Current ownership also includes this document,
`artifacts/reviews/repository-native-handoff-implementation-20261012/**`, and the
separately authorized narrow provenance/parser-test correction. Frozen producers,
runtime consumers, shared source maps, review locks, workflows and dispatch are
held. The roadmap and package inventory were read. Source inspection and
retained-byte verification do not establish installation, M2/16K compatibility,
production trust, promotion or performance.

## Recommended integration

The first held implementation passes73 modeled handoff tests and24 provenance
tests in fresh pinned copies, with no skips or PYC. Independent source peer
preflight passes28 affected modeled controls. It confirms the repaired output
root, cancellation-restoration and terminal-frame custody boundaries. Real
files, pipes and OS signals are exercised; Docker/native guards and authority
are modeled. The actual pinned Fish/Zsh parser regression is separately verified
without actors. An initial fresh-copy harness omitted its frozen49c test
dependency; that failed log is retained and the corrected complete capture passes.

See the [runtime interfaces](../../scripts/port/repository-native-handoff/README.md)
and [implementation checkpoint](../../artifacts/reviews/repository-native-handoff-implementation-20261012/checkpoint.json).
No shared adoption, real actor transport/supervisor, external policy/authority
issuance, local GPG producer execution or native handoff is claimed.

## Phase02 held implementation

The historical five-runtime checkpoint `2e42f08787c9f07fdf574ba7a2db6263df3bf0af9f5741800befa425834b796e`
and its captured sources are preserved. The new proposed closure has exactly
seven runtime files, adding `transport.py` and `supervisor.py`. The fixed Docker
CLI/socket/environment backend uses real finite duplex pipes, partial ACK writes,
natural-exit checks, sticky cancellation and registered CID commands. Only
harmless local Python fixtures have exercised its process machinery.

The callback supervisor returns actual JSON/byte results from registered forked
broker callbacks, with a registration ACK and separate stdout/stderr. PID/start
identities and Linux subreaper cleanup cover escaped process groups. Calls
require one parent thread and no existing children; this boundary prevents an
unrelated newly orphaned grandchild from being attributed to the role. The
one-use factory fixes the whole added envelope at1200 seconds, clipped to the
existing job deadline. Imports, source preflight and construction start no actor.

Input assembly now includes the15 required projected aliases and operation
index. The broad schema2 input tree has793 paths, or794 with its explicitly mapped
capture index; provenance241, base receiver689 and crypto128 remain separate
exact trees. `authority_candidate` derives all22 fields/16 refs/four archives but
returns PENDING for external root issuance. `attest_crypto` stages a fresh128-file
tree before its bounded role. Neither helper reconstructs omitted old raw argv,
CID or custody. Counts and byte bindings are recorded under
`artifacts/reviews/repository-native-handoff-implementation-02-20261012/`.

Root selected generic baseline policy SHA
`ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e` and
the existing MIT license SHA51a352. This grants only the original four packages
on exact341/lock89bdb with no supported Mac models. Shared collector/phase map
adoption, external authority and actual Docker/GPG/native execution remain open.

The final isolated19-source capture passes120 handoff controls and24 provenance
controls, no skips or PYC, plus exact seven-source actor-free preflight. Runtime
map proposal SHA is `9e6aa90e3cf9f6fc65bb8d410ec5acdbdfe2024f0bd1462cd51d52a5479d085e`.
Independent process replay preserves the old supervisor ownership failure and
confirms the corrected preexisting-child refusal before callback entry. The
first fresh-copy log's long Unix-socket fixture failure is retained; using a
relative socket name repairs that fixture without changing runtime source.
Final bounded broker/supervisor peer receipts report no open material findings;
`terminal_inputs` is source-reviewed without a dedicated unit test. See the
[phase02 checkpoint](../../artifacts/reviews/repository-native-handoff-implementation-02-20261012/checkpoint.json).

Continue the existing initial native integration once. Add an authenticated
host launch observer and a container checkpoint wrapper for its repository
stage, then a bounded private consumer. Do not duplicate the outer bootstrap,
eight original builds or eleven-case repository producer. Start with the four
**baseline** archives for metadata and fresh TEST restaging; still retain every
original case, all six repositories, and all fifteen signature objects.

The actual outer entry is `scripts/ci/native_arm.py:main`, which already accepts
`integration_consumers`. `scripts/ci/integration.py:Controller.run` calls that
consumer after `run_stages`, before owned derivative cleanup and `finish`.
This callback can capture evidence and query the immutable base, but cannot
issue terminal repository authority. The later development aggregate is a
separate result; preserve the original seven-stage aggregate as the initial
prerequisite.

There is no `scripts/integration/native.py`. The container producer is
`scripts/integration/repository.py:Integration`. Its current launch uses
`docker run`; cleanup removes by name and checks a name-filtered, truncated-ID
listing. A callback after this removal cannot recover original full-CID custody.

## Proposed interfaces and ownership

All names below describe **new, held** interfaces. One coordinator
integrates the separately reviewed closure; workers do not edit shared maps.

| Owner / proposed files | Exact responsibility |
| --- | --- |
| Launch worker: `scripts/port/repository-native-handoff/launch.py` | `run_repository(command, log, private_root, original_executor)`: intercept only the exact nonce-bound repository launch; authenticate its contract and command; register CID before start; receive checkpoints; retain actual Docker observations; remove by CID. Delegate other launches unchanged. |
| Producer observer: `scripts/port/repository-native-handoff/producer.py` | Authenticate `/runner/repository.py` before compiling it, retain its actual `__file__`, install an observing `Integration` subclass, and invoke its unchanged `main`. Observe `command` immediately before the first `revoke-A-signing-home`, and `export_public_repositories` immediately after the original method, before `cleanup`. |
| Custody worker: `scripts/port/repository-native-handoff/capture.py` | `capture_pending(controller, checkpoints, launch_receipt)`: no-follow, finite capture of raw receipts/logs, contract, reset, snapshots, projection/public bindings and original source/build inputs. Status `CAPTURED/PENDING`; no admission. |
| Coordinator: new `entry.py` / `broker.py` | Authenticate original and added source closures; register the scoped launch observer; compose the existing callback; collect base and provenance; after `native.main` returns, `seal_terminal` validates actual final records and assembles externally pinned authority. Run successor acceptance/restaging only then. |
| Separate provenance correction worker | Review the narrow empty optional-URL parser correction. Updated archive ancestry is a separate, deferred change. |
| Root-owned registration | Select fresh trial source pins, generic policy/license authority, source packet/dispatch/deadline and any purpose-specific export grant. No worker rebinds these. |

A scoped interposition is an explicitly new execution chain, even when it
delegates frozen bytes. It must not be described as the old unmodified launcher.
The host wrapper must authenticate the entire original 159-source closure,
contracts and its own added closure before executing either. Restore scoped
bindings in `finally`; refuse overlapping launches, ambiguous command matching
or unsupported command changes. An alternative typed callback inside a future
producer would require new producer pins and is outside this proposal's held
source scope.

Compile the frozen container module under a non-`__main__` name, with its real
path; install the subclass before calling `main`. Its original guard still runs
first. Executing its `__main__` branch during compilation would bypass the
observer and must refuse.

## Checkpoints before irreversible operations

The producer already records actual argv, exit status, log bytes and hashes for
all commands. Most logs merge stderr into stdout; `stdout_only` commands have a
separate stderr file. Preserve this distinction rather than inventing a separate
stderr stream. The original signing operations supply A7 and B7 positive
signature observations; B's signed alias map is created later, after A revocation.

1. Immediately before invoking the original first
   `revoke-A-signing-home` command, seal the existing A7+B7 positive command
   indices, actual argv/log bytes/status facts, public certificate bytes and
   exact object/signature hashes. Do not execute new signing or certification
   commands. This is historical snapshot evidence, never current A authority.
2. After the original `export_public_repositories` returns, seal B's eighth
   object: the actual signed alias map, its original verify receipt and hashes.
   This checkpoint is after A revocation and before destruction of B's private
   home. No claim that all fifteen objects existed before revocation is possible.
3. Preserve original revocation imports, `REVKEYSIG` receipt, eleven cases,
   two-file cache reset, inventories, payload snapshots, final B cache and
   private-state cleanup without changing their order or content.

For actual **host custody before release of each checkpoint**, propose a new
framed stdout / digest-ACK stdin protocol. Docker creation explicitly uses `-i`,
records `OpenStdin=true` and `Tty=false`, and the host owns duplex pipes; the
unchanged original producer does not consume stdin.
The host validates an exact version/nonce/phase/sequence/hash frame, atomically
writes its bounded private bytes, fsyncs the file and containing directory,
confirms identity and rereads the hash, then acknowledges that digest.
The observer proceeds only after the exact ACK. Maximum two checkpoint frames,
4MiB decoded and6MiB wire bytes each, flushed unbuffered emission, 30 seconds per
handshake; EOF, cancellation, extra frames, wrong
digest, partial writes or timeout fail the wrapper and leave the original
`execute` cleanup mandatory. Tests must verify signal/failure behavior at both
boundaries before this interface is selected.

Checkpoint1 transfers observation/log/certificate bytes and object/signature
hashes, **not full package/signature-byte custody**. Those object bytes enter the
separately hash-bound final public export. Checkpoint2 includes the small signed
alias map and its signature as well as its observation. Both must match final
exports; failure cannot be repaired by claiming retrospectively captured bytes.

The frozen producer has no SIGTERM cleanup handler. The new wrapper must install
controlled INT/TERM refusal handlers before execution and defer the pair around
delegated original cleanup. Default TERM can bypass Python `finally`. A forced
host kill/removal disposes the owned namespace but cannot prove the original
private-state cleanup ran. Record that distinction and invalidate pending PASS.

Checkpoint frames contain only enumerated public/status evidence. Never read or
copy private keys, homes, trust databases, agent sockets or the standalone
revocation certificate. The latter may exist inside the original home before
the observed import; only its original argv receipt is retained. The host
separates typed frames from the original container log before that log reaches
the unchanged public exporter. Reserve the protocol marker; malformed, partial
or wrong-nonce frames fail closed and are never copied to the public log.
No checkpoint file is added to `/out`; its
empty-output guard, raw evidence map and generic export remain intact. There is
no extra container mount, socket, device or network channel.

## Full-CID launch and cleanup

Translate only the authenticated repository `docker run` into owned
`docker create -i --cidfile ...`, then `docker start --attach --interactive CID`.
Record the original requested command and the new actual commands separately.
Capture the full 64-hex ID before start; inspect by ID and verify its exact name
`cachy-asahi-repository-<32-hex nonce>`, immutable image, nonce/image environment,
mounts and allowed runtime settings. An empty/partial create reply does not prove
no container was created: use a bounded name lookup for recovery and record
uncertainty. Never remove a guessed ID or an unrelated same-name container.

Capture terminal `State` before removal: stopped, exit 0, no OOM, no daemon error,
and original wrapper result PASS. Under paired signal deferral, remove only the
proven ID and perform successful daemon queries with full IDs proving **both**
exact name and exact ID absent. Raw argv, stdout/stderr, statuses and query maps
must bind this receipt to the same run/attempt/nonce/image. First removal/query
failure, stale identity, cancellation or unknown ownership remains FAIL even if
a recovery attempt later disposes of the object. Keep recovery attempts bounded.
The successor's `gate._accept` requires all these full-CID/name/ID fields; a
source-derived command template or the old name-only receipt cannot satisfy them.

Keep detailed Docker argv/inspect/log observations in the private launch map.
The original outer log receives only the original producer's text; its adjacent
launcher/cleanup summaries contain finite statuses and the validated
name/CID/absence facts. Verify these summaries against the unchanged exporter
before selection. Do not expose host bind paths through a new public receipt or
weaken the credential guard to accommodate them.

Preserve the original repository guard and policy: native aarch64 daemon,
linux/arm64 immutable image with pull never, network none, private cgroup namespace,
read-only root, root UID, no-new-privileges, drop-all plus exactly CHOWN,
DAC_OVERRIDE, FOWNER, SETUID, SETGID and SYS_CHROOT (mask `0x400cb`), 512 PIDs,
8GiB RAM and four CPUs. `/scratch` is 6GiB and `/test-home` 128MiB, both dedicated
empty tmpfs mounts with existing flags. Inputs and runner remain read-only;
only original `/out` is writable. Add the authenticated observer to the existing
runner directory. Frozen `/runner/repository.py` still has its exact 49c87f41
bytes and path, and its guard runs before key commands or output creation.
The stdin/entry-wrapper delta is separately recorded and tested, not hidden.
The original outer repository timeout remains 1800 seconds.

Do not reuse `common.run_owned` unchanged for this launch: its worker policy is
nonroot/capability-free and differs from the original root/six-cap producer.
Do reuse its reviewed signal/ownership principles through the authenticated
dependency closure or a separately reviewed equivalent, with appropriate tests.

## Private evidence and terminal sealing

`capture_pending` selects the exact `work/repository-raw/result.json`, every
declared original evidence file, original input contract, all11 cases and
snapshots, reset, actual launcher/cleanup observations, projection and projected
receipt, public manifest/acceptance, runner/source snapshot, integration/recipe
locks, fixture manifest, bootstrap and complete341 package lock. Capture raw
bytes before public projection substitutes argv hashes or operation aliases.
Retain raw and projected forms separately and verify their original hash/byte
bindings using the unchanged projection contract. No recursive workspace export.

Use independent bounded maps for repository authority, base observations and
provenance: no-follow single-link regular files, exact permitted directories,
16MiB per file, 64MiB per map and at most2048 files, with tighter current consumer
bounds preserved. No cache, rootfs archive, dependency binary or arbitrary raw
tree enters these maps. Reread inputs before finalization. Capture failure is
reported separately from the original aggregate and blocks this new consumer.

Only after `native.main` returns0, its integration record and original seven
stage results PASS, no cancellation, actual public export/acceptance PASS and
owned installed-derivative cleanup/absence PASS may `seal_terminal` assemble the
authority. Bind actual workflow commit, recipe origin, native runner/job/run/
attempt identity, immutable image, nonce, original and new source pins and every
reference hash. Observation files cannot grant themselves external authority.
The shared bootstrap base is protected; the original controller removes only
its owned installed derivative. The new collector removes only its own worker.
No new code removes the shared base or an unregistered image/tag.

## Real341 metadata and provenance

While the same-job bootstrap image remains available, invoke authenticated
`base.collect_base(image_id, bootstrap_raw, bootstrap_pin, packages_raw,
packages_pin, worker_source_map, output, inputs_raw=..., inputs_pin=...)`.
Then independently call `receive_base` with an external result pin. The real
worker supplies682 ALPM `desc`/`files` records, actual `pacman -Q/-Ql` stdout and
stderr, parsed base and observations:688 observation files plus the result.
It checks dependency/provides/conflict/ownership facts against the exact341
inventory. A union of rootfs and248 input package metadata gives versions but
cannot replace installed records, ownership or observed queries.

Preserve the collector's read-only, nonroot, no-network/cap0 worker, 128 PIDs,
2GiB RAM, two CPUs and64MiB tmpfs. Record its own full-CID cleanup separately.
Existing limits remain4MiB per ALPM record,64MiB total and16MiB per query output;
commands have the current45-second/300-second aggregate deadline. This is a
generic builder observation, with no supported Mac models.

Call `provenance.consume` using an externally pinned exact baseline request:
all four archives, both actual build trees per package, required generated
metadata/config/environment/locks, actual validation/logs/recipe inputs,
comparisons/diffs, fixture manifest, generator and builder-entry bytes. Preserve
recipe-origin commit `ebd5812640b0b69f5c09a47752b739e37e338754` versus the new
workflow execution commit. Source/license grants permit gathering the original
inputs; they do not prove byte authentication or build success. Package license
payloads must equal the reviewed MIT input. `bind_metadata` also needs external
authority, reviewed protected/coordinated generic policy and project license;
keep `supported_models=[]`.

There are independent unresolved prerequisites:

- `provenance.package_bytes` currently refuses every empty value. Actual Fish
  and Zsh contain `url = `. Review a narrow singleton empty optional-URL rule
  consistent with the selected crypto rule; required/unknown empty fields,
  duplicate URLs, malformed spelling/CR, whitespace and controls still refuse.
  The A356 crypto correction alone does not fix provenance. A separate held
  provenance correction now passes24 parser tests and the pinned actual Fish/Zsh
  predecessor-red/current-green control. Root's collector and phase dependency
  registrations require rebinding before runtime use of that new source.
- Updated-role `consume` assumes each generated filename has a same-name base
  input. Setup's `base-setup.py` is a renamed copy of `cachy-asahi-setup`; the
  hash matches but the current ancestry contract cannot express that mapping.
  Baseline-first postpones this correction. Updated metadata also requires its
  complete actual build trees, not just public flat receipts.
- The inspected private stores lack `perl-5.42.3-1` required by current input
  lock3c16; they retain older `perl-5.42.2-2`. Obtain/authenticate the exact granted
  refreshed archive and signature before recreating this base. This is a
  historical store observation: root subsequently reports exact refreshed inputs
  accepted in recent501-input native trials. Retain the actual accepted chain;
  this wrapper has not acquired or independently authenticated those trial bytes.
  Never substitute
  the old Perl bytes, relabel a different341 lock, or attach a fresh image to an
  old authority. The store inventory was checked, not freshly rehashed in full.

## Phase admission, source registration and queue

After terminal sealing, independently attest the exact six public repositories
with actual-clock GPG and public certificates only. Schema2 keeps all15 snapshot
objects `VALID/SNAPSHOT_ONLY`; terminal A7 is `REVOKED`, B8 is
`VALID_AT_OBSERVATION`. Preserve actual original pre-revocation argv/status and
revocation-import ordering. Terminal revoked A never becomes usable authority.
Build the successor's externally pinned typed request/receipt references and
unchanged raw reset/projection/custody refs, then call authenticated phase
`entry.py accept` and, only with complete bound metadata, `restage`.

The old collector `orchestrator.post_terminal` deliberately returns NOT RUN at
its v1 boundary; do not translate schema2 into fifteen unqualified VALID rows.
Select a new broker that invokes the phase-aware successor directly. Fresh TEST
restaging uses a distinct signer, records original phase hashes and revoked A,
retains `original_B_continuity=false`, and runs frozen release checks/all seven
client cases. Its PASS requires private state/process teardown and publication.

Root must register original159 source identity unchanged, the new host/container
closure, collector seven-source closure, successor five-source closure and
transitive frozen release/client sources, with exact byte hashes/modes and
externally authenticated launchers. Use `python -I -B` for new host entries;
authenticate captured bytes before compile, validate standard-library origins,
and never load PYC. Root has adopted the crypto/phase correction through its
9340/510 proofs; the earlier stale-map observation is historical. The newly held
provenance URL delta needs its own collector/phase rebind. Source bytes on disk
are not proof of registration. Root owns those rebinds and future trial pins.

No new job or concurrent native queue slot is required. Run the bounded observer,
base collection, capture and terminal consumer serially inside the existing job;
baseline provenance uses existing build outputs. Proposed added consumer budget
is1200 seconds maximum, including the300-second collector, bounded crypto and
420-second client stage plus packing/cleanup. Register a finite enclosing job
deadline before dispatch: the existing callback disables the3000-second initial
timer, which cannot serve as the new consumer's deadline. Do not silently extend
workflow limits or dispatch until root selects this interface and source packet.
Use immutable accepted cache inputs; never write observed metadata back to the
package cache or install anything on the host.

## What old run38274341668 actually supplies

The [retained-byte audit](../../artifacts/reviews/repository-native-handoff-20261012/observations.json)
records exact paths/hashes and source pins. Initial aggregate PASS is distinct
from broader development FAIL. The initial workflow commit is
`d1e489b8d2c5024e5d25a90231f45164ea08d574`, nonce
`e4d92e05250221c76ec93fa72103cbc1`, and image
`sha256:faa8a9d0ae8b7ae2f708af938b838909178522aecb30f858621c5d6d96294f21`.

| Derivable from retained bytes | Missing original custody or fresh action |
| --- | --- |
| All11 projected repository cases PASS;198 command rows and385 declared evidence hashes;15 positive original GPG status logs and revoked-A diagnostic retained. | Original206637-byte raw result with actual argv is not supplied; projection retains argv hashes. Source-derived argv or an exactly reconstructed omitted query config remains derived evidence, not raw receipt custody. |
| Projection binds original hash `cc6f53aa…` and projected hash `37cdae8c…`; named cleanup PASS. | No original full CID, pre-start ownership/inspect chain or ID-absence proof. Cannot retrofit these onto the old cleanup. |
| Exact341 inventory, bootstrap and current input lock; all222 original eight-build file/recipe hash bindings verified, eight distinct clean IDs, four comparisons and reviewed MIT licenses. | No real ALPM desc/files/query map or installed ownership. Collect actual immutable-image metadata in a freshly bound native job; no unrelated host/emulation substitution. |
| Six repository exports, original certificates, A/B signature bytes, public fixture manifest, updated flat logs/receipts/validation/comparisons. | Updated recipe/artifact/environment trees and diffs are not supplied completely by the public projection. New private same-job capture is required for updated provenance. |

Old public bytes can support structural inspection and independent public
cryptographic observations under the selected parser. They cannot manufacture
the omitted raw result, original CID, retrospective pre-revocation handoff or
native authority. Do not rerun an outer producer merely to change the label of
this evidence; the next accepted job must create and retain the genuinely new
observations under its own run/image/nonce/source chain.

## Finite implementation acceptance

Before native execution, independently review the new closure and causal tests
for wrong/partial CID, stale name ownership, exact inspect options, both absence
queries, cancellation during create/start/ACK/remove, pending signals and receipt
invalidation. Test both checkpoints with real original ephemeral TEST producer
commands, preserve command chronology/all11 cases, and prove no framed bytes or
private material reaches unchanged public export. Verify raw/projection/reset
mutations still refuse, source/byte/mode/PYC drift refuses, and map bounds fail
without retained PASS. Review the separate provenance URL correction with real
Fish/Zsh archives and hostile optional-field controls.

For the selected native job, require all original initial stages, both durable
checkpoint ACKs, real341 receiver acceptance, four complete baseline provenance
pairs, full-CID producer and worker cleanup, final export/aggregate/derivative
cleanup, independent A7/B8 phase proof, bound metadata, fresh TEST signer and
seven client cases. Every partial failure remains explicit FAIL/NOT RUN; no
native admission, installation or hardware result follows from this proposal.
