# Kernel daemon baseline preservation proposal

**Selected for source implementation.** The coordinator selected the cooperative
observed-preservation contract below. Its six source/test files and two guides
are changed candidates pending independent review and coordinator rebind.
Workflow, locks, packet.py, original producer, Git and host services remain held.
This source change is not authenticated by the historical kernel24/job packet.
Native kernel compilation, kernel execution, 16K/M2 validation, installation and
performance acceptance remain NOT RUN/NOT MEASURED.

## What the actual run established

Run 38253531983 executed commit `dcc170af543f3238f33efc0c623811d6620affaa`
with packet `afdb5a4947acf71e511fe1266921d68149561aedb4ec5b030e841112e827d9e2`.
It failed at `source/DAEMON_OCCUPIED` before producer or acquisition launch;
both child records are `NOT_RUN` with null codes. Cleanup remained FAIL.
The retained [public status](../../artifacts/ci/38253531983/public-status.json)
and [root revalidation](../../artifacts/ci/38253531983/root-public-verification.json)
record these actual resource readings:

| Reading | Actual bytes | Existing lower bound |
| --- | ---: | ---: |
| Physical memory | 16,722,006,016 | 16,106,127,360 (15 GiB) |
| Available memory | 15,229,763,584 | 15,032,385,536 (14 GiB) |
| Initial free disk | 115,214,491,648 | 32,212,254,720 (30 GiB) |

These readings satisfy the initial resource guards. Pre-kernel disk was not
observed. They do not establish resources for a later runner or build outcome.

The current predicate is `not containers and not images`. It queries images
only if the container query returns empty. `DAEMON_OCCUPIED` is the context
fallback during both inventory calls, so a query/parse failure can also produce
that reason. No counts, identity rows or failing query were retained publicly.
The result therefore does **not** establish preloaded images, zero containers,
specific image names, or pre/post preservation. Cleanup FAIL is not evidence
that any image was removed.

The setup log identifies Ubuntu 24.04-arm image `20261004.142.1`. Its
[published software inventory](https://github.com/actions/runner-images/blob/ubuntu24-arm64/20261004.142/images/ubuntu/Ubuntu2404-Arm64-Readme.md)
lists Docker 28.0.4, but does not establish this VM's image/container inventory.
Preloaded images are an explanation to measure, not a confirmed cause.

## Recommendation and limits

Replace the empty-image assumption only with an independently reviewed
**observed-preservation** contract on a cooperative disposable VM. Keep the
empty-container requirement. Existing images are protected borrowed resources,
never cleanup targets. Original producer CLI/source/receipt formats remain
unchanged, and all current native, source, resource, timer and cancellation
checks remain mandatory.

This is narrower than mutation prevention: positive snapshots attest named
image identities/references at recorded checkpoints. They cannot exclude a
concurrent writer between observations, prove arbitrary daemon storage bytes,
or prevent every internal legacy-builder action. Empty containers alone does
not prove an exclusive daemon. If the coordinator requires enforcement against
shared/concurrent writers, do not adopt this observation-only design; select a
separately reviewed scoped transport or a genuinely isolated builder instead.
Neither privilege escalation nor host daemon/service reconfiguration is proposed.

Two current ownership gaps must be closed before allowing baseline images:

1. The original build permits cache use. An observed successful build and valid
   IID file can return an image ID that existed before the job; completion alone
   does not make it owned. Such a collision must refuse kernel launch and image
   deletion, rather than borrowing ownership from the accepted receipt.
2. Both outer base removal and kernel derived tag/ID removal omit `--no-prune`.
   Moby's [deletion handler](https://github.com/moby/moby/blob/v28.0.4/api/server/router/image/image_routes.go)
   enables ancestor pruning by default. Its
   [image deletion implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/images/image_delete.go)
   can remove untagged parents. An exact target ID therefore does not by itself
   limit deletion to that image. Every authorized image removal must explicitly
   disable ancestor pruning and retain no-force behavior. This also protects
   the accepted base from implicit derived-image cleanup.

## Proposed operation contract

1. Capture containers and images independently, without boolean short circuit,
   using the actual pinned CLI/socket/daemon and bounded zero-exit queries.
   Preserve the current 256-row bound. Record counts only after valid queries;
   query failure is UNVERIFIED, never zero. Refuse any existing container and
   run no producer or acquisition after refusal.
2. Canonicalize unique immutable image IDs into protected set B. Privately
   capture each ID's architecture, OS, full Config, RootFS type/layers, size,
   parent ID where supported, RepoTags and RepoDigests. Foreign architectures
   are preserved, not executed. Bound every response to the existing 128-KiB
   CLI limit and the aggregate metadata to 4 MiB. Sort references and records;
   reject duplicate/ambiguous reference bindings and incomplete observations.
   Repeat both inventory and full projection capture; require identical ID sets,
   reference bindings and metadata across the two bounded passes. Same-ID
   retagging must not pass merely because counts stayed equal. Use this positive
   capture procedure again at later checkpoints. No tag/ref string is interpreted
   as a filesystem path or emitted publicly.
3. Fsync the source/run/packet/daemon/CLI/socket-bound baseline before launching
   the unchanged original producer. A random job nonce identifies its journal,
   not a proof that an unlabelled Docker object is owned. Preserve the original
   source authentication, signed inputs, four build pairs and receipt checks.
4. After both parallel children return, preserve actual exit classifications.
   Only a complete accepted producer may bind its IID as a cleanup candidate.
   Require that ID be absent from B and still match the accepted receipts and
   actual ARM64/Linux inspection. Collision means FAIL/no deletion/no kernel.
   Newly observed unexplained IDs are not automatically owned because they are
   absent from B; do not delete them. Legacy intermediates/cache remain a
   separately stated uncertainty.
5. Reinspect B and its reference mapping after producer acceptance and before
   kernel launch. Require exact equality with the captured baseline projection.
   Record a fresh positive observation, not merely unchanged image counts.
6. In the kernel image helper, reserve the fresh nonce tag and journal a bounded
   protected set of all pre-commit image IDs before POST. This includes B, the
   accepted base and already existing intermediates. Returned **or recovered**
   IDs must be absent from that set before any image tag/ID removal is authorized.
   Preserve accepted twelve-field Config, layer/size/ARM checks, uncertain POST
   FAIL, recovered-ID journaling, and both tag and ID absence observations.
   A collision can already have attached the new private tag to an existing ID;
   refuse deletion and retain FAIL. Do not claim tag preservation or perform a
   speculative rollback that could delete the existing image.
7. Cleanup may remove only the separately journaled, validated new base ID and
   nonce-owned derived tag/ID, always with `--no-prune`, never global prune or
   force image deletion. Recheck baseline exclusion immediately before deletion.
   The kernel broker retains exact nonce-owned container cleanup. Keep zero
   containers as the final requirement; refuse unexplained remaining containers
   rather than removing them. Never delete baseline resources to make a check pass.
8. After scoped cleanup, positively reinspect every baseline ID and its complete
   protected reference mapping. Require exact preservation and known owned-ID
   absence before aggregate cleanup PASS. Missing/changed state or incomplete
   observation means FAIL/UNVERIFIED. A late or interrupted producer stays
   uncertain FAIL even if inventories subsequently appear empty or unchanged.

Use existing absolute setup/parallel/kernel/cleanup cutoffs, output bounds and
later-phase reserves for all observations. Do not add a later grace period or
reduce the five-hour kernel/two 7,200-second build budgets. An observation that
cannot finish inside its reserve fails visibly. Full legacy cache/layer absence
remains **NOT ESTABLISHED**, including when known scoped removals succeed.
Eventual VM teardown is not substituted for scoped absence or baseline proof.

## Selected schemas and code scope

The proposed private baseline schema is closed:
`schema_version`, `source_commit`, `packet_sha256`, `run_id`, `run_attempt`,
`nonce`, `daemon_id`, `daemon_architecture`, `docker_cli_sha256`,
`cli_socket_identity`, `containers`, `images`, `identity_sha256`, `observations`.
Image rows have exactly `id`, `architecture`, `os`, `config`, `rootfs`, `size`,
`parent`, `repo_tags`, `repo_digests`. Use these proposed finite limits:

- At most 256 distinct image IDs and 256 raw inventory rows, including dangling
  IDs. At most 256 references per ID; each reference is a string of at most
  512 UTF-8 bytes. Canonical references are unique and sorted. An image-list
  duplicate caused by multiple tags is deduplicated by ID, not silently counted
  as another image; conflicting reference-to-ID mappings are refused.
- IDs are exactly `sha256:` plus 64 lowercase hex digits; parent is such an ID
  or null when unsupported/absent. Architecture/OS are nonempty strings of at
  most 64 bytes. Size is an actual integer in 0–2^60. RootFS has exactly `type`
  and `layers`: type is at most 64 bytes and layers is at most 256 immutable
  layer digest strings. Preserve full Config as JSON, including unknown fields;
  reject unsupported JSON values instead of dropping them. Per inspected image:
  depth at most 16, at most 8,192 JSON nodes, individual strings at most 64 KiB,
  response at most 128 KiB. Aggregate canonical image projection is at most 4 MiB.
- `source_commit` is 40 lowercase hex digits, packet/CLI/identity hashes are
  64; nonce is 32 random lowercase hex digits. Run ID and attempt are decimal
  strings of 1–20 digits. Daemon ID retains the existing 8–128-byte grammar;
  daemon architecture retains `aarch64`/`arm64`. CLI/socket identity is exactly
  two rows of five actual integers (device, inode, UID, GID, mode), each 0–2^64−1,
  with the existing local path, no-symlink, root-socket and CLI-hash checks.
- Containers is an empty array on an accepted baseline. Three observation rows
  have exactly `stage`, `monotonic_ns`, `container_count`, `image_id_count`,
  `identity_sha256`; stages are `before_producer`, `before_kernel`,
  `after_cleanup`. A partial receipt has only positively completed rows, in that
  order; absence is never synthesized. Monotonic timestamps are actual integers
  in 0–2^63−1; counts are 0–256. The complete private receipt is at most 8 MiB,
  mode 0600, owned by the job UID, single-link regular file in the validated
  private directory, fsynced and atomically replaced without following symlinks.

Canonical bytes use UTF-8 JSON, sorted object keys, sorted ID/reference arrays,
compact separators and no non-finite numbers. Hash the complete protected image
projection, including references and full Config, rather than only IDs or counts.
The initial image rows stay fixed; later rows hash fresh observations restricted
to B and its protected references. Other image IDs are excluded from this digest,
but included in bounded total inventory counts. An empty B has a valid positive
digest of the empty projection; null means no accepted observation.
The receipt remains private; no raw Config/Env/tag/daemon output is exported.
The kernel journal's protected-ID array is sorted, unique and bounded to 256
IDs and the existing journal byte limit; failure to fit refuses POST.

The selected public schema 3 adds exactly one `daemon_baseline` object to
the current 24 keys. Its exact fields are `initial_container_count`,
`initial_image_id_count`, `pre_identity_sha256`, `post_identity_sha256`,
`preservation`, `owned_absence`, `producer_mutation`, `legacy_build_cache`.
Counts are null or integers 0–256; digests are null or lowercase 64-hex strings;
preservation/absence are `NOT_RUN`, `PASS`, `FAIL`, `UNVERIFIED`;
producer mutation is `NOT_STARTED`, `COMPLETE_ACCEPTED`, `COMPLETE_REJECTED`,
`UNCERTAIN`;
cache status is only `NOT_ESTABLISHED`. Preservation PASS requires valid equal
pre/post digests, an initial container count of zero and a known initial image
population. The post digest is published only from a completed final observation;
no before-kernel digest stands in for it. Missing evidence is `UNVERIFIED`; a
positive unequal projection is `FAIL`. Cleanup/aggregate PASS also
requires known owned absence, empty containers, complete producer and all old
acceptance conditions. No unavailable observation is defaulted to PASS.

The finite new first-cause pairs are:

| First phase | New fixed reason | Meaning |
| --- | --- | --- |
| `source` | `DAEMON_CONTAINERS_PRESENT` | Valid initial container inventory is nonempty |
| `source` | `DAEMON_BASELINE_UNVERIFIED` | Query, parsing, metadata bound, binding or repeat-capture stability failed |
| `producer` | `PRODUCER_BASELINE_ID_COLLISION` | Accepted producer IID belongs to B; no image deletion or kernel launch |
| `producer` | `DAEMON_BASELINE_CHANGED` | Positive post-producer projection differs from B |
| `producer` | `DAEMON_BASELINE_UNVERIFIED` | Post-producer observation could not be established |
| `cleanup` | `DAEMON_BASELINE_CHANGED` | Positive final projection differs from B |
| `cleanup` | `DAEMON_BASELINE_UNVERIFIED` | Final positive preservation observation is unavailable |
| `cleanup` | `OWNED_ABSENCE_UNVERIFIED` | Scoped deletion/absence or final empty-container observation is unavailable |

A kernel returned/recovered protected-ID collision retains the existing kernel
failure gates and cannot pass its private image-ownership validator. All old
reason pairs remain valid for their existing triggers; new initial refusals no
longer use the ambiguous `DAEMON_OCCUPIED` fallback. Keep original first-cause
immutability and actual native outcome gating. Counts stay null until positively
observed. Not-started producer means `NOT_STARTED`; termination or mutation
completion that cannot be established remains `UNCERTAIN`, even after stable
later snapshots. Async uncertainty takes precedence over observed child exit.
A producer known to have completed but whose receipt/ownership was rejected is
`COMPLETE_REJECTED`; a borrowed IID remains a collision FAIL and never becomes
an owned cleanup candidate. `COMPLETE_ACCEPTED` requires accepted receipts, a
new IID and positive post-producer baseline preservation. The kernel pre-commit
journal extension uses `protected_image_ids` and cannot authorize deletion of
a member.

The six **implementation/testing** files are explicit:

| Path | Selected source change |
| --- | --- |
| `scripts/port/kernel-native-job/job.py` | Bounded baseline capture/attestation, IID exclusion, scoped no-prune removal, final preservation gate |
| `scripts/port/kernel-native-job/test_job.py` | Baseline/ownership/churn/budget/unknown-actor and actual cancellation regressions |
| `scripts/port/kernel-native-job/public.py` | Exact schema 3 baseline summary, finite new reason pairs, stronger PASS requirements |
| `scripts/port/kernel-native-job/test_public.py` | Counts/digest/status poisoning and baseline/absence/outcome consistency |
| `scripts/port/kernel-native-stage/image.py` | Pre-commit protected IDs, collision refusal on returned/recovered IDs, no-prune on every image removal |
| `scripts/port/kernel-native-stage/test_image.py` | Existing-parent survival, collision/no-delete, tag and ID absence/uncertainty regressions |

This is not a six-file total adoption claim: existing job/kernel guides must be
updated, and the coordinator must rebind kernel24, its literal dependent pin,
the job packet and actual committed Git/mode/bootstrap proof. Those documentation
and registration changes are additional. The original producer and build helpers
are not edited. Registration remains held until the new candidates are reviewed.

## Required tests and native adoption gates

Tests must cover nonempty tagged and dangling baselines, multiple references per
ID, unrelated foreign architectures, unchanged pre/post positive captures and
zero containers. Negative cases include query failure with null counts, stopped
or running containers, retagging with the same ID/count, missing images, Config
or layer/size drift, preexisting producer IID, pre-commit returned/recovered ID
collision, metadata overflow, inventory churn, unknown new IDs and daemon drift.
Deletion fixtures must simulate untagged ancestors and require no-prune on base,
derived-tag and derived-ID paths; protected IDs must never reach a removal call.

Retain actual TERM/INT and final-unmask tests, timeout/output-bound peer cleanup,
first-cause/private-public binding, memory/disk refusal and every phase reserve.
New snapshot failures and cancellation must not rewrite an earlier cause or
clear uncertain producer/commit state. Poisoned public counts, digests, nested
keys, resource values and fabricated preservation PASS must be refused.

Only after source/packet/Git proof should a separate finite native Docker trial
measure actual inventories, borrowed image survival, all deletion flags and
returned/recovered-ID behavior. Then a complete native producer/kernel job may
establish compilation, with kernel runtime, installation, 16K/M2 and performance
remaining separate gates. No proposed test or source claim is native acceptance.

## Scoped transport alternative and KSM216 reference

If the cooperative observation boundary is unacceptable, use a new dedicated
kernel producer transport; do not merely import or bless the KSM executor.
The separately held KSM 216-test candidate, checkpoint
`1f71d1ee22fe36e72fb0f64113ba67c9474462e2f655c5985abd7550eeb8bdfc`, demonstrates a private PATH Docker shim,
bounded Unix RPC, main-thread serving, context/nonce ownership journals and
source/receipt binding while preserving original CLI argv and output schemas.
It is **not coordinator-adopted or native-tested**. Its current image cleanup
also omits no-prune and it does not supply this baseline-preservation contract.

A kernel adaptation must allow only the frozen info/version/context probes,
validated scratch bootstrap context/IID, exact inventory probe and original
recipe container grammar. Reserve before mutation; attach fresh nonce/context
identity to bootstrap images and nonce/image identity to rewritten create
requests. Disclose that labels, tags and actual daemon requests change even
though producer source, CLI argv and output formats remain unchanged. Kernel
accepted-base/Config checks mechanically preserve inherited labels, but adoption
must exercise that compatibility with actual validated receipts.

A proxy must protect B before every mutation/removal, prohibit pulls/imports,
unrelated tags/IDs/mounts and global prune, preserve uncertain requests as FAIL,
and force no-prune for all authorized image deletion. For an uncertain returned
commit ID, separate immutable-ID classification from assignment of the reserved
private tag where the reviewed API permits it; do not attach a tag to a protected
ID first and declare that preservation succeeded afterward.

Existing kernel `run_many` has no service callback. A PATH shim would block
without separately reviewed runtime integration. The coordinator must serve
bounded RPC while draining/accounting both producer and acquisition pipes,
maintain the single 2,050-second cutoff and later reserves, and prove nested
backend calls cannot starve either child or bypass cancellation/reaping. KSM's
one-outer-child callback is a reference, not proof of this parallel behavior.
This alternative honestly needs a larger reviewed file closure for transport,
broker, runtime, tests and existing kernel image cleanup; it is not a safe
four-to-six-file cosmetic patch. A cooperative PATH shim scopes participating
clients' requests; it does not isolate the daemon from independent outside
writers with socket access.

## Actual work delivered and adoption boundary

The original proposal was independently source-reviewed at SHA256
`2e005091a2fa9459bfa04b30e303cbbc5dff0991e1e883ee917184afe9c61516`;
its unchanged bytes and receipts remain under ignored proposal/audit artifacts.
The coordinator subsequently selected the cooperative contract for the explicit
six-file implementation plus both existing guides and this selected proposal.
New source tests and peer checks belong to a separate implementation checkpoint;
they do not overwrite the old 130-test/schema 2/kernel24 e47/job115 afdb evidence.

The actual run receipts and held source were read. Producer and KSM ownership
paths were source-audited; upstream image-deletion behavior was checked against
pinned Moby 28.0.4. The implementation preserves full Config, including null,
and normalizes the pinned API's omitted empty RootFS Layers to an empty array;
see the [pinned inspect response](https://github.com/moby/moby/blob/v28.0.4/api/types/image/image_inspect.go).
This does not drop nonempty layers or unknown Config fields.

No native Docker probe, workflow dispatch, host installation, global prune,
preloaded-image removal or privileged daemon was performed. Native adoption
still requires the coordinator's kernel24/literal pin/job packet/Git rebind and
an actual finite hosted execution. The KSM alternative remains a reference only.
