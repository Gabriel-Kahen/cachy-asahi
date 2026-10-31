# Offline coordinated platform transitions

`python3 -B scripts/platform/platform_transition.py` compares two checksum-bound
local release inventories and produces an actionable data plan for M7/R3 and
M8/R5. It preserves the existing Python-only recovery preflight. It does not
prepare or commit an ALPM transaction, download anything, change boot assets,
probe a live target, or execute package payloads/hooks.

The report distinguishes exact version changes, same-version metadata/archive
changes, missing archives, unsatisfied dependencies, package conflicts, possible
runtime consumers and missing baseline recovery assets. Required platform
packages cover the retained Asahi boot/kernel/firmware/Mesa/audio/protection
stack; names come from `recovery_preflight.PLATFORM`. The baseline protected
closure comes from the actual tuple report, not an invented package shortlist.
A retained `grub` package is treated only as existing Asahi metadata; no PC
bootloader commands or assumptions are introduced.

## Inputs

All references have exactly these fields, using an absolute regular file path:

```json
{"path":"/absolute/retained/file.json","size":123,"sha256":"64 lowercase hexadecimal characters"}
```

JSON references use `transaction.bound` and duplicate-key/non-finite rejection
from `tuple_audit`. Archive/signature/asset references also reject symlinks and
hard links through the maintained recovery reader. Outputs require an existing
owned mode-0700 directory, use mode0600, and never overwrite an existing file.

The contract has exactly these fields:

```text
schema_version: 1
before_release: {id: string, inventory: REF, archive_index: REF}
candidate_release: {id: string, inventory: REF, archive_index: REF}
protected_tuple: REF
coordinated_policy: REF
retained_recovery_assets: REF
```

An inventory contains exactly one of `packages` or `proposed_final_inventory`.
Each row has `metadata` with retained ALPM `NAME`, `VERSION`, `ARCH`, dependency,
provision, conflict, replacement and license lists. Existing observed-image and
prepared-final-inventory envelopes are supported. A final row's name/version
and repository annotations must match its metadata. Architectures are
`aarch64` or `any`; neither proves native execution or M2 compatibility.

The protected tuple uses the existing `input_sha256.image` and
`proposed_installed_dependency_graph` fields. Its image digest must equal the
before inventory reference, and every unique protected name/version must match
the before inventory. Missing platform members remain explicit blockers even
when an operator permits their removal.

An archive index is:

```text
{schema_version: 1, kind: "platform-archive-reference-index", packages: [
  {name: "mesa", archive: REF, signature: REF,
   provenance: {document: REF, row: 0}}
]}
```

`provenance.document` identifies an original retained receipt/capture with a
`packages` list. `row` selects one record containing `metadata` or
`observed_image_metadata`, `archive`, and `signature`. Names, full epoch-bearing
versions, architecture, dependency/provision/conflict/replacement/license values
must match the release inventory. Archive and signature size/hash must match
the original record; original `bytes` fields are supported. Capture records
without paths require explicit local paths in the index; paths are never
inferred or URLs fetched by the planner. Superseded recovery receipts must bind
the exact before inventory. Unsupported receipt shapes require a separately
reviewed producer rather than guessed normalization.

Every indexed archive/signature is rehashed. A bounded child uses the maintained
inert XZ `.PKGINFO` reader and `verify_pkginfo`; license values are also checked.
The report carries original provenance references and retained signature claims.
Required before/candidate archives need a retained valid-signature claim for a
known project-pinned upstream primary. Raw GPG status, when present, is parsed
with the existing fail-closed status reader. These are checks of retained
observations, **not fresh signature verification or independent owner trust**.
No claim about full payload/ABI/hook correctness follows from inspecting PKGINFO.

Baseline recovery requires every protected/platform package and every changed
or removed before package. Candidate retention requires changed/added packages
and the platform stack. Missing archive evidence is unknown, not proof of a
same-version byte replacement. Both known archive digests must differ before
such a replacement is reported.

## Explicit policy and recovery assets

The policy binds the exact `before_release` and `candidate_release` objects,
including both archive-index references:

```text
{schema_version: 1, kind: "coordinated-platform-version-policy",
 before_release: BEFORE, candidate_release: CANDIDATE,
 coordinated_sets: [
   {name: "reviewed-platform-tuple",
    before: {"mesa": "old-full-version", "linux-asahi": "unchanged-full-version"},
    candidate: {"mesa": "new-full-version", "linux-asahi": "unchanged-full-version"},
    allow_changes: ["mesa"], allow_downgrades: [], allow_removals: []}
 ]}
```

Each set must have identical unique member names on both sides and exact
versions from the corresponding inventory. A missing package is represented by
JSON `null`. Sets cannot overlap. Every change, including additions and
same-version metadata/archive changes, requires `allow_changes`; downgrades and
removals also require their separate explicit allowances. An empty set list is
an explicit hold: it permits no changes. The full referenced inventories bind
unchanged packages as well. Policy acceptance means an exact proposed data set,
not a tested compatible version tuple or permission to install.

Recovery assets bind the before inventory:

```text
{schema_version: 1, for_inventory: BEFORE_INVENTORY_REF, assets: [
  {role: "boot-chain", artifact: REF}, {role: "kernel", artifact: REF},
  {role: "kernel-release", artifact: REF}, {role: "firmware", artifact: REF},
  {role: "user-configuration", artifact: REF},
  {role: "system-configuration", artifact: REF}
]}
```

All supplied assets are rehashed; missing roles become concrete next actions.
The planner cannot determine completeness or restore a machine from these bytes.
Use `target_snapshot.py` and the appropriate exact-target preflight separately
for target/runtime identity; keep 13-inch `apple,j413` and 15-inch `apple,j415`
physical evidence separate.

## Run and interpret

```sh
mkdir -m 700 /absolute/private-output
python3 -B scripts/platform/platform_transition.py \
  --contract /absolute/transition-contract.json \
  --contract-sha256 CONTRACT_SHA256 \
  --output /absolute/private-output/transition-report.json
python3 -B scripts/platform/test_platform_transition.py
```

Exit0 / `PASS-offline-data-plan` means this supplied data plan has no listed data
gaps. Exit2 / `BLOCKED-data-gaps` is a valid assessment with package/side/version
or recovery-role actions. Exit1 refuses malformed, mismatched or over-budget
inputs and creates no final report. Reports always leave transaction,
installation, fresh crypto, owner trust, hardware and recovery acceptance false.
Both M2 Air hardware workflows remain `NOT RUN`.

Dependency witnesses retain every matching provider. Consumer impact reuses
`compare_releases.dependency_impact`; added-only package dependencies are reported
separately. Neither consumer paths nor successful dependency witnesses select
providers, prove rebuild requirements, inspect file conflicts or replace a
reviewed ALPM preparation. Native/installed lifecycle, exact-target boot,
audio/protection, session-preserving suspend and actual interrupted-update
recovery remain separate integration gates.

Resource bounds: 4096 inventory/index rows, existing 20MiB document reader,
64MiB unique provenance documents, 512MiB unique archive/signature bytes, 300MB
per archive, 64KiB per signature, 8,000,000 witness scan work estimate: (dependencies + conflicts) × (packages + provides),
120-second aggregate assessment, and 20-second/15-CPU-second/512MiB archive
children. Consumer impact runs in a separate 30-second/15-CPU-second/512MiB
child with 8MiB request/response limits. The existing comparison graph adds independent finite edge/work/path
bounds. No bound implies the inputs are trusted.
