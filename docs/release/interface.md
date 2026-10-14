# Local release CLI and evidence contract

Status: implemented and exercised on x86_64 Linux with **synthetic packages and ephemeral keys**. No real overlay was built, installed, hardware-tested, promoted, or published. The coordinator selected the root MIT license; package licenses still require their own audits. M3 remains incomplete.

`python3 scripts/release/release.py --help` describes four local operations. Requirements are Python 3.11+, installed `repo-add`, `bsdtar`, `vercmp`, and GnuPG. No dependencies are downloaded or installed by this CLI. Tests use only synthetic local archives. No production key or project identity is generated. Inputs contain no secrets; a signing custodian runs this tool outside untrusted build execution.

## Commands

Every invocation requires `--root LOCAL_STORAGE --gpg-home EXTERNAL_GPG_HOME --key FULL_FINGERPRINT` before its subcommand. The GPG home must exist outside both storage and the project checkout. The key is supplied by the caller; verification requires that full primary or signing-subkey fingerprint. An explicitly pinned primary permits its bound signing subkey. GnuPG validity, expiry/revocation status and SHA-2 signatures are checked; a default-key fallback is never used. Keys are never retrieved, imported, exported, locally trusted, revoked, or distributed by this tool.

```sh
python3 scripts/release/release.py --root /srv/local-overlay --gpg-home /secure/signing-home --key "$RELEASE_FINGERPRINT" stage --spec /srv/reviewed-inputs/spec.json
python3 scripts/release/release.py --root /srv/local-overlay --gpg-home /secure/verification-home --key "$RELEASE_FINGERPRINT" verify --release-id rc-1 --channel staging
python3 scripts/release/release.py --root /srv/local-overlay --gpg-home /secure/signing-home --key "$RELEASE_FINGERPRINT" promote --release-id rc-1 --gates /srv/reviewed-inputs/gates.json
python3 scripts/release/release.py --root /srv/local-overlay --gpg-home /secure/signing-home --key "$RELEASE_FINGERPRINT" verify --release-id rc-1 --channel stable
python3 scripts/release/release.py --root /srv/local-overlay --gpg-home /secure/signing-home --key "$RELEASE_FINGERPRINT" withdraw --release-id rc-1 --reason /srv/reviewed-inputs/incident.txt
```

These are examples, not a configured endpoint or an instruction to modify a running machine. Exit 0 prints one JSON result; exit 1 prints an error. Subprocess arguments are passed directly without a shell. Invalid or incomplete input fails closed. Inputs and output storage must be operator-controlled; the cooperative exclusive lock does not secure them against another user with filesystem write access.

`stage` verifies all supplied hashes, parses package archives without executing recipes/hooks, checks the complete dependency transaction, signs each package and both repository databases, and creates a signed `release.json`. `repo-add` embeds the matching package signatures; database names, versions, architectures, filenames, hashes and relations are compared back to the artifacts. Verification repeats those checks and checks the exact file set and managed symlinks. Staging permits clearly labeled native/cross/emulated/synthetic results and an absent project license so blocked work remains inspectable. Staging conveys no installation approval.

`promote` verifies and freezes the staged bytes and validated gate object, checks every required gate, signs a separate promotion record, retains a copy under `stable/ID`, and switches `stable/current` by local atomic symlink replacement. It never uploads or publishes. Downgrades of a package present in the preceding selection are rejected. `verify --channel stable` also verifies the signed promotion record and rechecks the gates. There is no boolean approval override.

`withdraw` creates a signed local incident record, removes `stable/current` if it names the affected release, and prevents normal verification or subsequent promotion of that ID. It retains every archive and record. It does not regenerate a public endpoint, contact clients, revoke a key, repair installed packages, or automatically select an older base/overlay combination. See [recovery policy](recovery.md).

## Storage and retention

```text
LOCAL_STORAGE/
  .release.lock
  staging/ID/{release.json,release.json.sig,spec.json,base.json,
              project-license.txt,repo/,provenance/,evidence/}
  stable/ID/                 # immutable copy of the signed staging bundle
  stable/current -> ID      # local selection only
  promotions/ID.json{,.sig}  # signed frozen gates and release checksum
  withdrawals/ID.json{,.sig} # signed incident/recovery text; artifacts retained
```

Names use letters/digits then letters/digits, `.`, `_`, `+`, or `-`; `current` is reserved. Existing release IDs are never overwritten. All releases are retained: no prune/delete command is supplied. Package `.pkg.tar.gz`, `.pkg.tar.xz` and `.pkg.tar.zst` inputs are supported. Parent managed directories and input files may not be symlinks. Only the normal repo-add basename symlinks are retained inside a bundle.

Atomic selection is a local visibility property. There is no power-loss durability claim, multi-host transaction, public anti-replay protocol, or storage-capacity automation. A failure after retaining a stable copy but before selection leaves an inactive retained copy; inspect signed records and repair the local selection under operator control, or use a new release ID. Never infer that this state is a tested machine recovery.

## Staging specification, version 1

JSON inputs use SHA-256 lowercase hex digests. Each file reference is `{ "path": "relative/file", "sha256": "64-hex" }`, relative to the specification's directory; absolute paths, traversal and symlinks are rejected. Copy externally produced files into an operator-reviewed input directory first. Original input paths are recorded, not assumed retrievable indefinitely.

Required top-level fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `release_id`, `repo_name` | Unique release ID and pacman repository basename |
| `source_commit` | Full 40-hex project source commit |
| `target_arch` | `aarch64` |
| `synthetic` | Set `true` for any fixture; blocks stable |
| `base` | File reference plus `snapshot_id`; complete target transaction inventory |
| `packages` | Nonempty array of `{artifact: FILE_REF, provenance: FILE_REF}` |
| `policy` | Exact selected package, machine and compatibility scope described below |
| `evidence` | Array of file references plus unique `id`; stored as `evidence/ID` |
| `project_license` | File reference plus `spdx`, e.g. reviewed root `LICENSE` with `MIT`; absent license blocks stable |

`policy` requires `selected_packages` (names exactly matching the overlay artifacts), `supported_models` (a nonempty subset of `m2-air-13`, `m2-air-15`), `protected_packages` (nonempty actual baseline package names), and nonempty `coordinated_sets`, each `{name, versions: {package: exact_version}}`. The coordinator, not this CLI, selects those sets. Include boot/firmware/kernel/Mesa/audio/protection packages actually present in the frozen baseline; a short test fixture list is not an acceptable real platform policy. This contract is not a modification of the shared package manifest.

The base inventory is `{schema_version: 1, snapshot_id, target_arch: "aarch64", kind: "complete-target-transaction", packages: [...]}`. Each entry needs `name`, `version`, `arch`, `depend`, `provides`, `conflict`, and `files`; the last four are arrays, including empty arrays. Files are canonical relative file/symlink ownership paths, excluding shared directories. Record the intended installed base plus the full dependency closure for the candidate, not every alternative in a repository. Overlay packages shadow same-name base entries in the modeled transaction except protected packages, which cannot be replaced/provided/conflicted with. Differently named `replaces` relations are rejected for manual base redesign. Versioned dependencies and virtual provides use ALPM `vercmp`, including epochs; unversioned provides do not satisfy versioned dependencies. All modeled packages' dependencies, conflicts, ownership, and coordinated exact versions must agree. This is a conservative consistency check, not a full libalpm transaction solver or runtime ABI proof.

Per-artifact release provenance is:

```json
{
  "schema_version": 1,
  "artifact_sha256": "64-hex",
  "package": {"name": "PACKAGE", "version": "VERSION-REL", "arch": "any"},
  "source_commit": "40-hex project commit",
  "recipe_sha256": "64-hex PKGBUILD digest",
  "licenses": ["MIT"],
  "sources": [{"url": "upstream URL", "commit": "40-hex upstream commit"}],
  "build": {"execution": "native", "architecture": "aarch64",
            "environment": "pinned builder description", "snapshot_id": "BASE_SNAPSHOT"}
}
```

A source uses either an exact Git `commit` or archive `sha256`; all licenses/notices and source verification receipts belong in retained review evidence. Architecture-neutral package metadata (`any`) still requires native aarch64 build execution for stable. Release provenance is an assembly envelope: it supplements, never replaces, the build worker's raw provenance. No adapter guesses a PASS from `.SRCINFO`, README declarations, or successful static checks.

## Optional recipient-source association, version 1

A draft specification may opt in with `source_delivery: {schema_version: 1,
index: {id: "source-delivery-v1.json", path: "delivery/index.json", sha256:
"<actual-index-SHA256>"}}`. The index is an already prepared, hash-pinned input.
Staging calls `scripts/release/source_delivery.py` to assemble its exact finite
evidence set, merges those references with existing evidence, and copies them
through the normal evidence transport before signing. A conflicting ID refuses
staging. The staged specification records the complete assembled evidence set;
the original draft is unchanged.

The index has exactly `schema_version: 1`, `purpose: "release-source-delivery"`,
an explicit `synthetic` boolean and `packages`. There must be exactly one row for
every package in the release's explicit selected set. Each row has:

- `package`: exact `name`, full `version`, `arch` and binary `sha256`;
- `bundle`, `source_map`, `recipe`, `authorization`: material descriptors;
- a nonempty `notices` array of material descriptors;
- `recipe_key`: the recipe's canonical relative key in the flat source map;
- `review_status`: the supplied existing package-review status, retained as data.

A material descriptor is exactly `{id, path, sha256, bytes}`. IDs are unique
simple evidence basenames across the index and all materials. `path` is a safe
input-relative publisher path; recipients read only the corresponding signed
`evidence/ID`, never that input path. Required materials must be nonempty.
`source-delivery-receipt.json` is reserved for recipient output. File, aggregate
and count ceilings remain 512 MiB, 2 GiB and 4,096, with 4 MiB JSON limits.

The source map is the existing producer's flat canonical relative-path to
SHA-256 map. Its `recipe_key` must equal both the actual retained recipe hash
and the existing package provenance's `recipe_sha256`. No generic archive
reconstruction is performed. Consume an existing reviewed package source bundle,
its source map and notices; FDK already provides its own pack/read/reconstruct
implementation.

The `authorization` material retains an existing package completeness/review
artifact as opaque, nonempty, hash-bound data. It need not use a new JSON schema,
name a new approver or contain an approval boolean. `review_status` is the
supplier's existing status label; values such as INCOMPLETE or NOT RUN remain
visible and do not prevent a byte-association check. The helper does not turn
that label into license permission, source completeness or binary/source
correspondence. Existing package-specific review records, producer verification
and stable/license gates retain their own authority. The signed payload binds
which exact binary and materials were associated; it does not establish that a
supplied review statement is true.

The index contains no enclosing release digest. Its material hashes are fixed
first, then the signed release's existing payload map binds the index and all
material bytes. Release verification repeats the complete association check.
The existing development client validates it without changing the envelope's
version or target vocabulary. Its `sources` command first verifies the existing
signatures/freshness/namespace, rejoins the actual enclosing release SHA and
payload bytes, and then performs exact-identity lookup or private local export.
Export copies data only, with no build, fetch, install, upload or source execution.

Without opt-in, staging explicitly reports `source_delivery: "NOT_DECLARED"`.
A checked association or export always leaves source-completeness acceptance
false. Legacy development fixtures are not full-port source-delivery evidence.
Existing stable, licensing, signing, native-build and hardware gates remain in
force; this optional versioned interface does not promote any release or add an
admission prerequisite to queued jobs.

## Stable gate envelope, version 1

A gate envelope contains `schema_version: 1`, `release_id`, `release_sha256` (signed `release.json` digest), `source_commit`, `base_sha256`, `project_license_sha256`, `package_sha256: {name: digest}`, `synthetic: false`, and `records`. Every record requires `kind`, `result: "PASS"`, a named `operator`, `date_utc`, nonempty `commands` (actual command strings), and nonempty `logs` (IDs of nonempty checksum-bound staged evidence). FAIL, NOT RUN, duplicate required records, synthetic records, missing IDs or mismatched release hashes are rejected.

The evidence must be assembled before staging so raw files are frozen and signed. The final envelope can be assembled after staging to bind its release digest. Gate records are trusted factual attestations from the signing custodian and independent reviewers; software cannot determine whether an operator fabricated physical-machine logs. The custodian must authenticate provenance and reviewer/machine identities outside this schema. Checksums and signatures establish byte binding, not the truth of a claim.

Required records:

- One `release-review` with `custodian`, `alternate_custodian`, `hardware_owner`, and evidence IDs `release_notes`, `retained_base_inputs`, `recovery_plan`, `license_review`. Record actual availability of ongoing owners in that evidence; ephemeral agents are not custodians.
- For every package, two `native-build` records with `package`, `attempt: 1`/`2`, `execution: "native"`, `architecture: "aarch64"`, exact `artifact_sha256`, `snapshot_id`, `environment_digest: "sha256:64-hex"`, distinct `clean_environment_id`, `dependency_lock`, and the raw build bindings below. Retain distinct nonempty logs.
- For every package, one `package-review`, whose operator differs from the build operators. It needs `inspection_report` and `checks` mapping `licenses`, `source-pins`, `files-ownership`, `hooks`, `config-preservation`, `protected-platform`, `16k-pages` to `"PASS"`. For no compiled binary, record why the page-size review is satisfied in the report.
- For every package, one `reproducibility` with `method: "byte-identical"`, `artifact_sha256: [first_digest, second_digest]`, and `second_artifact` (actual archive evidence ID). This first implementation deliberately requires byte identity. A content-equivalent build remains blocked pending a separately reviewed policy/schema for documented reproducibility limits.
- For each advertised model, one `functional`, one `install-removal`, and one `upgrade-recovery` record. Each needs the same `machine_id`, `model`, and `machine_record` ID. Different Air sizes must have separate records. `checks` maps each required name below to `{result: "PASS", evidence: "RAW_EVIDENCE_ID"}`. Each evidence file must exist, be nonempty and match the signed manifest.

### Raw native build interface

`native-build.build_record` is the evidence ID of the build worker's actual `provenance.json` from `scripts/build/build.py`. Release validation requires `schema_version: 1`, `status: "built-package-static-pass"`, `mode: "native"`, `builder_host_arch: "aarch64"`/`"arm64"`, a digest-pinned `image`, matching `image_id`, `clean_environment_id`, `exit_code: 0`, exact `artifacts: {archive_filename: digest}`, and `recipe_inputs.PKGBUILD` matching release provenance.

`file_bindings` maps **every** original raw-provenance `files` path to its staged evidence ID; every file digest is rechecked. The raw files must include `build.log`, `validation.json`, and the actual `artifacts/ARCHIVE_FILENAME`; each attempt's actual build log must appear in its record's `logs` and use a distinct evidence ID. The raw build command is required. `recipe_bindings` maps **every** raw-provenance `recipe_inputs` path to its staged evidence ID, likewise checked. `builder_package_lock` identifies the actual sorted `pacman -Q` lock whose digest equals raw `expected_packages_sha256`. Retain original path-to-ID mappings in release assembly review. This directly consumes raw build output without editing the build worker's files or trusting a PASS flag alone.

`dependency_lock` is a release-side JSON augmentation: `{schema_version: 1, snapshot_id, packages: [{name, version, sha256}], retrievable_inputs: [{uri, sha256}]}`. Record **all transitive build dependencies**, source/OCI inputs and verified artifact locations; the package-transaction `base.json` serves a different purpose. The augmented package/version set must exactly match the original builder package lock, without duplicates. This CLI checks fields/checksums, not remote retention availability. The custodian verifies availability and security suitability in the release-review evidence.

### Exact-machine interface

`machine_record` JSON needs `model`, `machine_id`, `soc: "M2"`, `execution: "physical"`, the release's `base_sha256` and `package_sha256`, nonempty `platform_versions`, and evidence IDs `baseline`, `acceptance_contract`. The baseline and contract are retained files, not booleans. Use the project hardware and acceptance records, with exact kernel/boot/firmware/Mesa/Hyprland/Aquamarine/audio/protection versions. Freeze the contract before trials; its JSON includes a positive integer `sleep_wake_repetitions`. `functional.sleep_wake_completed` must meet that count.

| Gate | Required check names |
| --- | --- |
| `functional` | `accelerated-login`, `scaling-brightness`, `keyboard-trackpad`, `wifi-bluetooth`, `audio-speaker-protection`, `headset-microphone`, `browser-video`, `lock-unlock`, `repeated-sleep-wake`, `applications-preserved` |
| `install-removal` | `fresh-install`, `existing-config`, `interrupted-setup`, `repeat-setup`, `remove`, `reinstall`, `user-edits-preserved` |
| `upgrade-recovery` | `repository-trust-bootstrap`, `repository-fresh-install`, `previous-release-upgrade`, `base-overlay-full-upgrade`, `interrupted-upgrade`, `failed-upgrade`, `service-startup-failure`, `rollback`, `boot-recovery`, `session-recovery`, `functional-baseline-rerun` |

`upgrade-recovery` additionally needs a distinct `previous_release_id` and a retained `previous_release_record` evidence ID. Before the first public release, test an actual local release pair through the signed repository on the exact machine. A snapshot, a package extraction, a mocked gate, another Mac model, or an emulated build is not that test. External-display limits are recorded separately; they do not override required checks.

## Scope boundaries and remaining work

Original project licensing is resolved by root `LICENSE`; upstream license resolution, native build inputs/builds and exact-machine results remain separate gates. A stable bundle can be prepared only after all required evidence exists. Publishing endpoint configuration, public trust bootstrap/distribution, capacity enforcement, signing-custody establishment, authenticated key rotation/revocation deployment, stale-metadata client protection, freshness/security review of upstream pins, and actual machine recovery remain operator/integration tasks. No public release exists.

The build comparison tool currently supports content equality as well as byte equality. Use its `--require-bytes` mode for this release contract. Content-only results must remain explicitly blocked rather than being silently promoted. Shared-manifest proposals: record selected package names, immutable base inventory hash/snapshot, protected package names, coordinated exact versions, supported exact models, release/provenance/evidence hashes and promotion state. The coordinator alone edits shared manifests.

## Upstream sources and local verification

`repo-add` creates database/file-list archives and embeds adjacent package signatures; signing and database verification are separate operations. This tool signs explicit keys and independently verifies the frozen outputs. [Pacman repo-add manual](https://man.archlinux.org/man/repo-add.8)

Runtime dependency/provides/conflict metadata comes from `.PKGINFO`, and ALPM comparison semantics come from `vercmp`. [Pacman PKGINFO manual](https://man.archlinux.org/man/PKGINFO.5.en), [vercmp manual](https://man.archlinux.org/man/core/pacman/vercmp.8.en)

The implementation checks GnuPG's status protocol, including `EXPKEYSIG`, `EXPSIG`, `REVKEYSIG`, invalid/error statuses and pinned `VALIDSIG` identities. GnuPG exit success alone is insufficient. [GnuPG status interface](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html), [GnuPG status definitions](https://github.com/gpg/gnupg/blob/master/doc/DETAILS)

Run `python3 scripts/release/test_release.py`. Tests create temporary synthetic packages and an explicitly named disposable signing identity, kill only their own GPG agents, and delete their temporary homes/artifacts afterward. They exercise signed staging/verification, missing/synthetic gates, raw-evidence schema modeling, dependencies/providers/epochs/conflicts/ownership, protected scope, tampering and full fingerprint checks, expired/revoked-key rejection, retained withdrawal, and frozen promotion data. One atomic-selection test **mocks gate validation** solely to test storage mechanics; it proves no real stable gate. No test result certifies ARM or M2 behavior.
