# Supported Asahi composition adapter

This DATA-only adapter connects the retained Asahi image/protected tuple and
repository catalogs to current project candidates, using the existing
`scripts/platform/transaction.py::prepare` engine. It does not introduce another
dependency solver or modify any previous proposal, protected list or selection.

```sh
python3 -B scripts/port/supported-composition/compose.py \
  --contract /absolute/composition-inputs.json \
  --contract-sha256 REVIEWED_SHA256 --output /absolute/new-output
python3 -B -Werror::ResourceWarning \
  scripts/port/supported-composition/test_compose.py
```

The preinstalled reviewed libalpm ABI must be `16.0.1`; bsdtar/libarchive and
Python are also required. Nothing is installed or fetched. Exit `2` means the
metadata plan prepared but remains **HOLD** for custody/acceptance. Exit `1`
means failed/incomplete metadata or refused input. Neither exit accepts a target
transaction, build, package installation, compatibility or hardware result.

## Exact contract

References have exactly `path` (absolute), `size` and lowercase `sha256`. Inputs
are bounded regular single-link DATA, non-writable by group/others, with no symlink ancestors;
JSON rejects duplicates/non-finite values. The contract has these exact fields:

```json
{
  "schema_version": 1,
  "kind": "supported-Asahi-composition-inputs-v1",
  "workflow": "project-extension",
  "image_inventory": {"path": "/retained/image-inventory.json", "size": 123, "sha256": "REVIEWED_SHA256"},
  "protected_tuple": {"path": "/retained/tuple-report.json", "size": 123, "sha256": "REVIEWED_SHA256"},
  "catalogs": [
    {"name": "asahi-alarm", "path": "/retained/asahi-alarm.db", "size": 123, "sha256": "REVIEWED_SHA256"},
    {"name": "core", "path": "/retained/core.db", "size": 123, "sha256": "REVIEWED_SHA256"},
    {"name": "extra", "path": "/retained/extra.db", "size": 123, "sha256": "REVIEWED_SHA256"}
  ],
  "candidate_srcinfo": [
    {
      "srcinfo": {"path": "/checkout/package/.SRCINFO", "size": 123, "sha256": "REVIEWED_SHA256"},
      "archive": {"path": "/retained/candidate-1-1-any.pkg.tar.zst", "size": 123, "sha256": "REVIEWED_SHA256"},
      "archive_scope": "host-assembled-unqualified"
    }
  ],
  "roots": [{"name": "candidate", "version": "1-1", "repo": "project"}],
  "providers": [],
  "allowed_base_changes": []
}
```

Values above are schema examples, not supplied artifact identities. Workflow is
`project-extension` or `full-desktop`. The latter additionally requires the full
named Asahi boot/kernel/firmware/Mesa/audio/protection set in final metadata.
A minimal extension cannot count as a complete supported system.

The original image/tuple binding and every protected name/version are checked.
All original protected identities remain protected. Any baseline platform member
from the maintained platform-name set is also preserved. Original protected
versions cannot be relaxed by a caller base-change entry. Missing boot anchors
or full-workflow platform members fail explicitly. `mesa-dummy` and alternative
protected versions stay excluded with named decisions.

Roots have exact `name/version/repo`; repositories are the supplied catalog
names, `project`, or an explicitly selected `observed-Asahi-base`. Provider
entries add `requirement` to that identity. The pinned package must declare a
matching effective provider before and after preparation. Multiple provider
alternatives are not approved defaults: the existing engine's unapproved-choice
result fails. Unknown/filtered roots remain named unsatisfied pins.

An unprotected base version change requires an exact
`{name, before, after, repo}` entry in `allowed_base_changes`, bound to this
baseline. Removals are never approved here. These entries express caller DATA
policy only; they do not establish ABI, source, signature or update acceptance.
Same-version project replacement needs a separately explicit reinstall path and
is held rather than silently satisfied by the old installed package.

## SRCINFO and real archive boundary

Only single-package SRCINFO with one `aarch64` or `any` declaration is supported.
Declared runtime relations, including target-specific aarch64 fields, are parsed
as text. Recipe/source commands are never evaluated. Split-package inheritance
or unsupported architectures refuse rather than being guessed. Source lists,
checksums, licenses and an architecture declaration are not build/source/license
or hardware evidence.

A candidate's optional archive must be real supplied bytes with an exact
reference. `archive_scope` is caller-declared and unaccepted: accepted labels are
`host-assembled-unqualified`, `retained-native-development-unqualified` and
`synthetic-test-only`. No label grants native or production authority.

The maintained release PKGINFO parser is reused with a private bounded,
read-only bsdtar wrapper. Candidate identity, architecture, runtime relations and
license declarations must match SRCINFO exactly before admission. Only then do
its actual filename, size and SHA-256 enter the metadata DB. No archive identity
or checksum is manufactured from SRCINFO. A source-only reference, or a candidate
with `archive: null`, is a named missing-archive HOLD and gets no DB row.
Signature references remain unknown; this tool performs no signature verification.

Retained image/catalog metadata keeps its own distinct provenance. Unsupported,
sparse or malformed catalog entries are named unavailable holds with reasons;
a filtered selected root cannot disappear into a complete result. Catalog
filenames are required before entering libalpm. During development, incomplete
filename metadata produced errno41 and a C crash on a provider route; complete
filenames removed that failure, and normal explicit-provider/refusal behavior
was verified. No existing ctypes binding or frozen platform module was changed.

## Containment, outputs and next stage

Existing libalpm preparation/audit runs in a child with 90-second outer timeout,
60-second CPU limit, 1.5-GiB address-space limit, 32-MiB file limit and
`RLIMIT_CORE=0`. It exposes the same no-commit/no-download API. The adapter copies
only real semantic/archive declarations to the private DB representation; PGPSIG
and unrelated informational fields stay in the full source/provenance inventory.
The projection does not change dependency/conflict/provider semantics.

Each read-only archive command has a 20-second timeout and 1-MiB output check.
Input intake is capped at 20 MiB/reference and 64 MiB aggregate with a 120-second
reader deadline; candidate SRCINFO is capped at 1 MiB. Metadata/result bounds and
finite root/provider/candidate counts also apply. This is metadata-tool
containment, not a package sandbox or a general process controller.

A new mode0700 output directory retains `composition.json`, projected
`preparation-inputs.json`, worker stdout/stderr and all source/input pins.
Private DB/cache/GPG/hook directories are removed. C failure or timeout produces
FAIL with available DATA/diagnostics instead of terminating the parent adapter.
No host package DB, trust, configuration, filesystem image or payload is mutated.

Worker Python exceptions additionally expose a bounded JSON category/message in
the parent exception and failed report, so CI diagnostics survive test-directory
cleanup. Control/non-ASCII characters are escaped; unstructured import/C errors
expose only an escaped 512-byte stderr tail. Full stderr remains in the output.
This does not relax the existing engine's exact libalpm16.0.1 ABI gate. Both
Python3.12.13 and3.14.7 pass the 14 composition and eight maintenance controls
locally with that reviewed library; a distribution's different ABI still
refuses and requires a separately reviewed environment/engine, not a skip or a
version-string substitution.

`proposed_final_inventory` uses the existing platform-transition inventory
metadata envelope, including exact selected origin/version annotations. It can
supply a candidate inventory for the existing transition/recovery planner once
real archive/signature indexes and exact coordinated policy are supplied.
Per-package custody, signature authentication, installed payload/file/hook
correspondence, source/license/grant/maintainer review and native-build limits
remain explicit holds. This adapter never creates the missing acceptance facts.

## Optional three-package maintenance DATA proposal

`--maintenance-proposal /absolute/proposal.json` plus
`--maintenance-proposal-sha256 SHA256` adds a **second** metadata preparation.
The original contract is evaluated first, unchanged. Its top-level
`metadata_prepare_status`, blockers, protected decisions and candidate inventory
remain the original-policy result; `original_policy` preserves that summary.
The optional result is under `proposed_maintenance` and overall status is HOLD
with `approval_status: UNAPPROVED`, even when that second preparation passes.
There is no apply, selection or approval operation.

The proposal has exactly these fields:

```text
schema_version: 1
kind: unapproved-Asahi-three-package-maintenance-v1
approval_status: UNAPPROVED
composition_contract: REF to the exact unchanged original composition contract
image_inventory: exact same REF as the original contract
protected_tuple: exact same REF as the original contract
catalogs: exact same ordered name/REF array as the original contract
changes: exactly these three objects, in any order:
  {name: python, before: 3.14.7-1, after: 3.14.8-1, repo: core, reason: NONEMPTY_TEXT}
  {name: networkmanager, before: 1.58.1-1, after: 1.58.1-2, repo: extra, reason: NONEMPTY_TEXT}
  {name: perl, before: 5.42.2-2, after: 5.42.3-1, repo: core, reason: NONEMPTY_TEXT}
```

`REF` has the same exact `path/size/sha256` shape as other inputs. Every reason
must be nonempty, at most1024 characters and free of control characters. This
version is intentionally finite to the retained before/after identities above;
other changes need a different reviewed proposal implementation.

The original workflow must be `full-desktop`; all three after identities must
already be exact explicit roots/providers in it. The proposal cannot add or
retarget roots/providers, alter reference bindings, add another protected change,
change kernel/Mesa/boot/audio policy, substitute another after version or flip
its approval status. Missing before identities refuse. New after records come
only from the same retained catalog bytes. Only the proposed Python protection
value changes in memory for this second private run; original protected files,
original-policy evaluation and all other protections remain unchanged.

The second result checks that precisely those three baseline changes occur,
each with the exact repository/version, and that no additional implicit baseline
change/removal is introduced. It separately records unchanged original protected
versions and matches against proposed expected versions. Its inventory is
`proposed-maintenance/inventory.json`, explicitly marked unapproved. Worker
DATA/diagnostics remain in that subdirectory; private DBs are removed.
Custody/signature/source/license/native/hardware/recovery holds remain intact.

With a proposal, exit2 means only the proposed metadata preparation passed while
remaining unapproved; top-level original metadata may still correctly say FAIL.
`proposed_metadata_prepare_status` in the CLI summary and
`proposed_maintenance.metadata_prepare_status` in the report distinguish them.
Invalid proposals or failed proposed preparation return1.

## Map authenticated Overlay583 archives to a held candidate

`staged_archives.py` reads an existing composition report and its original
contract. It reopens the exact Overlay583 repository files and joins the pinned
authenticated preflight. For each candidate package, it compares the name,
version, architecture, filename, size and SHA-256. An exact archive can supply
candidate bytes only when the detached signature also matches the candidate
catalog, the recorded signer is from the historical ALARM scope, and the
candidate version preserves any original protected tuple.

```sh
status=0
python3 -I -B scripts/port/supported-composition/staged_archives.py \
  --contract "$contract" --contract-sha256 "$contract_sha256" \
  --composition "$report" --composition-sha256 "$report_sha256" \
  --staging "$overlay583" \
  --preflight "$preflight" --preflight-sha256 "$preflight_sha256" \
  --output "$output" || status=$?
test "$status" -eq 2
```

The report preserves repository choices, original blockers and any optional
unapproved maintenance inventory. It reports absent archives, different
versions or bytes, missing catalog pins, TEST signing and protected conflicts.
An exact match supplies archive bytes only. The command keeps the result on
HOLD and exits 2 after writing it. Input refusals exit 1. Fresh signature trust,
source correspondence, Asahi installation, hardware and release remain held.

Run the mapping separately with the retained contract/report pair for each
profile. Both candidate inventories have 626 packages and preserve the 201
original protected versions. The separate three-package maintenance proposal
still holds Python 3.14.8-1 against protected 3.14.7-1.

| Profile | Exact Overlay583 pairs | Catalog operands outside staging | Qt6 Base |
| --- | ---: | ---: | --- |
| Original | 330 | 35 | `6.12.0-2` archive body remains missing. |
| Optional, unapproved | 331 | 34 | `6.12.0-3` matches its own catalog archive and signature. |

The original proposal has 28 missing `extra` operands with exact catalog
archive and signature pins, and seven `asahi-alarm` operands with exact archive
pins awaiting detached-signature authentication. There are no missing `core`
operands in this held profile. The report separately identifies 259 observed
Asahi base rows that need archive-to-installed-payload binding and two project
candidates with distinct source requirements.

List the exact catalog operands for a later intake review.

```sh
jq '.original.missing_catalog_intake_operands' "$output"
```

Each operand is produced by the existing
`scripts/platform/authenticate_missing.py::archive_spec` parser. The
`authenticate_missing.py` command's v1 contract still requires its historical
150 missing rows and separate Python operand. This mapping supplies the same
individual operand shape for a separately reviewed intake.

### Retained addition-input readback

The private capsule for the optional Qt profile contains **367 verified
archive/signature pairs** totaling 593,004,670 bytes. It combines 331 exact
Overlay583 pairs, 34 subsequently authenticated catalog pairs, and two project
pairs signed with scoped TEST keys. The 367 inputs cover 365 added names and the
unapproved NetworkManager and Perl updates. The 259 unchanged observed Asahi
base packages are outside the addition set. The original metadata policy still
fails and the optional Qt profile remains unapproved. Production trust,
installation, rollback and physical M2 validation remain open.

With `ASAHI_ADD_CAPSULE` set to the absolute path of the retained private
capsule, verify its seal and readback locally.

```sh
(
  set -e
  cd "${ASAHI_ADD_CAPSULE:?set the retained private capsule directory}"
  printf '%s  %s\n' \
    dc91526a2416ec4c160d73b5f01491065bfb87501df73de995ca665dee85acc7 \
    SEAL.DATA.sha256 | sha256sum --check --strict --quiet
  sha256sum --check --strict --quiet SEAL.DATA.sha256
  jq -e '.pairs == 367 and .ordinary_artifacts == 734 and .bytes == 593004670
    and .graph_archive_objects_rehashed and (.original_policy_accepted == false)
    and .installed_Asahi == null and .physical_M2 == null' READBACK.DATA.json
)
```

### Index source evidence for the signed additions

`index_signed_addition_sources.py` reads a pinned stage receipt from
[signed addition assembly](assemble_signed_additions.md), rehashes the staged
archives and signatures, and indexes the signed `.BUILDINFO` recipe digests.
The v1 config uses kind `supported-Asahi-signed-addition-source-index-DATA`
and contains `schema_version`, `stage_receipt`, and `originals`. The receipt
uses an absolute `path/size/sha256` reference. Each optional original record
contains `name` plus references for `recipe`, `srcinfo`, and `provenance`.
Zstd archives require Python with `compression.zstd`.

```sh
source_index="$(mktemp -d)/source-index.json"
python3 -I -B scripts/port/supported-composition/index_signed_addition_sources.py \
  --config "$index_config" --config-sha256 "$index_config_sha256" \
  --output "$source_index" &&
  jq '{package_count, distinct_recipe_count, evidence_counts, proposal_status}' "$source_index"
```

The retained stage indexed 367 packages and 333 distinct recipe digests.
First Login and Setup matched their retained project originals and source
inputs. The other 365 package rows carry recipe digests only. A successful
index retains the composition verdict and leaves corresponding-source
fulfillment, license review, and production approval open.

### Join exact recipe history offline

`join_signed_recipe_history.py` checks retained, commit-specific GitHub
Contents or Arch GitLab Repository Files responses against the index. The v1
config has kind `supported-Asahi-signed-recipe-history-DATA`,
`schema_version: 1`, an `index` reference, and `candidates`. Each candidate
supplies the `package`, `repository`, full `commit`, `path` of its
`PKGBUILD`, and a `file_response` reference. References use absolute
`path/size/sha256` pins. The join verifies the returned Git blob bytes and
compares their SHA-256 with the package's signed recipe digest.

```sh
history_result="$(mktemp -d)/recipe-history.json"
python3 -I -B scripts/port/supported-composition/join_signed_recipe_history.py \
  --config "$recipe_history_config" --config-sha256 "$recipe_history_config_sha256" \
  --output "$history_result" &&
  jq '{counts, corresponding_source_delivery}' "$history_result"
```

The retained run found three new exact vendor `PKGBUILD` matches in
`asahi-alarm/PKGBUILDs`. They cover `asahi-audio 4.1-1` at `07c5fd03`,
`asahi-desktop-meta 4-10` at `c1362b9b`, and `bankstown 1.1.0-2` at
`79c52a53`. It reconfirmed the First Login project recipe and recorded 11
candidate snapshots with different digests. The join leaves corresponding
source delivery and release approval open.

### Verify the three maintenance updates and rollback archives

`join_maintenance_rollback.py` checks the Python, NetworkManager, and Perl
forward and rollback archives against the unapproved maintenance proposal.
The v1 config uses kind `supported-Asahi-maintenance-archive-rollback-DATA`
and pins `original_report`, `maintenance_report`, `stage_receipt`, and
`public_certificate`. The `supplements` list contains the Python forward
`name`, `archive`, and `signature`. Each of the three `rollback_pairs`
contains those fields and `prior_evidence`. File references use absolute
`path/size/sha256` pins. The join verifies all six detached signatures with
the pinned ALARM public certificate.

```sh
rollback_join="$(mktemp -d)/maintenance-archive-join.json"
python3 -I -B scripts/port/supported-composition/join_maintenance_rollback.py \
  --config "$maintenance_join_config" --config-sha256 "$maintenance_join_config_sha256" \
  --output "$rollback_join" &&
  jq '{status, approval_status, prepared_add_count, verified_forward_pair_count,
       verified_rollback_pair_count, rollback_transaction}' "$rollback_join"
```

The retained 626-package proposal prepared 368 additions and zero removals.
All three forward and all three rollback pairs verified. The older package
metadata still satisfies the 22 recorded dependency edges to these providers.
The original five policy blockers remain. The proposed maintenance stays
unapproved, with installed payload correspondence and an actual rollback
transaction still open.

### Prepare the disposable Asahi maintenance guest inputs

`prepare_maintenance_guest.py` verifies and stages the original Asahi
root image as a read-only seed. It uses the following exact v1 config.

- `kind` is `supported-Asahi-maintenance-disposable-guest-preflight-DATA`
  and `schema_version` is `1`.
- `image_zip`, `image_inventory`, and `image_capture` pin the original
  captured ZIP, its 261-package ALPM inventory, and its capture receipt.
- `archive_join` pins the maintenance archive-join result above.
  `stage_contract` pins the existing signed-addition assembly config.
- `boot` supplies the existing Overlay583 `kernel`, `config`, and
  `baseline` references for a separate control guest.

Every file reference uses absolute `path`, `size`, and `sha256`. Choose a
fresh output directory. Materializing the root requires its full raw size
plus the controller’s 2 GiB storage reserve. Repeat the preflight with
`--reuse-seed /absolute/seed-root.img` to rehash an existing read-only
seed without another copy.

```sh
python3 -I -B scripts/port/supported-composition/prepare_maintenance_guest.py \
  --config "$guest_config" --config-sha256 "$guest_config_sha256" \
  --output "$new_stage"
jq '{status, original_root, guest, expected_locks, expected_previews}' \
  "$new_stage/guest-plan.DATA.json"
```

The retained ZIP came from an observed HTTPS capture. Its materialized
`root.img` is 3,680,501,760 bytes with SHA-256
`76f95dae6180bc4a45ffdeaccec26681d75b2207b90062064fcd2a845adbf9db`.
The capture records no independent image signature. The retained seed has
514,011,136 bytes free. Grow a separate disposable copy before applying
the forward payload, whose package installed-size total is 2,988,144,063
bytes.

The plan pins the 261-package baseline, the 626-package forward result,
and the 626-package result after rolling back only Python, NetworkManager,
and Perl. That rollback restores the 201 protected versions and keeps the
365 additions. The proposal is `UNAPPROVED`. A separately authorized
offline AArch64 16 KiB guest must reverify signer scope and current TEST
certificates, preview both transactions, and check the full inventories.
The preflight reads inputs and writes private staging DATA. Physical M2
validation, production trust, and release acceptance require separate evidence.
