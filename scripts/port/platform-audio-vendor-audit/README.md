# Delivered Cargo vendor integrity and coverage

The existing finite source delivery pins the complete vendor archive and emits
historical `COMPONENTS.json` observations. It does not recompute those internal
file checksums or inspect dependency declarations. `audit.py` supplies that
missing executable check against the actual
[five-package handoff](../platform-audio-sources/README.md). Existing delivery
APIs, profiles, packages, source mirrors and handoff files remain unchanged.

The command first runs the frozen handoff verifier, preserving exact native
archive associations and generic protected-platform inspection errors. It uses
the existing bounded input readers and source-bundle verifier to obtain the
three compiled packages' exact source inputs. The trusted intake API is pinned
to SHA256 `be5be5ba3a47d462b70a821d1f88a54218fbe91c8341f7f03782e9ac9c6d06e8`.
Code is imported only from the trusted project checkout. Source archives,
PKGBUILDs, vendor files and native payloads are data throughout this operation.

## Operation

Supply the trusted handoff index hash and native input-profile hash used by the
delivery command. Run from the project checkout with Python 3.11 or newer:

```sh
task_private=$(mktemp -d)
python3 -I -B scripts/port/platform-audio-vendor-audit/audit.py \
  --handoff /private/relocated/handoff \
  --index-sha256 TRUSTED_HANDOFF_INDEX_SHA256 \
  --profile-sha256 e2ab9b6cc2810bf5d5b6454abdb9bcdeea6567797247c745b0d04541cb99c6c8 \
  --output "$task_private/vendor-audit"
```

The fresh mode0700 directory contains `vendor-audit.json`, mode0600. The summary
prints its length and SHA256. Existing destinations are refused and preserved.
No source extraction, build, Cargo invocation, network access, installation or
publication occurs. The report contains relative material names and hashes,
without private operator paths, and binds the checker bytes, handoff index,
source-bundle hashes, original archive binding receipts and publication holds.

The checker reads tar members without extracting them. It bounds each inner
archive to 32 MiB compressed, 64 MiB expanded, 8 MiB per member and 8,192 members; TOML
documents are limited to 1 MiB. Vendor links, hardlinks, special files, duplicate
names, unsafe paths and impossible file-as-parent namespaces are refused.
Speakersafetyd's 11 ordinary relative source symlinks are recorded inertly and
never followed; symlinks cannot supply manifests or license texts.

## What is checked and what stays held

- Every vendor subtree must contain `Cargo.toml` and `.cargo-checksum.json`.
  Declared file keys must exactly equal the actual regular files, excluding the
  checksum manifest itself. Every declared SHA256 is recomputed. The manifest
  itself and the enclosing archive are independently hashed.
- Every registry package in each Cargo.lock must map to one supplied exact
  name/version and matching vendor `package` checksum. Lock dependencies are
  resolved by exact available name/version/source identities, then joined to
  manifest dependency aliases, version requirements and source kinds. The
  recomputed package/lock/vendor observations are compared to COMPONENTS.json.
- Every normalized vendor Cargo.toml dependency table is inventoried, including
  renamed, optional, build, dev and target-specific declarations. Root and locked
  package declarations are also reported per project. All other vendor bytes,
  including Cargo.toml.orig, are checksummed without being interpreted as Cargo's
  effective manifest. Missing candidates and multiple candidates remain explicit
  holds. A vendor crate unused by one project is listed; a crate unused by all
  three delivered locks is flagged as an integrity/coverage error.
- Explicit path dependencies bind only to supplied regular Cargo.toml data
  within the source namespace, with matching declared package/version. Git URL,
  full commit or branch/tag selectors can be joined lexically to lock entries;
  git commit-to-vendor-tree provenance remains held. Named registry mappings,
  workspace inheritance, patch/replace resolution, unsupported dependency fields
  and unsupported version syntax produce named holds or format refusals.
- Stable numeric Cargo requirements support caret, tilde, exact/inequality
  comparators, comma intersections and trailing wildcards. Prereleases, build
  metadata, disjunctions and unmodeled syntax are held. Cargo feature activation,
  target evaluation, source replacement and full resolver behavior are not run
  or inferred. An optional/dev/target declaration with no supplied candidate does
  not prove the corresponding dependency was activated in a recorded build.
- The license declaration, declared license-file binding, candidate license/
  copying/notice filenames and actual nonempty UTF8 text presence are separate
  observations. Empty or non-UTF8 candidates remain identified. Filename/text
  presence does not authenticate terms, copyright ownership, applicability,
  required notice delivery or legal completeness.

The vendor `package` checksum and matching Cargo.lock checksum are declarations
being joined. No matching raw `.crate` archives are supplied or authenticated by
this interface. Their agreement is **not** raw crate authenticity or proof of
the upstream tree. Compiler, standard library, linker and runtime corresponding
sources remain held. Existing wmidi/nalgebra source/text association limitations,
effective build flags and relinking obligations stay unchanged.
`complete_corresponding_source_accepted` and `legal_acceptance` are always false.

Exit 0 means `AUDITED_DATA_WITH_HOLDS`: no detected integrity or lock coverage
error in this finite data model. Exit 1 records integrity/coverage errors; exit 2
refuses malformed, missing, changed or unsupported critical material, existing
output, or a nonisolated Python invocation. Neither success nor an empty error
list establishes complete corresponding source, an authenticated signature, an
accepted package transaction, audio safety, native execution or M2 compatibility.

## Actual local result, 2026-11-14

Python 3.14.7 audited the relocated actual handoff whose index is
`70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c`.
The shared vendor archive is 5,733,816 bytes/SHA256
`64cd55473b19f104f3a90570409d58c5ab69f63c61396541c4ad1e56e8d6293f`.
All 117 crates' 4,292 declared file hashes and exact file sets pass, covering 4,409
regular files and 57,569,078 expanded bytes. The locks bind 17/75/38 registry
packages for Bankstown/Speakersafetyd/Triforce respectively, with 117 in their
union and zero vendor subtrees outside that union. All 241 lock edges have a
supported lexical manifest join; feature/target activation remains unproven.

The 557 vendor declarations include 307 without a supplied matching candidate and
42 with multiple supplied version candidates. These are retained as holds with
their exact scopes and requirements. Of 117 vendor crates, 116 have a nonempty
UTF8 license-text candidate. wmidi 3.1.0 declares MIT but has no such file in its
vendor subtree; the separate retained notice association remains limited.

The actual 949,594-byte report SHA256 is
`ce9e9077b961c60dfcb890914256235ae6376bdb689376a9471b8ce3eb08ad80`;
the checker is 25,075 bytes/SHA256
`94b1c5c9196326354ec84d11b81c3cd114a3e0b9ba4fa914802db309cdb37d37`.
The report and package/source bytes remain private local outputs, not committed
or published artifacts. No new native build, runtime test or legal admission was
performed.

Thirty self-contained synthetic data controls and seven separately invoked
actual-handoff controls passed. The latter modify a real vendor member, omit the
real wmidi subtree, insert an undeclared real vendor file, exercise deterministic
private CLI output, and fence original source reads, subprocesses and network
access during the full actual audit. They require actual supplied inputs and do
not skip or substitute synthetic native evidence.

```sh
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-vendor-audit/test_audit.py
python3 -I -B -Werror::ResourceWarning scripts/port/platform-audio-vendor-audit/check_actual_handoff.py \
  --handoff /private/relocated/handoff \
  --index-sha256 70a94f1df45b982abd78644e2bc9182bf0b761f8a11549a993bc2f73e22e777c
```
