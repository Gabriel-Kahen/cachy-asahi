# Qt612 candidate package transport — source preparation

This slice proposes a separate Actions artifact channel for the frozen F recipe
`69a02851b87ca29daf2e197101b66bf75ff61889`, package
`cachy-asahi-qt612-base-source-reference 6.12.0-2`, aarch64/XZ. `basis.json`
pins its contract, complete `.SRCINFO` metadata and all 15 exported recipe input
hashes, including the
byte-identical `source.json` alias of `BUILD-CONTRACT.json`. The collector checks
that basis file against an embedded whole-file hash.

The complete transport directory must fit **128 MiB including its receipt and
manifest**, with at most **4096 regular files**. This version deliberately admits
exactly 14 payloads plus the producer receipt and manifest: 16 files. An archive
or report that exceeds the remaining budget causes HOLD, never truncation,
selective receipt omission or an invented complete result. These limits are a
source contract, not a measurement that real Qt packages fit.

No selected workflow, C producer, recipe, shared manifest or platform stack is
changed. No upload/download, Actions dispatch, package execution, signing, Root
grant, legal clearance, native result or release acceptance occurred here.

## Exact public payload namespace

For each distinct `build-1` and `build-2`, the source must contain exactly:

- `artifacts/cachy-asahi-qt612-base-source-reference-6.12.0-2-aarch64.pkg.tar.xz`
- `provenance.json`: unchanged complete normal builder provenance.
- `validation.json`: unchanged package validation report.
- `stage-contract.json`: actual retained stage report, exported before cleanup.
- `check-receipt.json`: new C receipt binding the genuine normal own-built check.
- `license-receipt.json`: new C receipt binding notice policy and package archive.

The other two payloads are `pair/comparison.json` and
`pair/qt-pair-finisher.json`. Directories must be exactly their ancestors. Files
must be ordinary, singly linked, mode 0644, with trusted ownership and stable
identities through read/copy/readback. Hidden files, signatures, links, FIFOs,
sockets, extra archives, extra directories and arbitrary extra receipts refuse.
Archives are opaque whole-file bytes in this collector: it neither extracts nor
executes them. C's independently reviewed package/ELF/stage/check/notice validation
must bind these exact bytes. A filename or a JSON success label is not package
validation or native execution proof.

C must prepare a fresh **public export** containing those 14 members. Do not point
`--source` at its entire build directory. No cache, image, build context, keyring,
raw environment file, private file or raw directory dump belongs in this channel.
C and Root must review the selected producer's publication policy and these
receipt contents; this collector is a finite namespace/byte verifier, not a
secret-content classifier. It does not rewrite or redact provenance.

## Required new C producer receipt

`collect` requires `--receipt` and its independently supplied whole
`--receipt-sha256`. This is a **new V1 interface for C to implement and review**,
not a claim that an existing C producer implements it. The receipt must be a
finite JSON object with exactly these keys:

| Key | Required value |
| --- | --- |
| `schema`, `kind` | integer 1; `QT612_REFERENCE_PAIR_TRANSPORT_RECEIPT_V1` |
| `recipe_commit`, `recipe_contract_sha256` | exact F69a commit and basis contract hash |
| `producer` | exact `source_commit`, `source_map_sha256`, `program_sha256`, `finisher_sha256`, `contract_sha256` pins |
| `run` | `repository` = `Gabriel-Kahen/cachy-asahi`; exact `head_sha`, decimal-string `run_id`, `run_attempt`, `job_id` |
| `files` | exact 14-path map, each `{bytes, sha256, mode: 420}` |
| `provenance_operands` | exact operand partition for both attempts, below |
| `external_retention` | opaque public `store_id` and whole `receipt_sha256` for Root-accessible retained evidence |
| `pair_checks` | all eight strict boolean assertions: `normal_comparator`, `archive_bytes`, `payload`, `pkginfo`, `buildinfo`, `own_check_each`, `stage_each`, `notices_each` |
| `Root_acceptance` | null |

Producer/source/contract/run pins are bound to the externally selected receipt;
they are not authenticated merely by being written in it. Root must first review
C's actual source and contract implementation and select that actual run/job.
Neither this source preparation nor a fabricated or MODEL receipt establishes
that identity. Missing C implementation, receipt, actual package or run remains
HOLD. The executable MODEL fixture in `test_transport.py` is a schema example,
explicitly not an actual producer receipt or package.

For each provenance document, partition the exact union of its `files` paths,
`artifacts/<basename>` and `inputs/<recipe_input>`. Coalesce aliases only when their
hashes agree. No referenced operand may disappear. Each descriptor contains
whole `bytes`, `sha256` and one of:

- `disposition: included`, `transport_path`: the exact corresponding member of
  this packet, with the same bytes and hash. The only rename aliases allowed are
  `artifacts/qt612-stage-contract.json` → `stage-contract.json`,
  `artifacts/qt612-check-receipt.json` → `check-receipt.json`, and
  `artifacts/qt612-license-receipt.json` → `license-receipt.json`, within the same
  attempt. Those operands cannot be marked external while their role is included.
- `disposition: external_retained`, `external_store_key`: an opaque 64-hex key
  within the retained external store bound above. It may not substitute for an
  included member. Empty external operands are allowed; each is bounded to 2 GiB.

The normal comparator requires raw environment/configuration/log/source-material
and input snapshots. They are deliberately excluded from this public channel,
not deleted from original retained evidence. **This packet alone cannot rerun
`compare_v2.verify()`**. Root must obtain/read back the exact externally retained
operands and their store receipt before qualifying the original provenance or
TEST signing. A store identifier/hash is a reference, not proof of availability
or a completed readback. Missing, expired, unreadable or mismatched external
records remain HOLD. No existing comparison or retention requirement is weakened.

## C phase/finisher bindings

The normal comparison must have `contents-reproduced`, no errors, and exactly the
one expected package with all four booleans true: installed contents, PKGINFO,
whole archive bytes and BUILDINFO. The collector checks both actual archive whole
pins are equal, each provenance declares a successful native/offline build with
the exact F69a recipe snapshot, both clean environment IDs differ, and their
image/source/inventory/configuration inputs agree. These are checked recorded
assertions; native actor/custody evidence remains C/Root's responsibility.

The new `check-receipt.json` is exactly `{schema: 1,
status: PASS_QT612_OFFSCREEN_API_SMOKE_ONLY, normal_makepkg_check: true,
recipe_commit: <F69a>, archive_sha256: <that actual archive>, check_log:
{operand, bytes, sha256}}`. `check_log` must bind the exact original nonempty
`artifacts/<package-version-arch>-check.log` entry in provenance and its external
operand descriptor. It is produced by
C after binding actual normal check-phase evidence, never inferred from a file
name or compilation. The new license receipt contains exactly `status:
PASS_QT612_SOURCE_NOTICES_ONLY`, `notices: 173`, `bytes: 636122`,
`notice_policy_sha256: <basis policy hash>`, `archive_sha256: <actual archive>`.
Those counts alone do not verify notice bodies; the reviewed C finisher must
verify the archive/stage bodies against the pinned policy.

The new finisher JSON has exactly `schema: 1`, `kind:
QT612_REFERENCE_PAIR_FINISHER_V1`, `status: PASS_QT612_REFERENCE_PAIR_ONLY`,
`recipe_commit`, `recipe_contract_sha256`, raw `comparison_sha256`, and `attempts`.
For each `build-1`/`build-2`, its entry contains exactly `archive: {bytes,sha256}`,
raw `provenance_sha256`, `stage_canonical_sha256`, raw `check_receipt_sha256` and
raw `license_receipt_sha256`. Canonical stage bytes are sorted, two-space JSON
plus newline, as emitted by `encoded()`; the role map separately binds the raw
stage-file bytes. The existing stage report must declare the AArch64 stage
contract and scope. Host-only stage results cannot satisfy this binding.

## Collection, Actions integration and Root readback

With independently selected C inputs, source preparation exposes:

```sh
python3 -I -B /absolute/selected/transport.py collect \
  --source /absolute/C/public-export \
  --receipt /absolute/C/producer-receipt.json \
  --receipt-sha256 EXTERNALLY_SELECTED_C_SHA256 \
  --output /absolute/fresh/closed-export
```

The source and output must be disjoint. The collector creates a fresh private
output, copies every whole member using retained directory descriptors, then
rehashes the copies. It writes `producer-receipt.json` unchanged and writes
`transport-manifest.json` last. Failure leaves HOLD and may leave a partial owned
output for diagnosis; a partial output must never be uploaded as complete.

`workflow.fragment.yml` is a nonselected integration fragment, outside
`.github/workflows`. It checks the independently frozen collector source and
external C receipt pins, then uploads **only** the fresh collector output after
successful collection. `ACTIONS-PINS.json` records the exact existing repository
upload-action pin and source provenance. Upload options are retention 3 days,
compression 0, hidden files false, overwrite false and missing files error.
Existing small fixed failure/report log export remains separate and unchanged.
Action options do not enforce the collector's byte/namespace contract.

Root must select the actual repository/run/attempt/job/artifact ID and immutable
artifact digest through its reviewed channel, download/extract into a fresh
ordinary directory, and obtain the manifest SHA from an independent trusted C/run
record. Do not trust a manifest hash calculated from the downloaded manifest as
its own authority. With both external pins:

```sh
python3 -I -B /absolute/selected/transport.py verify \
  --root /absolute/fresh/downloaded/export \
  --manifest-sha256 EXTERNALLY_SELECTED_MANIFEST_SHA256 \
  --receipt-sha256 EXTERNALLY_SELECTED_C_SHA256
```

`PASS_TRANSPORT_BYTES_ONLY` means the complete finite packet matched those pins.
Its `native_acceptance` is false, `Root_acceptance` null and
`offline_comparison_complete` false. `external_readback_required` remains true
while excluded provenance operands exist. The verifier does not track remote
artifact identity, download anything, sign, publish, install or grant authority.
Three-day retention is temporary delivery, not durable archival or an artifact
billing claim. Expiry or a budget failure requires a fresh reviewed solution;
never silently switch to truncated logs or dropped evidence.
