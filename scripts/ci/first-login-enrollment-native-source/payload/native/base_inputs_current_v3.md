# Finite base349 cache references

Source implementation and offline DATA checkpoint only. No acquisition, actor,
GPG, signing, installation, lease, network, publication, or Root grant ran.
Neither cached bytes nor an upstream architecture declaration qualify a native
image. All returned actual input-packet and Root fields remain NULL.

API `BASE349_CACHE_REFERENCES_V3` exposes:

```python
metadata(*, source_root, source_map, base_lock, bootstrap_profile)
assess_selected_references(*, materials, source_root, source_map, base_lock,
                           bootstrap_profile)
build_selected_references(*, materials, source_root, source_map, base_lock,
                          bootstrap_profile)
build_references(*, cache_root, source_root, source_map, base_lock,
                 bootstrap_profile, consumed_names=None)
acquisition_plan(plan, *, cache_root, public14_root, retained_root,
                 retained_git, helper_root, deadline)
assembler_fields(complete_reference_result)
```

Every descriptor is exactly `{path, bytes, sha256}`. Paths are explicit absolute
ordinary operands. `source_map` is the externally selected whole Source map;
`source.lock.json` must be its separate byte-identical alias. The provider reads
only this finite metadata closure, never walks Source or searches for caches.
Its complete selected Source descriptors are authenticated by the caller's
existing Source/publication boundary; hashing a caller-invented map alone is
not Root authentication.

The genuine Source139 at
`cachy-asahi-retained-llvm260-proofs-20261116-r1/work/current-onboarding-v3-real-source-DATA-20261116-r1/source`
retains the fixed factory profile and expected inventory. Its factory's parent
descriptors identify two additional explicit metadata operands; their bodies
are not themselves in Source139:

| Operand | Bytes | SHA256 |
|---|---:|---|
| `scripts/ci/first-login-enrollment-native-source/profile.json` in Source | 62259 | `ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa` |
| original `bootstrap/scripts/ci/inputs.lock.json` | 328101 | `beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f` |
| original `native/input-profile.json` | 168201 | `2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c` |
| Source `inputs/stages/baseline349.expected.lock` | 6800 | `579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453` |

The repository's `scripts/ci/inputs.lock.json` is the exact original lock.
The exact supplemental profile also exists at
`scripts/ci/desktop-current011-native-source/fixtures/native/input-profile.json`
and `scripts/ci/perl5423-repro-native-source/references/input-profile.json`.
The provider does not silently discover or select those copies. Missing
`base_lock` or `bootstrap_profile` produces a named `MissingInput` for the
authoritative original member.

## Real composition and consumer blocker

The original lock's 165 rootfs records and 248 selected package records yield
**341** final names, exactly matching `profile.original341.packages`. The
original maintained owner audits/builds that signed341 base, then audits and
normally installs eight additional signed packages: cmake, cppdap, jsoncpp,
libuv, meson, ninja, python-tqdm, and rhash. They add names without replacing a
baseline package, yielding the exact349 expected inventory. Versions, epochs,
`any`/`aarch64` values, rootfs metadata, package names and whole detached
signature pins are retained; no replacement or dependency bypass is introduced.

The complete finite cache therefore has **517 files / 1,558,660,382 bytes**:

- `base_materials`: rootfs+signature and 248 archive/signature pairs =498;
- `supplemental_materials`: eight archive/signature pairs =16;
- `keyring_materials`: `archlinuxarm.gpg`, `archlinuxarm-trusted`, and the
  deliberately zero-byte `archlinuxarm-revoked` =3.

The declared primary is `68B3537F39A313B3E574D06777193F152BDBE6A6`; the three
public keyring pins and their immutable upstream keyring commit join the lock.
This is a metadata join, not fresh GPG authentication. Real separately issued
current public trust remains a required caller input.

The final committed `67c7460d` image consumes the explicit bootstrap profile and
fixed8 references. Portable controls feed genuine committed lock/profile/factory
and inventory metadata into that exact image's base selector. The provider
preserves the original lock and returns the16 supplemental
refs separately; it never rewrites248 into256 or invents a new fixed lock hash.

The maintained assembler now consumes exactly five provider fields:
`base_lock`, `bootstrap_profile`, `base_materials` (498),
`supplemental_materials` (16), and `keyring_materials` (3).
`assembler_fields(...)` maps only a complete517 reference result to those
operands. A partial checkpoint still raises a named missing-material HOLD;
NULL input raises `complete517_reference_result`. The adapter grants no trust
or authority and never promotes a producer verdict. The assembler independently
rehashes metadata, verifies frozen Source factory parent descriptors, reconstructs
the original341-plus-fixed8 union, checks every reference and current public
trust, and reproduces the exact349/350/372/374 inventories. The image consumer
extension and its actual normal signed ALPM/metadata checks remain separately
owned; no image body was edited here.

## Cache behavior and available bodies

`materials` is an explicit map of fixed filename to whole reference. The selected
reference APIs support separate retained carriers and content-addressed paths;
they enumerate no directories. Unrelated carrier files are never read. All
selected names and whole pins must join the exact finite517 metadata closure,
and every selected path must be distinct. Unknown names, mismatched pins,
missing selected paths, aliases, stale bytes or later mutations refuse.

`assess_selected_references` streams each selected body once and returns
`BASE349_REFERENCE_CHECKPOINT_DATA_V3`. An incomplete selection has
`complete:false`, `status:HOLD_MISSING_EXPLICIT_MATERIALS`, and every missing
filename with its exact bytes, SHA256, pinned URL and group in
`missing_materials`. The three material maps contain only verified references.
It never fills missing roles from other caches or substitutes producer verdicts.
`build_selected_references` requires all517 roles and returns the same complete
handoff shape as `build_references`; missing roles raise a named `MissingInput`
before archive streams. Completing references does not satisfy the independent
consumer, current trust or GPG gates.

`build_references` requires an existing caller-owned0700 cache with exactly the
517 fixed names. Its only enumeration is one directory level with a fixed518
entry ceiling; it never descends into directories. Missing or extra consumed
members refuse before body reads. An optional `consumed_names` list must be the
same exact finite set, without duplicates. Use a dedicated finite cache, not a
broader shared574 cache with undeclared extra files.

All selected leaves are streamed once, not copied. The provider checks complete
size/SHA256, ordinary file type, single link, ownership, nongroup/nonworld-writable
mode, no symlink ancestry, and stable inode/mode/size/timestamps. It rechecks all
metadata and selected operand identities at the end, so an earlier verified
leaf or metadata file moving during a later stream refuses. The dedicated-cache
API additionally rechecks its directory identity and exact namespace.
Zero-byte revoked-key metadata is a real pinned operand, not an omitted file.

The retained immutable carrier
`artifacts/development/core376-native248-cache-development-20261021/carrier574/packages`
contains all 512 package/signature bodies for the original248 plus fixed8.
This task independently streamed all512: **729,289,259 bytes**, every whole pin
matched, and inode metadata remained stable. The report is
`work/base349-provider/retained-body-availability.DATA.json` in this worktree.
It gives no current trust, Source provider selection, native or release credit.
The carrier does not contain the remaining five original parent-fetch operands:
the 829367415-byte pinned rootfs, its566-byte signature, and the three public
keyring files. No complete517 cache was established from these authoritative
retained paths. Other caches elsewhere were not searched or inferred.

The explicit-reference delivery independently re-read the genuine Source139
metadata and streamed those same512 actual retained bodies through the maintained
provider. It returned HOLD for all five missing operands, rather than a complete
provider. Local delivery files in this owned worktree are:

- `work/base349-provider/selected-materials.DATA.json`: exact metadata operands
  and512 caller-selected whole references, usable directly with
  `assess_selected_references` after removing its `schema` and `kind` labels;
- `work/base349-provider/selected-reference-checkpoint.DATA.json`: verified496
  base refs,16 supplemental refs, zero keyring refs, and all five missing pins;
- `work/base349-provider/selected-delivery.DATA.json`: whole code/request/result
  pins, with every actual selection/authority field still NULL.
- `work/base349-provider/assembler-base-seam.DATA.json`: the actual maintained
  assembler base seam re-reading genuine Source139 descriptors and refusing the
  incomplete selection at `base_materials/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz`.
  The provider adapter independently refuses the same missing role. All five
  missing files remain listed; no archive path is invented to complete them.

The later complete handoff was explicitly supplied at
`cachy-asahi-current-onboarding-host-prerequisites-20261116/work/onboarding-base517-local-reference-handoff-DATA-20261116-r1/verified-with-identities/assembler-base-fields.DATA.json`,
178733 bytes, SHA256 `c6fc5c467ad7694c64dc0bb24e8c9615488d905ebafc20addeb2b124f30178b3`.
The maintained assembler base seam streamed every actual file: **517 files,
1,558,660,382 bytes**, groups498/16/3, `missing:{}`. All identities were checked
again after the last stream. This closes the earlier five-file HOLD for this
explicit selection. The historical incomplete checkpoints above remain intact.

- `work/base349-provider/complete517-assembler-seam.DATA.json`: current whole-byte
  seam result and exact code/handoff pins;
- `work/base349-provider/complete517-image-fields.DATA.json`: resulting image
  operands, including the genuine Source baseline inventory;
- `work/base349-provider/complete517-identities.DATA.json`: all517 final identity
  observations.

No GPG, package program, native image, Root trust or acceptance was established.
The complete seam's assembler is41570 bytes, SHA256
`a1838fe056f95ae5baae5a70b9ba20a623271475160c9010ae59e3c751e90f9c`;
the provider remains18820 bytes, SHA256
`9e35c3ae6c3e1e9596f54806279d05cc77ae6a2cb5fb284d469df549e1d3abc6`.
These local DATA artifacts are not committed Source or an issued provider
selection. The coordinator must explicitly select authenticated operands and
the exact committed module. No archive body was copied into the worktree.

## Hosted acquisition plan DATA

`acquisition_plan` emits actual existing seed argv plus the fixed public URLs,
whole pins and bounded curl argv for only the missing parent-fetch5 and fixed8
archive/signature16 operands. It executes nothing, reads no environment or
secret store, and declares no transport admission. A hosted owner must provide
fresh destinations, verify every downloaded whole pin, enforce a finite role
deadline, select permitted transport hosts, and run the unchanged current GPG
and metadata gates before installation. Existing files must not be overwritten
or silently retried through substitutes. Retained exact bodies may satisfy
those pins without acquisition, under the existing retained-source proof.

The original22 secret names are returned solely as names and tested against the
existing workflow. Private6 seeding remains the original
`old_four_seed.seed_current_build_cache` entry; no broader secret set is added.
Public14 stays Source `04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd`, seed SHA
`a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3` and index SHA
`a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300`.
The retained native248 seed remains Source
`ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad` with the maintained source-proofed
`prepare.py --mode native248` entry and original caller deadline. Root owns the
workflow, full fixed carrier proof, secret allowlist/environment wipe and
transport execution. This module is not an acquisition actor.

Twelve small permanently fenced tests pass on Python 3.12.14 and 3.14.7. They use
tiny, explicitly inert lock/profile/cache bodies with all actual fields NULL;
no operational Root fixture or package program is executed. They cover complete
517 single-stream references with no writes, missing/extra/aliased/moving/stale
operands, strict metadata, preserved22/public14 plan semantics, and genuine341
plus fixed8 metadata in the final image consumer. Explicit-reference controls cover partial512
HOLD with all five missing pins, complete split carriers, no directory discovery
or writes, and refusal of unknown/stale/duplicate selections. Native
image/build/hardware behavior is NOT RUN.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/first-login-enrollment-native-source/payload/native/test_base_inputs_current_v3.py
```
