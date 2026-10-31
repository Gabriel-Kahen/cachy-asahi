# Hosted native developer input closure

Successor to the frozen 138-file constructor. No prior/canonical source is edited.
Actual source/ref/run remain NULL until Root publication and genuine run metadata.
Source construction/controls do not execute compiler/native/GPG/ALPM/Git/install
actors. Bounded public acquisition was explicitly authorized separately.

## Exact frontend and separate backend

Official uv 0.11.28 resolves to commit
`ebf0f43d7c4267876fc256f5fce75982c33f4399`. Primary sources are the
[GitHub release](https://github.com/astral-sh/uv/releases/tag/0.11.28) and
[exact PyPI backend metadata](https://pypi.org/pypi/uv_build/0.11.28/json).
Licenses are `MIT OR Apache-2.0`; the exact notices are retained.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| uv-aarch64-unknown-linux-gnu.tar.gz | 24,689,886 | `03e9fe0a81b0718d0bc84625de3885df6cc3f89a8b6af6121d6b9f6113fb6533` |
| uv_build-0.11.28-py3-none-manylinux_2_28_aarch64.whl | 1,616,098 | `d99cb38411412134781140cc64dc7d296dbc383fa1e81ddc13ecb6863852ecf5` |
| uv_build-0.11.28.tar.gz, source | 408,697 | `daba66fd25a9a82caa23949686e967cbb69fd056177e991650643186057adaef` |

The release supplies uv/uvx, not an importable Python uv_build package. Exact
source distinguishes the direct Rust fast path from PEP517. The unmodified shim
has `USE_UV_EXECUTABLE=False` and calls `uv-build`, supplied by the separate wheel.
That wheel has no Requires-Dist dependencies; RECORD, shim and license joins were
checked. No importability claim is inferred from the uv binary alone.

`python_backend.py` retains the original project/journey and process core. It
installs the pinned local backend wheel into a fresh private venv with offline,
no-index/no-deps; prepends its bin path; verifies original shim/uv-build payloads;
and uses `--force-pep517 --no-build-isolation`. Backend files are pinned around
every command. Nothing is installed on the host, and no shim is modified.

Archive inspection is not execution. ELF metadata shows AArch64 and GLIBC>=2.28;
the ALARM rootfs pins glibc 2.43. Loader resolution, backend import, builds, native
16K and M2 remain NOT RUN. Primary HTTPS/size/hashes were verified; independent
signatures, attestations and reproducible binary builds were not verified.

## Closed source construction

```sh
python3 -I -B scripts/ci/native-developer-workflows-input-closure/construct.py \
  --predecessor /absolute/path/to/frozen-138-file-source \
  --acquisition /absolute/path/to/input-closure-packet/acquisition \
  --output /absolute/path/to/new-closed-hosted-source
```

The predecessor must match map
`e41a4b76269528ba678bdf1d0fbd7f1a997b9799decfa6ade352e33dc79a56bd`.
The fixed primary-acquisition handoff and all copied archives/provenance are
verified. Original code/data limits stay held; only the two named public tool
archives use exact larger file pins. Ordinary source reads retain their 16 MiB cap.

Original ALARM 341 plus eight packages stays exact 349. uv is a separately pinned
tool under /opt in the disposable image; uv_build stays in the private developer
venv. Neither is passed off as an ALARM package. The guest must actually pass
Python PEP517, compiled extension, CMake and Meson before reporting component PASS.

## Practical hosted route

The source emits byte-identical canonical/dedicated aliases:
`.github/workflows/native-arm-build.yml` and
`.github/workflows/native-arm-developer-workflows.yml`. Root uses existing
canonical workflow 381664314 on `ubuntu-24.04-arm`, as PGO102 did. Ubuntu only
actuates Docker; selected-base execution is inside the exact ALARM environment.
No preseeded/dedicated runner or new secret is required.

The workflow checks exact Git source before secrets, uses the original 22 private
chunks and public14 seed, moves that checkout outside the source, fetches the
original 1154 carrier once to `pgo-hosted-retained` under the proven 480s envelope,
and atomically copies 16 exact leaves for the eight build-tool archive/signature
pairs. The original owner then proves the full carrier, builds 341, authenticates
the eight-package overlay and runs all four real component journeys.

Existing process/cleanup/resource gates remain: bootstrap 2250s subdeadline,
consumer 2 CPU/4 GiB/256 PIDs/1800s, no network, read-only source/root, direct final
waits, named inventory probe, exact owned images and both GPG-home retirements.
Provisioning failure yields bounded DATA diagnostics. No phase ran here.

## Root stage and one dispatch

Publish the complete generated namespace from an isolated source checkout,
retaining its map/Git blobs/ref. Root fills genuine values in the NULL dispatch
JSON, then invokes the existing canonical route once:

```sh
gh api repos/Gabriel-Kahen/cachy-asahi/actions/workflows/381664314/dispatches \
  --method POST --input /root-owned/bound-dispatch.json
```

The body requires `ref`, `inputs.source_sha`, `inputs.source_map_sha256`.
Attempt 1 and exact GitHub source/workflow/ref/run equality are mandatory. Run
selectors are bound only after dispatch metadata exists. No main/PR6 merge occurs.

The matching passive reader checks exact binding, provisioning, both daemon
inspections, resource/mount predicates, raw actor/feature logs and all four actual
component outcomes. NULL bindings refuse before original-artifact reads. DATA
diagnostics confer no native acceptance; Root authenticates original custody.
Native 16K, M2, installed Asahi, performance and release qualification stay separate.

## Bounded public-tree transport

The retention phase writes one regular `upload/public-tree.tar` for the ordinary
artifact uploader. A canonical uncompressed USTAR capsule carries an exact index,
explicit directory modes, file modes/bytes and symlink target bytes as ordinary
data payloads. No archive entry is a link. The matching reader checks the capsule
in memory; it never extracts or creates host links and never reads link targets.
The complete capsule, including metadata/tar overhead, must fit 32MiB; each ordinary
payload remains at most 16MiB. Private caches/key material are excluded.

Run `native/reader.py --capsule ORIGINAL_PUBLIC_TREE_TAR --binding ACTUAL_JSON`
only after Root authenticates the ordinary artifact ZIP and its sole capsule
member. NULL actual bindings refuse before capsule access. Local tar/ZIP fixture
roundtrips are transport-model controls, not actual GitHub or native evidence.

## Causal bootstrap failure retention

The owner now retains the original bootstrap acquisition.json and the original
key-import/build streams and signature-result JSON when present. A narrow DATA
guard verifies the pinned producer, exact501-input metadata/record schema, fixed
source command shapes, stable ordinary files and public-text privacy rules.
Accepted bytes are copied unchanged with private0600 copy permissions and original
source modes recorded. Refused content is never mirrored into generic actor logs;
accepted named streams are reused there without duplicate bytes.

The standalone guard receipt and enclosing owner receipt agree. Expected guard
failures keep fixed codes and preserve an already-active primary exception. A
guard failure cannot produce a positive native result. The existing32MiB capsule,
16MiB member/resource/deadline limits, four journeys, input URLs/pins and package cache-only
seed policy remain. Acquisition records retain their original generic error
fields; they do not invent a more specific cache cause. No retry is performed.

The complete declared seed union has520 names. Exactly the five original base
rows (rootfs, signature and three keyring files) are outside it. The original
pinned parent fetch now handles only those five exact metadata rows, matching
the held PGO behavior. Original and overlay package/signature rows remain strictly
cache-only; a failed package cache check never falls back to HTTP. Unknown or
mutated rows refuse before either callback. No URL/pin, retry or resource limit
is changed, and the development consumer remains network-none. This source
closure proof is not a runtime404/cache-miss finding.

## Owned local base alias and exact cleanup

The overlay FROM uses the source-created local base tag, checked against the
exact owned image ID before and after the network-none/pull-false build. Both
source aliases and the owned namespace must be absent before creation. Only
known successful source build rows register alias ownership. No registry fallback
or BuildKit disabling is introduced.

Cleanup uses recorded natural owned build retirement (including a naturally
failed client), not a latched building flag. It removes only proved created
image aliases still bound to expected IDs, and proved stopped created containers,
without force or image-ID removal. Unknown/foreign/preexisting state is held.
All retirement rows remain captured on errors; independent final daemon queries
are required for PASS. Ledger and retirement DATA are retained standalone and
in the existing receipts. These source/model checks do not prove a native run.

## Original consumer diagnostics and finite public projection

The start-attached consumer actor now emits a source/run/map-bound DATA receipt
before cleanup and capsule packing, on success or failure. It retains the exact
indexed actor exit/retirement fields, original whole-log pin, and at most64KiB of
original UTF-8 suffix bytes with an explicit offset and completeness flag. The
whole log must satisfy the private-marker/text guard before any window is emitted.
A refused log is also blocked from generic mirroring. The guest records bounded
phase/type/message failure DATA and re-raises the original error.

The owner projects finite public reports, original command logs and pinned backend
files into a fresh sibling directory. It does not traverse disposable guest home,
temporary, project, build or general virtual-environment trees. The original output
is preserved. The capsule format, strict private-path guard and32MiB/16MiB limits
remain. Packing refusals emit bounded member/path/phase context before raising;
no rejected payload or key material is printed. A passive failure DATA result does
not pass the native component or cleanup gates.

The genuine182 run reached the consumer start but did not export its inner error.
Its separate private-path pack refusal did not print the offending path. These
causes remain UNKNOWN; source-backed fixtures show retention behavior only.

## Build-summary failure diagnostics and fresh safe fallback

Before the aggregate CMake/Meson guard, the guest writes and emits a whitelist of
aggregate/project status enums, fixed missing-tool/presence booleans, and original
result/command-log hashes. Unknown strings become UNKNOWN; arbitrary values are
never emitted. The host binds this unchanged guest DATA to its source/run/map.
The original guard and default feature payloads remain unchanged.

A private-marker refusal reports only a fixed neutral rule ID, a source-whitelisted
logical JSON field or UNCLASSIFIED with a field-path hash, and bounded file/context
hashes. It never prints the matched marker, value, body or private material. The
strict original privacy predicate and positive acceptance gates remain.

When owner public output exists without a completed projection, retention writes a
fresh disjoint safe-diagnostic sibling. It copies only schema/privacy-qualified
consumer-frame, build-summary and fixed refusal metadata. Original public/projected
bytes remain untouched and untraversed. This direct finite capsule has an explicit
failure-DATA authority and cannot qualify native work. Original result and feature
log bodies absent from this safe capsule are marked unavailable for pin verification.

Actual184 only proves the aggregate guard failure and journey/result.json privacy
refusal; aggregate/project/missing-tool values and the matched privacy rule/field
remain UNKNOWN. New fixtures do not identify those actual values.

## Bounded complete retained transport

Carrier transport reuses the byte-exact maintained retained_git_transport helper
and owned-process supervisor. A source adapter fetches exact shallow commit/tree
metadata with blob:none, verifies a zero-blob metadata object inventory, then fetches
every deduplicated required blob OID explicitly. It admits only the exact final
commit/tree/blob inventory and materializes all1154 original paths, modes, sizes,
SHA256s and Git blob hashes. Checkout, filters, submodules, lazy fetch, history and
unselected objects provide no fallback. The original later legacy full proof stays.

Both acquisition roles share one absolute400-second budget; aggregate delivery and
materialization remain480 seconds with the existing500-second outer bound. Both
fetch roles use --progress with the canonical bounded merged output and original
supervision. No credential or HTTP tracing is enabled. Failed/unknown retirement
remains failure. Data-only retention captures safe original bounded windows and
phase/error fields while preserving the original error.

A separate16MiB maximum metadata proof binds the actual raw commit, NUL-delimited
whole tree, complete inventories, canonical receipt, non-material raw Git logs and
all1154 material pin/mode records. It never copies package/material stdout. Native
admission and passive reading validate actual canonical supervision instead of
inventing PGO actor lifecycle fields. The public32MiB capsule and private guard stay.

This full profile still requires1,046,432,165 material bytes. No payload reduction,
latency improvement or native GitHub protocol compatibility is claimed. Stock Git
can transfer blobs before an ignored-filter inventory refusal; those results are
refused, with no full-fetch retry. Local Git fixtures establish bounded Source
behavior only. Actual187's fetch log was empty after deadline-triggered forced
retirement; its underlying HTTP/Git/network cause remains UNKNOWN.


# Hosted native developer input closure

Successor to the frozen 138-file constructor. No prior/canonical source is edited.
Actual source/ref/run remain NULL until Root publication and genuine run metadata.
Source construction/controls do not execute compiler/native/GPG/ALPM/Git/install
actors. Bounded public acquisition was explicitly authorized separately.

## Exact frontend and separate backend

Official uv 0.11.28 resolves to commit
`ebf0f43d7c4267876fc256f5fce75982c33f4399`. Primary sources are the
[GitHub release](https://github.com/astral-sh/uv/releases/tag/0.11.28) and
[exact PyPI backend metadata](https://pypi.org/pypi/uv_build/0.11.28/json).
Licenses are `MIT OR Apache-2.0`; the exact notices are retained.

| Input | Bytes | SHA256 |
| --- | ---: | --- |
| uv-aarch64-unknown-linux-gnu.tar.gz | 24,689,886 | `03e9fe0a81b0718d0bc84625de3885df6cc3f89a8b6af6121d6b9f6113fb6533` |
| uv_build-0.11.28-py3-none-manylinux_2_28_aarch64.whl | 1,616,098 | `d99cb38411412134781140cc64dc7d296dbc383fa1e81ddc13ecb6863852ecf5` |
| uv_build-0.11.28.tar.gz, source | 408,697 | `daba66fd25a9a82caa23949686e967cbb69fd056177e991650643186057adaef` |

The release supplies uv/uvx, not an importable Python uv_build package. Exact
source distinguishes the direct Rust fast path from PEP517. The unmodified shim
has `USE_UV_EXECUTABLE=False` and calls `uv-build`, supplied by the separate wheel.
That wheel has no Requires-Dist dependencies; RECORD, shim and license joins were
checked. No importability claim is inferred from the uv binary alone.

`python_backend.py` retains the original project/journey and process core. It
installs the pinned local backend wheel into a fresh private venv with offline,
no-index/no-deps; prepends its bin path; verifies original shim/uv-build payloads;
and uses `--force-pep517 --no-build-isolation`. Backend files are pinned around
every command. Nothing is installed on the host, and no shim is modified.

Archive inspection is not execution. ELF metadata shows AArch64 and GLIBC>=2.28;
the ALARM rootfs pins glibc 2.43. Loader resolution, backend import, builds, native
16K and M2 remain NOT RUN. Primary HTTPS/size/hashes were verified; independent
signatures, attestations and reproducible binary builds were not verified.

## Closed source construction

```sh
python3 -I -B scripts/ci/native-developer-workflows-input-closure/construct.py \
  --predecessor /absolute/path/to/frozen-138-file-source \
  --acquisition /absolute/path/to/input-closure-packet/acquisition \
  --output /absolute/path/to/new-closed-hosted-source
```

The predecessor must match map
`e41a4b76269528ba678bdf1d0fbd7f1a997b9799decfa6ade352e33dc79a56bd`.
The fixed primary-acquisition handoff and all copied archives/provenance are
verified. Original code/data limits stay held; only the two named public tool
archives use exact larger file pins. Ordinary source reads retain their 16 MiB cap.

Original ALARM 341 plus eight packages stays exact 349. uv is a separately pinned
tool under /opt in the disposable image; uv_build stays in the private developer
venv. Neither is passed off as an ALARM package. The guest must actually pass
Python PEP517, compiled extension, CMake and Meson before reporting component PASS.

## Practical hosted route

The source emits byte-identical canonical/dedicated aliases:
`.github/workflows/native-arm-build.yml` and
`.github/workflows/native-arm-developer-workflows.yml`. Root uses existing
canonical workflow 381664314 on `ubuntu-24.04-arm`, as PGO102 did. Ubuntu only
actuates Docker; selected-base execution is inside the exact ALARM environment.
No preseeded/dedicated runner or new secret is required.

The workflow checks exact Git source before secrets, uses the original 22 private
chunks and public14 seed, moves that checkout outside the source, fetches the
original 1154 carrier once to `pgo-hosted-retained` under the proven 480s envelope,
and atomically copies 16 exact leaves for the eight build-tool archive/signature
pairs. The original owner then proves the full carrier, builds 341, authenticates
the eight-package overlay and runs all four real component journeys.

Existing process/cleanup/resource gates remain: bootstrap 2250s subdeadline,
consumer 2 CPU/4 GiB/256 PIDs/1800s, no network, read-only source/root, direct final
waits, named inventory probe, exact owned images and both GPG-home retirements.
Provisioning failure yields bounded DATA diagnostics. No phase ran here.

## Root stage and one dispatch

Publish the complete generated namespace from an isolated source checkout,
retaining its map/Git blobs/ref. Root fills genuine values in the NULL dispatch
JSON, then invokes the existing canonical route once:

```sh
gh api repos/Gabriel-Kahen/cachy-asahi/actions/workflows/381664314/dispatches \
  --method POST --input /root-owned/bound-dispatch.json
```

The body requires `ref`, `inputs.source_sha`, `inputs.source_map_sha256`.
Attempt 1 and exact GitHub source/workflow/ref/run equality are mandatory. Run
selectors are bound only after dispatch metadata exists. No main/PR6 merge occurs.

The matching passive reader checks exact binding, provisioning, both daemon
inspections, resource/mount predicates, raw actor/feature logs and all four actual
component outcomes. NULL bindings refuse before original-artifact reads. DATA
diagnostics confer no native acceptance; Root authenticates original custody.
Native 16K, M2, installed Asahi, performance and release qualification stay separate.

## Bounded public-tree transport

The retention phase writes one regular `upload/public-tree.tar` for the ordinary
artifact uploader. A canonical uncompressed USTAR capsule carries an exact index,
explicit directory modes, file modes/bytes and symlink target bytes as ordinary
data payloads. No archive entry is a link. The matching reader checks the capsule
in memory; it never extracts or creates host links and never reads link targets.
The complete capsule, including metadata/tar overhead, must fit 32MiB; each ordinary
payload remains at most 16MiB. Private caches/key material are excluded.

Run `native/reader.py --capsule ORIGINAL_PUBLIC_TREE_TAR --binding ACTUAL_JSON`
only after Root authenticates the ordinary artifact ZIP and its sole capsule
member. NULL actual bindings refuse before capsule access. Local tar/ZIP fixture
roundtrips are transport-model controls, not actual GitHub or native evidence.

## Causal bootstrap failure retention

The owner now retains the original bootstrap acquisition.json and the original
key-import/build streams and signature-result JSON when present. A narrow DATA
guard verifies the pinned producer, exact501-input metadata/record schema, fixed
source command shapes, stable ordinary files and public-text privacy rules.
Accepted bytes are copied unchanged with private0600 copy permissions and original
source modes recorded. Refused content is never mirrored into generic actor logs;
accepted named streams are reused there without duplicate bytes.

The standalone guard receipt and enclosing owner receipt agree. Expected guard
failures keep fixed codes and preserve an already-active primary exception. A
guard failure cannot produce a positive native result. The existing32MiB capsule,
16MiB member/resource/deadline limits, four journeys, input URLs/pins and package cache-only
seed policy remain. Acquisition records retain their original generic error
fields; they do not invent a more specific cache cause. No retry is performed.

The complete declared seed union has520 names. Exactly the five original base
rows (rootfs, signature and three keyring files) are outside it. The original
pinned parent fetch now handles only those five exact metadata rows, matching
the held PGO behavior. Original and overlay package/signature rows remain strictly
cache-only; a failed package cache check never falls back to HTTP. Unknown or
mutated rows refuse before either callback. No URL/pin, retry or resource limit
is changed, and the development consumer remains network-none. This source
closure proof is not a runtime404/cache-miss finding.

## Owned local base alias and exact cleanup

The overlay FROM uses the source-created local base tag, checked against the
exact owned image ID before and after the network-none/pull-false build. Both
source aliases and the owned namespace must be absent before creation. Only
known successful source build rows register alias ownership. No registry fallback
or BuildKit disabling is introduced.

Cleanup uses recorded natural owned build retirement (including a naturally
failed client), not a latched building flag. It removes only proved created
image aliases still bound to expected IDs, and proved stopped created containers,
without force or image-ID removal. Unknown/foreign/preexisting state is held.
All retirement rows remain captured on errors; independent final daemon queries
are required for PASS. Ledger and retirement DATA are retained standalone and
in the existing receipts. These source/model checks do not prove a native run.

## Original consumer diagnostics and finite public projection

The start-attached consumer actor now emits a source/run/map-bound DATA receipt
before cleanup and capsule packing, on success or failure. It retains the exact
indexed actor exit/retirement fields, original whole-log pin, and at most64KiB of
original UTF-8 suffix bytes with an explicit offset and completeness flag. The
whole log must satisfy the private-marker/text guard before any window is emitted.
A refused log is also blocked from generic mirroring. The guest records bounded
phase/type/message failure DATA and re-raises the original error.

The owner projects finite public reports, original command logs and pinned backend
files into a fresh sibling directory. It does not traverse disposable guest home,
temporary, project, build or general virtual-environment trees. The original output
is preserved. The capsule format, strict private-path guard and32MiB/16MiB limits
remain. Packing refusals emit bounded member/path/phase context before raising;
no rejected payload or key material is printed. A passive failure DATA result does
not pass the native component or cleanup gates.

The genuine182 run reached the consumer start but did not export its inner error.
Its separate private-path pack refusal did not print the offending path. These
causes remain UNKNOWN; source-backed fixtures show retention behavior only.

## Build-summary failure diagnostics and fresh safe fallback

Before the aggregate CMake/Meson guard, the guest writes and emits a whitelist of
aggregate/project status enums, fixed missing-tool/presence booleans, and original
result/command-log hashes. Unknown strings become UNKNOWN; arbitrary values are
never emitted. The host binds this unchanged guest DATA to its source/run/map.
The original guard and default feature payloads remain unchanged.

A private-marker refusal reports only a fixed neutral rule ID, a source-whitelisted
logical JSON field or UNCLASSIFIED with a field-path hash, and bounded file/context
hashes. It never prints the matched marker, value, body or private material. The
strict original privacy predicate and positive acceptance gates remain.

When owner public output exists without a completed projection, retention writes a
fresh disjoint safe-diagnostic sibling. It copies only schema/privacy-qualified
consumer-frame, build-summary and fixed refusal metadata. Original public/projected
bytes remain untouched and untraversed. This direct finite capsule has an explicit
failure-DATA authority and cannot qualify native work. Original result and feature
log bodies absent from this safe capsule are marked unavailable for pin verification.

Actual184 only proves the aggregate guard failure and journey/result.json privacy
refusal; aggregate/project/missing-tool values and the matched privacy rule/field
remain UNKNOWN. New fixtures do not identify those actual values.


This205-leaf composition uses finite profile native191-installed-alpm205-v1. Root must bind actual published191 parent; runtime acceptance NOT_RUN.


## Explicit205 installed ALPM successor

This version composes bounded191 transport and frozen201 installed source.
The exact finite native191-installed-alpm205-v1 profile has204 nonrecursive rows;
legacy unnamed callers retain<=200. Root's genuine published191 parent is
4c3171a1937489badd22d350835e8287fee3c52a. New runtime selectors remain NULL.

Only installed-alpm-v1 adds two supervised makepkg builds in fresh distinct
recipe roots, recreated fixed BUILDDIR and epoch1791748800. Exact archive,
payload, PKGINFO and BUILDINFO equality precedes signing. These builds share
one owned image; check() remains explicitly NOT_RUN under held --nocheck.
The operation requires full /usr and moved-prefix workflow/build-systems/
debugger/Python journeys with independent original DATA and pinned backends.
Complete home/trust/config metadata and hashes must return exactly along with
354/355/354 inventories and scoped signing/trust home retirement.

The default23 features, retained1154 DATA leaves,400s shared Git/480s total/
500s outer limits, supervision, public32MiB capsule and diagnostic retention
remain held. Source preparation and reader controls grant no native, ALPM,
16K, M2, performance, production trust or release acceptance.


## Cache canonical retirement wiring successor

Cache seeding now calls existing transport_retired() with the completed canonical
transport report and unchanged full profile, binding, whole source-map and proof.
The historical nonempty PGO actor validator remains strict; canonical actors=[]
is not replaced with fabricated actor rows. Validation precedes the one-shot
marker and all cache writes. Original120s seed,400s shared Git/480s total/500s
outer budgets, complete1154 DATA and default/installed routes remain held.
This source correction does not establish a successful later seed or consumer.


## Overlay failure scalar diagnostics v1

The original205 failure proves only owned overlay Docker actor exit1 and a
PRIVACY_07 refusal of its8360-byte private log; inner cause stays UNKNOWN.
This source adds fixed enum-only installed-image failure phases and an exact
source-bound overlay actor diagnostic before cleanup/projection. It prints the
finite summary into the future direct job log and writes private work JSON.
No raw log window, arbitrary exception text/type, secret value or private stream
is exported. A missing, malformed, duplicate or wrong-map marker remains
NOT_OBSERVED/REFUSED with UNKNOWN phase. Public projection, privacy and capsule
fallback protocols remain unchanged; this diagnostic grants no native credit.


## Resumed source correction, 2026-10-31

The pair caller now uses total600, within the unchanged workflow constructor's
600-second maximum. Its previous total900 was rejected before any makepkg actor.
This is a source-proven blocker, not a recovered diagnosis of the original run.
Cleanup-only failures retain their first enum phase/category before subsequent
cleanup work. Direct-log enum export is attempted even if the private JSON save
fails. Raw logs, capsule privacy, process ownership and acceptance gates are held.
