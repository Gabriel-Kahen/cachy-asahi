# Finite generic desktop dependency preview

Implemented a reviewable M5 inventory **proposal and generic metadata preview**.
This is not a release inventory lock or an accepted Asahi transaction. The target
Asahi boot/kernel/firmware/Mesa/audio transaction, signed archive authentication
for newly selected packages, installation, file/hook compatibility, native ARM
execution of this preview, 16K execution and both-model hardware checks remain
**NOT RUN**. No system package, service, mount or repository state was changed.

## Proposed package set and actual result

[`desktop-proposal.json`](../../scripts/port/desktop-proposal.json) selects 45
finite generic roots from the [coverage audit](../port/desktop-coverage.md), with
exact repository versions. Baseline Vim `9.2.0849-1` and Nano `9.1-1` provide the
editor function; Neovim `0.12.6-1` is explicitly optional and was not selected.
The roots cover Hyprland, session services, networking, Bluetooth, fonts,
clipboard/screenshots, browser, file management, shells and native development.
Applicable Cachy management tools and the separate compiled development recipe
have their own audits; they are not silently counted as these upstream roots.

The actual host pacman `7.1.0` / libalpm `16.0.1` print-only run read a new private
metadata context for the exact retained **341-package generic builder**. It
resolved **233 additions**, **zero changed baseline versions**, and **574 final
candidate metadata records**. Prospective download size is **285,857,540 bytes**
(about 272.61 MiB); no packages were downloaded. All **2,933** final dependency
relations were satisfied through libalpm's version/provider semantics; an
independent fixed `pacman --deptest` against the reconstructed candidate DB
returned 0. Native `alpm_checkconflicts` found no package conflicts. All 341
baseline records remain, so this selected metadata candidate requires no removal.
This does not establish filesystem/hook compatibility, installed execution, or
an actual committed transaction's removal behavior.

The full selected inventory and dependency/provider relations are in
[`generic-desktop-receipt.json`](../../scripts/port/generic-desktop-receipt.json).
It records current and proposed root versions, all additions, repository versions,
archive identities where available, metadata licenses, public upstream URLs,
maintenance ownership classes, snapshot/source hashes and exact limitations.
The 574 records include the retained base and build-only packages; this is not a
minimal fresh-install closure. The earlier 586 all-provider name graph is not
used as an installable closure or a package inventory.

Provider choices are explicit for this **generic** preview:

| Relation | Selected provider | Selection basis |
| --- | --- | --- |
| `opengl-driver`, `libva-driver` | stock `mesa 1:26.2.4-1` | Retained generic builder provider; explicitly pinned |
| `jack`, `libjack.so=0-64` | `pipewire-jack 1:1.6.9-1` | Explicit generic provider constraint |
| `dbus-units` | `dbus-broker-units 37-3` | Existing generic provider; explicitly pinned |
| `ttf-font` | `noto-fonts 1:2026.10.01-1` | Explicit desktop root already in the transaction |

Stock Mesa is not a proposed replacement for target Asahi Mesa. Generic
PipeWire/provider resolution does not establish Asahi DSP/protection/audio
integration or service activation. The actual target stack still needs exact
protected package metadata, provider/version identity and platform ownership.

## Immutable inputs and trust limits

This run deliberately uses the **earlier retained builder** core/extra snapshots,
not floating current mirror metadata or the later coverage graph cache. Both
snapshot hashes and sizes are checked before a private copy is supplied to
pacman. Only core and extra participate; alarm/aur are not required for these
selected generic additions.

| Input | SHA256 | Bytes |
| --- | --- | --- |
| core.db | `56bb9080bb5334b8a27e7c6aed58383e7bc542544b0e89335ce98669a2539ad6` | 256702 |
| extra.db | `ba1bdb823c22936ba7c9f700d168da139403b1d65683e115b66bd9c9a82ce069` | 10613813 |
| Builder input lock | `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41` | Recorded in existing native evidence |
| Exact builder inventory | `7f40e51da419514c3ffe4fc9ed5bd9d6f242e576a585347c4799cd20bfd32104` | 341 sorted name/version rows |
| Proposal | `d39a04fb680b57b9b45eb5ec8cfdee4e7f834976564fc90c69e23e267ad0722a` | Retained in repository |

The DB snapshots are **unsigned availability metadata**. Retained rootfs and
248 package archives are rehashed, and complete rootfs local descriptors and
archive `.PKGINFO` are read to reconstruct the builder inventory, including
versioned provides, depends, conflicts and replaces. These are genuine retained
input bytes, but this helper does **not** repeat signature verification. The
[existing native input authentication record](../validation/native-arm.md) is
separate prior evidence. No newly selected archive/signature bytes were retained
or authenticated. A metadata `PGPSIG` field is not a signature-verification PASS.

The snapshots contain a missing-name `extra/findnewest` entry and malformed
version relations in unselected `nextcloud-app-spreed`. Both are reported; neither
can be selected. Malformed selected metadata stops the preview. Source recipe,
source commit/patch/license text and vendored attribution review remain required;
package license fields and upstream links do not close those reviews.

## Operation and checks

The [small helper](../../scripts/port/preview.py) accepts proposal/input paths and
hashes, not forwarded pacman options. It generates a private temporary root,
local/sync DB, cache, empty keyring and hook directory, log path and config under
`/tmp/cachy-port-*`; cleanup runs on success and failure. There are no Includes,
host mirrorlists, host keyrings or default host package databases. Servers point
at `metadata.invalid`; print mode does not contact them. Descriptor bytes are
read directly without unpacking archive payloads or a root filesystem.

Its fixed command is `pacman --sync --print --needed --noconfirm --print-format`
with explicit config/root/db/cache/gpg/hook/log/architecture paths and exact
`name=version` targets. Its only second pacman operation is `--deptest` in the
same private candidate DB. The guard rejects extra/reordered/custom arguments,
mutating/download/refresh flags, external config and symlinked contexts. This
uses the documented [pacman print/deptest interfaces](https://man.archlinux.org/man/pacman.8.en).
The native libalpm audit reads that private final DB and checks providers and
package conflicts; it never initializes or commits an installation transaction.

Reproduce using retained local inputs (the `/tmp` archive cache is temporary and
must be retained separately for future reruns):

```sh
python3 -B scripts/port/preview.py \
  --proposal scripts/port/desktop-proposal.json \
  --proposal-sha256 d39a04fb680b57b9b45eb5ec8cfdee4e7f834976564fc90c69e23e267ad0722a \
  --builder-lock docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json \
  --database-dir /tmp/cachy-asahi-native-arm-audit \
  --archive-cache /tmp/cachy-asahi-native-arm-audit \
  --installed-lock artifacts/ci/38189520114/decoded/native-evidence/packages.lock \
  --output /tmp/new-generic-desktop-preview
python3 -B -m unittest discover -s scripts/port -p 'test_*.py' -v
```

**10 tests PASS with no skips**, including actual temporary pacman/libalpm
fixtures. They exercise host/custom-argument and config refusal, context
symlinks, duplicate/nonfinite JSON, exact pins and finite roots, separated
DB dependency/provider metadata, malformed selected metadata, architecture,
explicit provider selection, epoch/inequality/SONAME comparisons, unversioned
provider rejection and native conflicts. The fixture print leaves its private
local DB and package cache unchanged. Tests do not authenticate archives or
establish target behavior.

Coordinator work remains: review the finite proposal; assign named upstream,
package/platform and release custodians; retain/authenticate selected archives,
source/licenses and build provenance; replace generic assumptions with the
actual Asahi target inventory; resolve its transaction; then exercise disposable
and target installation/upgrade/recovery. No shared inventory manifest, build
input lock, original recipe, Git state or CI workflow was edited by this owner.
M5 remains incomplete.

## Archive data authentication follow-up

Implemented [`authenticate.py`](../../scripts/port/authenticate.py) and an owned
[`233-archive proposal`](../../scripts/port/desktop-archives-proposal.json), without
changing the frozen preview/proposal or any shared manifest. Archive lock SHA256
is `119f420629a8b594e8fc46ddf6d5f0cbcc2a3176867cda75f3c5d0ccf73b1a86`.
It binds the proposal, preview receipt, original builder lock, exact unsigned
core/extra snapshot hashes, package versions/architectures/metadata and official
HTTPS archive URLs. Detached signature URLs are exactly each archive URL plus
`.sig`, as in the audited native input helper. Their SHA256/size pins come from
the captured DB's decoded signature bytes; GPG verification subsequently tests
those actual signatures against each actual archive, not the DB field alone.
The bounded new input total is **285,989,418 bytes**, including 233 signatures.

**Actual result: FAIL for the complete set; 232 of 233 archives authenticated.**
The CA official mirror returns **HTTP 404** for the exact frozen
`libfdk-aac-2.0.3-2-aarch64.pkg.tar.xz`, SHA256
`11a8590845e29d7287d9d8b14e50d6046b009f52f37e21bb555c446ecedc514c`.
Florida and de3 official mirrors also return 404 for the same name. NJ failed
TLS issuer verification; the default mirror failed TLS hostname verification.
TLS verification was preserved. The [official package page](https://archlinuxarm.org/packages/aarch64/libfdk-aac)
advertises that same version/file; this does not establish binary availability.
The missing package was not skipped, changed or accepted. The full native generic
extension transaction is **not ready** while the set is incomplete.

[`archive-availability-failure.json`](../../scripts/port/archive-availability-failure.json)
retains exact DNS/network failures and same-file alternate-mirror observations.
The first sandbox attempt had DNS failures for all packages. An authorized
network run then downloaded and authenticated 232 packages with the one 404.
The final current-source replay rehashed/reverified those cached bytes and
reported the still-missing package's sandbox DNS failure. None of these failed
attempts is reported as complete authentication.

Each successful package passed SHA256/size pins, the actual detached signature,
zero GPG exit, exactly one `VALIDSIG` from primary
`68B3537F39A313B3E574D06777193F152BDBE6A6`, and exact `.PKGINFO`
name/version/arch/depends/provides/conflicts/replaces/license comparison to the
resolved records. Bad, missing, different-signer, expired/revoked, failure and
nonzero statuses are rejected. Only pinned official public key files were read;
GPG used a fresh public-only temporary home with `--no-options`,
`--no-auto-key-retrieve`, and `--no-autostart`. No signing key, host keyring,
ownertrust changes, package installation, mounts or services were created.

The [compact crypto receipt](../../scripts/port/archive-authentication-receipt.json)
binds source/helper/lock hashes and each hashed per-package observation under
[`observations`](../../scripts/port/observations). These public
records retain full installed paths, public build metadata, ELF headers,
scriptlet/hook hashes, and license-notice hashes. Archive payload bytes and
signatures remain private under `/tmp/cachy-asahi-port-auth-cache` (roughly
274 MiB); neither archive bytes nor the temporary GPG home are published.
Observations do not unpack or execute payloads. They reject traversal/duplicate
paths, special nodes, unsafe hardlinks and nonregular/oversized metadata/hooks.

The authenticated subset contains **44,563 installed paths**, **1,188 ELF
headers**, **11 hooks/scriptlets**, and **150 license-notice files**. ELF headers
show 1,179 AArch64 objects and nine EM_BPF rc-keymap objects in `v4l-utils`, all
64-bit; this is static archive observation. No ELF loading, 16K compatibility,
application/session execution, hook action or source/license clearance is
established. Declared licenses and retained notice/build metadata do not supply
complete corresponding sources or vendored/source license closure.

**16 tests PASS, no skips**: six additional authentication/archive tests exercise
exact finite set/signers/URLs/bounds/duplicates, receipt metadata tampering,
bad/nonzero GPG statuses, hash/size/HTTPS/redirect/cached-symlink refusal, archive
traversal/duplicate/special-node/metadata mismatch, and nonexecuted hook/ELF/link/
license observations. The earlier ten include actual private pacman/libalpm
fixtures. No production key signing or package installation is a test side effect.

```sh
python3 -B scripts/port/authenticate.py \
  --lock scripts/port/desktop-archives-proposal.json \
  --lock-sha256 119f420629a8b594e8fc46ddf6d5f0cbcc2a3176867cda75f3c5d0ccf73b1a86 \
  --proposal scripts/port/desktop-proposal.json \
  --preview-receipt scripts/port/generic-desktop-receipt.json \
  --builder-lock docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json \
  --public-key-directory /tmp/cachy-asahi-native-arm-audit \
  --output /tmp/new-archive-data-authentication
```

Before a later native batch, recover the exact missing archive/signature through
an authenticated retained/official source or coordinate a separately reviewed
snapshot/provider change and a fresh resolution. Then require all 233
verification records to pass; retain the unchanged 341 baseline, stock generic
Mesa, explicit providers and exact 574 candidate inventory for a disposable
native transaction. Package file/hook compatibility, public source/license
closure, update ownership and integration checks remain separate gates. No
expanded native installation is accepted by this evidence; actual Asahi/M2
installation and hardware acceptance remain **NOT RUN**.

## Original native input availability blocker

The corrected initial native integration run `38199269315` passed source
preflight, its 213 boundary checks and the native probe, then stopped acquiring
inputs with HTTP 404. **The ARM build did not start.** The original source lock
remains `7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41`.

The [read-only availability checker](../../scripts/port/availability.py) probed
all **501 original URLs** with four parallel HEAD workers between
`2026-10-12T03:27:12.996063+00:00` and
`2026-10-12T03:27:45.970369+00:00`. Result:

| Original input | Availability |
| --- | --- |
| `perl-5.42.2-2-aarch64.pkg.tar.xz` | CA, Florida and de3 official mirrors return HTTP 404 |
| Its exact detached `.sig` | Same three official mirrors return HTTP 404 |
| Other 499 original pinned files | HTTP success with exact expected Content-Length |

NJ probes failed TLS issuer verification and default-mirror probes failed TLS
hostname verification; TLS was never relaxed. HEAD requests consumed **zero
response-body bytes**. The checker permits a one-byte Range GET only for HEAD
405/501, closes immediately, and never treats HTTP success as archive/signature
authentication. That fallback was not needed here. All **501 durable local
retained files rehashed to their original pins**, including the missing remote
Perl pair. Those bytes were not uploaded, published or unpacked; previous
signature authentication remains separate evidence.

[`original-input-availability.json`](../../scripts/port/original-input-availability.json)
retains each exact filename/URL/pin/status/Content-Length, mirror failures,
source hash and local retained-pin result. This identifies a reproducible input
loss consistent with the run's previously opaque 404. The unavailable package
was neither skipped nor replaced. No CI, shared lock, original recipe or Git
state was changed by this audit. Existing earlier native build evidence remains
bound to its original environment; it does not accept this interrupted run.

The actual current official core metadata now advertises **Perl 5.42.3-1**,
archive `perl-5.42.3-1-aarch64.pkg.tar.xz`, SHA256
`f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f`,
16,017,184 bytes. The bounded current DB observation is 256,696 bytes, SHA256
`5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08`.
Both this new archive and its 566-byte signature return HEAD 200 with matching
lengths. Version and `provides` change; `depends`, conflicts, replaces, licenses
and architecture remain identical in the compared metadata. This is an
**unsigned source proposal**, with authentication **NOT RUN**. The official
[Perl package HTML](https://archlinuxarm.org/packages/aarch64/perl) still showed
the older version during the check; actual repository metadata and availability
are recorded in
[`current-perl-metadata-observation.json`](../../scripts/port/current-perl-metadata-observation.json).
This illustrates why an HTML package listing or old hash cannot establish
current artifact retrieval, as already seen with the missing desktop libfdk-aac.

The safe corrective path is an explicit, coordinator-reviewed snapshot refresh:
retain and authenticate the proposed Perl archive/signature under the unchanged
pinned official signer policy; capture exact repository inputs; recompute the
complete builder dependency/provider transaction and installed inventory;
refreeze the reviewed source/build environment; then rerun the complete original
native integration batch and its clean-build comparisons. An alternative would
need an approved actual ARM environment already holding the original retained
bytes. This audit does not authorize uploading them. Merely changing a Perl URL,
using new bytes under old hashes, choosing an unreviewed version, relaxing TLS or
reusing previous build acceptance would not satisfy these gates.

**21 scoped tests PASS, no skips**. Five new cases cover no HEAD body reads,
bounded Range fallback only for unsupported HEAD, preservation of 404/TLS
failures, credential/nonofficial/HTTP/redirect refusal, and the exact original
501-item/signature set. These complement the existing 16 data-authentication and
private pacman/libalpm tests.

```sh
python3 -B scripts/port/availability.py \
  --input-lock docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json \
  --output /tmp/new-original-input-availability.json
```

This is a read-only availability audit and corrective proposal. New Perl
signature/archive authentication, replacement transaction acceptance and the
interrupted native integration batch remain **NOT RUN**. No M2 or Asahi target
connection or hardware acceptance is established.

## Explicit migration candidates and refreshed generic desktop

Perl `5.42.3-1` and libfdk-aac `3.0.0-1` were downloaded into a separate private
candidate cache and **authenticated as data** with the unchanged official public
key and exact primary signature policy. Complete signed `.PKGINFO` fields match
their captured current DB records. Old Perl bytes were separately rehashed and
inspected for the exact before/after relation comparison. The candidate tool,
[`migration.py`](../../scripts/port/migration.py), never installs or executes
payloads. Its bounded public evidence is in
[`migration-evidence`](../../scripts/port/migration-evidence).

The coordinator independently accepted
[`builder-perl-migration-proposal.json`](../../scripts/port/builder-perl-migration-proposal.json),
SHA256 `d39c1b744ea54e282663e99932d58976336496426f7c3c6fd12b94526ff09a8f`.
Its exact `inputs.lock.json`-compatible Perl dictionary, actual `VALIDSIG`,
signed old/new metadata and private libalpm comparison establish a consistent
**341-package proposed builder** with **1,582 satisfied dependency relations**,
zero conflicts/removals and only the explicitly reviewed Perl change. New Perl
archive SHA256 is
`f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f`,
16,017,184 bytes; signature SHA256 is
`f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca`,
566 bytes. Native installation and build/integration acceptance remain separate.

The coordinator adopted builder source lock
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
The original `7d53775b...` lock and evidence are preserved at
`docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json`.
Historical replay examples and owned tests now explicitly read that preserved
snapshot, not the mutable current source lock. Historical receipt hashes and
failed attempts have not been rewritten as results under the new environment.

The **separate FDK candidate** retains provider `libfdk-aac.so=2-64`, but its
license declaration changes from `custom` to `LicenseRef-Fraunhofer`. It passed
actual hash/signature/metadata checks; this does not establish legal clearance,
complete corresponding sources or runtime ABI execution. Its archive SHA256 is
`7dc8dc21e95888bdf8c9ee3b0a45e5adea62c2b9a5dc3a57ea502f46330b00d8`,
1,201,016 bytes; signature SHA256 is
`f79301738e44aba1a927472659546c7f5d40c68cd8606919f2ad96d63ac32fa7`,
566 bytes. It is not silently substituted into the old desktop proposal or
adopted as a supported release input.

[`re_resolution.py`](../../scripts/port/re_resolution.py) performed an actual
private **pacman print-only re-resolution**, now explicitly bound to builder
lock `3c16c37d...` and a declared 341 inventory with hash
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`.
It used exactly the current captured core `5f184763...` and extra `66cfbeae...`
bytes, all 45 exact original generic roots, explicit providers and reviewed
Perl `5.42.3-1`. The run resolved **233 additions**, **zero additional baseline
version changes**, **574 final records**, **2,933 satisfied relations**, no
package conflicts/removals and `--deptest` exit 0. Prospective addition bytes are
**286,427,064**, reflecting only the new FDK archive among the additions.
This is a declared candidate builder baseline, not an assertion of a newly
installed native builder or fresh Asahi installation.

Public [refreshed desktop evidence](../../scripts/port/refreshed-desktop) retains
a separate proposal, archive lock, receipt and proposed builder inventory. The
new proposal SHA256 is
`d7189a0526cfaa09d75011f06cdb6a5811dbd70a7b419784681ea669fa76b131`;
archive lock SHA256 is
`96bce50d99ebcc10ac3897f17f05e66ec185aad85e807e5d09928c1cbfa5c9a8`;
print receipt SHA256 is
`b7f53cc24eb8e12119050c76554f78f7daa215d6fa048c2c4336037f824b2deb`.
All **233 refreshed addition archives** subsequently passed fresh actual GPG,
hash/size and exact `.PKGINFO` checks using the retained private bytes, including
the separately authenticated FDK successor. This closes data acquisition for
this proposed generic set; it does not clear FDK/source licenses, native
installation, hooks, workflows, promotion, the Asahi stack or M2 hardware.
The earlier 232/233 failure remains a truthful result for its original pins.

## Separate compiled-updater builder extension

The updater owner's immutable `builder-extension-proposal.json`, SHA256
`38a26d91d5b153951b64991c1c018a907835ffa89525e90b91a54d59ad5a2fe4`,
requested nine finite roots: Rust, scdoc, Git, GLib, gettext, pkgconf, Bats,
Python and make. [`updater_extension.py`](../../scripts/port/updater_extension.py)
resolved exact owner pins using the retained current core/extra snapshots and
builder `3c16c37d...`, seeded by the declared 341 inventory `89bdb06f...`.
It refuses any baseline version change and never amends the shared input lock.

**Actual private print/deptest/libalpm result: PASS for metadata**, with **13
additions**, **354 final packages**, **1,642 satisfied dependency relations**,
zero baseline changes/conflicts/removals and `--deptest` exit 0. The additional
archive bytes total **74,752,420**. Every addition subsequently passed actual
SHA256/size, detached GPG zero-exit/exact-primary policy, and full `.PKGINFO`
identity/dependency/provider/conflict/replacement/license checks. This supplies
real authenticated compiled ARM toolchain bytes; compiler execution and updater
compilation remain **NOT RUN** until the native extension stage executes.

| Additional package | Exact version |
| --- | --- |
| rust | `1:1.99.0-1` |
| compiler-rt | `23.1.1-1` |
| lld | `23.1.1-1` |
| llhttp | `9.3.1-1` |
| libgit2 | `1:1.9.7-1` |
| scdoc | `1.11.5-1` |
| perl-error | `0.17030-3` |
| perl-timedate | `2.35-1` |
| perl-mailtools | `2.22-3` |
| zlib-ng | `2.3.3-1` |
| git | `2.56.0-1` |
| parallel | `20260922-1` |
| bats | `1.14.0-1` |

Rust's signed package provides Cargo and rustfmt and requires the matching
LLVM 23 runtime. `llvm-libs 23.1.1-1` is already in the 341 baseline and is
preserved; compiler-rt and lld 23.1.1 are explicit additions. Other direct roots
remain at their owner-pinned, already present versions. The archive observations
contain **46 AArch64 ELF headers**, **1,523 installed paths**, **13 license notice
files** and **one scriptlet/hook**; all are static observations, with no execution.
Embedded object archives, 16K loading, runtime behavior and corresponding-source
license closure are separate checks. No optimization or M2 compatibility is
claimed from these bytes.

[`updater-extension/builder-extension.lock.json`](../../scripts/port/updater-extension/builder-extension.lock.json)
SHA256 is
`988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776`.
It records the exact 13 archive/signature URL/hash/size and metadata inputs,
public key pins, owner roots, snapshots, base identity and complete expected
354 inventory hash
`d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271`.
The [receipt](../../scripts/port/updater-extension/extension-receipt.json), SHA256
`f48c3fa41de8df649260e3c16fa3361f0c4b65e28c70e431baee8d887bcf4490`,
binds actual print/version relations, GPG statuses and per-package observation
hashes. All literal receipt-relative observation paths and hashes resolve.
Archives/signatures remain private under
`/tmp/cachy-asahi-updater-extension-cache`; no upstream binary blobs or private
cache were published. GPG used only pinned public keys in a removed temporary
home, without host defaults, signing keys, ownertrust changes or network key
retrieval. Original 341 packages, including generic platform/graphics inputs,
are unchanged; this is not a transaction on the Asahi target stack.

**25 scoped tests PASS, no skips.** Four additional migration/extension cases
exercise exact successor metadata/signature pins, architecture/bad-signature
encoding refusal, native versioned-provider migration failure, the exact
341 seed hash, finite root pins/duplicates, and baseline-change refusal. Native
source/build checks and the full target release remain independent gates.

The coordinator can now review the separately frozen extension lock, use its
13 authenticated inputs and exact 354 inventory in a fresh disposable native
builder, invoke `rustc`/Cargo/scdoc and the upstream checks, then perform the
compiled updater's two clean builds. Cargo sources/licenses and recipe payload
review are owned separately. No native extension installation, compiler
invocation, package build, service activation, Asahi/M2 or 16K runtime acceptance
is established by this source/data task.

## FDK source/license correction proposal

The bounded [FDK source audit](../../scripts/port/fdk-source/README.md) replaces
the broad clearance placeholder with concrete inputs and actions. The signed
upstream `libfdk-aac 3.0.0-1` includes the classic library **and** new xHE library,
but only the classic NOTICE. The exact classic notice matches upstream source;
the separate complete [xHE grant](https://github.com/mstorsjo/fdk-aac/blob/a68a51aa45d86a43c7b228e3d45624af09dcdd8d/xhe-aac/NOTICE)
is missing from its binary materials. Authentication of that archive remains
PASS; its notice/source redistribution conditions are a different result.

Pinned upstream source is tag object `a53bfb8e62714f74612e4b85e679dbeb6b971606`,
commit `a68a51aa45d86a43c7b228e3d45624af09dcdd8d`. Its canonical Git archive
BLAKE2 hash exactly matches the source checksum in the immutable Arch
[3.0.0 recipe](https://gitlab.archlinux.org/archlinux/packaging/packages/libfdk-aac/-/blob/b0c45e29a1bac452ece793799738e066d0c3f2cb/PKGBUILD).
That recipe has no declared codec patches. The signed ARM BUILDINFO recipe hash
`c8c2385b...` differs from the inspected Arch recipe `6a231a87...`; the current
ALARM override tree has no FDK entry. Exact retained-binary recipe/source
identity is therefore unresolved. **A project native source rebuild is the
preferred correction**, with its own immutable recipe and resulting BUILDINFO.

Both Fraunhofer grants permit copyright redistribution with complete notices,
free complete source copies to binary recipients, no copyright-license fee or
endorsement, and required change/date/modified-version notices for modified
codec source. They grant no patents; appropriate authorization for the intended
use remains distinct. No legal approval or blanket patent clearance is claimed.
The audit preserves both complete grants, source copyright headers and all nine
observed complete Fraunhofer header variants. Apache-licensed example/test
source, BSD-style SHA1 and Windows public-domain/MIT notices are also preserved;
these optional/example/Windows branches are not selected for the proposed Linux
Autotools build.

Two bundled PDF manuals explicitly forbid reproduction without publisher
permission. A Rust packet test vector has no established redistribution grant.
The **prepared codec source packet** excludes exactly those three non-source
assets, retains all **1,190** remaining upstream source-file bytes unchanged,
and adds the complete official Apache 2.0 license text. Codec and selected
Autotools build source are unchanged and fully present. The private packet is
3,861,432 bytes, SHA256
`1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49`.
Its [manifest](../../scripts/port/fdk-source/prepared-source-manifest.json)
binds every included/excluded file and original/source/script hashes. It is
ready as a reviewed source input; no publication or build occurred. Verify a
native build from this same recipient packet before selecting its binaries.

The exact 574 graph has one direct FDK consumer, `pipewire-audio`. Its transitive
reverse set is `pipewire-audio`, `pipewire-jack`, `pipewire-pulse`, `portaudio`,
`libopenmpt`, `ffmpeg`, `firefox` and `waybar`. Static `readelf` on exact signed
archive objects identifies the direct FDK-linked object as
`usr/lib/spa-0.2/bluez5/libspa-codec-bluez5-aac.so`; its
[immutable source](https://github.com/PipeWire/pipewire/blob/8fa27cabdc6c0c1350c69c026af5850ef0af1e26/spa/plugins/bluez5/a2dp-codec-aac.c)
is MIT. The examined FFmpeg, libopenmpt, PortAudio and PipeWire JACK/Pulse objects
have no direct FDK DT_NEEDED. Package graph reachability is not proof of a
GPL-linked FDK work. No direct GPL/FDK incompatibility was found at the actual
MIT AAC plugin; a separate GPL-enabled FFmpeg/FDK build would need its own
review. No objects were executed.

Proposed namespace: **`packages/libraries/cachy-asahi-fdk-aac`**, version
`3.0.0-1`, aarch64. Runtime: glibc. Build: baseline GCC, make, autoconf,
automake, libtool and pkgconf. Build from the prepared immutable source with
`--prefix=/usr --disable-static --disable-example`; install both complete grants
and copyright/header materials. Expected providers are `libfdk-aac=3.0.0`,
`libfdk-aac.so=2-64` and `libfdk-xhe-aac.so=0-64`; conflict with upstream
`libfdk-aac`, with **no automatic replaces action**. One explicitly reviewed
upstream-to-project provider substitution keeps 574 packages and changes no
341 builder/Apple platform package. Actual native ELF/providers, ownership,
transaction consistency, two clean builds, source delivery and lifecycle tests
are still required. No package recipe or candidate lock was edited here.

A notices/source sidecar could accompany the upstream binary and add a package
(575), but cannot settle its unmatched exact build recipe. If FDK cannot be
selected, a distinct project PipeWire audio provider built with
[`-Dbluez5-codec-aac=disabled`](https://github.com/PipeWire/pipewire/blob/8fa27cabdc6c0c1350c69c026af5850ef0af1e26/meson_options.txt)
can remove the AAC plugin/FDK dependency while retaining required audio,
Pulse/JACK, SBC A2DP and HFP/mSBC workflows. That explicitly defers Bluetooth
AAC and requires reviewed package re-resolution and target tests; it does not
remove PipeWire audio or replace Asahi DSP/protection. The full
[source-built/provider/sidecar proposal](../../scripts/port/fdk-source/source-built-package-proposal.json)
is ready for implementation-owner assignment.

Source packet member/inclusion/exclusion hashes, all preserved codec/build
source bytes, notice identity and the exact linked-consumer finding were
verified. This source/documentation task needed no package implementation tests;
no build, installation, publication, source-equivalence, performance, 16K or
hardware pass is claimed. Original and refreshed authentication receipts remain
unchanged.

### FDK audit publication-reference correction

Before publishing the locally committed audit, the bounded
[source-reference check](../../scripts/port/fdk-source/publication-check.json)
verified the copied packaging/source grants independently. The immutable Arch
[LICENSE](https://gitlab.archlinux.org/archlinux/packaging/packages/libfdk-aac/-/blob/b0c45e29a1bac452ece793799738e066d0c3f2cb/LICENSE)
and [REUSE mapping](https://gitlab.archlinux.org/archlinux/packaging/packages/libfdk-aac/-/blob/b0c45e29a1bac452ece793799738e066d0c3f2cb/REUSE.toml)
explicitly cover PKGBUILD under 0BSD; the exact two copied recipe references
remain with the full grant/copyright. PipeWire's immutable
[LICENSE policy](https://github.com/PipeWire/pipewire/blob/8fa27cabdc6c0c1350c69c026af5850ef0af1e26/LICENSE)
explicitly makes all source MIT except two named libraries, neither among the
copied AAC/Meson reference files; that policy and complete COPYING are retained.
The SHA1/Windows helper copies preserve their own inline redistribution grants.

Five FDK standalone references lacked an established explicit file/repository
publication grant: **`Makefile.am`, `configure.ac`, `ChangeLog`,
`source-rust-build.rs`, `source-rust-Cargo.toml`**. Those copied bodies are now
withheld from the public audit tree; private originals remain retained, while
hashes, immutable provenance and observations stay available. Codec grants and
Cargo metadata are not inferred as permission for all standalone source text.
The prepared source packet remains private and needs those grants established
or independently licensed build/reference replacements before source
publication. This names a specific remaining obligation; codec notices/source
observations and binary-authentication results are unchanged.

The unpushed parent audit commit already held those files, so simply appending
file deletions would still publish their bodies through history. The coordinator
must replace/amend the unpublished audit commit before push; this owner performed no
Git commands or history edits. This check claims no blanket legal approval.
