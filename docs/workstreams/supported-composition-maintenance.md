# Three-package coordinated-maintenance DATA proposal

November 14, 2026. The actual retained 626-package composition **prepares as
metadata under an explicit three-package proposal**. The original protected
policy still fails and remains visible. Overall result is **HOLD / UNAPPROVED**;
no package, protected-list file, repository selection or system was changed.

This is a separate optional phase of the
[supported composition adapter](../../scripts/port/supported-composition/README.md).
It reuses the same bounded private libalpm worker and does not create a solver,
installer, acceptance authority or changed default profile.

## Exact proposal

The schema is `unapproved-Asahi-three-package-maintenance-v1`, with explicit
`approval_status: UNAPPROVED`. It binds the exact original composition contract,
image inventory, protected tuple and ordered Asahi/core/extra catalog references
by their full paths/sizes/SHA-256 values. Its only change records are:

| Package | Exact retained before | Exact proposed after | Repository |
| --- | --- | --- | --- |
| Python | `3.14.7-1` | `3.14.8-1` | core |
| NetworkManager | `1.58.1-1` | `1.58.1-2` | extra |
| Perl | `5.42.2-2` | `5.42.3-1` | core |

Each record requires its own nonempty bounded reason. Extra changes/fields,
missing before identities, different versions/repositories or changed bindings
refuse. All three after identities must already be explicit roots/providers in
the original composition; the proposal cannot add or retarget them. Additional
kernel/Mesa/boot/audio protected target changes refuse, and any extra implicit
baseline change fails proposed preparation.

The original 201-protected policy is evaluated first without relaxation. The
second private run uses an in-memory proposed Python version and exact three
base-change expectations. Root/provider policy and all other original protected
versions remain fixed. Neither that temporary model nor successful dependency
preparation adopts the proposal.

## Actual retained-data run

The original full-held-desktop contract remains SHA-256
`af4622c393f1fb0ec8d3ba81b1ff3f9179e6033049c375e8d209f28a83b0fd45`.
Its before image/protected/catalog references and two actual unqualified host
candidate archives are unchanged from the
[previous demonstration](supported-composition.md).

The new local ignored proposal is
`work/supported-composition-20261114/three-package-maintenance-proposal.json`,
2468 bytes, SHA-256
`a8f8cb9faf69f0fbb297ef9cc1f18cd15d3682efa494e1894b509536ddf419f3`.
The exact command executed was:

```sh
python3 -B scripts/port/supported-composition/compose.py \
  --contract /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/full-held-desktop.json \
  --contract-sha256 af4622c393f1fb0ec8d3ba81b1ff3f9179e6033049c375e8d209f28a83b0fd45 \
  --maintenance-proposal /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/three-package-maintenance-proposal.json \
  --maintenance-proposal-sha256 a8f8cb9faf69f0fbb297ef9cc1f18cd15d3682efa494e1894b509536ddf419f3 \
  --output /home/gabe/Documents/ChatGPT/cachy-asahi-install-completion-20261114/work/supported-composition-20261114/three-package-maintenance-result
```

The output path is exclusive; repeat with a new one.

| Observation | Original policy | Explicit proposed policy |
| --- | --- | --- |
| Metadata status | FAIL | PASS |
| Policy blockers | Original five retained | Zero |
| Tentative packages / dependency relations | 626 /3202 | 626 /3202 |
| Python | Protected `3.14.7-1`; `3.14.8-1` target refused | Proposed `3.14.8-1` selected |
| Base changes permitted | None | Exactly the three named records |
| Original protected versions unchanged | 201/201 in the original diagnostic run | 200/201; only explicitly proposed Python differs |
| Proposed expected protected versions matched | Not applicable | 201/201 |

The proposed worker returns0/errno0 under libalpm16.0.1. Every original root and
provider remains satisfied in that proposed model; no fourth baseline change or
platform removal appears. CLI exit2 and overall HOLD/UNAPPROVED do not mean the
original policy passed or that this is an accepted maintenance transaction.

The report retains all original five blockers and original holds/26 catalog
exclusions. The proposed inventory separately retains 626 per-package acceptance
holds, including archive custody, signature authentication, corresponding source/
license/grant/maintainer review, installed payload/hooks/ABI/recovery and native/
hardware work. Python's catalog declaration is not substituted for an inspected,
authenticated native archive or its source/build provenance.

Retained local identities:

```text
three-package-maintenance-result/composition.json: 2672044 bytes
SHA-256 64f6c7419f602712ef783a30d5a190d9575b5bddf6bde20b9b4a97d1dee00bd4
proposed-maintenance/inventory.json: 1333961 bytes
SHA-256 3575118db3240a4a343490771eff536f0ded2231870f51c20c2d5a2bd0ba01d4
```

Both private DBs were removed; original/proposed worker DATA and diagnostics
remain. No network acquisition, package/recipe execution, installation, image
assembly, native dispatch or shared-policy mutation occurred.

## Verification and next gate

The original 12 composition controls still pass. Eight new real-libALPM synthetic
proposal controls pass: exact positive model with original failure retained,
unchanged default failure, wrong versions/reasons/extra changes, reference
binding mismatch, absent before identity, kernel/Mesa/audio target changes,
extra implicit baseline change, root-retarget and approval-flip refusal.
Synthetic fixtures are explicitly labeled and do not supply real package facts.

The resulting unapproved inventory is concrete input for reviewing this exact
coordinated maintenance set and preparing the existing transition/recovery
contract once real authenticated archive/signature/provenance and recovery assets
are supplied. ABI consumers, protected-platform update/recovery and actual
supported-machine behavior still need their own evidence. Source DATA success
cannot authorize a changed protected tuple, install/update, native acceptance,
production signing or either M2 model.

## November 25 offline selection and custody

The R132 transport recheck hashed all 753 files (653,469,760 bytes) against
manifest `08a1f949794b085158608c9577476574514fa963a8168554ca523c2242f35178`.
All 368 forward archive names, versions and runtime package metadata match
the pinned 626-package selection. Of those, 366 match vendor catalog archive
pins and 359 also match the catalog's embedded signature bytes. The seven
community archives use separately pinned detached signatures. The three
rollback pairs match their original archive join, including the signed
`.PKGINFO` hashes. All 371 pairs produce the expected cryptographic
`VALIDSIG`. The two project TEST certificates have expired. The current strict
signature check refuses them and a new rehearsal requires fresh scoped trust.
The four key fingerprints and raw verifier status are in the
[local readback receipt](#local-evidence-pins).

All five [Overlay Preview 1](../release/overlay-preview-1.md) archives match
the retained release checksums. Each archive's `.BUILDINFO` recipe hash
matches the bundled PKGBUILD and release provenance. The source bundle
contains all five license and notice pairs. The adapter joined each archive's
package identity and runtime relations to its retained SRCINFO.

| Profile | Libalpm metadata result | Final packages | Qt6 Base |
| --- | --- | ---: | --- |
| Preview 1 under original protection policy | FAIL with the same five blockers | 629 diagnostic | 6.12.0-3 in the private alternate catalog |
| Preview 1 with three proposed updates on the frozen catalogs | PASS, unapproved | 629 | 6.12.0-2, historical archive unavailable |
| Preview 1 with three proposed updates and the exact R132 Qt catalog alternative | PASS, unapproved | 629 | 6.12.0-3, archive SHA-256 `2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31` |

The last row has 371 proposed archive additions, zero removals and 3,213
dependency edges. It preserves all 201 versions expected by the proposal.
Compared with the installed R132 forward lock, First Login moves from
`0.1.0-2` to `0.1.0-3` and the Fish, Zsh and Hyprland settings packages join.
The other 625 shared package metadata rows match R132, including Setup8,
the Asahi graphics and audio stack and the three maintenance versions.

An explicit development variant swaps vendor `libfdk-aac 3.0.0-1` for
`cachy-asahi-fdk-aac 3.0.0-1`, archive SHA-256
`237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247`.
The project archive's BUILDINFO matches the current recipe, and its regular
license files include the complete classic and xHE notices. The variant
preserves the other 628 package metadata rows and all three proposed
maintenance changes. All three explicit provider pins resolve. PipeWire
uses the project package for `libfdk-aac` and `libfdk-aac.so=2-64`.
The variant remains unapproved. The exact project binary previously passed
the generic native ARM replacement and AAC-LC callback trial. Its TEST
certificate has since expired. A local pack and recipient reconstruction
verified all 25 recipe inputs, including the 900-file codec source packet.
The source bundle SHA-256 is
`577305d7575e23dfcf3d55fb6da7fdc53f4257b5f44390acaa35a5d2850ec631`.
[FDK provider trial](../validation/fdk-provider-native-20261015.md)

Release decisions still needed for this composition:

- Approve the exact three-version proposal and the reviewed Qt archive selection.
  Bind the new project set to a signed installation, recovery and installed
  Asahi kernel boot exercise.
- Hold vendor FDK for redistribution. Its archive includes both codec
  libraries with only the classic notice. If using the project FDK variant,
  finish recipient source delivery and applicable rights review, bind a fresh
  TEST signature, and exercise the provider on the selected Asahi system.
- Finish source and license review across the selected inventory, including
  the 258 unchanged inherited base packages and the two missing forward
  build-time recipes. `asahi-desktop-meta 4-10` requires
  `widevine 4.10.2891.0-1`, whose archive declares `custom` and includes a
  Widevine EULA. Review delivery from the vendor or an explicit profile
  change before including it in a project repository.
  [R132 recipe custody](supported-composition-update-sources.md)
- Preserve the Asahi audio and graphics owners and versions in the proposal.
  Audio source review, Mesa source correspondence, installed loader closure,
  production trust and physical boot, accelerated rendering, protected audio
  and failed-update recovery on both Air sizes remain open.

### Local evidence pins

Selection reports are under
`~/.cache/asahi-preview1-composition-20261125.cobdq0my/`. The archive readback
is under `~/.cache/asahi-r132-selection-recheck-20261125.6pmy5WWJ/`.
The FDK variant is under
`~/.cache/cachy-asahi-preview1-qt-fdk-provider-alpm-ffr8ubsm/`.

| Receipt | SHA-256 |
| --- | --- |
| `r132-transport.ACTUAL.json` | `020410486a6fddedec735c96229fc7b1fe530d684683a0c4ef0c8cde53653cae` |
| `preview1-archive-source-joins.ACTUAL.json` | `4517e48eb55f2077cba2be53536d42550965626f2fb59d494123d56a67e42b40` |
| `qt-alternative-preview1-selection.ACTUAL.json` | `aeb0536068e09140bbf577ee36beec960520ca4415f095c30d77379bc2302cfc` |
| FDK variant `comparison.DATA.json` | `62bb1911fbcd1f1aef194d2b54c4b82d1ebeb863d672b000aa635e11bc1730ab` |

## November 26 sign-free 629-package preflight

The exact 629-package profile with vendor Qt6 Base `6.12.0-3` has all 374
forward and reverse archive bodies in local custody. The readback rehashed the
original 753-file R132 transport and verified 366 forward and three reverse
vendor signatures with the existing guest signature predicate. All five Preview
archives matched the proposed inventory, the published checksums and the
retained synthetic staging bundle. Their `.PKGINFO` and `.BUILDINFO` matched
the expected package metadata and build records. All five detached signatures
verified with the retained staging TEST certificate. Setup `0.3.0-1` matches
the R132 archive bytes. First Login `0.1.0-3` requires its own signature over
the new archive bytes. [Local signed staging rehearsal](../validation/b08-b09-signed-staging-20261125.md)

Projected locks start from the same 261-package Asahi Minimal base. The
371 forward operands yield 629 packages. The three reverse operands restore
the original NetworkManager, Perl and Python versions with 629 packages still
present. The preflight did not apply either transaction. The receipt and
projected locks are under `~/.codex/evidence/asahi629-sign-free-preflight-Bhh1eY/`.
`archive-and-certificate-preflight.json` has SHA-256
`0ff4c9cb9679525c3aa982d9bfc06106c208f876ba6c07581fb0c12413e92793`.

An independent ownership preflight rehashed the five project archives,
369 vendor archives and the original raw Asahi seed. It checked 31 distinct
project payload leaves and their 21 ancestors against the exact archive
members, the seed's 261 ALPM file lists and read-only inode lookup. No project
leaf collided with an existing path, and every shared ancestor was a
directory. The five project archives contain no package install scripts or
ALPM hooks. The later guest trial covers vendor hooks and the resulting
filesystem.
The private `asahi629-ownership-preflight.uk5lcJES/receipt.json` has SHA-256
`6afb50be120c9bc831184b68c872210776560f0b371f760b6483ebdbf9dae686`.

The staging TEST certificate `3F31C957865CD10AF794C90D177CA1397E0C5806`
expires November 26 at 19:49:12 UTC. It had 1,019 seconds remaining at the
readback, short of the existing 5,820-second bind and run budget. The synthetic
staging release was withdrawn and its signing home was removed. The two
original R132 project TEST certificates are already expired. A stock R132
rerun needs fresh review and signatures for both original project roles.
At that point the 629 trial still needed current TEST signatures for all
five project archives, a separate binding and fresh one-use authority.
The existing runner selected the exact R132 626-package transaction.
The 629 preflight recorded **HOLD / UNAPPROVED**.

The retained R132 Asahi Minimal seed was rehashed from its compressed copy.
The historical generic control disk path was absent at readback. A generic
16 KiB guest trial also needs the exact control disk or a separately reviewed
replacement. This setup exercises the filesystem transaction and recovery.
[Historical control disk pin](../validation/arm16k-warm-second-boot-observation-20261116.md)

### Independent cold control and separate runner

A fresh cold control was assembled from the signed generic ARM64 inputs.
An independent readback verified the ext4 image and all 111 package
directories. A disposable snapshot over that exact read-only backing image
booted in offline QEMU, reported 16 KiB pages and completed serial PAM login
and logout with systemd, logind and D-Bus active. The raw control SHA-256 is
`825613f10f54f560f78fdd9829cecd93ef967c26e37d3a6f62dc260ec9028b1c`.
The private boot qualification receipt SHA-256 is
`3ca1f670b13a3fb4256c209cd392809fcfda730ef913351c0616d312e6e64bcb`.

The [629 rehearsal runner](../../scripts/install/asahi629_trial/README.md)
binds that independent boot receipt and the exact 629 transport. The
transaction uses the R132 generic kernel with PL031 RTC support and checks
that the RTC set the guest clock before accepting current TEST signatures.
An unissued 767-file transport with five fresh TEST signatures passed
whole-file verification. Its manifest SHA-256 is
`ca7589d52396699be5ba923cfbc0907d2f5e3bb41883adb4e9e555e30ba5755c`.
That transport was unissued.

### November 27 offline installation and reversal

The dedicated runner passed with a fresh TEST-only selection on the exact
Asahi Minimal seed in an offline emulated AArch64 16 KiB guest. The first
attempt stopped before boot after a private owner script overwrote its
container name while recording memory statistics. The exact unstarted
container was verified and retired. The successful retry used a fresh
binding, nonce and TEST certificate.

All five actual package and preview locks matched the selected locks. The
forward transaction went from 261 to 629 packages. ALPM recorded 368 new
installs and three upgrades. The reversal kept 629 packages, including all
five Preview packages, and changed exactly these versions.

| Package | Forward version | Restored version |
| --- | --- | --- |
| NetworkManager | `1.58.1-2` | `1.58.1-1` |
| Perl | `5.42.3-1` | `5.42.2-2` |
| Python | `3.14.8-1` | `3.14.7-1` |

All 362 protected boot and mount entries matched across baseline, forward
and reversal. The runner retained the forward hook's generated initramfs
and restored the exact original. The guest retired all three trust homes
and the target submounts. QEMU and the outer actor exited zero, the
independent observer confirmed both absent twice, and the original inputs
were reverified. The composition remains **UNAPPROVED**.

| Retained evidence | SHA-256 |
| --- | --- |
| Successful one-use transport manifest | `11959697e9dd4dcce85d1d7878504c57bf3a74e22b04649b9c2056028deda89a` |
| Guest result | `7acb1874ae50cd41910e3bc420e67afbb63147d93140ed7e482faa52e860987b` |
| ALPM log | `bf5981bbafd2882306e89c556f4e5c665d03d73192f89da770f8a715898bfe51` |
| Outer terminal receipt | `d32b162c363160e8a7f36794019cbf94b76ba45dcc91b843583660d450c85435` |

The installed stock Asahi kernel lacks the selected PL011 console and the
original initramfs lacks the VirtIO modules used by the R132 QEMU boot path.
Default boot with the stock initramfs, the Apple firmware path, and
physical M2 recovery remain open.
[R132 generic guest and stock boot evidence](../validation/asahi626-maintenance-emulated-arm16k-20261118.md)

### November 28 renewed-input transaction evidence

The TEST-signed Asahi629 forward and rollback commands both exited 0 with
renewed Preview inputs in an offline emulated AArch64 guest with 16 KiB
pages. The stopped export contained the exact 261 → 629 → 629 locks and
the same 362 protected paths at all three checkpoints. The rollback
inventory query and ALPM restoration check also exited 0.

The enclosing JBIG/TIFF trial held at its baseline runtime probe. The
installed GTK 4.24.1 SDK requires GIO 2.89.3 or newer, and the restored
inventory provides GIO 2.88.3. The retained GTK archive also requires
`g_markup_parse_context_get_attribute_position` and
`g_timeout_source_new_ns` through strong AArch64 relocations. The
authenticated GLib 2.88.3 archive lacks both exports. A compatible
GTK/GLib pair is required for full consumer qualification. Both scoped
provider transactions remain unrun. QEMU powered off normally and both
retirement scans were empty.
[JBIG/TIFF trial](../../scripts/integration/jbig_tiff_asahi629/README.md)
· [GLib markup API](https://docs.gtk.org/glib/method.MarkupParseContext.get_attribute_position.html)
· [GLib timeout API](https://docs.gtk.org/glib/func.timeout_source_new_ns.html)

| Retained evidence | SHA-256 |
| --- | --- |
| Exported guest result | `8eeb276879462a8a1d76f270d047ff8342fbf587639322b0a1cfecd8bff8c5e7` |
| Restored 629-package lock | `f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa` |
| Three protected-path snapshots | `b80e21324a84d747471f685887fba782d7c2effb5db3dcdcfff79b6988930ed2` |
| Outer HOLD receipt | `5ba27edeb4eeb3e219fd8b05e1ea2b198da42b6e2b41fee2dcdf703c9803af93` |
