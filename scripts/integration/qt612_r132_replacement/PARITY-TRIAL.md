# Asahi629 Qtbase parity trial design

The restored provider is ALARM's `qt6-base 6.12.0-3`. The replacement is
`cachy-asahi-qt612-gui-server-source-reference 6.12.0-4` from the source
projection in `f00d72cac36027b7d9804b5e5413ebfcb47ede42`. The existing
6.12.0-3 replacement remains a separate trial. Its 7,056-byte PASS receipt
has SHA-256 `8ee4c063ab5b34665b01fe56f5c1b5b9ff06eff44ea0cb261d2e53350e16f9a4`
and still verifies with the existing V1 reader.

The projected lock was calculated directly from the retained Asahi629 rollback
lock. All phases have 629 packages and the same other 628 rows. The installed
database must preserve the original provider's install reason and all 362
protected boot and mount entries.

| Phase | Qt package row | Lock bytes | SHA-256 |
| --- | --- | ---: | --- |
| Baseline and restoration | `qt6-base 6.12.0-3` | 12,346 | `f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa` |
| Replacement | `cachy-asahi-qt612-gui-server-source-reference 6.12.0-4` | 12,383 | `8df473640fc9713377f97a0b1900d09af629819fe293441cb124a99d8e80cb2a` |

`prepare.py` projects both directions with the explicit project version.
`transaction.py` uses the separate identities for installed package lookups,
signature-required ALPM loads, conflict answers, prepared add/remove lists
and checkpoint locks. `readback.py` can independently verify those locks,
the journal's prepare rows and the four package actions at the mixed versions.
These controls have inert coverage. The parity handoff, staged plan, guest
journal and stopped receipt bind one independently reviewed profile. The
historical V1 route retains its original input roles and receipt schema.

## Verified build on November 28

The explicit `parity` profile at `162429209eb90524d5a91733a70ce204086840f2`
completed one serial offline `makepkg` build on the 357-package Q3 build
root in emulated AArch64 with 16 KiB pages. The smoke test exercised
offscreen Qt Widgets painting and the local Wayland server display API.
The guest reported `PASS complete`. QEMU and the outer container exited
0, the exact container was absent on both scans, and the original inputs
verified unchanged. The build evidence set `qt629-parity-build-20261128`
retains `owner-retirement.INDEPENDENT.json` and the files below.
[Build source and readback procedure](../qt612_vulkan_md4c_successor/PARITY.md)

| Retained build evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| `cachy-asahi-qt612-gui-server-source-reference-6.12.0-4-aarch64.pkg.tar.xz` | 14,333,964 | `d78d8101fac9386f5d2fd2ecc620748ba476c3c94f3041b9487eeb8099617865` |
| `plan.json` | 58,421 | `23f3c3ab72b49ced5da17cb9aa810354c2b46a653b4bb114f3b160565eb5cc93` |
| `build-readback.json` | 36,049 | `d3c68f353ea3d4e8cb106eaaa8c744c11028fe67e593d875b29ca84802127e90` |

The plan and readback bind the same `parity` profile and source digest
`c65c07662f1b0206d15fc0556db2c7d2892f96705977650c67fc703d76f52e31`.
Stopped-disk readback verified the archive hash, `.BUILDINFO`, `.PKGINFO`,
all 5,164 `.MTREE` entries and 62 AArch64 ELF objects. Against the prior
project archive, it verified the exact 31 added files and the new
`printsupport` directory, with zero removals. It also verified retained
exports across all 18 Qt libraries, the AT-SPI bridge export and its
Wayland and XCB imports, CUPS and XCB EGL plugin linkage, and the
Vulkan/md4c ABI checks. [Independent archive reader](../qt612_vulkan_md4c_successor/arm16k_readback.py)

## Reviewed profile inputs

Create a canonical JSON profile using `C.wire` from `prepare.py`. Preserve
the exact allowed fields below. Every pin is an object with integer
`bytes` and lowercase hexadecimal `sha256`.

| Field | Required value |
| --- | --- |
| `kind` | `QT612_ASAHI629_REVIEWED_PARITY_PROFILE_V1` |
| `official_version` | `6.12.0-3` |
| `project_version` | `6.12.0-4` |
| `recipe` | Retained `PARITY.UNISSUED.json`, 4,460 bytes and SHA-256 `0fc98bc3f5556b96012efa230d97f5eace3046c0f42984f9fc562040a7af0364` |
| `project_archive` | Retained unsigned `-4` archive pinned above |
| `build_plan` | Original sealed full-build `plan.json` pinned above |
| `build_receipt` | Canonical independent `build-readback.json` pinned above |
| `abi_comparison` | Fresh signed-629 consumer audit saved as `comparison.json`, binding the `-4` archive, official archive and rollback lock |
| `alpm_prepare` | Fresh mixed-version forward and reverse prepare-only transcript saved as `alpm-prepare.txt` |
| `test_review` | `signature` and `certificate` pins, uppercase 40-hex primary `fingerprint`, and integer UNIX `not_before` and `not_after` for the fresh TEST certificate |

For `prepare.py` use the same arguments as for the historical handoff, with
`--profile` and `--profile-sha256`. In `--recovery`, retain the new
archive under its full package filename next to `plan.json`,
`build-readback.json` and `PARITY.UNISSUED.json`. In `--audit`, supply
`comparison.json` and `alpm-prepare.txt`. Keep the existing official archive,
original adjacent ALARM signature, ALARM public key and Asahi629 rollback
operands.

For `controller.py`, add `--profile`, `--profile-sha256`,
`--test-signature`, `--test-certificate`, `--reviewed-source-pins` and
`--reviewed-source-pins-sha256` to the retained controller arguments,
including the reviewed Weston intake path and digest. The reviewed source
pins file is the canonical path-to-pin map from
`controller.source_selection(qt_source)` after review of the selected
checkout. The launch authority continues to select the exact new preparation
digest using the existing launch contract. No authority is issued by
preparation. The new receipt kind is `QT612_ASAHI629_PARITY_SCOPED_RECEIPT_V1`.
Read it with `readback.py --bundle`, `--receipt-sha256`, `--profile` and
`--profile-sha256` using the separately retained reviewed profile.
The parity receipt adds the `guest_plan`, `stopped_disk`,
`stopped_observation` and `asahi_owner` pins. Public readback checks the
original plan, observation and owner JSON bodies. The owner must identify
the same plan and nonce, baseline lock, protected state, trust retirement
time and completed Qt journal. Its cleanup digest must match the canonical
cleanup facts in the stopped observation. The stopped observation supplies the
digest of the result disk reviewed by the exporter.

## Compare the candidate on Asahi629

Compare the exact candidate against both audited 6.12.0-3 archives.
Require normal dependency resolution and forward and reverse prepare-only
transactions against the untouched 629-package database. Recompute the ABI
scan against the retained consumer set and verify package ownership,
SONAMEs, versioned and unversioned references, and the expected additions.
Record fresh comparison and ALPM transcript pins. Replacement adds project
`6.12.0-4` and removes official `6.12.0-3`. Restoration does the inverse.

## Stage and independently verify a fresh trial

1. In `prepare.py`, the parity handoff reviews the exact candidate archive,
   new build seal, ABI comparison and prepare-only transcript. It checks the
   official version and original archive, adjacent
   ALARM signature, certificate, rollback lock, retired predecessor and
   R132 pins against the existing records. Check the candidate's own
   `.PKGINFO` for the project name, version, AArch64, explicit conflict and
   bare `qt6-base` provision. Join each record to the same exact candidate
   archive. The verified archive fits the 16 MiB media cap. Verify the
   same limit across packing, guest rehash and stopped export.
2. TEST-sign only the independently accepted `-4` archive. Stage a fresh
   detached signature and public certificate with pinned bytes, primary
   fingerprint and validity bounds. Require a signer distinct from the
   vendor and Asahi Preview keys and enough validity for the preparation and
   launch allowance. Keep the official identical ALARM-signed reversal
   operand. Verify both archive/signature pairs before the first commit and
   require `Required TrustedOnly` in libalpm.
3. `controller.py`, `host_stage.py`, `launch.py` and `guest_entry.py`
   carry the same reviewed parity profile from the handoff into the guest
   plan. They build the exact media allowlist from its two archive names and
   adjacent signatures. Verify the named project archive and signature
   together at host staging, launch derivation and guest intake. Bind the
   profile and source closure in a fresh unissued preparation and separately
   issued launch authority. Use a fresh nonce, writable clone, result disk,
   isolated keyrings, and output directory. Pass the validated project
   version to both the transaction's backend and its checkpoint projection.
4. `export.py`, `receipt.py` and `readback.py` use a distinct parity
   receipt kind and exact role set that bind the selected profile, both
   archive/signature identities, the new build and ABI evidence, three
   observed inventory locks, both ALPM commit boundaries, and the stopped
   disk and process-retirement observations. The reader must compare those
   inputs to the independently selected profile before validating the
   mixed-version journal, exact `pacman.log` actions and byte-identical
   official restoration. Keep the V1 schema and historical packet intact.
5. This scoped receipt covers the existing ordinary-user vendor/project
   offscreen and Weston software checks and the inventory reversal. Before
   broader runtime parity acceptance, rerun those checks after restoration
   and retain distinct phase evidence. Add bounded ordinary-user
   probes for the Hyprland screen-sharing picker's portal and AT-SPI roles
   and focus, a private CUPS queue that receives a print job, and a
   rendered XWayland frame with the forced EGL integration plugin. Also
   check automatic XCB selection with GLX available. A scoped software swap
   result and runtime parity require their respective observations.

TEST signing, the mixed-version Asahi629 installation and restoration,
and installed provider parity remain open. Physical validation on both M2
Air sizes also remains open.
