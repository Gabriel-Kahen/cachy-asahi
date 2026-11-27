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

## Inputs to supply after an accepted build

Create a canonical JSON profile using `C.wire` from `prepare.py`. Preserve
the exact allowed fields below. Every pin is an object with integer
`bytes` and lowercase hexadecimal `sha256`.

| Field | Required value |
| --- | --- |
| `kind` | `QT612_ASAHI629_REVIEWED_PARITY_PROFILE_V1` |
| `official_version` | `6.12.0-3` |
| `project_version` | `6.12.0-4` |
| `recipe` | 4,460 bytes and SHA-256 `0fc98bc3f5556b96012efa230d97f5eace3046c0f42984f9fc562040a7af0364` |
| `project_archive` | Pinned unsigned `-4` archive exported by independent ARM16K build readback |
| `build_plan` | Original sealed ARM16K full-build `plan.json` |
| `build_receipt` | Canonical independent full-build readback stdout saved as `build-readback.json` |
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

## Seal the candidate archive

1. Give the parity build its own authenticated-input profile. In
   `../qt612_vulkan_md4c_successor/arm16k_inputs.py`, bind the canonical
   `PARITY.UNISSUED.json` instead of the predecessor recipe receipt for that
   profile. A clean source projection at `f00d72cac` produced 4,460 bytes
   with SHA-256 `0fc98bc3f5556b96012efa230d97f5eace3046c0f42984f9fc562040a7af0364`.
   Join the upstream, recipe and dependency pins to the new plan. Verify the
   original ALARM-signed CUPS and AT-SPI inputs against the recipe and the
   exact Q3 lock before normal dependency resolution. The Asahi629 lock
   already has `libcups 2:2.4.20-1` and `at-spi2-core 2.62.1-1`. Keep
   the original md4c and Vulkan header update and leave the build lock
   formula unchanged if the signed Q3 inventory confirms those two parity
   dependencies are already present.
2. In `arm16k-build.sh`, `arm16k-guest-init.sh` and `arm16k_readback.py`,
   bind the new profile to
   `cachy-asahi-qt612-gui-server-source-reference-6.12.0-4-aarch64.pkg.tar.xz`.
   Seal a fresh ARM64/16 KiB plan and build with the existing offline serial
   makepkg policy. Verify the retired archive's metadata, stage inventory,
   content hashes, QtGui AT-SPI bridge, CUPS and XCB EGL plugin linkage,
   retained Vulkan/md4c checks, and all 31 expected added paths. Bind the
   result to the new recipe, build nonce and natural retirement receipt.
   Use the full archive audit report from `162429209eb` with `mtree`,
   `path_delta`, `libraries` and `atspi_bridge_abi`. The replacement
   reader requires explicit `profile: parity` and `source_sha256` in both
   the build plan and the independent readback. It recomputes the source
   digest over the profile, payload, launcher and actor pins. A historical
   parity build plan that predates the explicit seal does not qualify.
   Keep the historical recovery seal with the earlier archive.
3. Compare the exact candidate to both audited 6.12.0-3 archives. Require
   normal dependency resolution and the forward and reverse prepare-only
   transactions against the untouched 629 database. Recompute the ABI scan
   against the retained consumer set and verify package ownership, SONAMEs,
   versioned and unversioned references, and expected additions. Record fresh
   comparison and ALPM transcript pins. In the transcript, replacement adds
   project `6.12.0-4` and removes official `6.12.0-3`. Restoration does
   the inverse.

## Stage and independently verify a fresh trial

1. In `prepare.py`, the parity handoff reviews the exact candidate archive,
   new build seal, ABI comparison and prepare-only transcript. It checks the
   official version and original archive, adjacent
   ALARM signature, certificate, rollback lock, retired predecessor and
   R132 pins against the existing records. Check the candidate's own
   `.PKGINFO` for the project name, version, AArch64, explicit conflict and
   bare `qt6-base` provision. Join each record to the same exact candidate
   archive. Measure its size before reusing the 16 MiB media cap. Any
   required higher ceiling must be finite and consistent across packing,
   guest rehash and stopped export.
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

The `-4` build, archive acceptance, TEST signing, guest trial and runtime
parity are pending.
