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
These controls have inert coverage. The current controller, guest entry and
public receipt reader still admit the original V1 operands only.

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

1. In `prepare.py`, add a distinct parity handoff kind and review the
   exact candidate archive, new build seal, ABI comparison and prepare-only
   transcript. Check the official version and original archive, adjacent
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
3. In `controller.py`, `host_stage.py`, `launch.py` and `guest_entry.py`,
   carry the same reviewed parity profile from the handoff into the guest
   plan. Build the exact media allowlist from its two archive names and
   adjacent signatures. Verify the named project archive and signature
   together at host staging, launch derivation and guest intake. Bind the
   profile and source closure in a fresh unissued preparation and separately
   issued launch authority. Use a fresh nonce, writable clone, result disk,
   isolated keyrings, and output directory. Pass the validated project
   version to both the transaction's backend and its checkpoint projection.
4. In `export.py`, `receipt.py` and `readback.py`, add a distinct parity
   receipt kind and exact role set that bind the selected profile, both
   archive/signature identities, the new build and ABI evidence, three
   observed inventory locks, both ALPM commit boundaries, and the stopped
   disk and process-retirement observations. The reader must compare those
   inputs to the independently selected profile before validating the
   mixed-version journal, exact `pacman.log` actions and byte-identical
   official restoration. Keep the V1 schema and historical packet intact.
5. Run the existing ordinary-user vendor/project offscreen and Weston
   software checks, then rerun them after restoration and retain distinct
   phase evidence. To claim runtime parity, add bounded ordinary-user
   probes for the Hyprland screen-sharing picker's portal and AT-SPI roles
   and focus, a private CUPS queue that receives a print job, and a
   rendered XWayland frame with the forced EGL integration plugin. Also
   check automatic XCB selection with GLX available. A scoped software swap
   result and runtime parity require their respective observations.

The `-4` build, archive acceptance, TEST signing, guest trial and runtime
parity are pending.
