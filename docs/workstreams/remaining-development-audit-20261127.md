# Remaining development audit, November 27, 2026

Audited [draft PR #625](https://github.com/Gabriel-Kahen/cachy-asahi/pull/625)
at `db7acf84f8e3205b5812c101480d9d3bcafcd544` against the [roadmap](../roadmap.md),
[package inventory](../../manifests/packages.toml) and [acceptance matrix](../acceptance.md).

## Next engineering work

1. **Qualify Qtbase 6.12.0-4 on the exact Asahi629 rollback inventory.**
   The project Qtbase 6.12.0-3 archive was recovered and verified
   from the retired ARM16K build. The build guest recorded HOLD during its final
   census/export because boot-side `cmp` was missing. The source gained a
   hashing fix. The initial handoff bound the recovered archive, original
   official signature, rollback inventory, passive audit of 145 consumer
   objects and prepare-only ALPM output.
   [Recovered build](../../scripts/integration/qt612_vulkan_md4c_successor/README.md#november-27-build-and-offline-package-recovery)
   · [Replacement input handoff](../../scripts/integration/qt612_r132_replacement/README.md)

   Follow-up: the first vendor-control guest held before the swap because
   Qt's QML loader needed directory enumeration; its stopped disk restored
   the original Asahi629 lock. The corrected fresh-nonce guest then passed
   signed one-provider replacement and restoration, ordinary-user vendor and
   project Core/Gui, Qt Quick, Wayland and Lavapipe/QRhi software probes,
   independent readback and owned retirement. Its 629-package final lock,
   628 untouched rows and 362 protected paths matched. The Wayland probes
   used headless Weston/Pixman, and the Vulkan probes used Lavapipe.
   Runtime probes ran before and during replacement. Post-restoration
   runtime remains untested. The package audit found 22 omitted vendor
   plugins. The project configuration disables Qt's AT-SPI bridge and
   omits native CUPS printing and XWayland EGL fallback.
   The selected Hyprland screen-sharing picker still needs a real portal
   and accessibility check. Physical M2 GPU and DRM/KMS remain **NOT RUN**.
   [Scoped result](../../scripts/integration/qt612_r132_replacement/README.md#corrected-scoped-guest-trial-november-27)

   The parity follow-up has source-prepared Qt 6.12.0-4 controls for AT-SPI,
   CUPS and XWayland EGL. A cold AArch64/16 KiB build stopped at Ninja step 50
   and the launch receipt records SIGTERM. Its original plan also lacks the
   source seal required for admission. This run is a diagnostic HOLD. A
   fresh, explicitly sealed parity build started. Archive acceptance and
   the mixed-version replacement trial remain pending. The 6.12.0-3 result
   is the only Asahi629 Qt provider-swap PASS.
   [Parity recipe](../../scripts/integration/qt612_vulkan_md4c_successor/PARITY.md)
   · [Trial contract](../../scripts/integration/qt612_r132_replacement/PARITY-TRIAL.md)
2. **Fix two independently reproduced package preflight defects.** These are
   source work and can proceed alongside the hosted and guest jobs.
   - `recipe-check` returned exit 0 and `static-pass` from a directory with a
     valid `.SRCINFO` and no recipe file. Both a missing `PKGBUILD` and a missing
     arbitrary filename passed, with `.SRCINFO` as the only hashed input. The
     staged Build Tools v2 launcher reproduced the missing `PKGBUILD` result.
     The checker needs to require the explicitly supplied recipe as a regular,
     hashed input before selecting metadata. Verify both `.SRCINFO` and literal
     recipe paths. The standalone v2 checker and both Build Tools package
     copies were byte-identical, so an installed-command fix needs the package
     source pin and checksums updated through the existing provenance path.
     The original checker has the same metadata branch.
     [Versioned checker](../../scripts/checks/package_checks_v2.py#L156)
     · [Original checker](../../scripts/checks/package_checks.py#L102)
     · [Installed v2 source pin](../../packages/tools/cachy-asahi-build-tools-v2/source-provenance.json#L122)
   - The dependency planner reported `conflicts intersects inventory/overlay`
     for a sole selected package that both provides and conflicts with the
     same virtual name. The recorded origin already identifies the selected
     package. Exclude that origin when checking intersections while preserving
     real matches against repository providers and other selected packages.
     Test the no-competitor and competing-provider cases together.
     [Dependency planner](../../scripts/checks/dependencies.py#L72)
   The follow-up source fixes now require the named regular recipe and ignore
   a selected package's own conflict provision. Both Build Tools recipes were
   advanced to `0.1.1-2` and `0.2.0-2`; unsigned x86_64 host archives and
   source receipts are retained under
   `/home/gabe/.codex/evidence/build-tools-declared-sources-20261127-281lrtcu`.
   Both corrected `-2` releases subsequently passed two byte-identical
   native ARM4K builds, their 8 or 11 package checks, TEST-signed disposable
   installation and removal, exact 349 → 350 → 349 inventory restoration and
   independent reader replay. The exact hosted runs are
   [0.1.1-2](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46077326937)
   and [0.2.0-2](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46077329221).
   Native 16 KiB and physical M2 remain **NOT RUN**; release admission remains
   **NOT ADMITTED**. The prior `-1` native receipts remain historical. Both
   package READMEs are frozen inside the qualified archives and describe the
   pre-run status. This manifest and the exact native receipts record the later
   qualification; changing the installed README would require a new package
   build and qualification.
3. **Requalify the hosted repository handoff after the callback state fix.**
   Run the corrected composed lane on the authenticated retained inputs. The
   prior hosted attempt exercised generic AArch64 QEMU, produced and retired
   the desktop session, passed signed repository transactions and ARM C01,
   then failed downstream. The later diagnostic identified an extra field on
   the controller before the public receiver. The source fix bounds that field's
   lifetime. Exact-head source controls passed, while the corrected composed
   execution still needs a terminal result from the repository receiver. The
   existing actual workflow is bound to a dedicated push branch and an exact
   registered plan, so use that lane with the corrected Source and Data pins.
   [Desktop and repository evidence](virtual-desktop-completion-v2-admission.md#hosted-execution)
   · [Actual workflow entry](https://github.com/Gabriel-Kahen/cachy-asahi/blob/9aab573388a5ec30095965241b90f43eedba0fa8/.github/workflows/maintained-composed-virtual-desktop-v2-retained.yml)
   · [Exact-head source controls](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46055211894)
4. **Prepare the next Asahi-specific consumers and reconcile source custody.**
   Audit JBIG/TIFF consumers against the exact selected Asahi package set and
   use the result to scope an emulated ARM16K signed replacement/restoration.
   Then bind the updater's coordinated platform update and recovery cases to
   that chosen composition. For source custody, obtain exact ALARM workunits
   or final `PKGBUILD` bytes for Python 3.14.8-1 and Perl 5.42.3-1, and check
   them against the signed `.BUILDINFO` hashes. If the exact inputs stay
   unavailable, any replacement needs its own provenance and qualification.
   [JBIG/TIFF remaining scope](../validation/project-libraries-native-20261125.md#remaining-qualification)
   · [Updater guest evidence](../validation/updater-q3-emulated-arm16k-20261126.md)
   · [Recipe intake and expected hashes](../../scripts/port/supported-composition/README.md#recover-signed-maintenance-recipes)

   A subsequent read-only audit of the exact Asahi629 rollback set found seven
   direct `libtiff.so.6` consumer objects in `lcms2`, `gtk4`, `openjpeg2` and
   `spandsp`. Their 84 versioned imports match the retained project TIFF
   exports, and the retained two-package JBIG/TIFF pair passed prepare-only
   forward and reverse dependency checks. The project TIFF recipe omits
   `tiffgt`, which the original Asahi629 provider supplies; the signed guest
   trial must account for that package-parity gap and check all four consumers
   at original, project and restored checkpoints. The signed pair swap and
   its installed consumer probes remain **NOT RUN**. The exact Python 3.14.8-1
   and Perl 5.42.3-1 PKGBUILD hashes in their signed `.BUILDINFO` still differ
   from the public exact-version recipes. The current ALARM workunit URLs
   now serve newer versions. Exact original recipe bytes remain unrecovered.

   A corrected project TIFF 4.7.2-1.2 unsigned AArch64 archive passed a
   Minimal206 QEMU user-mode build, three package tests and independent
   archive audit. It restores `libjpeg.so=8-64` and matches the retained TIFF
   shared libraries. Its 861,952-byte SHA-256 is
   `f6df34ab9ddd3496407a9dd4707abd44a2270a3abbd3fe6e27862db4dda59e4f`.
   A distinct TEST-signed two-package Asahi629 packet passed independent
   signature and prepare-only ALPM readback. Its first issued actor stopped
   **before QEMU boot** when host memory PSI exceeded its 3% guard; no guest
   package transaction ran. The scoped retry source requires copy-on-write
   reflinks for its two disposable image clones and records cache/writeback
   telemetry. A resealed, fresh-nonce packet passed independent admission and
   signature review. Both reflinks succeeded and its AArch64/16 KiB guest
   booted, but candidate validation raised `IndexError: 2` because
   `jpeg_recipe.py` assumed a repository parent absent at `/trial-code`.
   The guest reported **HOLD_ASAHI629_JBIG_TIFF_ENTRY** before the pair's ALPM
   transaction. Independent stopped-disk readback found the exact original
   629-package lock and all 362 protected paths. The replacement lock with
   627 unchanged rows was verified as a projection only. The actor retired
   with zero swap and no OOM events. The host pressure guard stopped
   controller readback after QEMU exited. The path fix is integrated and
   passes an exact guest-layout regression. The next fresh-nonce actor
   stopped **before QEMU boot** at the unchanged 6 GiB cgroup limit.
   Its file cache reached about 5.97 GiB while rehashing the control-root
   clone after earlier pinned reads. No pair transaction ran. Actor swap
   and OOM stayed zero, and ownership retired.
   A scoped, fail-closed reader now rehashes the exact pinned originals and
   owned clones in 1 MiB chunks with cache-discard advice. It preserves the
   byte, size and file-identity checks and leaves the generic controller
   unchanged. All 50 lane tests and a bounded Btrfs probe passed. A full
   **cold no-guest replay** then passed preboot and post-QEMU verification with
   a hard QEMU denial, 3.56 GiB peak actor memory, 2.44 GiB headroom, and zero
   limit, swap or OOM events. Independent readback confirmed the result.
   **Warm replay remains NOT RUN**: one attempt refused before actor creation
   and another after creation but before start when live admission could not
   be maintained. No later guest pair transaction has run.
   [Trial runbook](../../scripts/integration/jbig_tiff_asahi629/README.md)

   A separate refreshed Preview TEST public transport passed independent
   verification of 767 payload pins, five archive bodies and signatures,
   mismatch refusal, and unchanged vendor and lock bytes. Its admission
   runway extends to November 28 at 7:33:54 a.m. Eastern. A bounded scoped
   stage attempt stopped at the 3% sustained host PSI guard after writing
   inputs but before publishing either manifest; it issued no authority.
   The retained samples show worker reclaim, but do not identify which
   preflight command caused the host spike. A source-only follow-up adds
   phase and file/anonymous-memory records, uses cache advice for digest-only
   Preview reads, and confines public GPG checks to the worker runtime. Its
   63 lane tests and small guarded probe passed; full refreshed staging and
   new cold/warm replays remain **NOT RUN**.

   A lock-to-manifest reconciliation found four of the 14
   development-selected project packages in Asahi629, plus First Login
   0.1.0-3. The other ten were outside this bounded Preview composition;
   updater integration and the project FDK provider still need their own
   selected trials. The manifest now records the exact First Login v3 and
   Zsh installation evidence while keeping First Login outside the
   development selection until its graphical journey is checked.

   Static now registers the existing signed installer handoff and Bubblewrap
   relocation suites alongside the base handoff suite. All 28 tests passed
   locally under Python 3.12 and 3.14, including two real Bubblewrap cases.
   The exact-head hosted run passed all 28 and restored its temporary runner
   setting. A separate offline Asahi629
   updater preflight verifies the exact 629-row before, candidate and recovery
   locks and six signed ALARM archive pairs. It remains **HOLD** because the
   updater-equipped inventory, lane-specific trust, signed repositories,
   protected Apple transition and boot/session recovery inputs are unselected.
   Its 47 input, updater-policy and platform-transition controls passed.
   [Updater preflight](../../scripts/update/ASAHI629_PREFLIGHT.md)

## Qualification already recorded

- **Full Port APT fix.** The fix restricts prerequisite downloads to the
  hosted runner's signed Ubuntu sources. The original run at `db7acf84f`
  and the later PR run at `fb862ffea` both passed all 51 jobs, including
  the signed-source prerequisite steps under Python 3.12 and 3.14. The
  latter PR head finished with 302 passing checks and one skipped cache-seed
  job. The selector narrows reviewed changes and keeps a full fallback
  for common or unknown paths.
  [Original run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46055216134)
  · [Reverification](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46098927295)
  · [Selector](../../scripts/ci/component_selection/select.py)
- **Asahi629** passed TEST-signed forward and reversal on the exact Asahi
  Minimal filesystem copy under emulated AArch64 with 16 KiB pages and a
  generic R132 kernel. The actual inventories were 261 → 629 → 629, the three
  prior versions returned, and 362 protected boot and mount entries matched.
  The composition is unapproved. Reserve the next guest run for a new provider
  or update scope. [Installation and reversal](supported-composition-maintenance.md#november-27-offline-installation-and-reversal)
- **Issue [#622](https://github.com/Gabriel-Kahen/cachy-asahi/issues/622)** was
  open. At `f113b1347ae4ac1cd0f976e6206bbff70497b777`, the independently
  audited maintained 341-package baseline produced two identical native
  AArch64 4 KiB archives per library. The signed swap and restoration passed
  with unchanged `tificc` and a TIFF/JBIG roundtrip at each checkpoint. The
  earlier Minimal206 fresh lifecycle and legacy replacement also passed at
  their own revisions. Update the issue with these passes and the residual
  Asahi consumer, physical and distribution scope. Repeating the maintained
  build and migration adds no coverage with the same inputs.
  [Maintained input audit](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45822018823)
  · [Maintained build and migration](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45822448301)
  · [Earlier Minimal206 lanes](../validation/project-libraries-native-20261125.md)
- **Issue [#623](https://github.com/Gabriel-Kahen/cachy-asahi/issues/623)** was
  open. At `4e5493cbd384feaae027abb476437c90b7c07cba`, the hosted native
  AArch64 baseline and candidate builds, output verification and run-owned
  cleanup passed. The publication is status and receipt metadata. A future
  boot or installation exercise needs a retained, authenticated output or a
  dedicated build that supplies one. Update the issue with the build pass and
  the explicit outstanding boot scope.
  [Kernel build pair](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45784522085)
  · [Implementation status](../implementation-status.md)

## Physical and release gates

The stock Asahi kernel reached installed systemd with an auxiliary initramfs.
The retained seed lacks the EFI volume for the default-boot rehearsal. The
stock kernel and original initramfs also lack capabilities used by the generic
QEMU control. Physical Apple boot, the original initramfs path and actual
boot/session recovery still need evidence. Both the 13-inch J413 and 15-inch
J415 remain **NOT RUN**. Baselines, desktop, installation, coordinated update,
boot recovery and performance need exact-machine records for each.
[Stock boot evidence](../validation/asahi626-maintenance-emulated-arm16k-20261118.md#direct-stock-kernel-boot-with-an-auxiliary-initramfs)
· [13-inch](../validation/m2-air-13.md) · [15-inch](../validation/m2-air-15.md)

Release still requires a reviewed supported composition, complete corresponding
source and distribution review, production signing custody, a repository host
and accountable ongoing maintenance. Overlay Preview 1 remains a five-package
preview. Full-port signoff also needs the integrated release and a subsequent
stable release run through the same lifecycle. [Release contract](../release/interface.md#stable-gate-envelope-version-1)
· [Full-port milestones](../roadmap.md#full-arm-port-m5m9)
