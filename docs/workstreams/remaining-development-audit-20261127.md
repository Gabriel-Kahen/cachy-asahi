# Remaining development audit, November 27, 2026

Audited [draft PR #625](https://github.com/Gabriel-Kahen/cachy-asahi/pull/625)
at `db7acf84f8e3205b5812c101480d9d3bcafcd544` against the [roadmap](../roadmap.md),
[package inventory](../../manifests/packages.toml) and [acceptance matrix](../acceptance.md).

## Next engineering work

1. **Verify the full-port APT fix on the current PR head.** The change restricts
   APT to the runner's signed Ubuntu sources for the security, support and
   orphans component prerequisites. The exact-head full-port run was queued,
   and its selector was the only job GitHub had listed at the time of review.
   Check the affected matrix jobs under both Python versions once they run.
   For CI efficiency, distinguish runner queue time from prerequisite setup
   time before tuning either. An earlier successful full-matrix run contained
   50 component jobs plus the selector. The selector already narrows reviewed
   changes and deliberately keeps a full fallback for common or unknown paths.
   [Exact-head run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/46055216134)
   · [Earlier full-matrix run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45936750153)
   · [Selector](../../scripts/ci/component_selection/select.py)
2. **Finish the signed Qt provider replacement on the exact Asahi629 rollback
   inventory.** The project Qtbase 6.12.0-3 archive was recovered and verified
   from the retired ARM16K build. The build guest recorded HOLD during its final
   census/export because boot-side `cmp` was missing. The source has a hashing
   fix, and the recovered archive is available for the next trial. The unissued
   handoff binds the archive, original official signature, rollback inventory,
   passive audit of 145 consumer objects and prepare-only ALPM output. Finish the
   runner and independent readback, then use a fresh TEST signature for the
   scoped swap and restoration. Check installed ownership, the ordinary-user
   Qt Quick, Wayland and Vulkan paths, and which of the 22 omitted vendor
   plugins affect the selected desktop. Require exact restoration of official
   Qt and preservation of the other 628 package rows.
   [Recovered build](../../scripts/integration/qt612_vulkan_md4c_successor/README.md#november-27-build-and-offline-package-recovery)
   · [Replacement input handoff](../../scripts/integration/qt612_r132_replacement/README.md)

   Follow-up: the first vendor-control guest held before the swap because
   Qt's QML loader needed directory enumeration; its stopped disk restored
   the original Asahi629 lock. The corrected fresh-nonce guest then passed
   signed one-provider replacement and restoration, ordinary-user vendor and
   project Core/Gui, Qt Quick, Wayland and Lavapipe/QRhi software probes,
   independent readback and owned retirement. Its 629-package final lock,
   628 untouched rows and 362 protected paths matched. There was no
   post-restoration runtime probe. A follow-up package audit found that the
   22 omitted plugins do not block the tested default Hyprland software path,
   but the project configuration disables Qt's AT-SPI bridge and omits native
   CUPS printing and XWayland EGL fallback. The selected screen-sharing picker
   still needs a real portal and accessibility check; physical M2 GPU and
   DRM/KMS remain **NOT RUN**.
   [Scoped result](../../scripts/integration/qt612_r132_replacement/README.md#corrected-scoped-guest-trial-november-27)
3. **Fix two independently reproduced package preflight defects.** These are
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
4. **Requalify the hosted repository handoff after the callback state fix.**
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
5. **Prepare the next Asahi-specific consumers and reconcile source custody.**
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
   at original, project and restored checkpoints. Neither the trial nor an
   installed runtime probe has run. The exact Python 3.14.8-1 and Perl
   5.42.3-1 PKGBUILD hashes in their signed `.BUILDINFO` still differ from the
   public exact-version recipes; the current ALARM workunit URLs now serve
   newer versions. Exact original recipe bytes remain unrecovered.

## Qualification already recorded

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
