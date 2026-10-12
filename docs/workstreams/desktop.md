# Desktop workstream report

October 11, 2026. Exclusive implementation paths: `packages/desktop/`,
`docs/audits/desktop.md`, and this report. No shared manifest, Git state, or
other worker's files were changed. No host package/dependency installation,
service activation, compositor session launch, or protected-stack change.

**Result:** thorough M0 source audit and M1 source implementation delivered.
One original opt-in desktop recipe is frozen for coordinator selection.
Two final-input **existing x86_64 host packaging runs** succeeded. Clean native
ARM builds, real dependency transactions, installation and exact M2 hardware
checks remain **NOT RUN**. No milestone or performance gain is claimed.

## Coordinator integration proposal

- Preserve the original `cachyos-hyprland-settings` candidate as deferred, with
  pinned CachyOS recipe commit `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f` and
  settings commit `449635e3718f4f178503682b29b159b0a758e5e7` (tag `1.4.4`).
  Reasons: incomplete license evidence, unresolved CachyOS/AUR dependency set,
  PC assumptions, broad configuration ownership, and v0.56.2 parser failures.
- Add `cachy-asahi-hyprland-settings`, recipe
  `packages/desktop/cachy-asahi-hyprland-settings/PKGBUILD`, version `0.1.0-1`,
  `arch=any` (seven text files), status `source-implemented` or equivalent.
  Record required runtime/build/optional dependencies from its reviewed
  `.SRCINFO`, provenance audit, and actual **host packaging** evidence separately
  from native ARM build state. Do not mark it selected for stable publication.
- Compatibility proposal: existing base Hyprland `>=0.56.2`, `<0.57.0`, audited
  against v0.56.2 commit `efb50993780079460b0cbed1363e2166a2de1d9f`.
  Dependencies must resolve while preserving the actual Asahi graphics/audio/
  kernel/boot stack; otherwise defer. This is not a tested machine compatibility set.
- Original material is MIT, following the coordinator's root license decision.
  Local packaged `LICENSE` matches root bytes, SHA-256 `51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7`.
  Excluded upstream CachyOS assets remain outside that grant.

The coordinator owns actual manifest reconciliation, source revision pinning to
its integration commit, release selection, and hardware/build resource decisions.
This worker proposes no additional desktop recipes in the initial set.

## Delivered implementation

- [Audit](../audits/desktop.md): exact upstream commits/archive checksums,
  GPL declaration versus missing asset grants, complete upstream dependency
  inventory, installed paths and skel/profile effects, session commands,
  PC assumptions, modern syntax failure evidence, version/base gates.
- [Original recipe](../../packages/desktop/cachy-asahi-hyprland-settings/PKGBUILD)
  and reviewed `.SRCINFO`: fixed local SHA-256 inputs; no floating downloads,
  platform hooks, service files, skel/profile/home writes, or binaries.
- [Lua template](../../packages/desktop/cachy-asahi-hyprland-settings/hyprland.lua):
  auto panel mode/scale, small touchpad settings, Command/SUPER keyboard/window
  controls, explicit Swaylock binding, existing WirePlumber volume routing,
  backlight-class brightness. No GPU backend override, ALSA Master manipulation,
  power policy, automated session logout, or destructive gestures.
- Optional original Waybar/Mako templates: display-only bar; no weather/network
  requests, updates, external helper scripts, icon-font requirement, or fixed
  PC device name. Startup is commented out to require base-session reconciliation.
- [Package guide](../../packages/desktop/cachy-asahi-hyprland-settings/README.md):
  explicit new user copy, version gate, base session-manager/portal/polkit checks,
  optional startup review, package upgrades, user-copy preservation and removal.
- [Inventory](../../packages/desktop/upstream-inventory.json): all 34 upstream
  files hashed, primary source pins, ARM core/extra metadata and checksums,
  Asahi repository observation, dependency name/provider closure. Signatures and
  dependency constraints not verified; closure includes alternative providers,
  **not** an install plan. Asahi graphics-provider names are not acceleration proof.
- [Local check runner](../../packages/desktop/check-local.py): reproducible
  existing-tool source checks and two separate temporary package builds, exact
  seven-file payload assertion, evidence output; no dependency installation.

## Actual commands and results

Commands ran with existing tools only. `makepkg 7.1.0`, `Lua 5.5.1`, and host
`Hyprland 0.56.2` were present; Hyprland's version/ABI output is preserved in
[`host-packaging.json`](../../packages/desktop/evidence/host-packaging.json).

| Command/check | Actual result | Limit |
| --- | --- | --- |
| HTTPS GitHub API/raw/codeload acquisition of exact pins | PASS; upstream asset SHA-512 equals recipe | Source audit only; no assets installed/reused |
| Read official ARM mirror core/extra databases and Asahi ALARM database | PASS; exact database and package hashes recorded | Signatures, repository priority and target transaction NOT RUN |
| `python packages/desktop/check-local.py` | PASS | Existing x86 host; installs no dependencies |
| `bash -n PKGBUILD` | PASS | Syntax only |
| `luac -p hyprland.lua` | PASS | Lua syntax only |
| `python -m json.tool waybar.json` | PASS | JSON syntax; no Waybar session/rendering |
| `makepkg --verifysource` | PASS, all seven source hashes | No ARM dependency resolution |
| `Hyprland --verify-config --config .../hyprland.lua` | PASS, `config ok`, exit 0 | Existing x86 v0.56.2 parser, no session/hardware |
| Pinned upstream config in temporary copy, import paths rewritten, same verifier | FAIL, exit 1 | Expected audit finding; exact diagnostic preserved |
| `makepkg --nodeps --noconfirm`, final inputs, separate temp dirs, twice | PASS, exit 0 each, `check()` executed | Data packaging on non-clean x86 host |
| Assert artifact contains exactly the seven reviewed input text files | PASS | Ownership/lifecycle still requires installed-base check |
| Shared `package_checks.recipe()` and `.package()` on this recipe/artifact | PASS; no hooks/protected paths/ELF | Static inspection only |
| Compare final `.PKGINFO` to reviewed `.SRCINFO`, root license bytes | PASS | Recorded in `metadata-consistency.json` |
| Independent read-only subagent review | PASS; no blocking source/recipe issue after fixes | Native/session/hardware gates stay open |
| Failure-injection check of local runner | PASS; a failed rerun invalidates previous PASS summary | No package built/installed in the failure test |

Source checks, build command output, `.PKGINFO`, `.BUILDINFO`, member hashes,
metadata comparisons, and upstream failures are stored under
[`packages/desktop/evidence`](../../packages/desktop/evidence). Package archives
are local ignored development artifacts. No artifacts were installed/published.

Final package run 1 SHA-256: `019829e3a8d7859a19fa53d40c33b8235e4e59b025a44cbf827fc1665337201b`.
Final package run 2 SHA-256: `01323403cfb5268e147e024ea2b67ace879d4ac471c13585c8317bfc0388ea5d`.
The seven installed file hashes match; archive bytes differ. The recorded
`.BUILDINFO` difference is the temporary `builddir`/`startdir` path. Fixed
`SOURCE_DATE_EPOCH=1791748800` does not remove this
metadata difference. This evidence does not claim clean-build reproducibility.

## Remaining gates and next bounded work

1. **M0 integration:** coordinator reconciles target base/repository snapshot,
   Hyprland/library/graphics/audio versions and protected providers. A mirror
   listing/name closure does not prove version constraints or installed-base
   compatibility. No absent upstream CachyOS dependency is silently skipped
   while claiming the upstream bundle complete.
2. **M1 execution:** use a verified native clean aarch64 builder with signed,
   snapshot dependencies; run recipe source checks/build; independently rebuild
   and inspect contents/provenance/reproducibility. The package ships no ELF,
   but its existing compositor/dependencies require their own 16K/platform checks.
3. **M2 session/lifecycle:** record the exact M2 Air and unmodified baseline;
   inspect proposed package-manager transaction; exercise new configuration,
   existing-user configuration, opt-in, upgrade/remove/reinstall, preserved
   copies and running-process behavior. Reconcile polkit, portals, UWSM and
   environment activation with the base. Lock-before-sleep/lid/idle integration
   is intentionally not implemented by this package and needs explicit testing.
4. **M2 hardware:** accelerated rendering, panel scale/notch and brightness
   permissions, keyboard mappings, touchpad, protected audio/speakers/headset/
   mic, Wi-Fi/Bluetooth, notification/bar state, browser/video/portal behavior,
   screen lock and repeated suspend/resume, optional external display. Check
   each Air size separately; every check is currently NOT RUN.
5. **M3/M4:** release promotion, signing/upgrade/recovery and any performance
   measurements wait on integrated build/hardware gates. No improvements claimed.

Within this worker's available resources, the source recipe, audit, local
packaging runner and evidence are concrete and reviewable. Further deployment
and compatibility changes require the real baseline/build/hardware evidence;
this report identifies those gates rather than inventing passed results.

## Follow-up review fixes and final recipe freeze

The coordinator supplied the verified project origin
`https://github.com/Gabriel-Kahen/cachy-asahi`. The original recipe and `.SRCINFO`
now use that URL rather than a CachyOS asset repository; upstream references
remain only in audit/NOTICE provenance.

The [desktop lifecycle peer review](../reviews/desktop-lifecycle-review.md)
identified a TTY documentation path that bypassed upstream's launcher/watchdog.
The packaged README now preserves the base's validated launcher and UWSM
invocation. A standalone `start-hyprland -- --config PATH` example is conditional
on the base supplying that wrapper and supporting TTY startup. Direct
`Hyprland --verify-config` remains a parser check. No wrapper/compositor was
launched.

README SHA-256: `3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525`. PKGBUILD SHA-256: `4c55f488c5b886a88a277c058afde5266e4cefd3e348847f89801aef8d841bcc`.
The README checksum and reviewed `.SRCINFO` were refreshed. Seven source hashes,
source/config checks, two final-input local host packages, exact payload match,
and shared static/artifact/metadata checks passed again. `url` consistency is
now explicitly checked in retained metadata evidence. Archive bytes still
differ only as documented by build-path metadata. **Final desktop recipe frozen
for coordinator review**; native ARM, installation, M2 and release gates remain
NOT RUN.


## Native CI metadata failure and narrow correction

October 11, 2026 local date; retained native stage ran at October 12 UTC.
Coordinator reported revision `f4fc643`, CI run `38189058133`. The retained
aarch64 provenance records **FAILED**, exit **1**, builder/image ID
`sha256:d2ab65321238d7d8809d18de9703f184514e4a462ca8dbfa3df6b03e2d856b90`.
The log stops at the strict reviewed-versus-generated `.SRCINFO` comparison,
before source verification/package construction. **No successful native desktop
artifact or acceptance is inferred.** The earlier NOT RUN statements are the
initial source/host-packaging state; this first native attempt is now recorded
as FAILED at the metadata gate. Corrected-input native rerun remains NOT RUN.

Cause: reviewed metadata put `arch=any` before `url`, while native
`makepkg --printsrcinfo` put `url` before `arch`. Every metadata key and ordered
value list was equal; no dependency, source hash, license, version, URL or
architecture value differed. The old static semantic check did not enforce
field ordering; the strict native check correctly refused it.

Narrow fix: copied the retained native-generated metadata form into the owned
`.SRCINFO`, including removal of the old review-only introductory comment.
No PKGBUILD/payload or strict-checker change. Final identities:

- Original `.SRCINFO`: `23cc907dc9fcad75f598b1796ce65bebf3be74343d9dd94e1fcfa4d5ed076d04`.
- Corrected/native-generated `.SRCINFO`: `feeb68da93a0a81f274125e00588c98ad5e7b9772377172a0973c06d5cf94c89`.
- Unchanged PKGBUILD: `4c55f488c5b886a88a277c058afde5266e4cefd3e348847f89801aef8d841bcc`.
- All seven packaged-source SHA-256 values are unchanged and match the native
  attempt's retained inputs and previously inspected host payloads.

The exact `compare_srcinfo()` function was extracted without executing the
container entry point or changing it. With original/native files it returns
**1**, retaining the `arch`/`url` order diff; corrected/native files return
**0**. The corrected file also matches generated bytes exactly. Independent
semantic comparison confirmed the full metadata dictionaries equal before and
after. Current shared static recipe check passed and its input-hash report was
refreshed; no unnecessary package rebuild was used for this metadata-only fix.

Original evidence remains preserved under
[`packages/desktop/evidence/native-ci-38189058133`](../../packages/desktop/evidence/native-ci-38189058133):
`reviewed-original.SRCINFO`, `generated-native.SRCINFO`,
`native-failure-build.txt`, `native-failure-provenance.json`, both strict
comparison outputs, previous host recipe-check report, and
`correction-check.json`. Original native log SHA-256:
`e809f5598e5a7a0b3d2b7fa7e57033c7f4cd446af05f7c1032a6c55767d2a654`; provenance SHA-256:
`0a1203f2ce3e8a8ec80945c586d70566805f9a35ce434f29d18d395488443872`. These copies preserve the failure rather
than replacing it with source-check success.

**Desktop-owned files frozen for coordinator integration/rerun.** Current
source/strict metadata checks PASS; original native attempt FAILED;
corrected native rerun, native artifact/rebuild acceptance, installation,
exact-M2 validation and release acceptance remain NOT RUN. No Git or shared
manifest/checker edits were made.
