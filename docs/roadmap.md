# Roadmap

The destination is a maintained, independent CachyOS-derived ARM port for Apple Silicon covering all five requirements below. The initial overlay is an intermediate release, not full-goal completion. See [goal.md](../goal.md) for the ambition and [implementation sequence](../outline.md) for dependencies and parallel work.

All milestones are currently incomplete. Four original development packages have passed two clean native ARM builds each, inspection, and byte comparison; the selected Asahi target dependency transaction and M2 hardware validation remain open. See [implementation status](implementation-status.md) and [native ARM evidence](validation/native-arm.md). These builds do not establish a complete ARM port, an accepted target transaction, or hardware compatibility.

## Five required workstreams

| Requirement | Initial foundation | Required long-term milestone |
| --- | --- | --- |
| R1. Maintained Cachy-derived aarch64 package repository | Audits, reproducible builds and signed overlay in M0–M3 | M5: release-defined package coverage, dependency closure, continuous rebuilds and maintained signed releases |
| R2. Real ARM performance engineering | Controlled experiments in M4 | M7: validated ARM/M2 tuning, optimized package selection and published final-system measurements |
| R3. Integrated Apple hardware stack | Preserve Asahi and verify desktop/update behavior in M2–M3 | M7: maintained boot, kernel, graphics, audio and firmware integration with reviewed compatible Cachy changes |
| R4. Applicable CachyOS tools and desktop experience | Selected shells, settings and Hyprland integration in M0–M2 | M6: coherent ARM/Apple implementations of the applicable management tools, defaults and desktop experience |
| R5. Complete installation and maintenance lifecycle | Overlay installation, updates and recovery in M2–M3 | M8: reproducible fresh installation, upgrades and recovery; M9: support and recurring maintained releases |

All five workstreams are required for the destination. Package coverage, resources, licensing and platform audits select the implementation approach and identify blockers; they do not make the full port optional. Official CachyOS affiliation is an external agreement, not an engineering completion gate. Publish the result as independent Cachy-derived work or an unofficial port, with accurate attribution and no claim of CachyOS team approval.

Each release defines a finite base, desktop and supported application set with its complete dependency closure. Record which packages are project-built, which come from a maintained upstream ARM repository, and who owns compatibility and updates. Full-port acceptance requires the supported set to provide the complete system; a configuration-only package set does not satisfy it. Rebuilding every upstream CachyOS or Arch package is unnecessary. Document exclusions for x86-only, PC-specific or otherwise inapplicable packages, and provide tested adaptations or alternatives wherever their functions are required.

## Initial overlay: M0–M4

## M0: source and dependency audit

For each initial package, record the pinned source commit, upstream license, runtime/build dependencies, installed paths, package hooks, and dependencies available on the chosen ARM base. Select the minimum working desktop overlay. Reject or defer packages that change the platform stack.

Done when every selected package has an evidence-backed recipe plan and no unresolved dependency or license questions.

## M1: reproducible package builds

Create a clean aarch64 build environment with recorded base versions and pinned inputs. Build the selected configuration packages; capture logs and checksums. Inspect installed file lists, conflicts, package hooks, and 16K page compatibility where compiled binaries are introduced.

Done when a second clean build reproduces the documented package contents, and all selected packages pass package-level review. Record reproducibility limits rather than claiming byte identity without checking it.

## M2: M2 Air installation and removal

Install onto an existing Asahi ALARM system. Confirm accelerated Hyprland rendering, basic session services, selected shell configurations, and preservation of the Asahi stack. Verify removal restores package-owned changes and does not discard user configuration.

Done when hardware evidence is recorded for the exact tested machine and installation/removal are documented. Test the other Air size before claiming both.

## M3: dependable updates

Provide a signed overlay repository, compatible dependency versions, build checks, and a documented recovery path. Exercise upgrade, failed-upgrade, rollback, and service-startup scenarios on the target machine.

Done when an update round preserves the hardware-validation baseline and package dependency consistency. Snapshot creation alone does not prove boot recovery works.

## M4: measured performance experiments

Evaluate selected architecture-neutral Cachy patches and compiler settings against the unmodified Asahi baseline. Change one variable at a time. Record responsiveness under load, throughput, idle/load battery draw, suspend drain, and sustained thermals.

Done only for individually measured experiments. No blanket promise of better performance or battery life.

## Full ARM port: M5–M9

These are required development milestones. Begin independent design, package audits and resource planning before the initial overlay completes; their release acceptance depends on the relevant build, hardware and recovery evidence. The milestone numbers identify deliverables rather than requiring every workstream to wait for the previous number.

## M5: maintained Cachy-derived ARM repository (R1)

- Define the full-port release package inventory: base operating system, Hyprland desktop, applicable Cachy tools, selected applications and transitive dependencies. Establish supported upstream ARM inputs and the packages we must build and maintain ourselves.
- Expand beyond the original development packages into audited aarch64 recipes for the applicable Cachy-derived package set. Resolve licenses and repository/distribution arrangements before publication; track unresolved terms as delivery blockers.
- Maintain source pins, patches, license records, toolchain/build environment records, retrievable inputs and complete build provenance. Produce repeated clean native builds and record reproducibility limits.
- Publish signed packages and repository metadata through staging and stable promotion. Keep dependency sets consistent; test the complete fresh-install and upgrade transactions against the actual supported base.
- Operate scheduled rebuilds, dependency/security monitoring, review, artifact retention, signing-key custody and emergency correction. Resource and rebuild-cost audits choose a sustainable pipeline with accountable maintainers.

**Done when:** the declared base/desktop/application set and its dependency closure resolve and install on the target; the Cachy-derived ARM package set is published with provenance and signatures; a subsequent maintained repository release passes rebuild, promotion and upgrade checks. Package exclusions and upstream ownership are explicit. Four native development-package build pairs alone do not satisfy this milestone.

## M6: complete applicable CachyOS experience (R4)

- Inventory the applicable CachyOS management tools, defaults and desktop behavior, beyond shell/configuration templates. Classify each as ported, adapted, replaced or excluded with a reason and an accountable package/integration owner.
- Provide ARM/Apple-safe kernel and system management behavior where needed. Replace PC bootloader and hardware-detection assumptions with the supported Asahi path; do not enable unreviewed `chwd` or kernel-manager behavior merely for feature parity.
- Deliver a coherent Hyprland session: accelerated rendering, display scaling, brightness, keyboard/trackpad behavior, networking, audio, locking, session services and power behavior. Include development-environment and selected application workflows from the release inventory.
- Preserve user-owned configuration across first setup, interrupted/repeated setup, upgrades, removal and reinstall. Document supported customization and configuration migrations.
- Have an independent contributor follow the supported workflow and perform representative terminal/editor/build/application tasks on the actual supported system.

**Done when:** the published feature inventory has tested implementations or appropriate documented exclusions; all required user workflows pass on both Air sizes; package and configuration lifecycle behavior is verified. A collection of copied desktop settings does not satisfy this milestone.

## M7: measured ARM optimization and maintained Apple integration (R2, R3)

### ARM performance engineering

- Turn M4 experiments into an ongoing ARM engineering process. Select packages and workloads where compiler tuning, appropriate LTO/PGO, architecture-neutral kernel improvements or defaults could deliver a useful result.
- Define the supported CPU/ISA baseline and M2-specific variants explicitly. Check toolchain support, 16K-page compatibility, numerical correctness where relevant and actual execution on supported machines. Do not transplant x86 optimization flags.
- Build and compare the selected optimized packages against documented baseline recipes. Include profile collection/provenance and repeatable rebuild/update procedures for retained PGO/LTO variants.
- Measure baseline versus the final integrated system on each Air size: throughput, interactive latency under load, memory use, graphics, idle/load power, battery behavior, suspend drain and sustained thermals. Control test order, environmental conditions and variability; retain raw results.
- Keep only tuning that meets predefined usefulness and regression budgets. Publish failed experiments and tradeoffs; if a candidate provides no useful benefit, retain the baseline rather than claiming a gain.

**Done when:** selected ARM tuning and package optimization candidates have been built, executed and measured; retained changes have reproducible evidence and recovery paths; final-system reports for both Air sizes meet declared budgets. No specific winning flag, kernel patch, universal performance improvement or advantage over macOS is guaranteed.

### Apple platform integration

- Maintain a tested version set for Asahi boot integration, firmware, kernel, Mesa/graphics, audio and speaker protection together with the ARM repository and desktop. Track both 13-inch and 15-inch M2 Air separately.
- Reuse and contribute to Asahi's platform implementation. Own our integration and regression handling; neither a rewrite of Asahi nor original reverse engineering of every hardware block is required.
- Audit applicable Cachy kernel changes against Apple drivers, boot conventions, memory/page-size requirements, graphics, audio and power management. Include only justified compatible changes; record rejected changes and preserve a tested recovery kernel.
- Exercise coordinated platform updates, fresh boot, graphics, input, networking, audio/protection, locking and repeated session-preserving suspend/resume on both supported sizes. Record optional unsupported hardware functions separately from core acceptance failures.
- Keep local integration patches reviewed and upstreamable, track upstream changes and establish a release response for regressions.

**Done when:** both Air sizes pass the required exact-machine validation on the shipped platform set, including a subsequent coordinated update and actual boot/session recovery. Provenance, compatibility constraints, maintenance ownership and remaining optional limits are published. A driver compiling or working on another Mac cannot satisfy this gate.

## M8: complete installation and recovery path (R5)

- Ship a reproducible supported fresh-install path from macOS through Apple boot/platform setup, repository trust bootstrap, complete package installation and first usable Hyprland login. Using Asahi's installer with tested project integration is acceptable; a custom macOS partitioner is not required.
- Exercise the full documented journey independently on both Air sizes, including disk/boot prerequisites and configuration ownership. Existing-Asahi overlay installation may remain supported but cannot be the only evidence for full-port fresh installation.
- Test normal and interrupted setup, previous-release upgrades, coordinated base/platform/repository changes, failed-update recovery and actual boot/session restoration. Retain known-good packages and platform artifacts; test recovery instructions rather than merely documenting snapshots.
- Publish versioned installation/update guides and sanitized validation records, tied to the same package and platform set as the supported release.
- Establish named package/platform/release/support maintainers, builder and repository capacity, signing-key custody/rotation, dependency/security monitoring and incident handling. Agent implementation work supplements rather than replaces ongoing accountable maintenance.

**Done when:** an independent user can complete the fresh installation journey on both Air sizes; normal and failed-update recovery paths pass against the full-port candidate; configuration handling, support ownership and retained recovery artifacts are documented and exercised. A custom installer is unnecessary, but end-to-end target evidence is mandatory.

## M9: integrated acceptance and maintained full-port releases (R1–R5)

- Integrate M5–M8 against one release-defined package/platform set. Complete every required acceptance-matrix entry with linked source commits, package checksums, release IDs and exact-machine evidence; an overlay-only release does not satisfy this gate.
- Publish the full-port release, signed repository, provenance, install/update/recovery guides, performance reports and known optional limits. Required package coverage, user workflows and hardware behavior must pass on both Air sizes.
- Demonstrate a subsequent stable full-port release through the same build, promotion, installation/upgrade and regression process. Verify maintained package/dependency coverage, platform compatibility, configurations and recovery on both supported sizes.
- Record named ongoing package, platform, release and support ownership; builder/repository capacity; signing-key custody/rotation; dependency/security monitoring; and incident response. Missing maintenance coverage remains unfinished work.
- Complete independent contributor onboarding, the reusable ARM component demonstration and actual applicable upstream submissions. Track external merge and affiliation decisions honestly; official recognition is not required to complete an independent port.

**Done when:** all five required workstreams and the initial gates pass on the shipped system with evidence, the complete system is published, ongoing ownership is recorded, and a subsequent stable full-port release exercises the same lifecycle. Missing hardware, untested recovery, unpublished measurements, unresolved publication terms or missing maintenance capacity prevent signoff. Full-goal completion requires the implemented port rather than a feasibility decision or a one-off demo. Maintenance continues after signoff.

## Development order and completion

The initial release follows **target baseline and audits → reviewed desktop slice → native package builds → hardware integration → signed updates and recovery → overlay release**. The four verified native build pairs are progress within that path; the actual Asahi target transaction and M2 tests remain required.

The full port adds **release package coverage and build lifecycle (M5) + complete applicable experience (M6) + measured ARM engineering and maintained platform (M7) + end-to-end installation/recovery (M8) + integrated acceptance and repeat full-port releases (M9)**. Independent audits, recipes, benchmark design, release tooling and installation design can run in parallel. Serialize changes and measurements on shared hardware; integrate against one reviewed package/version set.

Use the [implementation sequence](../outline.md), [acceptance matrix](acceptance.md) and [implementation status](implementation-status.md) to record owners, dependencies, evidence and corrective tasks. `FAIL`, `NOT RUN`, unavailable target hardware, unresolved publication terms or missing maintenance capacity remain visible blockers. Resolve them through implementation, platform/base decisions, collaboration or an explicitly authorized goal change; do not silently drop a required workstream.

## First implementation workstreams

1. Audit `cachyos-hyprland-settings` and its current Hyprland dependencies.
2. Audit the Fish/Zsh configurations and proposed system defaults.
3. Specify the clean ARM build environment and package checks.
4. Coordinator merges the audit results and selects the M1 package set.

The original audit batch has produced four development candidates and native build evidence; reconcile its findings with the actual Asahi target before final release selection. Full-port package coverage and end-to-end fresh installation are outside M0–M4, but mandatory in M5–M9.
