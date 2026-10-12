# Development outline for cachy-asahi

Turn the ambition in [goal.md](goal.md) into a maintained Apple Silicon Linux system, beginning with the small overlay defined in [docs/roadmap.md](docs/roadmap.md). Develop independent pieces in parallel, then integrate them through shared package, hardware, and release gates.

**Starting point:** repository scaffold only. Packages, installer behavior, hardware support, and performance improvements remain unverified. This outline proposes work; it does not mark any milestone complete.

**Completion rule:** an initial overlay release is an intermediate result. Completing the goal requires the evidence in section 11, including both M2 Air sizes and published final-system performance/power results. A plan cannot guarantee hardware behavior, access to resources, or upstream agreements; unresolved core requirements remain unfinished work.

## 1. Development sequence and dependencies

| Stage | Main result | Prerequisite | Work that can run in parallel |
| --- | --- | --- | --- |
| 0. Establish the development baseline | Recorded base, available machines/builders, acceptance plan | None | Package audits, build design, test/benchmark design |
| 1. Audit and select the overlay (M0) | Pinned, licensed initial package set with resolved dependencies | Base/interface decisions; hardware capture can proceed separately | Desktop, shell/defaults, build-environment audits |
| 2. Build reproducible packages (M1) | Reviewed packages and repeatable clean builds | Each package and its dependencies audited; full-set gate at milestone completion | Separate package recipes, build automation, installation documentation |
| 3. Integrate the M2 desktop (M2) | Installed, removable overlay and machine-specific validation | Reviewed desktop slice and baseline machine record; full-set gate at milestone completion | Desktop fixes, shell fixes, documentation, second-machine testing |
| 4. Make updates dependable (M3) | Signed repository, tested upgrade and recovery | Reviewed artifacts for update prototypes; integrated overlay for full acceptance | Repository tooling, dependency checks, recovery procedures, failure tests |
| 5. Run performance experiments (M4) | Individually justified optimizations | Research/build design from audited inputs; target experiments after stable hardware/recovery gates | Isolated package/default/compiler experiments; separate kernel research |
| 6. Deliver a maintained supported system | Documented installation, releases, maintenance and support process | Hardware and update gates; early overlay release may precede final acceptance | User guides, contributor tooling, release operations, usability review |
| 7. Complete the goal and expand the foundation | Both Air sizes, published measurements, demonstrated reuse and upstream work | Stable reference release; each track starts when its specific inputs are available | Second-size closure, final benchmarks, ARM reuse, upstream fixes |
| 8. Evaluate a fuller distribution | An evidence-backed decision and, if justified, staged implementation | Sustainable overlay, release capacity, platform integration plan | Repository coverage audit, installer design, upstream collaboration |

The first release's critical path is **base decision and per-package audits → reviewed desktop slice → early hardware integration → complete selected package set → integrated upgrade/recovery acceptance → release**. Baseline capture must precede changes to the test machine, but hardware availability need not block source audits or clean builds. Milestone exit gates certify the integrated result; they are not blanket barriers to starting independent work.

The full-goal critical path additionally includes **both-size validation + final measurements + independent onboarding + repeat maintenance release + demonstrated ARM reuse/upstream work → final acceptance**. Start those tracks as soon as their inputs exist. A fuller distribution and a new installer are later decisions, not substitutes for completing the supported system.

## 2. Stage 0: establish the baseline

- Record the chosen Asahi ALARM base and repository versions. Confirm its current installation/support path and identify upstream limitations before promising features.
- Inventory access to a clean aarch64 builder and the exact M2 Air reference machine. Track the 13-inch and 15-inch models separately; unavailable hardware remains a named blocker.
- Record the unmodified machine's boot/firmware, kernel, Mesa, Hyprland, Aquamarine, and audio versions using [docs/hardware-validation.md](docs/hardware-validation.md).
- Establish the protected platform components: preserve Asahi boot integration, firmware, kernel, graphics integration, audio, and speaker protection for the first milestone.
- Choose a license for original project material and define the provenance, logs, and validation records that contributors must provide.
- Design functional checks and repeatable performance/power workloads now. Capture versions, core behavior and measurements relevant to the first changes before modifying the machine; retain a reproducible unmodified reference state for the full comparison suite. Comprehensive thermal/battery testing need not delay the first desktop build.
- Create the acceptance matrix described in section 11 before implementation. Define required checks, sleep/wake repetitions, representative development workloads, and responsiveness/power/thermal budgets before tuning; derive practical budgets from recorded baselines and intended use, then freeze them for the release.
- Confirm the base can supply the required platform behavior, maintained dependencies, and supported updates. Missing essential features or an unsustainable base require a recorded design decision and corrective track; do not turn them into passing results by calling them upstream limitations.
- Assign package, release, and hardware owners now, and reserve builder/test-machine capacity. Use the smallest working build/check/publish path first; automate proven repeated or failure-prone operations before building a generalized framework.

**Gate:** the base, resources, acceptance contract, and validation method are recorded. Source audits/builds may proceed without a test machine; installation and hardware acceptance require the machine's baseline and recovery preparation. Assign each missing resource or platform gap an owner and next resolution step rather than waiting indefinitely.

## 3. Stage 1: audit and select the overlay (M0)

Run three bounded workstreams concurrently:

1. **Desktop:** audit `cachyos-hyprland-settings`, its dependency graph, session services, installed paths, user configuration behavior, and compatibility with the selected graphics/desktop versions. Identify PC-specific assumptions and Apple integration gaps.
2. **Tools and defaults:** audit `cachyos-fish-config`, `cachyos-zsh-config`, and each proposed `cachyos-settings` change. Verify ARM dependencies, service conflicts, power implications, and whether each default belongs in the initial overlay or a later experiment.
3. **Build and validation:** specify clean aarch64 builds, source acquisition, package inspection, dependency/conflict checks, artifact storage, and evidence reporting. Design installation/removal and hardware checks alongside the audits.

For every selected package, record pinned source revisions, licenses/notices, build/runtime dependencies, source verification, installed files, hooks, and a recipe plan. Resolve unavailable dependencies by supplying an audited recipe, choosing an alternative, or explicitly deferring the candidate.

Prioritize the riskiest dependency: a working Hyprland session on the chosen Apple graphics stack. As soon as the desktop slice and all its dependencies pass audit, begin its recipe/build/integration work; independent Fish/Zsh audits need not delay it. Package choice serves the user requirements, so add narrowly scoped integration packages when the candidates alone cannot deliver the required experience.

Keep `cachyos-kernel-manager` and `chwd` deferred until their Apple boot/kernel assumptions are justified. Audit conclusions are proposals; the coordinator alone reconciles [manifests/packages.toml](manifests/packages.toml) and selects the minimum useful package set.

**Gate:** every selected package has a complete audit and recipe plan, with no unresolved license or dependency questions. The initial set preserves the working Asahi platform stack.

## 4. Stage 2: implement builds and package checks (M1)

- Implement recipes in separately owned package directories, with upstream pins and required attribution. Keep installation hooks narrow and reviewable; research/build scripts must not mutate the host system.
- Implement clean-build provisioning, dependency installation, build logs, checksums, and provenance capture. Record the build image/toolchain and exact transitive dependency versions; retain or reference retrievable inputs so a later rebuild does not depend on moving repositories. Distinguish native aarch64 results from cross-build or emulated results.
- Check package contents, file ownership, conflicts, hooks, dependency resolution, and configuration handling. Check 16K-page compatibility when introducing compiled binaries.
- Prepare installation, removal, and troubleshooting instructions against actual package behavior while other workers finish builds.
- Rebuild the selected set in a second clean environment. Compare contents and, where feasible, artifact bytes; document any reproducibility limits.
- Send the first reviewed desktop slice to the reference machine for login/rendering and install/remove smoke checks while other packages continue. Keep this an integration test, not a supported release; use its failures to revise recipes and base decisions early.
- With the first artifacts, exercise install → configure → changed-package upgrade → remove → reinstall in a disposable environment, including existing user configuration. Repeat relevant paths on the reference machine; draft the user guide and have another contributor follow the working slice before M2 signoff.

**Gate:** all selected packages build from documented inputs, pass review, and reproduce their documented contents. Failed or deferred packages stay visible; changing the release package set requires coordinator reconciliation.

## 5. Stage 3: integrate the M2 desktop (M2)

- Install on an existing reference Asahi system after recording its baseline and recovery procedure. Maintain a tested compatibility set for kernel/graphics/desktop/audio components.
- Integrate accelerated Hyprland rendering, scaling, brightness, keyboard shortcuts, trackpad behavior, Wi-Fi/Bluetooth, shell setup, and session services into one coherent experience.
- Validate speakers and protection, headset, microphone, audio startup after login/resume, browser/video behavior, session locking, repeated lid-close sleep/wake, and preserved applications after resume. Define the repetition counts before testing.
- Exercise external-display connect/reconnect where the selected platform supports it. Record unsupported upstream features and overlay regressions separately.
- Test fresh configuration, existing user configuration, installation, removal, and reinstall. Package removal must preserve user-owned changes and restore package-owned changes as documented.
- Repeat validation independently for the other Air size before advertising support for both. Publish the exact machine and version set with PASS, FAIL, or NOT RUN evidence.

One-size validation can support an explicitly limited early release. Both sizes are required for full-goal acceptance. Core audio, input, networking, locking, and session-preserving sleep/wake failures block their requirements even if inherited from the base. Optional features such as unsupported external-display modes can remain documented limitations with a tracked upstream investigation.

Independent fixes, documentation, and testing on separate machines can proceed in parallel. Serialize installation, suspend/power testing, and system changes on each shared machine so results remain attributable.

**Gate:** the supported machine passes the required daily-use checks, installation/removal are documented and exercised, and remaining feature limits are explicit. Compilation cannot satisfy this gate.

## 6. Stage 4: dependable updates and recovery (M3)

- Build a signed overlay repository with documented key distribution, signing-key custody and revocation, package provenance, compatible dependency sets, and visible build results.
- Exercise signing-key rotation/revocation and the documented user trust transition in the staging repository before relying on that procedure for recovery.
- Keep signing credentials outside untrusted package/agent/CI execution. Promote reviewed artifacts by checksum from clean builds; publish packages, signed repository metadata, trust-bootstrap instructions, and versioned release records at the actual supported endpoint.
- Add automated checks for recipes, missing dependencies, package conflicts, stale pins, and incompatible coordinated desktop-stack updates.
- Define staging and stable promotion, versioning, release notes, retained recovery artifacts, and an emergency withdrawal/fix process.
- Exercise normal upgrades, interrupted/failed upgrades, service-startup failures, rollback, and actual boot/session recovery on the target machine. Do not treat a snapshot's existence as a recovery test.
- Re-run the functional baseline on release candidates and document the supported upgrade paths. Keep experimental changes out of stable promotion until their own gates pass.
- Test fresh installation and previous-release-to-candidate upgrades through that repository, including a local test release pair before the first public release. Validate base and overlay upgrades together; define how incompatible upstream updates are handled without requiring untested partial-system upgrades or permanent stale pins.

Repository tooling and recovery documentation start during M1/M2. Exercise a small test update as soon as reviewed artifacts exist; stable promotion still waits for integrated hardware and upgrade evidence.

**Gate:** a staged update preserves dependency consistency and daily-use behavior, signatures are verified, and the documented recovery path has restored a usable machine after a controlled failure.

## 7. Stage 5: measured performance experiments (M4)

- Prepare reproducible development workloads: builds, interactive desktop use under load, memory pressure, and graphics activity. Record versions, power state, ambient conditions, and repeated trials.
- Investigate architecture-neutral CachyOS defaults/patches, selected optimized ARM packages, and compiler settings in isolated branches. Avoid importing x86 tuning assumptions.
- Measure throughput, interactive latency/frame behavior, memory use, idle/load power, battery behavior, suspend drain, and sustained thermals together. Control fanless-machine heating and test order.
- Set an acceptance rule before each experiment: what useful improvement it targets, what regressions are unacceptable, and how variability will be handled. Change one variable at a time and retain raw evidence.
- Explore kernel improvements only after the working baseline and recovery gates. Preserve the stable Asahi kernel as the recovery option; test experimental kernels separately.
- Integrate winning changes one at a time, then re-test their combination. Revise or remove changes whose costs outweigh their measured benefit.
- Publish baseline and final-release measurements even if no experimental tuning wins. The final system must meet the previously defined use/performance budgets; unmet budgets remain open requirements. Useful kernel or compiler changes are conditional on evidence, not mandatory changes for their own sake.

Workers may develop independent experiments concurrently. Serialize benchmark runs on a shared machine; additional equivalent machines allow more throughput but require their own baselines.

**Gate:** each retained optimization has reproducible measurements, published tradeoffs, hardware regression checks, and an exercised removal/recovery path. No blanket performance or battery claims.

## 8. Stage 6: deliver and maintain the supported system

- Publish the supported installation path from the chosen base through overlay setup to first Hyprland login, with prerequisites, machine support, configuration ownership, upgrade, removal, and recovery instructions.
- Exercise the entire documented journey, including upstream installation prerequisites and repository trust setup, with someone other than its author. Verify that a new user can reach a usable development desktop without undocumented steps or a preconfigured developer machine.
- Deliver reviewable overlay activation/configuration and removal commands or tooling that match the guide. Test interrupted setup, repeat execution, existing configuration, and preserved user edits through upgrades/removal; a custom partitioning installer is unnecessary for the initial supported path.
- Provide development-environment examples, contributor onboarding, reproducible bug reports, package rebuild instructions, and bounded tasks that contributors can pick up.
- Assign maintainers for packages, desktop integration, releases, documentation, and hardware validation. Define release cadence, upstream-change monitoring, issue triage, and response to dependency/security fixes.
- Record actual ongoing maintainer availability and builder/repository/hardware capacity. Agents supply bounded engineering work; ephemeral workers do not provide ongoing custody of signing keys or incident response.
- Require automated package checks and real-machine validation for stable candidates; archive sanitized evidence, provenance, known issues, and release notes. Demonstrate a subsequent release through the same process.

**Gate:** users can install, work, update, and recover through the published supported path; contributors can reproduce builds and failures; maintainers have exercised a subsequent release. This can deliver a maintained overlay before a standalone distribution exists; full-goal completion still requires section 11.

## 9. Stages 7–8: expand the foundation and evaluate a distribution

- Add machines only as upstream platform support and validation capacity permit. Give each model its own baseline, compatibility record, support status, and release checks.
- Complete the second M2 Air size, final-system reports, and remaining section 11 requirements before full-goal signoff. Keep additional Mac models in a capability/resource-based backlog rather than making every Apple model a prerequisite.
- Design reusable ARM build/provenance/repository boundaries during M1, then demonstrate at least one component on another ARM target. Packaging/build reuse can use a separate ARM builder; it does not require certifying another machine's desktop.
- Investigate upstream gaps as they are found, submit useful reproducible bug reports and applicable fixes, and track responses and retained local patches. Coordinate version requirements and credit sources; upstream merge decisions and official affiliation remain external outcomes and cannot be guaranteed.
- Evaluate an official ARM foundation as opportunities arise. Audit package coverage, rebuild cost, dependency maintenance, licensing, signing, release staffing, and platform integration before committing to a fuller distribution.
- If justified, proceed incrementally: broaden the signed package set, validate the base/repository combination, then design installation media or a macOS installation integration with explicit partitioning, boot, upgrade, and recovery checks.
- Give any new installer a separate implementation and hardware acceptance track. Release it only after supported-machine installation and failure recovery are exercised; retain the proven overlay route during development.

**Gate:** all section 11 evidence is present for full-goal acceptance; model expansion preserves the reference guarantees. Record the fuller-distribution feasibility decision with package coverage, capacity/cost, platform ownership, installer constraints, and a justified implementation backlog or blocker. A new distribution is pursued only with sustainable infrastructure and tested installation/recovery.

## 10. Parallel development and integration rules

Use one coordinator and initially three focused workers, following [docs/agent-work.md](docs/agent-work.md). Split additional work only when ownership and resources permit independent progress.

| Role | Owns | First deliverable |
| --- | --- | --- |
| Coordinator | Shared manifest, scope, compatibility set, integration and release decisions | Baseline contract, accepted audit set, dependency/task map |
| Desktop worker | Desktop audit and later desktop recipes/configuration | Pinned Hyprland package/dependency audit |
| Tools/defaults worker | Shell audits, recipes and individual settings proposals | Pinned Fish/Zsh audits and reviewed defaults shortlist |
| Build/validation worker | Build tooling, package checks and validation procedure drafts | Clean ARM build specification and acceptance checklist |

- Before each batch, give every task a deliverable, prerequisite, exclusive file ownership, evidence requirement, and reviewer. Shared-manifest edits go through the coordinator.
- Keep an execution backlog with task IDs, accountable owners, dependencies, expected artifacts, status, and the next concrete action for blockers. Prioritize work that removes uncertainty on the critical path; bound experiments by a declared trial set and review point so research cannot consume delivery indefinitely.
- Use separate branches/worktrees for independent changes. Freeze common interfaces and package/version expectations before dependent implementation; integrate small reviewed batches frequently.
- Build independent packages concurrently; order dependent builds by the actual dependency graph. Schedule shared builders, signing, and hardware explicitly.
- Prepare documentation, benchmark harnesses, release tooling, and upstream reports ahead of their execution gates whenever their inputs are known.
- Have another worker review each result. Platform-affecting changes need independent review plus integrated hardware checks.
- Record progress as proposed, source-audited, built, installed, or hardware-tested. Keep blockers and deferred work visible; report no milestone complete without its required evidence.
- At each integration review, reconcile results against the acceptance matrix. A failed check creates a corrective task, followed by the affected check and integrated regression checks. Reassign or redesign blocked work; only an explicit change to the project goal can remove a core requirement. Do not lower frozen acceptance budgets merely to declare success.

| Shared resource | Scheduling rule |
| --- | --- |
| Clean ARM builders | Run independent builds within capacity, recording each environment and artifact; dependency builds precede consumers |
| Each reference Mac | One tracked system-changing/test job at a time; record or restore its state before the next job |
| Suspend/power/thermal tests | Reserve uninterrupted controlled windows; keep unrelated workloads out of measurement runs |
| Coordinator and reviewers | Review small artifacts continuously; keep independent audit/build/docs tasks runnable during hardware tests |

**Immediate next batch:** the coordinator records the acceptance/resource matrix; the desktop worker audits the Hyprland dependency closure; the tools worker audits Fish/Zsh and defaults; the build worker prepares clean builds and inspection. Begin the audited desktop slice as soon as its dependencies are ready, then exercise it on the reference machine while finishing the remaining package set.

## 11. Full-goal acceptance and evidence

Create the following records during implementation; these paths are proposed deliverables, not files already present. Link evidence to source commits, release IDs, package checksums, and exact machine/version records. Assign the roles below to named contributors; one person may hold several roles, and agent assignments may rotate.

| Requirement | Accountable role | Deliverable and completion evidence |
| --- | --- | --- |
| Goal coverage and finite release scope | Coordinator | `docs/acceptance.md`: every goal requirement mapped to tasks, predefined checks/budgets, results and evidence; core features and optional platform limitations distinguished |
| Both M2 Air sizes provide a coherent desktop | Desktop/hardware owner | Per-machine records under `docs/validation/`: accelerated graphics, scaling, brightness, keyboard/trackpad, networking, audio/protection, lock and repeated sleep/wake with applications preserved; all required checks pass independently |
| New users can install and developers can work | Documentation/desktop owner | Tested installation and troubleshooting guides, shipped setup/removal tooling, and an independent complete onboarding exercise including representative editor/terminal/build workloads |
| User configuration survives the lifecycle | Package/desktop owner | Fresh/existing-user tests covering install, interrupted/repeated setup, upgrade, removal and reinstall; user edits preserved and package-owned changes handled as documented |
| Packages and provenance can be reproduced | Build owner | Recipes, license/source records, retrievable pinned build/dependency inputs, two clean-build results, artifact checksums, and visible CI logs for the release package set |
| Updates and failed updates preserve a usable system | Release/hardware owner | Published signed repository, verified trust bootstrap, compatible base/overlay update policy, actual repository install/upgrade tests, and exercised failure/boot/session recovery on both supported sizes |
| Performance philosophy is demonstrated | Performance owner | `docs/performance.md` plus harness/raw results: independent baseline versus final-system measurements for both Air sizes covering throughput, latency under load, memory, graphics, power/battery, suspend drain and sustained thermals; each model's declared budgets met and every claimed gain supported |
| Maintenance continues beyond one release | Ongoing maintainer/release owner | Named maintenance coverage, dependency/security monitoring, signing-key lifecycle, issue/support process, and a second stable release exercising the same build/promotion/update checks |
| Contributors can reproduce and improve the system | Coordinator/documentation owner | Bounded task backlog, contributor instructions and an independent contribution exercised through build, review and integrated validation |
| Other ARM work benefits and upstream work is returned | Reuse/upstream owner | A reusable component executed on another ARM target with instructions/results; useful findings/reproductions and applicable fixes actually submitted upstream, with external acceptance status recorded |
| Future distribution work has an actionable foundation | Coordinator | A written feasibility decision and scoped next steps; official collaboration and wider model support tracked honestly as conditional external/resource outcomes |

**Final signoff:** every required matrix entry passes with linked evidence on the shipped release. `FAIL`, `NOT RUN`, missing hardware, untested recovery, unpublished measurements, or missing ongoing maintenance coverage prevent full-goal completion. Optional platform limits and future expansion remain explicit; they cannot conceal a failed core requirement. Reassess resource feasibility at each milestone and resolve blockers through implementation, upstream work, a base-design correction, or an explicit goal change.

The completed deliverable is a maintained, installable and measured system with a repeatable release process. Continued maintenance remains ongoing work rather than a claim that future regressions are impossible.
