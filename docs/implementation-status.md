# Implementation and acceptance status

October 12, 2026. This record tracks the complete `outline.md` scope; an implementation artifact is not a passed release gate.

The full-goal responsibilities R1–R5 are mapped in `docs/acceptance.md`, with owned tasks and corrective next actions in `docs/backlog.md`. The destination now explicitly requires the maintained ARM package repository, native performance engineering, integrated Apple stack, broader Cachy system experience, and complete installation/release lifecycle. Both Air sizes, published final measurements, independent onboarding/contribution, subsequent full-port maintenance release, other-ARM reuse and actual upstream submissions remain required; an early overlay release or feasibility decision would not complete the goal. This scope update does not change any recorded execution result.

Latest coordinator checkpoint, October 12, 16:30 UTC. The earlier records below
remain historical; this checkpoint supersedes their pending-work descriptions.

- Native run `38259350917` passes the original generic integration aggregate:
  all seven stages, 650 locked-userspace source tests without skips, signed
  lifecycle, all eleven repository cases, installed software onboarding and
  desktop configuration verification. The broader aggregate remains FAIL only
  in the virtual desktop component. All owned-image/container cleanup passes.
  [Independent retained-evidence review](reviews/native-development-execution-38259350917.md)
  records the exact scope and limits; production trust and target recovery remain open.
- That run actually boots the generic ARM guest with 4K pages and passes software
  GBM rendering with llvmpipe. Hyprland's first IPC request returns exit6; no
  frames or usable session are accepted. The bounded IPC-readiness/log correction
  is implemented; guest/receiver correction is adopted at `d1e489b`, with206 development and22
  controller tests passing and exact211-source/canonical-copy verification.
  Successor38274341668 again fails the virtual stage: IPC attempts6,6,0 reach a JSON `[""]` reply, then the strict configuration predicate refuses it. All33 bundles/1623 members and1180 export files verify; no frame is accepted. Exact pinned-source response semantics are under read-only diagnosis. QEMU cannot
  establish M2 graphics, 16K runtime, audio, sleep or performance acceptance.
- FDK run `38260525391` records all501 acquisitions, four original comparisons,
  native/worker zero exits and worker cleanup PASS, then fails producer bootstrap
  receipt acceptance before FDK compilation. The narrow exact IID-byte grammar
  correction is committed at `a50d53f`; its128-source Git/inline-workflow/fresh-copy
  proof passes. Successor trial `38268251114` passes producer receipt acceptance, then fails
  at FDK source preparation before either build. All eight public files verify;
  final owned-image/container absence passes. The exact source predicate is
  unreported. A data-only replay exposes compressed-source serialization drift
  between standard zlib and zlib-ng. The independently reviewed canonical raw-tar correction is committed at `765067d`;77 stage and14 packet checks pass, actual128-source Git/inline-workflow/fresh-copy proof passes. Trial38277573107 is dispatched; native FDK compilation remains unaccepted.
  [Actual failed trial](reviews/native-fdk-execution-38260525391.md).
- The updater parent observation correction is committed at `2f8c13e`: 284 source
  tests pass, and actual85-file Git/source/snapshot verification passes for
  4,044,082 bytes. Workflow review found a contradictory-worker acceptance gap;
  its successive corrections pass507 author consumer cases and39 independent final cases. The accepted compile-receipt correction is committed at `ed76c11`; actual85-source Git/snapshot and workflow binding pass. Trial38277597310 is queued behind FDK; source85 remains unchanged.
  Earlier trial38251407975 remains FAIL; native compilation is not attested.
- KSM's229-test finite executor and152-source packet are committed at `b918c7c`;
  workflow registration is merged through PR5. First trial `38262440852` fails
  at source/ValueError before producer launch. The captured-import correction is adopted at `aef8836`; retry38271066975
  identifies daemon-image-baseline refusal: actual image query exit0/six lines,
  container baseline unobserved. Cooperative image-preservation implementation
  is underway; no producer or lifecycle ran in that retry.
- Kernel trial38253531983 remains FAIL before build at occupied-daemon refusal.
  The reviewed cooperative baseline-preservation correction is committed at
  `c3d3872`, with stage24/job115 and actual Git/bootstrap verification passing.
  Its separate hosted lane is adopted at `07450c5`. Retry38270726379 passes
  source, initial six-image/zero-container capture, producer and acquisition, then
  fails with KERNEL_EXIT before any recorded compile. Cleanup and final
  preservation/absence remain unverified. Finite child diagnostics are being
  implemented. An overbroad cleanup-timer diagnosis was withdrawn after verifying
  the existing broker renewal; those timers remain unchanged.
- The actual inert624-archive payload audit remains PASS. The first static ELF
  scan remains FAIL: 7,129 files, 4,536 missing-provider requests and22 firmware
  parser refusals. The clarified provider-only correction passes52 tests and
  retained-metadata replay resolves4,509 omissions, preserves three original
  candidates and leaves27 requests. The source correction is adopted at `7360b61`; the actual corrected624 scan
  verifies all archives and reproduces exactly27 missing requests, but remains
  FAIL from the same22 firmware parser refusals. Root retained-data verification
  passes. [Corrected execution](reviews/platform-elf-corrected-execution.md)
  preserves runtime/16K/hardware limits. Independent residual classification passes531 data checks but all27 requests/22 firmware refusals remain open. A bounded recursive metadata transaction packet is selected for21 direct provider roots; no extension archive is authenticated or adopted.
- The phase-aware repository-client successor passes110 copied-source tests,
  including real TEST GPG checks. Separate retained-data checks validate fifteen
  signatures at their recorded phases. Native admission remains NOT RUN;
  twelve empty-URL representation mismatches are reproduced against pinned
  repo-add semantics. Narrow normalization and internal typed-refusal corrections are held with252 source tests (141 collector/111 phase); independent review and coordinator map/dependency rebinding are next. Original admission/custody records remain required.
- The missing offline copied-root package transaction component is selected and
  being implemented under `scripts/install/`. Real bounded payload transactions
  are its next gate; hooks, first boot, image/key-owner trust and complete Asahi
  installation remain separate requirements.

| Stage | Source implementation | Required execution evidence | Acceptance |
| --- | --- | --- | --- |
| 0 Baseline | Collector, acceptance method and MIT license implemented; base choice retained | Native ARM VM builder executed; exact Asahi base snapshot and M2 Air inventories remain | INCOMPLETE |
| 1 M0 overlay audit | Pinned upstream audits and original development set reviewed; original source findings resolved | Complete chosen-base ARM dependency transaction and final recipe review | INCOMPLETE |
| 2 M1 builds | Four original recipes pass static inspection; build/inspection tooling passes local tests | Four original packages passed two clean native ARM builds, inspection and byte comparison; chosen Asahi target transaction still open | INCOMPLETE |
| 3 M2 integration | Baseline/protected-stack boundaries specified | Exact-model installation/removal, desktop/audio/resume/application-state checks | NOT RUN |
| 4 M3 updates | Signed staging/release tooling passes local synthetic/ephemeral-key tests and independent review | Real signed artifacts, consistent upgrades, induced-failure recovery on target | NOT RUN |
| 5 M4 performance | Frozen-plan measurement, telemetry and comparison harness implemented; six source findings independently resolved | Repeated controlled before/after timing, power, suspend drain, thermal and functional evidence | NOT RUN |
| 6 Maintained system | Installation/contributor drafts, release policy and packaged setup/removal helper implemented | Independent clean install, subsequent release, accountable maintainers | NOT RUN |
| 7 Overlay qualification and ARM reuse | Separate model records; actual native builder reuse and upstream drafts recorded | Both Air sizes, overlay reports, reusable component on another ARM target, actual upstream work | NOT RUN |
| 8 Complete ARM port (M5–M8) | Expanded package transaction preview, tool candidates, virtual desktop controller, offline development release client and ARM-C01 experiment implemented or source-audited; platform/install integration remains open | Broader native builds/runtime, complete licensed dependency coverage, target platform integration, measured tuning and A12–A15 evidence | INCOMPLETE |
| 9 Full-port acceptance and maintenance (M9) | Acceptance contract now covers all five responsibilities | Same-release both-size final validation, independent installation/recovery and subsequent complete-port release | NOT RUN |

## Verified local work

- Six project development chats dispatched on GPT 6.1 Sol with high reasoning, plus independent source reviews.
- Host/Docker are x86_64/amd64. Collector capture and the small onboarding C program ran locally; neither establishes M2 behavior.
- Coordinator's integrated test run: build/inspection 33, setup 40, baseline collector 3, release 19, benchmarks 28, native CI 45, setup synchronization 9: **177 passed**, no skips. These validate source behavior and controlled fixtures, not hardware acceptance.
- Four original recipes pass non-executing metadata/checksum inspection. Two host assemblies per recipe were produced by owners; payload comparisons and packaged CLI regressions are recorded separately from native execution.
- Independent reproductions closed four initial build/release findings, two setup findings and six benchmark findings. Desktop launcher documentation was corrected.
- Source-only ARM audit authenticated the dated rootfs and all 248 dependency package/signature pairs. This is data authentication on x86_64, not ARM execution or an accepted Asahi target transaction.
- Authenticated input cache and full audit retained privately at `/home/gabe/.local/share/cachy-asahi/private-inputs/`; upstream bytes are not published in Git.
- Free standard native ARM CI is implemented for the verified public repository, with a manual probe followed by hash-bound builds. [Actual execution record](validation/native-arm.md): static CI and the native ARM VM probe passed; first job failed metadata order; corrected full rerun passed all four native build pairs and byte comparisons, with retained evidence. Static CI has documented shell/release skips, separate from the full local test run.
- Read-only SSH attempt to configured `gabepi` timed out. No target Mac connection found in local SSH configuration.
- A source-only Asahi kernel checksum correction is actually submitted as
  [upstream draft PR #99](https://github.com/asahi-alarm/PKGBUILDs/pull/99).
  Independent checksum/diff/syntax review passed; compilation and hardware were
  not tested, and maintainer acceptance is not claimed. See the
  [submission record](upstream/linux-asahi-config-checksums.md).

## Complete-port development and connected native integration

- The generic ARM desktop/application preview resolves 45 minimum roots to a
  574-package inventory without replacing the 341-package builder baseline.
  This is a private print-only libalpm transaction, not an installed Asahi
  target. The original 232/233 authentication failure is preserved. A separate
  refreshed proposal authenticates all 233 additions after explicitly adopting
  the builder Perl refresh and proposing a new FDK archive. A separate FDK
  source-built candidate now has a reviewed complete selected-source packet,
  independently reconstructed inputs and 75 passing portable checks. Native
  builds, provider substitution, PipeWire runtime and installation remain open;
  the original broad private source packet remains uncleared. See
  `docs/port/desktop-coverage.md` and `docs/workstreams/port-resolution.md`.
- Cachy-update's actual Rust tray and shell updater have a development recipe,
  adapted behavior and independently authored licensed icons. Its reviewed Linux
  source/dependency/build-script closure and portable materializer are committed
  with exact input pins. All 167 registry archive checksums match; four historical
  macOS notice blockers remain excluded and refused. The separate hosted wrapper
  and actual Rust compilation are still pending. The separate KSM status
  candidate retains GPL provenance and passes local read-only/page-size fixture
  tests. Two clean native package builds now reproduce byte-for-byte in the first
  broader trial. Native installation/removal and required management functionality
  remain unfinished.
- ARM-C01 implements two baseline and two LTO zlib builds with cross-decoder,
  corruption, artifact, receipt-binding and cancellation checks; 91 local tests
  and independent review passed. The first native attempt compiled all four
  baseline/LTO builds, then failed during correctness checking. Timing and M2
  performance remain NOT RUN; partial compilation does not accept the experiment.
- A disposable generic virtual desktop route and controller are implemented,
  with 19 separately authenticated tooling packages and 29 local tests, including
  independently reproduced cancellation corrections. Actual
  guest boot, Hyprland/Wofi execution and captured-frame review remain NOT RUN;
  this route cannot accept Apple GPU, audio, suspend or platform behavior.
- The offline development release client passes 37 local tests with temporary
  real GPG signatures and independent race regressions. Production trust,
  supported release promotion and native onboarding remain separate gates.
- Connected V01–V09 execution has seven retained native failures. The first
  passed 211 host boundary tests but refused an incorrect source freeze. The
  corrected run passed 213 host tests, runner probe and full-source preflight,
  then failed fetching superseded pinned Perl inputs. The third authenticated
  the refreshed inputs, reproduced all four original native build pairs and
  passed 349 locked-userspace tests with no skips. Its fixture generation and
  integration suite failed on omitted locked audit inputs, and the desktop
  configuration verifier aborted. Installed lifecycle, repository transactions,
  onboarding and installed desktop stages did not begin. The fourth run passed
  fixture builds/signing, all 474 native source tests without skips, and the
  signed lifecycle component. The outer installed-image handoff and repository
  stages still failed; neither installed onboarding nor desktop ran. The fifth
  run passed all 499 native source tests without skips, package build pairs,
  signing and the lifecycle component. Its validated package inventory exports
  passed, but the committed-image verifier rejected differences in Cmd,
  Entrypoint and Labels. Repository creation reached repo-add, which could not
  create its temporary directory on the read-only root. Installed onboarding
  and desktop still did not run. Reviewed corrections pass 309 CI and 119
  integration tests locally, plus committed-blob and fresh-clone preflight.
  The sixth native run, `38212287407`, passes 560 native source tests without
  skips, fresh installed-image/lifecycle verification and installed software
  onboarding. It remains FAIL overall: repository rollback inventory text
  includes pacman diagnostics, and desktop publication refuses ANSI control
  codes despite its component checks passing. The owned image was removed with
  verified absence. Remaining repository transactions and actual desktop/session
  acceptance remain open. The seventh run passes 588 source tests without skips,
  installed lifecycle/software onboarding and desktop configuration verification
  including its corrected export. Eight repository case predicates pass through
  install, upgrade, rollback and signature rejection, but independent review
  finds zero-exit chroot errors in positive transactions; complete ancillary
  execution is not accepted. The aggregate still fails at the
  missing database-signature diagnostic classifier; later cases remain unrun.
  See
  [the actual execution record](validation/virtual-arm.md).

- The first broader native development trial, `38218102399`, builds and
  reproduces the KSM package twice. Its compiler experiment fails on truncated
  input handling; the 37-test client has one corrected permission-fixture failure,
  and virtual preparation refuses a signed-receipt interface mismatch. All remain
  separately recorded from the initial repository FAIL. The subsequent corrected
  original integration, `38221511121`, passes 603 native source tests without skips,
  ten repository cases, clean initial install/upgrade/rollback diagnostics and
  owned-image cleanup. Its final upgrade still reports a cached revoked-A sync
  signature error despite exit zero; the aggregate correctly remains FAIL.
  [Independent repository execution review](reviews/native-repository-run-review.md)
  verifies the actual checks. Further source corrections and separate FDK/updater
  native trial wiring continue; no complete-port milestone is accepted.

- The corrected original integration, `38227121568`, passes 620 native source
  tests without skips and all eleven repository transactions, including the
  clean final B upgrade after resetting the revoked-A cache. Its aggregate
  remains FAIL: the generic credential guard rejects nine evidence filenames.
  Corrected, purpose-validated public projection is still required; the raw
  reset receipt was not exported. Transaction PASS does not establish accepted
  publication, production trust or target recovery.
- The separate FDK trial, `38223759349`, passes all 501 input acquisitions but
  fails in the original producer before FDK compilation. Its exact failing
  operation remains unknown. The reviewed correction preserves delegated log
  bytes and finite phase diagnostics; 104 tests pass in both the workspace and
  exact copied 128-file packet, with committed Git byte/mode proof. The corrected workflow
  consumption and subsequent hosted execution are recorded below.
- The corrected FDK trial, `38230760444`, passes source/native prerequisites
  and all 501 acquisitions, then fails with the bounded diagnostic
  `producer-base-probe-runner-failed`. Its seven public files independently
  revalidate and owned-image absence is confirmed. The precise delegated Docker
  call/predicate remains under investigation; FDK compilation is NOT RUN.
- The updater native controller is committed after 136 source tests and
  independent process-cleanup review. Its 85-file committed closure is verified;
  the separate workflow is reviewed and registered. First native trial
  `38232511202` actually materializes all 168 inputs and reproduces the reviewed
  source/vendor hashes, then fails with RuntimeFailure while the native receipt
  remains at input-validation. Rust compilation is NOT RUN. Both cleanup and
  recovery report PASS, with nine captured public files independently verified;
  the exact validation/launch fault remains under investigation.
- The corrected platform proposal helpers pass 236 tests in a fresh committed
  checkout. The separately proposed coordinated Python transaction resolves
  all 55 target roots in metadata, while the original protected-version
  transaction remains FAIL. These are source/data results: 218 baseline payload
  archives remain unavailable, and installed ABI, hooks, coordinated platform
  updates and M2 recovery remain unaccepted.

- The corrected broader trial `38237127237` retains 31 authenticated public bundles / 1,508 regular members. ARM-C01's 505-command recorded correctness graph, four builds and 79 retained artifacts are consistent; all 37 native client tests pass and KSM builds reproduce. The eight sample CLI outputs outside the artifact bundle are not recovered evidence. All eleven repository cases, installed lifecycle/onboarding and desktop configuration pass, but the initial aggregate remains FAIL because the integration source suite fails. Repository binary-evidence publication is separately refused. Virtual tooling and disk preparation succeed; a QEMU capability guard stops before guest launch. Its tooling closure omits both concrete 2D virtio GPU modules. All reported owned-image/container cleanup passes. [Independent component review](reviews/native-development-execution-38237127237.md) records the limits and pending corrections.
- The updater scan correction is committed after 163 source tests and independent review; actual Git collection/verification binds 85 files / 3,915,170 bytes. Its diagnostic workflow passes 147 consumer fixtures. The FDK diagnostic workflow passes 30 fixtures and a closed 802-code schema. Actual finite reruns [FDK38239523997](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38239523997) and [updater38239531158](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38239531158) are dispatched at `756881b917ef68c614fcfb081debadf82282e80b`, serialized by the existing native-build group. Neither dispatch is a passed native result.
- The frozen kernel controller is committed after 140 source tests, exact 24-file source/Git acceptance and full output/cleanup corrections. Its separate hosted job proposal passes 93 source/runtime fixture tests; packet registration, default-branch workflow registration and actual kernel compilation remain pending. The 147-test KSM lifecycle is also committed with exact 14-path Git bindings; the separate native executor is still being implemented. Physical M2 execution, installation/recovery and performance remain NOT RUN.

- The diagnostic reruns now have verified terminal results: FDK38239523997 remainsFAIL at the exact base-lock inventory predicate, with501 acquisitions and owned-image absence verified; codec compilationNOTRUN. Updater38239531158 passes materialization/all527 acquisitions but the filesystem storage tick interrupts image bootstrap; its scoped cleanup and recovery bothFAIL, private-data removal is not confirmed, Rust compilationNOTRUN. Root validates seven FDK and eleven updater public files against the reviewed schemas and source pins. The owners are implementing bounded corrections; successful receipt publication is not successful execution.

These are distinct development results. No complete-port milestone or hardware
acceptance is granted by their local test counts or source reviews.

## Open inputs

- Exact M2 reference machine connection/access; 13-inch and 15-inch have independent gates.
- An upstream minimal-image candidate now has a retained 261-package inventory
  and seven separately authenticated current platform archives. Its image
  authentication, kernel source correspondence, complete target transaction and
  protected-stack integration remain unaccepted; generic native CI package
  build/comparison results are separately verified.
- Original project license is MIT. Excluded upstream configurations have separately recorded unresolved license notices.
- Final review and selection against the actual Asahi target dependency set; four original development candidates are selected, with no release selection.
- Release signing identity/custody and hosting destination, after package and hardware gates permit publication.

These are explicit unfinished gates. Source-only work, synthetic signing tests, container architecture declarations and documentation do not complete them.
