# Implementation and acceptance status

October 11, 2026. This record tracks the complete `outline.md` scope; an implementation artifact is not a passed release gate.

The concurrently revised outline's full-goal requirements are mapped in `docs/acceptance.md`, with owned tasks and corrective next actions in `docs/backlog.md`. Both Air sizes, published final measurements, independent onboarding/contribution, subsequent maintenance release, other-ARM reuse and actual upstream submissions remain required; an early overlay release would not complete the goal.

| Stage | Source implementation | Required execution evidence | Acceptance |
| --- | --- | --- | --- |
| 0 Baseline | Collector, acceptance method and MIT license implemented; base choice retained | Exact base snapshot, native ARM builder, M2 Air inventory | INCOMPLETE |
| 1 M0 overlay audit | Pinned upstream audits and original development set reconciled; final review underway | Complete chosen-base ARM dependency transaction and final recipe review | INCOMPLETE |
| 2 M1 builds | Four original recipes pass static inspection; build/inspection tooling passes local tests | All selected packages, two clean native ARM builds, artifact inspection and reproducibility comparison | NOT RUN |
| 3 M2 integration | Baseline/protected-stack boundaries specified | Exact-model installation/removal, desktop/audio/resume/application-state checks | NOT RUN |
| 4 M3 updates | Signed staging/release tooling passes local synthetic/ephemeral-key tests and independent review | Real signed artifacts, consistent upgrades, induced-failure recovery on target | NOT RUN |
| 5 M4 performance | Frozen-plan measurement, telemetry and comparison harness implemented; six source findings independently resolved | Repeated controlled before/after timing, power, suspend drain, thermal and functional evidence | NOT RUN |
| 6 Maintained system | Installation/contributor drafts, release policy and packaged setup/removal helper implemented | Independent clean install, subsequent release, accountable maintainers | NOT RUN |
| 7 Full-goal closure and ARM reuse | Separate model records and required reuse/upstream tasks tracked | Both Air sizes, final reports, reusable component on another ARM target, actual upstream work | NOT RUN |
| 8 Distribution decision | Provisional overlay decision documented; final decision awaits sustained operation | Coverage/cost/maintenance audit; separate tested installer track if justified | NOT RUN |

## Verified local work

- Six project development chats dispatched on GPT 6.1 Sol with high reasoning, plus independent source reviews.
- Host/Docker are x86_64/amd64. Collector capture and the small onboarding C program ran locally; neither establishes M2 behavior.
- Coordinator's integrated test run: build/inspection 33, setup 40, baseline collector 3, release 19, benchmarks 28, native CI 45, setup synchronization 9: **177 passed**, no skips. These validate source behavior and controlled fixtures, not hardware acceptance.
- Four original recipes pass non-executing metadata/checksum inspection. Two host assemblies per recipe were produced by owners; payload comparisons and packaged CLI regressions are recorded separately from native execution.
- Independent reproductions closed four initial build/release findings, two setup findings and six benchmark findings. Desktop launcher documentation was corrected.
- Source-only ARM audit authenticated the dated rootfs and all 248 dependency package/signature pairs. This is data authentication on x86_64, not ARM execution or an accepted Asahi target transaction.
- Authenticated input cache and full audit retained privately at `/home/gabe/.local/share/cachy-asahi/private-inputs/`; upstream bytes are not published in Git.
- Free standard native ARM CI is implemented for the verified public repository, with a manual probe followed by hash-bound builds. [Actual execution record](validation/native-arm.md): static CI and the native ARM VM probe passed; first native job authenticated inputs and provisioned the frozen builder, then failed desktop metadata order before package assembly; correction/rerun underway. Static CI has documented shell/release skips, separate from the full local test run.
- Read-only SSH attempt to configured `gabepi` timed out. No target Mac connection found in local SSH configuration.

## Open inputs

- Exact M2 reference machine connection/access; 13-inch and 15-inch have independent gates.
- Actual native CI execution/comparison results; source inputs are retained, but the chosen Asahi target snapshot/transaction remains unidentified.
- Original project license is MIT. Excluded upstream configurations have separately recorded unresolved license notices.
- Final review and selection against the actual Asahi target dependency set; four original development candidates are selected, with no release selection.
- Release signing identity/custody and hosting destination, after package and hardware gates permit publication.

These are explicit unfinished gates. Source-only work, synthetic signing tests, container architecture declarations and documentation do not complete them.
