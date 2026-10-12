# Full-goal acceptance matrix

This contract implements `outline.md` section 11. All full-goal requirements remain unaccepted. Source implementation, local tests and an early one-model release are intermediate results. Both M2 Air sizes, independent onboarding, final-system measurements, a subsequent stable release, ARM reuse and submitted upstream work are required for full signoff.

The outline was strengthened in a concurrent user chat during this first source batch. The coordinator re-read it and reconciled the additional completion requirements here. No core requirement is waived by lack of resources or an inherited base defect.

| ID | Required outcome and predefined checks | Accountable implementation owner | Artifact / evidence | Result and next action |
| --- | --- | --- | --- | --- |
| A01 | Goal coverage, finite release scope, every blocker has a corrective task | Lila, coordinator chat | This matrix, `docs/backlog.md`, manifest and status | INCOMPLETE: three development recipes chosen; base/compatibility transaction must be captured |
| A02 | Coherent desktop independently on both Air sizes: rendering, scale/brightness, input, networking, protected audio, lock, preserved applications after sleep | Coordinator and desktop chat; physical operator not identified | `docs/validation/m2-air-13.md`, `docs/validation/m2-air-15.md`, raw baseline/release records | NOT RUN: obtain exact-machine connections; record baseline before changes |
| A03 | Complete new-user install and representative editor/terminal/native-build workflow, independently followed from upstream prerequisites | Coordinator and build/setup chat | Installation guide, setup/removal helper, independent onboarding record | NOT RUN: helper implementation assigned; guide needs actual base/repository trust and target journey |
| A04 | Fresh/existing config, interrupted/repeated setup, changed-package upgrade, removal/reinstall preserve edits | Build/setup chat; desktop/package reviewers | Helper tests, package/target lifecycle records | INCOMPLETE: packaged helper and disposable lifecycle tests pass; exact-model lifecycle remains NOT RUN |
| A05 | All selected packages have licenses/pins, complete retrievable dependency inputs and two clean ARM builds | Build/validation chat, package chats, coordinator | Build provenance, dependency locks, artifacts, comparison and visible CI records | INCOMPLETE: all four native pairs passed with identical bytes and retained inputs; chosen Asahi target transaction/release selection still requires target review |
| A06 | Published signed repo/trust setup; base+overlay updates, key transition, induced failure and boot/session recovery on both models | Release chat and coordinator; permanent custodian/physical operator not assigned | Signed release pair, staging key-rotation/revocation record, both machine recovery records, actual endpoint | NOT RUN: local signed staging tested; physical/public trust and endpoint work still open |
| A07 | Published baseline vs final system on each Air: throughput, load latency, memory, graphics, idle/load power, battery, suspend drain and sustained thermals | Performance chat, coordinator; physical operator not identified | `docs/performance.md`, frozen plans, calibrated raw records, independent final reports | NOT RUN: harness source implemented; capture baseline and freeze practical budgets before tuning |
| A08 | Named ongoing maintenance, signing custody/security triage and second stable release through same process | Coordinator; ongoing human maintainer not assigned | Contributor/release policy, named coverage/capacity, second release and upgrade evidence | NOT RUN: assign actual ongoing capacity; agent chats do not supply permanent custody |
| A09 | Independent contribution follows bounded task, build, peer review and integrated validation | Coordinator and documentation/package reviewers | Backlog, contributor guide, independent contribution record | INCOMPLETE: source peer reviews occurred; clean ARM and integrated contribution path still required |
| A10 | Reusable component executed on another ARM target; useful bug reports/applicable fixes actually submitted upstream | Build/reuse owner and coordinator | Reuse instructions/execution report; submitted upstream URLs and response status | INCOMPLETE: native hosted ARM component reuse executed and independently reviewed; actual upstream drafts remain unsubmitted |
| A11 | Actionable fuller-distribution feasibility decision: coverage, cost/capacity, platform ownership, installer constraints and justified backlog | Coordinator | `docs/distribution-feasibility.md` | NOT RUN: decision follows sustainable overlay evidence; new installer is conditional, not a substitute for A01–A10 |

## Fixed functional and lifecycle checks

`docs/baseline.md` declares 3 cold boots/logins, 20 lid-close resume cycles (10 battery, 10 external power), 10 lock/unlock cycles, and 5 installation/removal/reinstallation cycles for both fresh and existing configurations. Preserve every failure and confirm application state after each resume. Supported display modes have 5 connection/reconnection cycles; unsupported optional modes retain an explicit limitation/upstream task.

Core audio/protection, input, networking, rendering, locking and preserved-session sleep are required. A preexisting failure is a base corrective task, not a passing overlay requirement. Optional external-display limits do not remove core checks. Each model/version set has its own result.

## Performance budget freeze

Representative workloads and control/repetition rules are in `docs/performance/`. Minimum five valid measured trials per variant, counterbalanced order, retained failures, fixed inputs and correctness checks apply. Final system measurement is mandatory even if no optimization wins.

Numerical responsiveness, throughput, memory, energy/battery, drain and sustained thermal budgets are **NOT DEFINED** until real unmodified baseline measurements and intended-use observations exist. Coordinator/performance owner must derive and freeze those budgets before any tuning or final comparison. Do not invent thresholds from this x86 host, lower a frozen budget after a failure, or treat missing telemetry as zero. CLI timing rules are preliminary and cannot pass A07.

## Evidence and signoff

Bind every executed record to exact model, physical machine pseudonym, source commit, release/artifact hashes, base/compatibility versions, operator, date, actual commands, raw observations and independent review. Retain inputs and evidence so hashes remain retrievable. Use PASS, FAIL or NOT RUN for checks; INCOMPLETE describes unfinished work, never acceptance.

Every A01–A11 requirement must pass for the shipped maintained system. Missing machine/resources, unpublished measurements, unexercised recovery or absent maintenance coverage block full-goal acceptance. Only a direct user change to the goal can remove a core requirement; source or tooling completion cannot do so.
