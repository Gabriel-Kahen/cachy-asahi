# cachy-asahi

An experimental CachyOS package and configuration overlay for Asahi Linux on Apple Silicon.

Long-term goal: a complete maintained CachyOS-derived ARM distribution covering signed package builds, native performance engineering, Apple hardware integration, CachyOS tools/desktop, and the full installation/update/recovery lifecycle. The overlay is the first delivery stage; see [the five responsibilities](goal.md#five-responsibilities-of-the-complete-port).

Initial target: an M2 MacBook Air running Asahi Arch Linux ARM and Hyprland. The 13-inch and 15-inch models require separate hardware validation.

## Status

Recent hosted AArch64 builds produced reproducible Fish, md4c, llhttp and
First Login packages with 4 KiB pages. On emulated AArch64 with 16 KiB pages,
the TEST-signed Overlay583 install and shell lifecycle, the Current606 desktop
pair, and the 626-package Asahi maintenance rehearsal passed their documented
checks.

- [Native build evidence](docs/validation/native-fish-md4c-reproducibility-20261118.md)
- [Overlay583 lifecycle](docs/validation/offline-overlay583-emulated-install-20261117.md)
- [Current606 desktop pair](docs/validation/current606-overlay-emulated-arm16k-r16-20261119.md)
- [Asahi maintenance rehearsal](docs/validation/asahi626-maintenance-emulated-arm16k-20261118.md)

Production promotion, installed Asahi kernel boot and recovery, and physical
validation on both M2 Air sizes remain open. See the
[implementation status](docs/implementation-status.md) and
[release acceptance criteria](docs/acceptance.md). This is an independent
project with no official CachyOS or Asahi affiliation.

## First milestone

Produce a small, reproducible ARM package overlay that applies selected CachyOS desktop and shell configuration to an existing Asahi installation. Preserve the Asahi boot components, firmware, kernel, Mesa integration, and audio stack.

Start with configuration packages. Audit their dependencies and licenses, pin upstream revisions, build in a clean aarch64 environment, and test installation and removal on the target MacBook.

Kernel experiments and CPU-specific optimization follow a measured, working baseline. An x86 optimization result is not evidence of an M2 improvement.

## Project files

- [Project goal](goal.md): the long-term purpose and ambition.
- [Roadmap](docs/roadmap.md): implementation milestones and completion criteria.
- [Development outline](outline.md): full project sequence and dependencies.
- [Implementation status](docs/implementation-status.md): progress, missing resources and acceptance evidence.
- [Full-goal acceptance](docs/acceptance.md): required results for both Air sizes and the maintained final system.
- [Open GitHub issues](https://github.com/Gabriel-Kahen/cachy-asahi/issues): focused engineering follow-ups.
- [Historical execution backlog](docs/backlog.md): prior work, decisions and evidence.
- [Historical branch archive](https://github.com/Gabriel-Kahen/cachy-asahi/tree/archive/branches-2026-11-22): original GitHub branch names and exact commits.
- [Baseline contract](docs/baseline.md): environment collector, protected platform and hardware test counts.
- [Coordination](docs/orchestration.md): active workstreams, file ownership and integration responsibilities.
- [Installation draft](docs/installation.md): candidate package/configuration ownership and unexecuted target procedure.
- [Contributing](docs/contributing.md): source/evidence requirements, bug reports and maintenance responsibilities.
- [Performance evidence](docs/performance.md): final-system measurement requirements and local harness.
- [Development example](examples/development/README.md): a small terminal/editor/compiler onboarding smoke check, separate from benchmarks.
- [Agent work plan](docs/agent-work.md): bounded parallel tasks and integration responsibilities.
- [Hardware validation](docs/hardware-validation.md): evidence required before support claims.
- [Source notes](docs/sources.md): starting references, checked October 11, 2026.
- [Package candidates](manifests/packages.toml): a starting inventory, not an install list.
- [Setup8 development](docs/setup8-development.md): selected 0.3.0-1 recipe, explicit user commands and accepted generic ARM scope.
- [Contributor instructions](AGENTS.md): evidence and collaboration rules.

## Development boundaries

The first deliverable is an overlay for an existing installation. Broader ARM repositories, applicable Cachy management tools, measured ARM tuning, maintained Asahi integration and complete installation/releases are required later milestones. A custom macOS partitioner and replacement of Asahi's hardware stack are implementation choices, not requirements for their own sake.

Original project code and documentation use the [MIT license](LICENSE). Third-party material retains its own terms; audit upstream licenses and notices before redistribution. The initial original templates do not resolve the license gaps found in excluded CachyOS assets.
