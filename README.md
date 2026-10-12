# cachy-asahi

An experimental CachyOS package and configuration overlay for Asahi Linux on Apple Silicon.

Initial target: an M2 MacBook Air running Asahi Arch Linux ARM and Hyprland. The 13-inch and 15-inch models require separate hardware validation.

## Status

Implementation is underway in six coordinated workstreams: desktop packaging, shells/defaults, ARM build/validation and setup, signed releases/recovery, performance measurement, and native ARM CI. Four original configuration/setup packages, baseline capture, build inspection, release recovery and measurement tooling are implemented and locally tested. No clean native ARM package builds, supported installer, custom kernel, stable release, or M2 hardware validation has been established. This is an independent project, not an official CachyOS or Asahi distribution.

See [implementation status](docs/implementation-status.md) for the complete outline's execution gates and [coordination](docs/orchestration.md) for worker ownership. Candidate recipes and tools are development artifacts until their gates pass.

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
- [Execution backlog](docs/backlog.md): accountable tasks, dependencies and next actions for blockers.
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
- [Contributor instructions](AGENTS.md): evidence and collaboration rules.

## Development boundaries

The first deliverable is an overlay for an existing installation. A macOS partitioning installer, complete optimized ARM repositories, and a replacement Asahi kernel are later decisions.

Original project code and documentation use the [MIT license](LICENSE). Third-party material retains its own terms; audit upstream licenses and notices before redistribution. The initial original templates do not resolve the license gaps found in excluded CachyOS assets.
