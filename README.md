# cachy-asahi

An experimental CachyOS package and configuration overlay for Asahi Linux on Apple Silicon.

Initial target: an M2 MacBook Air running Asahi Arch Linux ARM and Hyprland. The 13-inch and 15-inch models require separate hardware validation.

## Status

Repository scaffold only. There are no built packages, installer, custom kernel, or hardware validation results yet. This is an independent project, not an official CachyOS or Asahi distribution.

## First milestone

Produce a small, reproducible ARM package overlay that applies selected CachyOS desktop and shell configuration to an existing Asahi installation. Preserve the Asahi boot components, firmware, kernel, Mesa integration, and audio stack.

Start with configuration packages. Audit their dependencies and licenses, pin upstream revisions, build in a clean aarch64 environment, and test installation and removal on the target MacBook.

Kernel experiments and CPU-specific optimization follow a measured, working baseline. An x86 optimization result is not evidence of an M2 improvement.

## Project files

- [Roadmap](docs/roadmap.md): implementation milestones and completion criteria.
- [Agent work plan](docs/agent-work.md): bounded parallel tasks and integration responsibilities.
- [Hardware validation](docs/hardware-validation.md): evidence required before support claims.
- [Source notes](docs/sources.md): starting references, checked October 11, 2026.
- [Package candidates](manifests/packages.toml): a starting inventory, not an install list.
- [Contributor instructions](AGENTS.md): evidence and collaboration rules.

## Development boundaries

The first deliverable is an overlay for an existing installation. A macOS partitioning installer, complete optimized ARM repositories, and a replacement Asahi kernel are later decisions.

No third-party source is vendored yet. Audit upstream licenses and notices before redistribution; a license for this project's original material has not been selected.
