# The goal of cachy-asahi

Build a fast, polished, dependable Linux experience for Apple Silicon that brings CachyOS's performance philosophy and Hyprland desktop to the MacBook. Make the M2 MacBook Air a first-class Linux development machine, then turn what we learn into a foundation other Apple Silicon and ARM projects can use.

The destination is a complete, maintained CachyOS-derived ARM distribution running natively on Apple Silicon, with the M2 MacBook Air as its first reference platform. Own the package builds, ARM performance engineering, Apple platform integration, CachyOS system experience, and installation/release lifecycle together. The initial package overlay is the first step toward that distribution, not the final scope of the repository.

## Five responsibilities of the complete port

These are long-term requirements, not optional extensions after an overlay release. Each must have an accountable owner, implementation milestones, and acceptance evidence.

| ID | Responsibility | What this repository must deliver |
| --- | --- | --- |
| R1 | Maintained ARM package repository | CachyOS-derived aarch64 recipes, reviewed patches and tools, clean builds, signed packages and metadata, retrievable provenance, consistent dependencies, and repeated maintenance/security updates. Define the supported base, desktop, application set and complete dependency closure; expand coverage beyond the initial configuration packages. |
| R2 | ARM performance engineering | M2-appropriate compiler settings, selected LTO/PGO and compatible kernel/default experiments, with correctness, responsiveness, energy and thermal measurements. Publish final-system results and retain only justified changes. An x86 result or a changed compiler flag is not an ARM performance result. |
| R3 | Integrated Apple hardware stack | Maintain a tested Asahi boot/kernel/firmware/Mesa/audio combination with our ARM packages and applicable Cachy changes. Own compatibility, update handling, regression fixes and recovery on both M2 Air sizes while collaborating with the platform maintainers. |
| R4 | CachyOS system experience | Port or adapt the applicable CachyOS management tools, system defaults, shell configurations and Hyprland desktop. Provide Apple-aware hardware/kernel management and preserve user configuration; document architecture-specific exclusions and replacements. |
| R5 | Complete installation and maintenance | A reproducible new-user installation path, repository trust setup, coordinated upgrades, exercised failure recovery, release artifacts and notes, named ongoing maintainers, and subsequent supported releases on both Air sizes. |

R1 does not require rebuilding every package in Arch before the first port release. It requires an explicit release package set, a maintained source of its dependencies, and ownership of the Cachy-derived packages we ship. R3 builds on Asahi's hardware work; a platform-specific Asahi-derived kernel is compatible with this destination. R5 may integrate the established Asahi installer rather than inventing a new macOS partitioner, but the complete installation journey must be tested.

Publish the project's status as independent and its port as unofficial unless CachyOS accepts it as an edition. Official recognition is a separate collaboration outcome; obtaining it cannot substitute for the five engineering requirements. Resolve naming, source licenses and repository distribution arrangements before publication under the relevant identity.

## The experience we want to deliver

A user should be able to install cachy-asahi through a documented, supported path, open a responsive Hyprland desktop, and get to work. Display scaling, keyboard shortcuts, trackpad behavior, brightness, networking, audio, session locking, and power management should form one coherent experience.

Closing the lid and returning to work should preserve the session. Updates should keep the machine usable. Recovery should be understandable and tested. User configuration should remain theirs to change.

Our first reference machine is the M2 MacBook Air. We will earn support for both sizes through testing, and expand to additional Apple Silicon models as their platform support and our validation capacity allow.

## Performance that earns its claims

Bring the useful parts of CachyOS to ARM: carefully selected system defaults, maintained tools, optimized packages, and kernel improvements where they help Apple hardware.

Aim for excellent responsiveness during demanding development work, efficient use of memory, fast builds, smooth graphics, and strong battery behavior on a fanless laptop. Measure throughput, latency, power consumption, suspend drain, and sustained thermals together. Publish the baseline, method, results, and tradeoffs so others can reproduce them.

Every optimization must justify its place. Keep changes that deliver a useful measured improvement; revise or remove changes that cost more than they deliver.

## Infrastructure that makes the project sustainable

Grow from a small overlay into a dependable ARM build and release pipeline. Maintain pinned source inputs, license records, clean build environments, signed packages, compatible dependency sets, and visible build results.

Make installation, upgrade, removal, and recovery repeatable. Coordinate the graphics and desktop stack so users receive a tested combination. Develop release checks that catch packaging failures automatically, supported by real-machine testing for behavior that a build server cannot establish.

Use this infrastructure to deliver the complete CachyOS-derived Apple Silicon port. Capacity and feasibility reviews determine the implementation approach and identify blockers; they do not make the destination optional. Pursue collaboration with CachyOS and an official ARM foundation as those opportunities become available, while recording the selected base and its maintenance obligations explicitly.

## Build with the upstream projects

Asahi supplies the essential Apple platform work. CachyOS supplies performance ideas and software. Hyprland supplies the desktop foundation. Preserve their working integrations, credit their contributions, respect their licenses, and return useful fixes upstream.

Help close the gaps that affect everyday use: audio startup, reliable resume, display hotplug, ARM package availability, and consistent updates. Work with the relevant maintainers when a problem crosses project boundaries.

Keep Apple-specific integration distinct enough that reusable ARM packaging and build improvements can benefit other machines. Be precise about the project's independent status; official affiliation must be earned through agreement.

## Use agents to increase engineering capacity

Use coordinated agents for package audits, implementation, build debugging, documentation, and independent review. Give them concrete deliverables, clear ownership, and access to evidence. Maintain one accountable integration process.

Success is measured in working packages and verified user experience. Compilation, a plausible explanation, or an agent's confidence cannot substitute for execution on the target hardware.

## What success looks like

- All five responsibilities R1–R5 are fulfilled on the same maintained release; a configuration overlay or a feasibility report alone does not complete the goal.
- A new user can follow the installation guide and reach a usable desktop on a supported MacBook.
- A developer can rebuild the selected packages from documented inputs and inspect their provenance.
- The desktop remains responsive under load, with published performance and power measurements.
- Audio, input, locking, and repeated sleep/wake pass the supported machine's validation record.
- Upgrades preserve the working system, and a failed update has an exercised recovery path.
- Contributors can pick up bounded tasks, reproduce failures, and land improvements without relying on undocumented knowledge.
- Other ARM projects can reuse parts of our work, and upstream projects receive fixes that reduce everyone's maintenance burden.

This document describes the destination. Implementation and native ARM package builds are underway; target installation, supported releases, performance improvements and hardware acceptance must each be established with evidence. The [implementation status](docs/implementation-status.md) records actual progress. The [roadmap](docs/roadmap.md) and [development sequence](outline.md) cover the route from the initial overlay through all five responsibilities.
