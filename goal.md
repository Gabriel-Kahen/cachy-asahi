# The goal of cachy-asahi

Build a fast, polished, dependable Linux experience for Apple Silicon that brings CachyOS's performance philosophy and Hyprland desktop to the MacBook. Make the M2 MacBook Air a first-class Linux development machine, then turn what we learn into a foundation other Apple Silicon and ARM projects can use.

The ambition is a maintained system people can install, work on every day, update confidently, and help improve. The initial package overlay is the first step toward that system.

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

Over time, this infrastructure should make a fuller CachyOS-derived Apple Silicon distribution practical. Pursue collaboration with CachyOS and an official ARM foundation as those opportunities become available.

## Build with the upstream projects

Asahi supplies the essential Apple platform work. CachyOS supplies performance ideas and software. Hyprland supplies the desktop foundation. Preserve their working integrations, credit their contributions, respect their licenses, and return useful fixes upstream.

Help close the gaps that affect everyday use: audio startup, reliable resume, display hotplug, ARM package availability, and consistent updates. Work with the relevant maintainers when a problem crosses project boundaries.

Keep Apple-specific integration distinct enough that reusable ARM packaging and build improvements can benefit other machines. Be precise about the project's independent status; official affiliation must be earned through agreement.

## Use agents to increase engineering capacity

Use coordinated agents for package audits, implementation, build debugging, documentation, and independent review. Give them concrete deliverables, clear ownership, and access to evidence. Maintain one accountable integration process.

Success is measured in working packages and verified user experience. Compilation, a plausible explanation, or an agent's confidence cannot substitute for execution on the target hardware.

## What success looks like

- A new user can follow the installation guide and reach a usable desktop on a supported MacBook.
- A developer can rebuild the selected packages from documented inputs and inspect their provenance.
- The desktop remains responsive under load, with published performance and power measurements.
- Audio, input, locking, and repeated sleep/wake pass the supported machine's validation record.
- Upgrades preserve the working system, and a failed update has an exercised recovery path.
- Contributors can pick up bounded tasks, reproduce failures, and land improvements without relying on undocumented knowledge.
- Other ARM projects can reuse parts of our work, and upstream projects receive fixes that reduce everyone's maintenance burden.

This document describes the destination. The repository currently contains a scaffold; built packages, releases, performance improvements, and hardware support must each be established with evidence. The [roadmap](docs/roadmap.md) defines the first steps toward that destination.
