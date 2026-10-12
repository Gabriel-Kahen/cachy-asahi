# Roadmap

All milestones are currently incomplete. Parallel source audits and implementation are underway; see [implementation status](implementation-status.md). Tooling and recipe source do not substitute for native builds or hardware acceptance.

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

## First parallel implementation batch

1. Audit `cachyos-hyprland-settings` and its current Hyprland dependencies.
2. Audit the Fish/Zsh configurations and proposed system defaults.
3. Specify the clean ARM build environment and package checks.
4. Coordinator merges the audit results and selects the M1 package set.

Full ARM repository rebuilds and a fresh macOS installer are outside the initial milestones.
