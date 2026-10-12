# Complete-port implementation and feasibility plan

Current implementation route: start with the existing-Asahi overlay, then deliver all five responsibilities R1–R5 in `goal.md` through roadmap M5–M9. A complete maintained CachyOS-derived ARM port is the required destination. The capacity audit selects package coverage, dependency sources, platform ownership and installation approach; it cannot substitute an overlay or written decision for the port. A full rebuild of every Arch package, replacement of Asahi's drivers and a custom macOS partitioner are not prerequisites in themselves.

## Evidence available

- Four original opt-in configuration/setup candidates exist. The packaged runtime setup/removal helper is implemented and has local source tests and native package build evidence. Broader CachyOS desktop/shell/settings bundles have explicit source-license, dependency, configuration or platform risks. Kernel-manager and hardware detector remain deferred.
- The chosen base is Asahi ALARM. Its exact installed transaction, signed retained snapshot and compatibility set have not been captured. Public repository metadata is availability evidence, not a working target result.
- The development host is x86_64 with Docker. Hosted native ARM CI has executed all four configuration/setup package build pairs and byte comparisons, as recorded in `docs/validation/native-arm.md`. Neither exact Air is verified reachable; the configured Pi connection timed out.
- Source build/inspection, staging/signing and measurement tooling is locally tested. Native development artifacts exist, but a supported endpoint, production signing custody, independent onboarding, physical recovery and a maintenance release remain unfinished.
- Ongoing maintainer availability and release incident coverage are unassigned. Agent workers provide bounded engineering capacity; that does not establish a staffed distribution operation.

This evidence supports the overlay as the first delivery stage and a foundation for expanded ARM builds. It does not establish a sustainable full port or official upstream affiliation. Any resource shortfall remains an owned blocker to the long-term goal.

## Required feasibility audit

| Area | Evidence to collect | Owner / next action |
| --- | --- | --- |
| Package coverage | Exact requested applications/dependencies, missing ARM recipes, license/source closure, platform ownership, coordinated update groups | Coordinator/package owners: derive from actual supported desktop and development workloads |
| Build cost/capacity | Native wall time, peak memory, storage/log/artifact sizes, reproducibility, rebuild frequency, security-update turnaround | Build owner: measure clean native runs rather than extrapolating x86 data-only assembly |
| Repository operations | Real retained/signed snapshot, public endpoint, trust/freshness/withdrawal behavior, capacity and backup/retention costs | Release owner/custodian: establish and exercise the overlay endpoint first |
| Maintenance | Named coverage, available builder/hardware windows, triage/response, signing custody/rotation and a subsequent release | Coordinator/ongoing maintainers: demonstrate sustainable repeated operation |
| Platform integration | Exact boot/kernel/firmware/graphics/audio ownership and update obligations, supported model records and core failures | Desktop/hardware owners: close both Air records and preserve working recovery |
| Installer | Asahi integration route, macOS/APFS boundaries, boot/upgrade/recovery, failure tests and supported-model clean installs | Coordinator/installation owner: implement the complete journey; reuse the Asahi installer or qualify new tooling separately |
| Upstream relationship | Actually submitted reproductions/fixes and acknowledged collaboration/ownership, with response status | Reuse/upstream owner: return reviewed findings; do not imply affiliation or guarantee acceptance |

No hosting price, release staffing, native throughput or installer reliability is inferred. Capture actual costs/capacity and identify the responsible operators before revisiting the decision.

## Required implementation path

1. Establish the maintained overlay baseline, close its target execution gaps and record real operational capacity. Begin independent full-port audits as soon as their inputs exist; overlay acceptance is not full-goal acceptance.
2. Deliver M5/R1: declare broader base/desktop/application coverage and dependency closure; maintain ARM recipes, signed consistent package snapshots and update/rebuild operations.
3. Deliver M6/R4 and M7/R2–R3: port the applicable Cachy tools and defaults, evaluate native tuning, and maintain the coordinated Asahi platform with measured correctness/energy/thermal results and recoverable updates.
4. Deliver M8/R5: integrate the complete new-user installation path, trust setup, upgrades and recovery on both Air sizes. Choose reuse of upstream installation components or separately qualify any new installer.
5. Deliver M9: accept A01–A15 against the integrated full-port release, including independent onboarding, both-size final results and a subsequent full-port maintenance release. Record official collaboration separately without assuming its outcome.

Acceptance entry A11 remains unfinished until the implementation/resource plan has operational evidence and owned corrective tasks. Completing A11 does not complete A12–A15 or the full-port goal.

## Active nonphysical execution

The coordinator integrated the user's expanded scope revision `506f259` and
assigned independent M5 coverage, M6 tool functionality, M7 native trial design
and M8 installation-route audits. Ownership is in `docs/orchestration.md` and
next actions are in `docs/backlog.md`. A connected native software batch will
exercise real signed changed-package upgrades, rollback/trust rejection,
configuration lifecycle, installed payload verification and developer onboarding
in disposable containers. Source reviews have reproduced corrective findings;
actual new integration execution remains NOT RUN until those repairs and the
frozen source handoff pass review. Neither that generic ALARM builder nor its
inventory establishes the chosen Asahi target transaction.
