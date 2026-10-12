# Fuller-distribution feasibility decision

Decision: retain the existing-Asahi overlay route for current implementation. Do not start a full ARM repository rebuild, replacement platform stack, macOS partitioner or custom installer in this batch. This is a provisional scope decision from the source/resource audit, **not completed full-goal feasibility acceptance**.

## Evidence available

- Three original opt-in configuration candidates exist; a narrow runtime setup/removal helper and package are being implemented. Broader CachyOS desktop/shell/settings bundles have explicit source-license, dependency, configuration or platform risks. Kernel-manager and hardware detector remain deferred.
- The chosen base is Asahi ALARM. Its exact installed transaction, signed retained snapshot and compatibility set have not been captured. Public repository metadata is availability evidence, not a working target result.
- The verified development host is x86_64 with Docker. No native ARM builder or either exact Air is verified reachable. The configured Pi connection timed out.
- Source build/inspection, staging/signing and measurement tooling is locally tested. No real native artifacts, supported endpoint, production signing custody, independent onboarding, physical recovery or maintenance release exists.
- Ongoing maintainer availability and release incident coverage are unassigned. Agent workers provide bounded engineering capacity; that does not establish a staffed distribution operation.

This evidence supports implementing the small overlay, closing its execution gaps and measuring capacity before expanding repository scope. It does not justify claims of a sustainable standalone distribution or official upstream affiliation.

## Required feasibility audit

| Area | Evidence to collect | Owner / next action |
| --- | --- | --- |
| Package coverage | Exact requested applications/dependencies, missing ARM recipes, license/source closure, platform ownership, coordinated update groups | Coordinator/package owners: derive from actual supported desktop and development workloads |
| Build cost/capacity | Native wall time, peak memory, storage/log/artifact sizes, reproducibility, rebuild frequency, security-update turnaround | Build owner: measure clean native runs rather than extrapolating x86 data-only assembly |
| Repository operations | Real retained/signed snapshot, public endpoint, trust/freshness/withdrawal behavior, capacity and backup/retention costs | Release owner/custodian: establish and exercise the overlay endpoint first |
| Maintenance | Named coverage, available builder/hardware windows, triage/response, signing custody/rotation and a subsequent release | Coordinator/ongoing maintainers: demonstrate sustainable repeated operation |
| Platform integration | Exact boot/kernel/firmware/graphics/audio ownership and update obligations, supported model records and core failures | Desktop/hardware owners: close both Air records and preserve working recovery |
| Installer | Asahi integration route, macOS/APFS boundaries, boot/upgrade/recovery, failure tests and supported-model clean installs | Coordinator: separate acceptance track only if distribution expansion is justified |
| Upstream relationship | Actually submitted reproductions/fixes and acknowledged collaboration/ownership, with response status | Reuse/upstream owner: return reviewed findings; do not imply affiliation or guarantee acceptance |

No hosting price, release staffing, native throughput or installer reliability is inferred. Capture actual costs/capacity and identify the responsible operators before revisiting the decision.

## Conditional implementation path

1. Complete the maintained, measured overlay and all full-goal acceptance entries, including both Air sizes, final reports, repeat release, independent onboarding/contribution and other-ARM reuse/upstream return.
2. Audit the broader package set against that demonstrated capacity; provide missing recipes incrementally, preserving the supported overlay/recovery route.
3. Record a final feasibility decision with the collected coverage/cost/ownership evidence. If the repository expansion is sustainable, scope an installer/integration design and its own destructive-failure acceptance tests.
4. Release any fuller distribution only after its separate installation, boot, update and recovery evidence exists. A speculative new installer cannot close an unfinished overlay requirement.

Full-goal entry A11 remains unfinished until this preliminary decision is revisited with the required operational evidence and an actionable, justified expansion backlog or blocker.
