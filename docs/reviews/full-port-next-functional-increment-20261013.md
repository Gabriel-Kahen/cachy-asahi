# One next full-port functional increment

October 13, 2026. **Implemented private source proposal: current-user process memory
inspection, cachy-asahi-topmem.** Source and13 finite functional controls pass;
package builds, installation, native ARM/16K runtime, both M2 Air sizes and release
acceptance are NOT RUN. Primary manifests, maps, workflows and Git are unchanged.
This is forward R4/M6 functionality, separate from Root's current baseline,
installer and observation work. It adds no custody or execution-authority framework.

The current outline, roadmap, acceptance contract and package inventory were read
before implementation. R1–R5/M5–M9 remain mandatory on the same maintained release;
four initial configuration/setup build pairs and source models cannot satisfy the
full port. The tools-functionality audit explicitly classifies/usr/bin/topmem as
an optional process-memory diagnostic needing GPL/Lua-luv ABI, permission, race
and error review. No existing project package implements that function. Existing
standard process tools remain available; this increment supplies a project-owned,
bounded current-user replacement for the named applicable Cachy convenience.

This is the one selected capability. It is independently authored original MIT
code under the project's full grant, copied into the private package LICENSE with
an explicit NOTICE. No upstream topmem/Lua/luv source or assets are copied or
relicensed. Reusing the GPL/Lua-luv implementation would need additional license,
module/ABI and dependency work. This replacement uses only Python>=3.11 stdlib,
already the reviewed setup-package runtime dependency. The exact retained native
builder lock contains Python3.14.8-1; desktop-coverage records the corresponding
maintained ARM input. It adds no dependency names and bundles no interpreter.
A selected target still needs its existing Python/base closure verified; builder
presence is neither target installation nor M2 execution evidence.

The actual private implementation is
`artifacts/reviews/full-port-next-functional-increment-20261013/proposal/packages/tools/cachy-asahi-topmem/`.
The command reads bounded Linux/proc/PID/status snapshots, filters by current real
UID, lists the largest VmRSS estimates with deterministic PID tie ordering and
supports --limit1..50 and --json. VmRSS uses kernel-reported KiB multiplied by1024,
with no4K/16K page-size assumption, native ABI or PC kernel/boot backend. Process
names are quoted safely; command arguments are not read. Permission denials,
process exits, unavailable/malformed status and ordinary read errors are counted,
and an entry-limit truncation is visible. It neither kills processes nor alters
KSM, priorities, schedulers, sysctls, services, boot/kernel, networking or user
configuration. There is no daemon, watch loop, upload or history file.

A snapshot is approximate and not atomic. Shared pages can appear in several
processes; rows cannot be summed into unique physical usage, a memory budget,
performance gain or causal application diagnosis. The implementation promises
no PID lifetime or descriptor-generation guarantee. Its scope is current-user
process visibility, not all-system memory profiling or full Cachy tools parity.

Thirteen meaningful controls execute the actual Python helpers/CLI only against
finite private synthetic proc fixtures: descending memory/PID order, current UID
filtering, zero/KiB conversion independent of page size, names with spaces and
command-argument privacy, PID mismatch/duplicate/missing/unit/range failures,
bounded reads, race/permission/ordinary error counts, cancellation/fatal object
propagation, explicit truncation, non-PID/kernel-thread cases, safe terminal/JSON
output, no-scan help/invalid arguments, unreadable roots and unchanged fixture
state. They pass without failures/errors/skips/PYC. An audit hook refuses host/proc
reads and subprocess/spawn/exec/system/socket actors. No actual host or target
process inspection occurred. Package checksum/.SRCINFO and four install-path
checks pass as inert recipe-plan checks; bash/makepkg/native build were not run.

The proposed package installs one0755 command under/usr/bin and docs/full
MIT grant/NOTICE under/usr/share. It has no install hooks, services, autostart,
configuration or state to remove. Upgrade/removal should affect only package-owned
files; actual file ownership/conflict and install/remove behavior remain future
package lifecycle gates. The private PKGBUILD includes its synthetic test check;
source SHA256s and .SRCINFO are exact. A private metadata generation failure
was caught before packaging: a checksum rewrite used sorted JSON key order rather
than the recipe source-array order. The rejected recipe/SRCINFO remain captured;
paired source checksums now pass after correction. Root can review/adopt the one new package
directory without changing existing desktop/shell templates or setup interfaces.

| Full-port responsibility | Contribution and remaining acceptance |
| --- | --- |
| R1 / M5 | One proposed original package using the existing Python/base input. Independent source/license review, two clean native ARM builds, signed retrievable artifacts, release enrollment and maintenance ownership remain required. This original replacement is not a new compiled Cachy derivative and does not alone meet A12. |
| R2 / M7 | Useful resident-memory inspection only. It supplies no benchmark, tuning result, memory/energy budget or performance acceptance; mandatory final-system measurements remain open. |
| R3 / M7 | Preserves the Asahi platform and assumes no page size. Supported-kernel/proc behavior and both exact M2 Air sizes remain runtime gates; no hardware claim. |
| R4 / M6 | Implements one named management convenience as an original replacement with finite controls. Native terminal use and independent A13 workflow validation remain pending; broader shells/session/apps/management remain required. |
| R5 / M8–M9 | Reviewable package paths without user state or hooks. Actual install/upgrade/remove/reinstall, onboarding and subsequent full-port maintenance release remain pending; current installer work stays Root-owned. |

Bounded ownership for adoption: the next tools worker owns only
packages/tools/cachy-asahi-topmem/** after Root copies the reviewed proposal;
Root owns inventory/source-map/workflow/release selection; a separate build worker
owns the existing native package build/lifecycle consumer integration. No extra
platform or setup code is needed for this command. The independent reviewer should
check read-only scope, output/race/error behavior, dependency/license provenance
and recipe paths. Permanent human package maintenance remains unassigned and must
be resolved for A08/M9; this worker is not signing/maintenance custody.

Next concrete completion sequence: independently review the exact private package,
adopt it as a development candidate, build/rebuild it with the existing reviewed
Python builder input, inspect its four installed paths and execute native CLI
fixtures, then test read-only use and package lifecycle on each supported target.
Root must reconcile any eventual manifest entry and release source closure. No
additional planning input prevents this bounded source implementation; real
build/target evidence and accountable maintenance still prevent release acceptance.
All current input hashes, source pins, controls and proposed package paths are
retained under the owned review artifact directory.
