# Reviewed per-user settings removal

The opt-in `packages/tools/cachy-asahi-first-login-ui02` successor adds the missing
GUI deactivation path to the existing first-login app. Version 0.2.0-1 offers
**Preview removal → Remove reviewed settings** for explicit Fish/Zsh/Hyprland
selections. The current 0.1.0-2 recipe, backend packages, manifests and VM families
are unchanged. The successor is not selected for development or release.

The preview names each path and distinguishes a managed shell block from the
unchanged managed Hyprland copy. Other user lines and unselected modules remain.
An empty file originally created by setup may be deleted. Users must return to
the prior Hyprland configuration before deleting its copy; the app never stops,
launches or selects a session. Removal is still available for owned settings
when their template/program availability is lost.

The bridge invokes the existing Setup8 removal CLI with fixed explicit argv;
it delegates every ownership, journaling and write decision. Preview never
writes. The existing input fingerprints, exact report recheck, two-minute ticket
expiry and single-use consumption also cover removal. Unknown ownership,
pending/migration journals and edited managed content prevent an apply ticket;
a preexisting conflict in any selection blocks the whole selection before apply.
Unmanaged files cannot receive a ticket. A later interrupted removal can resume
through the existing recovery path with its original transaction and roots.

The CLI has no atomic preview/apply compare-and-swap. A writer can race the final
check; Setup8 may preserve a concurrent edited block while applying another
change, or resume a newly created journal. Reported conflicts/recovery therefore
produce explicit attention and require inspection, rather than a claim that all
selected settings were removed. This implementation changes no backend semantics.

Runtime remains the three isolated prefix-relative UI files and its declared
Python/PyGObject/GTK4, FirstLogin 0.1.0-2 and Setup8=0.3.0-1 dependencies. Package
installation/removal adds no autostart, hooks, services, privilege escalation or
user mutations. Only an explicit confirmed settings action delegates `--apply`.
The eight package-owned paths retain the previous package's layout. Check-only
backend fixtures remain exact uninstalled project source snapshots.

Validation lives in the candidate's `RESULTS.md`: real private-HOME backend
checks, relocated/source-hidden delivery and actual private Xvfb GTK button
journeys are distinguished from package dependency solving and assembly. These
checks do not qualify a native build, signed package lifecycle, real login,
Asahi/M2 hardware, performance or release. Native/integrated admission and any
inventory selection remain Root-owned future work.
