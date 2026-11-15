# UI 0.2.0-2 with FirstLogin 0.1.0-3 — 2026-11-15

This unselected packaging successor changes the exact backend dependency to
`cachy-asahi-first-login=0.1.0-3` and replaces its check-only implementation with
the genuine 03 archive payload. The archive/recipe/commit and fixture byte pins
are recorded in provenance. The launcher fixture, UI bridge/GUI, all test code,
Setup8 fixture and runtime ownership/operation predicates are unchanged.

Before changing the candidate, a private copy with the real archived 03 backend
passed **38 bridge + 6 delivery checks, zero skips**, plus **16 actual private
Xvfb GTK window/button checks**. These include moved-prefix/checkout-hidden
activation and removal, pending recovery, edit preservation, explicit removal
confirmation and removal of exactly eight UI payload files while retaining HOME.
Exact runtime/helper/test byte comparisons bind that run to the final candidate.
No user desktop or host dependency installation was used.

A fresh final recipe copy also passed all **44 checks** during unsigned
`makepkg --nodeps --force --noconfirm` assembly. Its archive is **26,692 bytes**,
SHA-256 `bd3efa1e04752b2ea8380010f7325b333bf347b7a7379b20de0289e763f9aa16`.
Independent archive inspection confirmed exactly eight regular root:root payload
files (entry 0755, other payload 0644), exact source bytes, and the genuine exact
03/Setup8 dependencies in `.PKGINFO`. Source SHA-256 pins and generated `.SRCINFO`
match. Neither fixtures nor hooks/autostart/services are installed.

Ordinary `makepkg --nobuild --noconfirm` exits 8 because neither exact
`cachy-asahi-first-login=0.1.0-3` nor `cachy-asahi-setup=0.3.0-1` is ALPM-installed
on this host. Dependency-closed build and signed ALPM install/remove remain
NOT RUN. Private filesystem payload removal is not ALPM uninstall. Native ARM,
M2, real graphical login, production trust and release remain unqualified.

Fresh local receipts, GUI JSON/images and both build logs are under
`work/first-login-ui02-backend03-20261115-r1/` in the implementation worktree;
the archive is in `final-recipe/`. They are not claimed as publicly durable.

The historical 0.2.0-1 record below is retained verbatim. Its earlier archive and
local receipts remain unchanged; none of those results are relabeled as 0.2.0-2.

---

# UI 0.2.0-1 development checks — 2026-11-15

This separate unselected successor adds reviewed settings removal. The prior
0.1.0-2 directory, its evidence, backend sources, shared manifests and VM
families remain unchanged. No inherited result qualifies this candidate.

Final host source and installed-prefix checks:

- Recipe `check()` passes **38 bridge + 6 delivery tests, zero skips**. Real
  project FirstLogin/Setup8 fixtures operate on private homes, including shell
  block removal with preserved surrounding user edits, a complete selected-set
  conflict refusal, missing templates, exact Hyprland-copy removal, retained
  unselected modules, stale/expired/single-use tickets, unsafe/pending/migration
  refusal and interrupted-removal recovery through the original journal.
- Delivery includes the actual installed isolated entry's `--help` under
  poisoned ambient Python, relocated runtime, absent-runtime refusal and an
  actual Bubblewrap checkout-hidden activation/removal journey. Another case
  uses the installed bridge for activation→removal, activates a new setting,
  then removes exactly eight UI-owned files from its private prefix while
  preserving every HOME byte. This is payload removal, not ALPM uninstall.
- Optional GUI test passes **16 actual private Xvfb GTK window/button checks**,
  with checkout-hidden moved runtime, private HOME/tmp/dev/bus and no network.
  It includes removal preview without writes, explicit confirmation, stale-edit
  refusal, selection invalidation, selected-only removal, preserved user lines,
  and real removal after a template disappears. Pending recovery and busy-window
  cancellation also pass. Activation/removal preview images were inspected;
  the removal actions and confirmation are readable. No user's desktop is used.

Commands (Python 3.14 host, existing Fish/Zsh/GTK4/PyGObject/Bubblewrap/Xvfb):

```sh
python3 -I -B -Werror::ResourceWarning test_bridge.py
python3 -I -B -Werror::ResourceWarning test_delivery.py
python3 -I -B -Werror::ResourceWarning test_gui.py --output PRIVATE_FRESH_DIRECTORY
makepkg --printsrcinfo
```

A fresh private recipe copy builds with `makepkg --nodeps --force --noconfirm`,
including its real `check()` and `package()` steps. The unsigned `any` archive
is **26,201 bytes**, SHA256
`386c8eea02a5d402b34013f0d79906d24575b7ea0ff9bff5bf408cb9101b3b4f`.
Actual archive inspection finds exactly eight ordinary `/usr` payload files and
three standard package metadata leaves; no hook, service, autostart or check-only
fixture is installed. Source checksums and generated `.SRCINFO` match the recipe.

The ordinary dependency check (`makepkg --nobuild --force --noconfirm`) exits8:
this host has neither exact `cachy-asahi-first-login=0.1.0-2` nor
`cachy-asahi-setup=0.3.0-1` ALPM-installed. Dependencies were not installed on the
host. The successful `--nodeps` assembly does not close dependency solving or an
installed package lifecycle. No signature, native ARM/16K, real graphical login,
Asahi/M2, performance, production trust or release acceptance is claimed.

Private retained outputs are under
`work/first-login-ui02-build-20261115-r2/` in the author worktree: actual build and
dependency logs, `host-package-report.json`, archive in `recipe/`, and GUI
JSON/stderr/images. They are local development artifacts, not a claim of public
retention. The candidate remains unselected pending separately admitted native
and integrated qualification.
