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
