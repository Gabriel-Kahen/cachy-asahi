# Manage your Cachy-Asahi settings — UI 0.2 candidate

An original, opt-in GTK4 front end for the delivered first-login and Setup8
commands. Open **Set up Cachy-Asahi settings**, select Fish, Zsh or Hyprland,
choose **Preview settings**, review the actions, then choose **Apply settings**.
Activation is disabled when its program/template is unavailable. Previously managed settings remain selectable for removal even after a template is uninstalled. Shell settings take effect in a
fresh shell; a Hyprland configuration copy does not launch or select a session.

To undo selected settings, choose **Preview removal**, review the named paths and
managed-block/copy actions, then choose **Remove reviewed settings**. This calls
the existing authoritative Setup8 `remove --components …` behavior; the UI does
not infer ownership or implement file deletion. Shell removal keeps surrounding
user lines. An empty file originally created by setup can be removed; an
unchanged managed Hyprland copy can be deleted. Unselected managed modules stay
in place. Switch Hyprland to your previous configuration before removal; this
application never stops or changes a running session.

Removal has its own expiring, single-use preview ticket. A conflict in any selected
component blocks the whole preview before an apply call. Edited managed blocks,
changed inputs, unknown ownership and pending/migration journals refuse removal.
Unmanaged user files never receive a removal ticket. Interrupted removal resumes
through the existing pending-recovery controls, using the original selection.
If the underlying helper reports concurrent recovery or preserved conflicts during
apply, the UI reports attention and requires another inspection; it does not say
that the whole selection was removed.

If an interrupted setup change is resumable, use **Preview pending recovery**,
then **Resume pending recovery**. Recovery resumes the original transaction,
not the current checkboxes. Edited files, unsafe journals and migration-owned
transactions remain blocked. Keep your edits and journal; migration recovery
requires the original manifest and the existing configuration migration CLI.

Inspect and preview do not write configuration. An explicit Apply/Remove/Resume click
is the only route to the helper's `--apply`. Installation adds no autostart,
hooks, services, root operations or user files. Removal removes only the eight
package-owned `/usr` files. User configuration remains owned by Setup8 and is
not removed by uninstalling this UI.

Preview tickets are held only in memory, expire after two minutes, and are
consumed on use. Changing the selection or inspecting again invalidates them.
The bridge rechecks the exact report plus bounded hashes/metadata of the three
targets, known templates, state, journal and backend implementation before
applying. This catches edits which leave the CLI's action labels unchanged.
Template locations recorded by existing ownership or a pending journal are
included, even when the current template-root option is different.
Symlinks, nonordinary/oversized inputs and unsafe roots are refused. Setup8
still serializes its own final writes and preserves edits: the existing CLI
does not offer an atomic preview-and-apply compare-and-swap, so other writers
can change files after the last UI check. No stronger guarantee is claimed. Another writer can create a pending transaction
after the last check; the existing helper may resume it. Such a reported recovery
is surfaced as attention, and this candidate does not promise an atomic
preview-to-apply or whole-selection compare-and-swap.

The application runs one fixed-argv helper action at a time, from `/` with a
minimal environment, no shell, fixed backend names and no privilege escalation.
Each helper call has a 15-second deadline and 2 MiB combined output limit. Activation/recovery use the existing schema-1 first-login JSON/exit interface.
Removal validates the exact Setup8 standalone operation/mode/component/action
interface after first-login inspection, with the same frozen path options. It never runs
JSON `next` strings as commands, and does not show configuration contents.
Closing a busy window requests cancellation and waits for worker/process-group
cleanup. Interrupting an apply can leave a journal; inspect on the next open.

Runtime closure is the three installed UI files plus declared Python,
PyGObject/GTK4, exact first-login `0.1.0-3` and Setup8 `0.3.0-1` dependencies.
It has no checkout imports. The launcher uses isolated Python and derives
runtime/backend paths from its installation prefix, including moved prefixes.
`--help` needs no display. Optional `--home`, `--template-root`, `--config-home`,
`--zdotdir`, `--state-dir` preserve the first-login CLI's path semantics; roots
are frozen for the window lifetime. It is intended for an ordinary user.

The source package includes exact check-only copies of the delivered backend
files. They are pinned in provenance, never installed by this package, and
exercise real project helper behavior in private homes. The GUI is independent
of Welcome8 and includes no Welcome source or artwork.
The recipe declares Fish and Zsh as check-only dependencies. Hyprland remains
optional: a missing compositor is an availability hold, not a configuration
conflict. Whole-selection conflict coverage uses the available Fish/Zsh pair.
The optional source-hidden delivery case probes its exact bwrap profile first.
Only positively identified namespace permission/support denial is reported as
NOT RUN, with the command and stderr retained; other probe failures fail the
test. The full source-hidden assertions run whenever the profile is supported.

```sh
python3 -I -B test_bridge.py
python3 -I -B test_delivery.py
python3 -I -B test_gui.py
```

The optional GUI test requires existing `bwrap`, `Xvfb`/`xvfb-run`,
`dbus-run-session`, GTK4/PyGObject and Fish/Zsh; it installs nothing. It opens a
real window and emits actual button/selection signals in a private Xvfb/bus,
with a new HOME/runtime directory, hidden checkouts, private `/tmp` and `/dev`,
and no network. It is outside required package `check()` so a builder without
these optional tools can still run the bridge/delivery controls. A missing
prerequisite is reported as NOT RUN, not a GUI pass.

This is unselected development software. Host private-home/GUI results do not
establish native ARM delivery, a real graphical login, M2 compatibility,
installation or release acceptance. Package dependency solving and actual
package assembly are reported separately in RESULTS.md.

GTK uses the official [Gtk.Application](https://docs.gtk.org/gtk4/class.Application.html)
and [main-loop callback](https://docs.gtk.org/glib/func.idle_add.html) interfaces.

This separate `packages/tools/cachy-asahi-first-login-ui02` recipe builds
`cachy-asahi-first-login-ui 0.2.0-2`. The previous 0.1.0-2 directory and all of its
recorded evidence remain unchanged. The successor is unselected; inherited
native/VM results are not qualification of these new bytes.

The 0.2.0-2 packaging successor binds the fixed FirstLogin 0.1.0-3 backend,
including helper environment/cwd isolation and isolated printed follow-ups.
The UI bridge, GUI and Setup8 fixture are unchanged. The earlier 0.2.0-1
results remain historical and are not relabeled as this candidate's evidence.
