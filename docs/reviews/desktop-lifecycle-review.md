# Desktop lifecycle peer review

Reviewed October 11, 2026. **One material documentation finding; no Lua/API or
package-ownership defect reproduced at Hyprland 0.56.2.** This review does not
accept a release, native ARM build, installation, hardware support or performance.
Only this review file is authored by the reviewer; desktop files, root documents,
user homes, host services and Git state were not changed.

Inputs: the final desktop PKGBUILD/.SRCINFO, hyprland.lua, Waybar JSON/CSS,
Mako config, README/NOTICE/LICENSE, retained package evidence, root
`docs/installation.md`, `docs/baseline.md`, roadmap and reconciled manifest.
The checks below used the x86_64 development host and temporary directories.
Two bounded read-only subreviews checked API/verifier semantics and
runtime-command/platform dependencies; the coordinator worker checked ownership,
metadata, retained artifacts and lifecycle documentation.

## Finding requiring correction

**[P2] Preserve the supported launch wrapper in the TTY fallback.**
[Desktop README lines 28–33](../../packages/desktop/cachy-asahi-hyprland-settings/README.md)
recommend `Hyprland --config …` from a logged-out TTY. At the exact audited
0.56.2 revision, upstream's shipped
[session entry](https://raw.githubusercontent.com/hyprwm/Hyprland/efb50993780079460b0cbed1363e2166a2de1d9f/example/hyprland.desktop.in)
executes `start-hyprland`, and its
[launcher implementation](https://raw.githubusercontent.com/hyprwm/Hyprland/efb50993780079460b0cbed1363e2166a2de1d9f/start/src/main.cpp)
provides watchdog/restart handling and forwards arguments after `--`.
The direct command bypasses that wrapper even though the README also asks users
to preserve their base launcher. This is source-confirmed, not a reproduced
physical-session crash.

Recommend retaining the base's validated launch procedure. If a standalone TTY
fallback is retained and the base supplies the upstream wrapper, its documented
form should be `start-hyprland -- --config PATH`. On a UWSM-managed base, preserve
the existing manager's invocation rather than replacing it with a generic naked
compositor command. Direct `Hyprland --verify-config --config PATH` remains the
appropriate parser check; do not replace that check with the launch wrapper.
Update the package README checksum/.SRCINFO and its build evidence after correction,
since the README itself is a packaged source input. No compositor was launched
by this reviewer to demonstrate the finding.

## Ownership, activation and removal

The recipe and both retained development archives agree on seven regular payload
files, all below `/usr/share`: four templates in `cachy-asahi/hyprland`, a package
README, NOTICE and MIT LICENSE. There is no `/etc`, skeleton, user-home, boot,
firmware, kernel, graphics/audio configuration, service, transaction hook or
session-registration payload. No install/remove hook is declared. The installed
license matches the actual root license byte-for-byte. Semantic `.SRCINFO`
metadata matches the PKGBUILD export; its extra introductory comment is harmless.

Activation is explicit: copy the Lua template to a new user-owned file and select
it through the supported launcher. A temporary-directory reproduction of `cp -n`
confirmed that an existing edited copy is preserved; no actual user home was used.
Package upgrades replace the shared template and leave user copies unchanged.
The guide correctly requires comparing revisions before incorporating changes.

Removal/reinstall documentation correctly distinguishes package-owned files from
user copies and running processes. The core user copy has no active package-file
reference. If the optional Waybar/Mako startup block is enabled, its config/style
paths remain package-owned and must be disabled or replaced before removal.
Neither removal nor reinstall implies editing/deleting that user copy, stopping
already-running applications or removing base dependencies. Reinstallation would
restore templates, with the user's prior copy and launcher choice still owned by
the user. These are reviewed source/file-ownership semantics, **not executed
pacman installation, removal or reinstallation results**. Root installation docs
correctly keep the full guide and transaction pending target acceptance.

## API/version and verifier results

The recipe requires `hyprland>=0.56.2` and `hyprland<0.57.0`; the Lua header pins
`efb50993780079460b0cbed1363e2166a2de1d9f`. The local verifier reports that exact
0.56.2 version/revision. Primary release inspection found 0.56.2 to be the latest
published stable release at review time. No later 0.56.x release was available to
exercise; future patch/VCS versions admitted by the range remain a compatibility
proposal, not verified range coverage. A future accepted base transaction must
freeze the actual package/provider/version set and recheck the config.

Bash syntax, Lua syntax, JSON syntax and all seven local SHA256 sources passed.
The default Lua config and a temporary copy with optional startup lines 40–43
uncommented both returned exit 0 and `config ok` under:

```sh
Hyprland --verify-config --config /TEMPORARY/PATH/hyprland.lua
```

HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_RUNTIME_DIR and working directory were
temporary. `packages/desktop/check-local.py` was deliberately not run because it
writes another worker's retained evidence and performs packaging outside this
read-only task. No compositor/session/daemon launcher or audio/brightness command
was invoked.

The [pinned compositor verification branch](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/Compositor.cpp#L271-L279)
and [main verification exit](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/main.cpp#L289-L299)
return before compositor startup. Optional `hyprland.start` callbacks are registered
during parsing; their bodies and app commands are not exercised by this result.
No syscall trace was available (`strace` absent), so this execution boundary is
supported by inspected source and verifier results, not process-trace evidence.

Source review also confirms the used monitor/config/bind/dispatcher forms,
case-insensitive keysyms, repeating/mouse flags, directional/workspace focus and
workspace window movement. Parsing does not prove physical Command/SUPER mapping,
input event delivery, rendering, or invoked program behavior.

## Commands, dependencies and protected platform

| Config behavior | Source/dependency review | Remaining target check |
| --- | --- | --- |
| Alacritty terminal, Wofi drun, Swaylock | Each invoked program has a declared runtime dependency | Display/input/PAM behavior, lock/unlock and resume; no idle/lid locking is supplied |
| `wpctl` volume/mute | WirePlumber declared; uses default session sink, upper volume ceiling 1; no ALSA Master/mixer command, profile reset or protection bypass | Effective DSP route and functioning protected Asahi audio stack; default sink can vary with headset/external devices |
| `brightnessctl` | Declared; selects backlight class with bounded lower value, no Intel device name or keyboard-LED assumption | Exact panel selection, permissions, key events and usable brightness range on each M2 |
| Waybar/Mako | Optional dependencies; startup disabled by default and user must avoid duplicate base-managed processes | Enabled callback execution, Waybar modules, notification ownership, startup/reload/resume |
| Portals and polkit | Optional integration candidates; no automatic agent/unit startup, enablement or replacement | Which providers/agent the actual base manages, environment propagation and readiness; missing base setup must be resolved before activation |

No material missing direct-command package dependency was found. Official ARM
metadata and the desktop audit identify available dependency entries; that does
not establish a trusted, complete transaction on the selected Asahi snapshot.
The exact Hyprland/Aquamarine/Mesa/provider compatibility set, dependency hooks,
ownership conflicts and optional feature builds still require the base inventory.
Do not install a generic graphics/kernel replacement to satisfy this recipe.

The volume binding is compatible with retaining existing session routing, but
`wpctl` and a 100% ceiling alone cannot certify speaker safety. Asahi's
[audio stack documentation](https://asahilinux.org/docs/sw/audio-userspace/)
and [asahi-audio requirements](https://github.com/AsahiLinux/asahi-audio/blob/main/README.md)
require the appropriate DSP/protection integration and functioning speakersafetyd.
This package neither provisions nor changes that stack. Verify its actual target
state and route before treating volume-key behavior as accepted. No audio was
played, speaker mixer changed, service restarted or power control written.

## Base-session contract and acceptance limits

The Lua template explicitly imports none of the prior base config. Therefore
startup helpers/env/portal-agent setup previously embedded in that config will
not be inherited merely because the same executable is selected. This is a
conditional integration gap, not proof that the unknown target base is broken.
The root guide correctly requires preserving the session manager and portal/
authorization setup; no accepted base record demonstrates how that happens yet.
[UWSM's primary documentation](https://raw.githubusercontent.com/Vladimir-csp/uwsm/master/README.md)
explains its environment, activation and graphical-session lifecycle contract.
Freeze the base launch mechanism and which processes it owns before choosing
configuration-specific startup. Do not treat the optional callback's successful
parse as readiness, duplicate-process prevention or service startup evidence.

The baseline contract is appropriately explicit: protected Asahi platform
components, exact model/version inventory, recovery prerequisites, predeclared
boot/login, lock, suspend and lifecycle counts, and separate 13-inch/15-inch
acceptance. No conflict with its protected-stack rules was found in package-owned
files or active config commands. The launch documentation finding above should
be corrected before the guide is used for target validation.

**Still NOT RUN:** clean native ARM builds/rebuilds; actual target dependency and
ownership transaction; session-manager/portal/polkit startup; package-manager
upgrade/remove/reinstall; physical keyboard/trackpad/scaling/notch behavior;
panel brightness permissions; GPU acceleration; protected speaker/headset/mic
routing; locking/lid/resume; network/Bluetooth; external displays; controlled
failure recovery; M2 Air 13-inch and 15-inch validation; performance/power trials.
None of these gates is satisfied by this peer review or the local verifier.

## Review input identity

SHA256 for the material desktop inputs at review:

| File | SHA256 |
| --- | --- |
| PKGBUILD | `0b3d54b8b813468d3df721ce1552650c493c719ce5f80de928211a8058150114` |
| hyprland.lua | `f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b` |
| README.md | `0457d280621cabdf46528fc91bf8cca9f3e343e555c01e33e2ec2c517f834a1c` |

Read-only artifact inspection (`scripts/checks/package_checks.py` module) passed
both retained desktop archives: seven regular payload files, no `.INSTALL`, ELF,
protected path or static error. Raw-byte metadata equality initially rejected the
manual `.SRCINFO` comment; semantic field comparison passed and no metadata drift
was reported as a defect. Source peer checks and this document report actual
results without changing the reviewed package or its prior evidence.
