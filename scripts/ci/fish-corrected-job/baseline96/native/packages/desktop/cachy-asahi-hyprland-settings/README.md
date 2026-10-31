# Opt-in desktop configuration

Development candidate only. This package supplies configuration files below
`/usr/share/cachy-asahi/hyprland/`; it installs no boot, graphics, audio, profile,
skel, portal, polkit, PAM, service, or package-manager defaults. Installing it
does not activate a session or change a user's configuration. Publication is
blocked by clean ARM builds, base dependency resolution, and target validation.
Original material is MIT licensed; the complete grant and provenance notice are
installed with the package.

The Lua API was audited against Hyprland **0.56.2**. The recipe limits Hyprland
to `>=0.56.2` and `<0.57.0`; other versions require a new audit. These bounds
are a source-compatibility proposal, not a tested Asahi desktop version set.
If the existing base cannot satisfy them while preserving its platform stack,
defer this package. Do not install a replacement kernel or Mesa to satisfy it.

After package installation on a validated base, copy the template to a **new**
user-owned file. These commands are documentation only and were not run against
a real user home during development:

```sh
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi"
cp -n /usr/share/cachy-asahi/hyprland/hyprland.lua \
  "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua"
Hyprland --verify-config --config "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua"
```

Run the configuration through the base's validated session launcher, passing
`--config` using that launcher's documented argument handling. Preserve the
existing UWSM invocation on a UWSM-managed base. If the base supplies the upstream
`start-hyprland` wrapper and supports standalone login from a logged-out TTY,
the wrapper forwards compositor arguments after `--`:

```sh
start-hyprland -- --config "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua"
```

This fallback is conditional on the validated base; do not bypass its launch
wrapper/watchdog or replace its session-manager contract. The earlier direct
`Hyprland --verify-config` command is a parser check, not a session launcher.

Do not start another compositor inside an active graphical session. The
package does not register a display-manager session or prescribe a replacement
for UWSM. Check the base's existing session manager, environment propagation,
portal selection, and authorization-agent startup before integrating it.

Command/SUPER+Return opens Alacritty; +Space opens Wofi; +Q closes a window;
+F toggles floating; +L calls Swaylock; arrows focus neighbors; numbers select
workspaces and Shift+numbers move a window. Brightness keys select the backlight
class; volume keys use the existing WirePlumber route with a 100% ceiling.
The ceiling does not replace Asahi speaker protection. Locking, brightness,
keyboard mappings, scaling, touchpad settings, and audio remain M2 test gates.

Optional Waybar/Mako templates are included. Install their optional dependencies
and uncomment the startup block only when the base is not already starting
these apps. Their explicit config paths avoid another user's default configs.
Review portal and polkit optional dependencies against the base; this package
does not start or enable them. There is no automatic idle lock, lid action,
suspend, hibernate, screenshot binding, update button, or network polling script.

Upgrade replaces only package-owned templates; your copy remains unchanged.
Switch back to your previous session/configuration before removing the package.
Removal deletes package-owned `/usr/share` files only; a user copy remains.
An enabled optional Waybar/Mako block references package-owned templates, so
disable or replace that block before removal. Package removal does not stop
running processes. Inspect dependency removal separately rather than removing
the base's Hyprland, WirePlumber, or other protected integration.

Local source checks:

```sh
bash -n PKGBUILD
luac -p hyprland.lua
python -m json.tool waybar.json >/dev/null
Hyprland --verify-config --config "$PWD/hyprland.lua"
makepkg --verifysource
```

Only the verifier runs during source validation; it must never be replaced with
a compositor launch in build or research automation. `makepkg --nodeps` can
exercise this data-only recipe on a development host, but cannot establish ARM
dependency resolution or satisfy the clean-build gate. See the desktop audit
and workstream report for actual results.
