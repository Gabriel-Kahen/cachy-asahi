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
suspend, hibernate, update button, or network polling script. Screenshot bindings
are optional and commented out until explicitly enabled.

## Explicit screenshots to a file

The optional helper uses the existing Wayland session; it does not start another
compositor. Install **grim** for full-screen capture and **slurp** for region
selection on a validated base. Both are absent from the frozen341-package
baseline, so this Source addition does not establish an installed screenshot
workflow, clean native build, compositor protocol support or M2 acceptance.

Run a capture yourself:

```sh
cachy-asahi-screenshot full
cachy-asahi-screenshot region
cachy-asahi-screenshot region --directory "$HOME/Pictures/Private-Screenshots"
```

The default is `~/Pictures/Screenshots`. Missing directories are created0700;
existing directories and their permissions are preserved. The final directory
must already be user-owned and private or be newly created by the helper.
Choose a new `--directory` if an existing shared directory is refused. Symlink
components and parent traversal are refused. No user config is sourced or edited.
The helper temporarily sets its own process umask077 and restores it afterward.
It does not change the shell's umask.

The output is a uniquely reserved0600 PNG. Grim writes to the held private
partial-file descriptor. Successful output is checked for PNG signature, IHDR
and terminator, synced, then linked to a fresh filename without replacing any
existing file; stdout prints its saved path. A private local POSIX filesystem
supporting hardlinks is required. This lightweight check detects empty/truncated
outputs; it is not an independent PNG decoder or image transformation.

Region selection uses slurp with closed stdin, accepting negative display
coordinates and positive dimensions. Esc, empty selection or any slurp failure
produces no capture and never falls back to the full screen. Nonzero slurp status
can also mean a Wayland/setup failure. The helper diagnoses missing tools and
capture errors. It limits selection to120 seconds and capture to30 seconds.
Normal failure, timeout, Ctrl+C or SIGTERM attempts to remove only the reserved
partial whose named inode still matches the held file; replacements are
preserved. An uncatchable termination/power loss can leave a private `.partial`;
no automatic background cleanup or capture is installed. This assumes a
quiescent private directory, not hostile concurrent writers sharing your UID.

To use keyboard capture, uncomment the two screenshot lines in **your separate
opt-in template copy** after installing the tools. Command/SUPER+Ctrl+Shift+S
captures all outputs; Command/SUPER+Shift+S selects a region. Neither conflicts
with the current template; review your own custom bindings before enabling.
Command/SUPER+Shift+3/4 remain workspace moves. No Print/PC-specific key is used.
There is no background capture, clipboard copy, public upload or image editing.

The helper reports errors on stderr; launch it from a terminal to see diagnostics
if a compositor binding does not display them. Disable/remove enabled screenshot
bindings before removing this package's `/usr/bin/cachy-asahi-screenshot` helper.
User screenshots and user config copies remain on upgrade/removal. Installing
this package itself still activates no configuration or capture.

Upgrade replaces only package-owned templates; your copy remains unchanged.
Switch back to your previous session/configuration before removing the package.
Removal deletes package-owned `/usr/share` files and the `/usr/bin` screenshot
helper; a user copy and saved screenshots remain.
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
