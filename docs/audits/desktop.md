# Desktop source audit

Audited October 11, 2026. Scope: `cachyos-hyprland-settings`, desktop assets,
dependencies, and one conservative opt-in alternative. **Source-audited and
locally packaged on x86_64; not built in clean ARM environments, installed, or
hardware-tested. M0 and M1 are not complete.**

## Decision and frozen proposal

Do not select the upstream CachyOS bundle unchanged. Propose exactly one initial
desktop recipe: `packages/desktop/cachy-asahi-hyprland-settings/PKGBUILD`, version
`0.1.0-1`. It packages original Lua configuration plus optional original Waybar
and Mako templates; no upstream CachyOS assets are redistributed. The local
package is a development candidate, not a release-ready replacement for the
upstream package. Original project material is now MIT licensed by the coordinator; upstream asset licensing remains unresolved.

Retain the upstream candidate in the manifest as `deferred-upstream-bundle`
(or the coordinator's equivalent status) with its pin and reasons. Add the
adapted package as `source-implemented`/development-only, record its recipe path,
local source SHA-256 values, Hyprland compatibility proposal, and build,
dependency and hardware gates. The coordinator owns the actual manifest edit.
Freeze this one-recipe set for review; theme, wallpaper, screenshot, login-screen,
idle/power policy, gesture, and upstream-script additions require another audit.

## Immutable references and verification

- [CachyOS package recipe](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-hyprland-settings/PKGBUILD): repository commit `c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`, dated October 10, 2026; recipe `1.4.4-1`, `arch=('any')`, `makedepends=('coreutils')`.
- [CachyOS settings assets](https://github.com/CachyOS/cachyos-hyprland-settings/tree/449635e3718f4f178503682b29b159b0a758e5e7): tag `1.4.4` resolves to `449635e3718f4f178503682b29b159b0a758e5e7` (September 18, 2025). The downloaded [tag archive](https://codeload.github.com/CachyOS/cachyos-hyprland-settings/tar.gz/refs/tags/1.4.4) has SHA-256 `6329177a462392ae018e81572359aaf4c530e4ff4136ef6f170ab33eb043893b` and SHA-512 `64a04b9f0adbc37bd7f6f19a9bd099fc0a30bad3b7e42207653f83cc3ecac9086ee9c3209e8be69d84eeac6a7f3f5611ae85183bd83e39feaa80af046fb4bf86`; the latter **matches the pinned recipe**. Audit downloads are not installed or recipe inputs.
- [Hyprland API example](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/example/hyprland.lua) and [license](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/LICENSE): v0.56.2, commit `efb50993780079460b0cbed1363e2166a2de1d9f`, BSD-3-Clause. These are API references, not bundled code. [Published release](https://github.com/hyprwm/Hyprland/releases/tag/v0.56.2).
- [Current Hyprland documentation source](https://github.com/hyprwm/hyprland-wiki/tree/b8b7239a5e8ffe69203654a53c7aa9206b6786bd): `b8b7239a5e8ffe69203654a53c7aa9206b6786bd`; current examples use Lua and the `hyprland.start` event. The v0.56.2 parser is the concrete compatibility reference for this candidate.
- [Asahi ALARM repository description](https://github.com/asahi-alarm/asahi-alarm/blob/9821995723fa3326553d0d942d0b900173462ea8/README.md): `9821995723fa3326553d0d942d0b900173462ea8`, September 21, 2026. Its package repository must be reconciled with an actual target baseline; the README is not a compatibility result.

[`packages/desktop/upstream-inventory.json`](../../packages/desktop/upstream-inventory.json)
records reference hashes, all 34 upstream files with hashes/modes, repository
observations, direct dependencies, and a repository-name dependency closure.
Local packaged inputs have exact SHA-256 values in the recipe and `.SRCINFO`.
There are no remote sources, floating tags, Git checkout, or `SKIP` checksums in
the adapted build. The repository commit selected by the coordinator becomes
its local-input revision pin.

## License audit

The CachyOS recipe declares **GPL-1.0-only**, but its 1.4.4 archive contains no
LICENSE/COPYING file, and the inspected configurations/scripts do not carry an
explicit license grant. A package metadata declaration is insufficient evidence
of each asset's redistribution rights and required notices. Resolve this with
upstream before importing any assets. No font, wallpaper, theme, or media asset
license is inferred from the desktop recipe; none is copied into the alternative.

The alternative is original project material under the coordinator-selected
MIT license. The package includes the complete root license text as a local,
SHA-256-verified source and installs it under `/usr/share/licenses`. Its notice
preserves the distinction from excluded CachyOS assets; MIT does not relicense
third-party material. Licensing of original material is resolved; successful
packaging still does not satisfy build, dependency, installation or hardware gates.

## Upstream ownership and installation behavior

The upstream `package()` creates `/etc` then copies the entire archive's `etc`
tree into it. There is no `.install`, pacman hook, backup array, explicit systemd
unit, or service-enabling call in that recipe. It both provides and conflicts
with `cachyos-desktop-settings`, so installing it can conflict with another
CachyOS desktop-settings bundle.

Installed tree includes `/etc/profile.d/Hyprland.sh`, `/etc/skel/.profile`,
`/etc/skel/.config/.dmenurc`, Hyprland's main config and 11 fragments, Waybar's
config/style/helper scripts, Wlogout, Wofi, Mako, Swaylock, GTK3/4, Qt5ct, and
Kvantum configurations. Exact filenames and executable bits are in the inventory.
Skel files seed **new** accounts through the base's account-creation behavior;
they do not automatically update existing homes. Later user copies are not
owned by pacman and remain after package removal. The global profile fragment
is package-owned and affects shells which source `/etc/profile.d`; removal
cannot retroactively undo environment values already inherited by processes.

## Dependencies: upstream bundle

Read-only observation from official ARM mirror [core database](https://fl.us.mirror.archlinuxarm.org/aarch64/core/core.db)
and [extra database](https://fl.us.mirror.archlinuxarm.org/aarch64/extra/extra.db).
See the inventory for observation time, database SHA-256 values, package hashes,
licenses, `DEPENDS`/`PROVIDES`, and archive names. Package database signatures and
artifact signatures were **not verified**, and no install transaction was run.
A package-name entry is availability evidence only; it proves neither target
compatibility nor successful dependency resolution on the selected Asahi base.

| Upstream runtime dependency | Observed ARM core/extra version | Initial decision |
| --- | --- | --- |
| `cachyos-alacritty-config` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `ttf-fantasque-nerd` | `3.5.1-2` | Keep only when independently needed by the base. |
| `ttf-font-awesome` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `otf-font-awesome` | `7.3.1-1` | Keep only when independently needed by the base. |
| `awesome-terminal-fonts` | `1.1.0-5` | Keep only when independently needed by the base. |
| `noto-fonts` | `1:2026.10.01-1` | Keep only when independently needed by the base. |
| `noto-fonts-emoji` | `1:2.051-1` | Keep only when independently needed by the base. |
| `ttf-fira-sans` | `1:4.301-2` | Keep only when independently needed by the base. |
| `ttf-hack` | `3.003-7` | Keep only when independently needed by the base. |
| `kvantum` | `1.1.8-1` | Keep only when independently needed by the base. |
| `qt5ct` | `1.9-2` | Keep only when independently needed by the base. |
| `swaybg` | `1.2.2-1` | Keep only when independently needed by the base. |
| `swaylock-effects-git` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `swaylock-fancy-git` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `hyprland` | `0.56.2-4` | Keep only when independently needed by the base. |
| `waybar` | `0.15.0-3` | Keep only when independently needed by the base. |
| `xdg-desktop-portal-hyprland` | `1.4.1-2` | Keep only when independently needed by the base. |
| `grimblast-git` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `slurp` | `1.5.0-2` | Keep only when independently needed by the base. |
| `mako` | `1.11.0-1` | Keep only when independently needed by the base. |
| `wob` | `0.16-2` | Keep only when independently needed by the base. |
| `pamixer` | `1.6-3` | Keep only when independently needed by the base. |
| `wofi` | `1.5.3-1` | Keep only when independently needed by the base. |
| `wlogout` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `wl-clipboard` | `1:2.3.0-1` | Keep only when independently needed by the base. |
| `polkit-kde-agent` | `6.7.5-1` | Keep only when independently needed by the base. |
| `bemenu` | `0.6.23-1` | Keep only when independently needed by the base. |
| `bemenu-wayland` | `0.6.23-1` | Keep only when independently needed by the base. |
| `xorg-xwayland` | `24.1.14-1` | Keep only when independently needed by the base. |
| `capitaine-cursors` | `4-2` | Keep only when independently needed by the base. |
| `cachyos-wallpapers` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `kvantum-theme-nordic-git` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `brightnessctl` | `0.5.1-3` | Keep only when independently needed by the base. |
| `cachyos-nord-gtk-theme-git` | **Absent by package name** | Defer; no substitute recipe is supplied. |
| `network-manager-applet` | `1.36.0-2` | Keep only when independently needed by the base. |

None of the absent names had a provider in the observed databases. An AUR `-git`
recipe or an upstream `arch=any` declaration would not close this gap. No
replacement Git recipes are proposed in the initial desktop set.

The recipe's declared graph is also incomplete for the shipped commands.
Active autostart uses **fcitx5**, **swayidle**, Bash, `mkfifo`/`tail`, systemctl,
and `dbus-update-activation-environment`; not all are listed as direct runtime
dependencies. Active keybindings use **playerctl**, **amixer** (`alsa-utils`),
and `pactl` (Pulse-compatible tooling) rather than the declared `pamixer`.
Waybar's active Spotify module imports Python **gi** and Playerctl's typelib;
weather invokes **curl** and **ping**. Installed optional/custom modules refer
to `checkupdates` (`pacman-contrib`), **paru**, **gammastep**, **btop**, **xsensors**,
**gsimplecal**, and **nwg-drawer**. These may be disabled blocks, so installation
alone does not mean every command runs, but copying the bundle silently makes
those features depend on undeclared tools. The mail module imports an absent
`mailsecrets` module; the screenshot click handlers, window-title script, and
keyboard-layout script referenced by Waybar are absent from the archive.

## Platform and session findings

| Finding in pinned files | Consequence and alternative decision |
| --- | --- |
| Global profile checks NVIDIA/i915/amdgpu modules and sets `GBM_BACKEND=nvidia-drm`/`EGL_PLATFORM` | PC-specific detection has no role on Apple GPU; omit the entire fragment. |
| Waybar hard-codes `intel_backlight` | Does not identify Apple's panel; use backlight-class selection in explicit brightness commands and require target verification. |
| Volume mute calls `amixer sset Master` | Bypasses the session routing abstraction and may target inappropriate controls; use existing WirePlumber `wpctl` routing only. Preserve Asahi audio/protection packages. |
| Wlogout exposes hibernate/suspend/power actions | Availability and wake safety are model-specific; omit Wlogout and all power actions. No automatic lid or idle policy is supplied. |
| Autostart launches Swayidle/Swaylock, Polkit KDE, Fcitx5, NetworkManager applet, Mako, Waybar and Wob FIFO | Existing sessions may already manage these processes. No system/user services are installed or enabled by the alternative; optional bar/notifier startup is commented out. Polkit/portal integration remains a base-session gate. |
| `systemctl --user import-environment` imports the whole environment and background D-Bus commands have no ordered contract | Leave environment and activation handling to the supported base session manager; don't replace it with these calls. |
| Logout bind uses `loginctl terminate-user ""` | Terminates the user's other sessions too; omit it. Session exit remains the supported base launcher/session manager's responsibility. |
| Waybar helper kills every Waybar and loops waiting; update click runs Paru; weather contacts wttr.in | Omit all helpers and custom network/update actions. Original bar contains display-only workspace/clock/network/battery modules. |
| Three-finger down gesture closes active window; VRR/direct-scanout/swallow settings | Do not import destructive gestures or unmeasured graphics/power choices. Input remains small and requires exact-model testing. |
| `.profile` sets TERM/BROWSER/Qt5 theme and hard-coded Cachy wallpaper/theme paths | Omit global/user profile and aesthetic package coupling. Use generic font fallback for optional bar. |

The CachyOS recipe has no Hyprland minimum/maximum version. Its configuration
uses legacy Hyprlang, old window/layer rule forms, `dwindle:pseudotile`, and a
`togglesplit` dispatcher. Its gestures and comments are not a compatibility
contract. On the existing x86 host's v0.56.2 verifier, the pinned configuration
**fails** (exit 1), including removed pseudotile, invalid rule fields, and missing
dispatcher. Source imports were rewritten in a temporary copy to preserve their
structure without accessing the user's real config. See
[`upstream-config-verifier.txt`](../../packages/desktop/evidence/upstream-config-verifier.txt).
No session was launched and no upstream autostart was activated.

## Alternative recipe contract

Required runtime packages: `hyprland>=0.56.2`, `hyprland<0.57.0`, `alacritty`,
`wofi`, `swaylock`, `wireplumber`, `brightnessctl`. Build/check packages: `lua`,
`python`, plus the standard makepkg/base-devel tooling (including `install`).
Optional packages: `waybar`, `mako`, `noto-fonts`,
`xdg-desktop-portal-hyprland`, `xdg-desktop-portal-gtk`, `hyprpolkitagent`.
All have observed ARM package entries; the check-tool versions were Lua
`5.5.1-1` and Python `3.14.8-1`. Compositor version bounds are deliberately
narrow source-audit bounds, not an Asahi-supported version promise.

The read-only dependency-name closure found 236 package records and no missing
names, including **all alternatives** for virtual providers. It does not select
an installable set, evaluate dependency version constraints, or reconcile
Asahi overrides. In particular `opengl-driver` lists stock Mesa, Mesa Amber,
and NVIDIA alternatives; these must never be automatically substituted for
Asahi's functioning graphics stack.

The observed [Asahi ALARM database](https://github.com/asahi-alarm/asahi-alarm/releases/download/aarch64/asahi-alarm.db)
contains `asahi-audio 4.1-1`, `alsa-ucm-conf-asahi 10-1`, `speakersafetyd 2.0.1-1`,
and `mesa-dummy 26.2.3-1` providing graphics dependency names. Its hash is recorded
but signature verification is pending. A dummy provider satisfying `mesa` or
`opengl-driver` says nothing about rendering on an M2. Audit a proposed pacman
transaction against the actual baseline and repository priority before any
installation. Defer this package if its dependency bounds force protected-stack
changes. This worker has not installed or replaced any runtime dependency.

The package contains exactly seven regular files:

- `/usr/share/cachy-asahi/hyprland/{hyprland.lua,waybar.json,waybar.css,mako.conf}`
- `/usr/share/doc/cachy-asahi-hyprland-settings/README.md`
- `/usr/share/licenses/cachy-asahi-hyprland-settings/{LICENSE,NOTICE}`

It has no `provides`, `conflicts`, `replaces`, backup entries, install script,
hook, symlink, executable, ELF object, session registration, or service unit.
Its `arch=any` declaration describes data-only output; it is not an ARM build
result. 16K ELF alignment checks are inapplicable to these seven text files;
the base's compositor and dependencies retain their own hardware/ABI gates.

Opt-in uses an explicitly new user copy and `Hyprland --config`; package
installation itself writes no home files. Upgrades replace templates only.
Removal preserves copies and does not stop running processes. Optional bar
and notifier paths must be disabled or copied before removal; the package README
states this and describes returning to the prior session. Real lifecycle checks
remain NOT RUN.

## Results and remaining gates

- Bash syntax, Lua syntax, JSON syntax and seven source SHA-256 values: PASS.
- Hyprland v0.56.2 x86 verifier on original alternative Lua: PASS (`config ok`).
- Two `makepkg --nodeps --noconfirm` runs in separate temporary directories:
  PASS; `check()` ran, no dependency installation. Existing host, not clean ARM.
- Packaged payload hashes: identical across both runs. Artifact bytes: different;
  `.BUILDINFO` contains different `builddir`/`startdir` paths. No claim of byte reproducibility.
- Shared static recipe/artifact inspector: PASS, no protected paths/hooks/ELF.
- Independent read-only subagent review: no blocking source/recipe issue; verified
  metadata/checksums, platform path ownership, and opt-in/removal contract.
  Its stale-summary finding was fixed; a failure-injection regression check passed.

Evidence is under [`packages/desktop/evidence`](../../packages/desktop/evidence)
and commands/results are summarized in the workstream report. Ignored package
archives and `.log` files are local development artifacts, not release assets.

Before selection/promotion: resolve the real Asahi base transaction/version/provider set; perform two native clean ARM
builds with snapshots and signatures; review installed ownership/conflicts;
test actual opt-in/upgrade/remove/reinstall; record the exact M2 Air baseline.
Then verify GPU acceleration, scaling/notch behavior, Command/SUPER shortcuts,
trackpad, panel brightness permissions, Polkit/portals, notification/bar startup,
Swaylock and resume behavior, Wi-Fi/Bluetooth, protected speakers/headset/mic,
and optional displays on each advertised size. Lock-before-sleep and lid/idle
policy are not supplied by this package and need explicit integration before
daily-use acceptance. No performance or battery gains are claimed.

Follow-up lifecycle review corrected the packaged guide to retain the supported
base launch wrapper/UWSM path, with a conditional `start-hyprland -- --config`
TTY example. The original recipe uses the coordinator-verified project origin,
`https://github.com/Gabriel-Kahen/cachy-asahi`. Final-input source hashes, local
packages, payload comparison and metadata checks were refreshed after these
changes. No session-launch or hardware result is implied.

Subsequent native CI run `38189058133` attempted the desktop metadata gate on
aarch64 and failed before package construction because reviewed `.SRCINFO`
ordered `arch` before `url`. The owned file now matches the retained native
`makepkg --printsrcinfo` form exactly; metadata values, PKGBUILD and payload are
unchanged. Original failure/provenance are retained in the desktop workstream
handoff. Strict source comparison now passes, but corrected native rerun and
successful native package acceptance remain NOT RUN.
