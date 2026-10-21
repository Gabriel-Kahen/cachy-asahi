# cachy-asahi Welcome

An original MIT GTK3 desktop companion: Terminal/Files launch buttons, offline
first-run/update/recovery guides, and lightweight current-system status. It is
independent of CachyOS Welcome/Hello and includes no upstream source or artwork.

```sh
cachy-asahi-welcome
cachy-asahi-welcome --status
cachy-asahi-welcome --status --json
cachy-asahi-welcome --guide first-run
```

CLI status/help/version/guide modes run before GTK initialization and need no
display or session bus. Status uses uname/sysconf plus read-only local pacman
records for six project packages. `installed` means one matching valid record;
`not-found` means no matching directory was observed in a readable database;
`unknown` covers an unavailable database, unreadable/malformed matching record,
or duplicates. This is a best-effort observation, not an atomic package snapshot,
complete inventory, release selection, Apple hardware check or performance claim.
JSON schema version is 1. Missing system fields become null in JSON. Status
returns 0 even when package records are unknown; invalid options return 2,
unavailable guide/display returns 1.

Terminal launches `/usr/bin/alacritty` without a command. Files launches the
installed `/usr/bin/thunar` or `/usr/bin/Thunar` with only a local home file URI.
An unavailable app has a disabled button; a later launch failure gets a dialog.
No command shell, privilege helper, package installation, network check, PC boot
action, configuration activation or support endpoint is supplied. There is no
autostart entry or stored preference. Existing app settings remain in use.

Build dependencies are GCC, make and pkgconf; runtime dependencies are GTK3
>=3.24 and GLib >=2.74. Native target build/CLI/GUI/package lifecycle checks are
**NOT RUN** in this proposal. Source and data are local, versioned originals
pinned by recipe SHA256 values; the coordinator selects the Git source freeze.

The held 574-package inventory already contains GTK3 `1:3.24.52-2`, GLib
`2.90.1-1`, GCC `16.1.1+r12+g301eb08fa2c5-1`, make `4.4.1-3` and pkgconf
`3.0.7-1`. Alacritty `0.17.0-1` and Thunar `4.20.10-1` are optional launch
targets already in that inventory. These metadata observations do not establish
this app's ARM build or GUI behavior.

For an explicitly owned build workspace:

```sh
make
make check
make DESTDIR=/absolute/private/stage install
```

`make check` runs seven GLib fixture cases, five CLI integration cases, and the
read-only source/payload checks. It does not open a GUI or launch Terminal/Files.
The linker requests 16 KiB maximum page alignment; inspect actual ELF LOAD
segments and separately execute at a 16 KiB guest/target before claiming that
runtime property. Staged install requires DESTDIR and owns nine files under
`/usr`: one binary, desktop entry, SVG icon, four documentation files and two
license files. No `/etc`, hooks, services, package-manager files or user config
are installed. Removing the package removes only those owned files; existing
user data/configuration remain, and running apps are not terminated.
