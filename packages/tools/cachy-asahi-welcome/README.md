# cachy-asahi Welcome

An original MIT GTK3 desktop companion: Terminal/Files launch buttons, offline
first-run/update/recovery guides, lightweight current-system status and an explicit
read-only Management panel. It is
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

The Management page has two optional actions with fixed argument vectors:
`/usr/bin/cachy-asahi-doctor --json` and
`/usr/bin/cachy-asahi-orphans assess`. Each runs as the ordinary desktop user,
only after a click. During a check, static “Running check…” text and a disabled
action button show the running state without continuous spinner redraws.
Missing tools have disabled buttons. Root execution is
refused. There is no startup scan, shell, PATH lookup, privilege escalation,
network request, install, removal, apply action or Apps launcher.

Reports provide observation/candidate counts with unknown, unavailable and
refused states preserved. Malformed or unsupported JSON produces no assessment
conclusion. Raw reports are plain text in an initially collapsed expander with a
64 KiB Doctor preview cap and an 8 KiB Orphans preview cap, each with an explicit
truncation notice when needed. The runner captures at most 1 MiB combined output and stops
execution after 30 seconds. A per-job Linux subreaper supervisor retires tool
children, including separate sessions, on completion, timeout, overflow or
window close; Welcome holds its application lifetime until cleanup finishes.
Failure to prove retirement is displayed and disables rerunning that check.
Complete bounded JSON validation runs in a background GLib task. “Preparing
report…” keeps the action disabled while the GTK main loop remains available.
Widget updates stay on the GTK main thread. Window close cancels the pending
result and retains application/state ownership until the bounded worker returns;
process supervision and retirement remain separate. No report is saved to disk. Check results do not certify health, hardware,
recovery or safe removal. Existing Doctor and Orphans tools are unchanged.

Build dependencies are GCC, make and pkgconf; runtime dependencies remain GTK3
>=3.24 and GLib >=2.74 (GIO is supplied by GLib). Doctor and Orphans are optional
runtime dependencies. The source snapshot is local original MIT code pinned by
SHA256; the coordinator selects the Git freeze. This successor is 0.1.0-4.
Historical 0.1.0-1/0.1.0-2/0.1.0-3 native/GUI evidence does not validate this successor. See the
associated development handoff for actual host checks, including the Xvfb GTK
integration harness. That harness exercises fixtures and window-close cleanup;
it is not native or installed-tool integration. Successor native ARM, native GUI,
installed lifecycle and M2 hardware validation remain NOT RUN here.

For an explicitly owned build workspace:

```sh
make
make check
make DESTDIR=/absolute/private/stage install
```

`make check` runs seven status fixture cases, five CLI integration cases, bounded JSON report
cases, three report-worker lifetime/buffer/re-entry cases, controlled temporary
process/descendant cleanup cases, and the
read-only source/payload checks. It does not open a GUI or launch Terminal/Files.
The optional `test-management-ui` target builds a GTK fixture integration harness
for an ordinary user in an isolated display/session; it is not required by
`make check` and adds no package dependency on Xvfb.
The private process test seam exists only in a test compile; production has no
program-path override or environment switch. Tests use owned temporary stubs
and do not invoke installed Doctor/Orphans. The linker requests 16 KiB maximum page alignment; inspect actual ELF LOAD
segments and separately execute at a 16 KiB guest/target before claiming that
runtime property. Staged install requires DESTDIR and owns nine files under
`/usr`: one binary, desktop entry, SVG icon, four documentation files and two
license files. No `/etc`, hooks, services, package-manager files or user config
are installed. Removing the package removes only those owned files; existing
user data/configuration remain, and running apps are not terminated.
