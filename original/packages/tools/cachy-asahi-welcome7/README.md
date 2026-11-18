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

The Management page has three optional actions with fixed argument vectors:
`/usr/bin/cachy-asahi-doctor --json` and
`/usr/bin/cachy-asahi-orphans assess`, and
`/usr/bin/cachy-asahi-dns --json profiles`. Each runs as the ordinary desktop user,
only after a click. During a check, static “Running check…” text and a disabled
action button show the running state without continuous spinner redraws.
Missing tools have disabled buttons. Root execution is
refused. There is no startup scan, shell, PATH lookup, privilege escalation,
network request, install, removal, apply action or Apps launcher.

Reports provide observation/candidate counts with unknown, unavailable and
refused states preserved. Malformed or unsupported JSON produces no assessment
conclusion. Raw reports are plain text in an initially collapsed expander with a
64 KiB Doctor/DNS preview cap and an 8 KiB Orphans preview cap, each with an explicit
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
>=3.24 and GLib >=2.74 (GIO is supplied by GLib). Doctor, Orphans and DNS2 are optional
runtime dependencies. The source snapshot is local original MIT code pinned by
SHA256; the coordinator selects the Git freeze. This successor is 0.1.0-5.
Historical 0.1.0-1/0.1.0-2/0.1.0-3/0.1.0-4 native/GUI evidence does not validate this successor. See the
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

## Welcome5: stored DNS profile discovery

This alternative recipe builds cachy-asahi-welcome 0.1.0-5 at the same installed
paths; it upgrades Welcome4 and does not coinstall with it. Doctor and Orphans
remain unchanged. The third Management action runs only when clicked, as an
ordinary user: `/usr/bin/cachy-asahi-dns --json profiles`. Install optional
`cachy-asahi-dns>=0.1.0-2` to enable it. Availability observes its bounded,
ordinary installed source-provenance.json package/version declaration; this is
metadata, not an execution or integrity guarantee. Missing, malformed, old or
unsupported version declarations disable the action. No NetworkManager query
runs at startup. Epoch/prerelease versions are unsupported and disable it.

The result lists stored UUID, connection type and display name as plain text.
Control and invisible formatting characters are escaped; names beyond 256
characters are visibly shortened. The parser refuses unknown schemas, duplicate
UUIDs, extra fields, ambiguous multiline names and more than 64 profiles. It
never displays passwords or full profiles. Results are held only in memory.
This is stored-profile discovery: no preview, apply, activation, reapply, write
or privilege helper is available. It makes no live DNS or connectivity claim.

The original 30-second, 1-MiB supervisor and cancellation/retirement rules remain
in force. DNS2 performs two individually bounded 15-second queries, so a
legitimate slow discovery can reach Welcome's unchanged timeout and show a
bounded refusal. No automatic retry occurs. This source/staged implementation
does not establish a native Welcome5 build or real desktop/M2 acceptance.

## Welcome6 candidate: optional visible boot history

This separate, unselected recipe builds Welcome0.1.0-6 at the existing paths;
it upgrades Welcome5 and does not coinstall. Its optional Boot history panel
runs exactly `/usr/bin/cachy-asahi-boot-report list`, only after a user click,
through the same30-second/1-MiB supervisor, cancellation and retirement rules.
Install optional `cachy-asahi-boot-report>=0.1.0-1` to enable the button.
No helper runs at startup. No shell, export, pstore read, elevation, system
mutation, bootloader action, or automatic retry is offered.

Only caller-visible boot IDs and journal indices/timestamps are displayed.
Empty output is not proof of absent history. Missing tools, inaccessible or
unavailable journals, unsupported/invalid JSON, timeouts and output limits
remain explicit refusals. History completeness is UNKNOWN and crash diagnosis
is NOT_ESTABLISHED. JSON is fully parsed under existing byte/depth/node bounds;
IDs must be exact unique lowercase32-hex strings and timestamps unsigned64-bit
microseconds. All text uses plain GTK labels/TextView, never markup. Raw previews
retain the existing64-KiB cap; no report is persisted.

All Doctor/Orphans/DNS, first-run/session/user-configuration behavior and owned
installed paths remain. Removal removes only package-owned files; user data is
untouched. The candidate adds no service/hook or mandatory runtime dependency.
Host tests/fixtures establish source behavior only, not native ARM builds,
real journal history, desktop/GUI acceptance or Apple hardware compatibility.

## Welcome7 report viewport successor (unselected)

This separate recipe builds cachy-asahi-welcome 0.1.0-7 at the existing paths.
Each raw management report retains its original native 160px scroller and tree.
A report-specific GtkTextView accessibility subclass preserves parent states and
AtkText behavior while deriving SHOWING from actual translated ancestor clipping
and deriving SCREEN extents from translated widget coordinates plus the original
parent component's backend-reported SCREEN anchor; unavailable anchors stay UNKNOWN.
Hidden/unmapped/clipped reports remain unavailable. The direct ATK dependency is declared as at-spi2-core, already present in the
frozen574 builder. No platform package selection changes. No visibility, ownership,
focus, geometry, report parser or command/output/deadline/cancellation predicate
is relaxed. No accessibility state or screen position is hardcoded.

The private test-management-ui --report-accessibility-tests mode covers actual
translated extents and hidden, collapsed, clipped, unrealized and destroyed states.
The --viewport-fixture orphans|dns modes expose the
actual report tree with fixed inert report data for isolated GTK/AT-SPI controls;
they are never installed and execute no management helper or live query. Host
mechanism controls are separate from fresh native build, installed lifecycle,
Wayland GUI, Asahi boot/hardware and performance qualification. Earlier Welcome5
and Welcome6 evidence does not qualify this successor. Release selection and
inventory remain unchanged pending reviewed native outputs.
