# cachy-asahi doctor 0.2.0

This is the separate same-name upgrade recipe `cachy-asahi-doctor2`, producing
`cachy-asahi-doctor 0.2.0-2`. Choose this recipe or Doctor1, not both. The frozen
Doctor1 source/recipe and its native results remain unchanged.

Small original MIT read-only diagnostic. Run as your normal user from the session
where the problem occurs. Root is not required.

```sh
cachy-asahi-doctor
cachy-asahi-doctor --json
cachy-asahi-doctor --output ./doctor-report.json
```

Human observations go to stdout by default. `--json` prints schema1 JSON for
local tools such as a welcome application. `--output` writes that same report to
one explicitly selected new file, mode0600. Its parent must exist. Publication
is atomic, never overwrites an existing file/symlink, refuses symlink directory
components and leaves no partial file at the final name. No directories are
created. Reports are never uploaded. Stdout is visible to its terminal/consumer.

`checked` means a fact was obtained; it includes confirmed absent packages and
failed/inactive services. `unavailable` means a required local tool/interface is
unavailable. `unknown` means the fact could not be established, including query
failure, malformed output, exhausted time or an unrecognized model. Coverage
counts are separate. Exit0 means report generation succeeded, not all healthy;
exit2 means usage/report publication failed. A user interruption stops collection.

The fixed diagnostic reference covers:

- Running architecture, kernel release and actual page size.
- Apple compatible board IDs, with known labels only for `apple,j413` and
  `apple,j415`. Unknown/ambiguous/invalid identifiers remain unknown. The model
  property is read only for availability; its raw contents are not reported.
  Device-tree data does not prove physical execution or supported operation.
- A fixed platform, desktop and project package list via `pacman -Q`. Presence
  and installed versions are reported; absence is recorded only when pacman
  explicitly confirms it. Alternative/optional packages are not an install plan.
- Three fixed system units and five current-user desktop/audio/portal units via
  `systemctl show` requesting only LoadState, ActiveState and SubState.
- Whitelisted session hints (type and boolean Wayland/Hyprland environment
  presence), and executable availability in `/usr/bin:/bin`.

There are at most ten queries, each limited to2s and64KiB combined output,
with a20s aggregate query allowance and a1s child-reap wait after a kill signal.
Output/time failures yield unknown. This is cooperative Linux process cleanup;
uninterruptible kernel I/O cannot be made a hard real-time guarantee. Only local
system/user service-manager IPC and the optional current-user PipeWire socket are used. Arbitrary remote D-Bus/loader environment
settings are not inherited. A missing current-user Unix bus skips user queries;
run from the affected login session to obtain those observations.

## Default audio output diagnosis

Doctor2 adds `audio/default-output` to the existing schema1 report. If `wpctl`
is installed and `/run/user/<current-uid>/pipewire-0` is an ordinary Unix socket
owned by the current user inside their mode0700 runtime directory, Doctor runs
only `/usr/bin/wpctl get-volume @DEFAULT_AUDIO_SINK@`. Every path component is
opened without following symlinks; runtime and socket identities are checked
before and after the query. Missing, unsafe or observed replaced paths yield
unavailable/unknown without exporting their paths or identities.

The child receives a fresh restricted environment with a fixed `pipewire-0`
remote and the verified local runtime directory. Inherited PipeWire remote and
runtime overrides, D-Bus addresses, user config paths, HOME and loader/Python
variables are discarded. The user configuration search path is `/nonexistent`;
ordinary installed system configuration remains in scope. No D-Bus availability
is required for this independent query. Same-UID hostile writers/ABA changes and
the identity of a process serving a socket are not authenticated by pathname
checks. A filesystem check and client connection are not atomic.

A complete successful scalar response such as `Volume: 0.50 [MUTED]` produces
`displayed_volume: "0.50"`, `muted: true`, `default_sink_responded: true`. This is
the rounded level printed by wpctl, not measured sound level or an unrounded
channel volume. Volume above1.00 remains a scalar observation, not a recommended
setting. Muted and zero-volume observations suggest reviewing mute/volume and
output selection in the user's audio controls; Doctor never changes them.

Missing default outputs, client failure, time/output exhaustion, warnings, empty
exit0 responses and malformed/extra output cannot become a valid volume. They
produce no raw stdout/stderr, device names, node IDs, application names or private
connection details. Query failure says **default output was not observed**; it
does not falsely diagnose the particular cause as a missing device. Run from
the affected login session, review output selection and inspect the separate
service observations. A valid volume/mute result does not test graph routing,
playback, audible output, Bluetooth transport, speaker protection or hardware.
The existing20s aggregate query allowance, process-group retirement and private
report publication remain in effect. Reading interfaces can update access times;
this is not a guarantee of zero kernel/service bookkeeping effects.

`wireplumber` is an optional runtime dependency providing wpctl. Its absence
leaves this observation unavailable and does not break the rest of Doctor.
Neither installation nor the CLI invokes a privilege helper, starts services,
plays sound, changes volume/default devices or writes configuration.

No raw journal, process arguments, home/key contents, network MAC/IP addresses,
hostname, machine ID or serial properties are collected. Raw command errors,
D-Bus paths and session signatures are not included. No network requests,
package changes, service starts/restarts/enables, repairs or boot changes occur.
The only optional file write is the requested report. No rendering, audio output,
speaker safety, device functionality, boot/recovery, performance or production
repository trust is certified. Service state and package presence cannot establish
those results.

Installation adds the command and these package-owned documentation/license files.
Removal removes only those packaged files; reports belong to the user and stay
where requested. There are no hooks, services, autostarts, desktop shortcuts,
privilege prompts or configuration changes. A GUI may consume `--json` without
creating a report file; it must keep unknown/unavailable results visible.

```sh
python3 -B -Werror::ResourceWarning test_doctor.py
python3 -B -Werror::ResourceWarning test_audio.py
```

The original sixteen regression controls retain their fixtures, with the new
optional socket observation disabled in those existing scenarios. Eleven new
controls cover scalar parsing/privacy, fixed argv/deadlines, current-user
socket/ancestry/mode/replacement guards and real disposable Unix IPC with
natural child retirement, timeout and output overflow. The disposable endpoint
is not a PipeWire server and does not establish PipeWire protocol or playback.
Other controls use fixtures and mocked process clients. No native package, live service,
physical hardware or performance result is established by these tests. The
architecture-independent recipe is a declaration; native ARM build/CLI and actual
Asahi user-session checks remain separate validation work.

## Offline before/after comparison

Save a report before an update and another after it, then supply both explicitly:

```sh
cachy-asahi-doctor --compare ./before.json ./after.json
cachy-asahi-doctor --compare ./before.json ./after.json --json
cachy-asahi-doctor --compare ./before.json ./after.json --output ./changes.json
```

`--compare` reads only the two supplied files. It does not collect a report,
launch commands, access service managers, query devices or request the network.
It compares the fixed package presence/version, service state, page size,
kernel/architecture, Apple model, session hints and tool availability fields.
Notes, limitations and collection timestamps do not count as observation changes.
Inputs remain private local files; no paths, notes or arbitrary extra fields are
copied to the comparison output. Reports are supplied observations, not signed or
authenticated evidence of a machine or update.

Inputs must be ordinary files, at most128KiB each, with no symlink path components.
The validator accepts complete schema1 reports from Doctor0.1.0 and Doctor0.2.0,
checks exact field sets, fixed check names, values, state/value consistency and
coverage totals, and rejects duplicate JSON keys. Doctor0.2.0's fixed default-audio
observation is supported as an added/removed check when comparing tool versions;
it is never inferred for a report that did not collect it. Unsupported versions,
malformed or incomplete reports and different known Apple model labels are
refused. An unknown model may be compared, but matching labels never prove the
same machine. Input chronology is supplied by the user and is not enforced.

The separate JSON result has `tool: cachy-asahi-doctor-comparison`, schema1,
`changed`, `change_count`, `unchanged_count`, before/after coverage, and `changes`.
Each change names the fixed check and contains before/after `{state,value}`
observations, or null for a check absent from that tool version. `kind` is `value`,
`state`, `state-and-value`, `check-added` or `check-removed`. Normal report JSON and
Welcome's existing schema1 consumer are unchanged; comparison JSON is a separate
result, not an input to Welcome or another comparison.

`checked` includes confirmed package absence and failed/inactive services.
`unknown` and `unavailable` remain explicit; neither means absent or healthy.
Unchanged observations are not a successful update/health certificate. Changes
alone establish neither update causation nor regression, hardware behavior,
speaker safety, recovery or performance. Compare from equivalent affected
sessions and review the observations in context. No automatic repairs occur.

Exit0 means a comparison was generated, including when changes exist. Exit2
means invalid input, usage or publication failure; errors do not echo report
contents. `--output` retains the same private atomic new-file-only publication
rules as ordinary reports and cannot overwrite either input. No output file is
created until both reports pass validation.

```sh
python -B test_doctor.py
python -B test_comparison.py
```

These are host fixture/tempfile checks, including actual CLI subprocess controls;
native ARM builds, installed behavior and physical M2 acceptance are NOT RUN.
No additional runtime dependency, installed file, hook or service is introduced.
