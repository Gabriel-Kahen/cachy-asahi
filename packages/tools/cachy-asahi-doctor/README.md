# cachy-asahi doctor

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

There are at most nine queries, each limited to2s and64KiB combined output,
with a20s aggregate query allowance and a1s child-reap wait after a kill signal.
Output/time failures yield unknown. This is cooperative Linux process cleanup;
uninterruptible kernel I/O cannot be made a hard real-time guarantee. Only local
system/user service-manager IPC is used. Arbitrary remote D-Bus/loader environment
settings are not inherited. A missing current-user Unix bus skips user queries;
run from the affected login session to obtain those observations.

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
python -B test_doctor.py
```

Controls use fixtures and mocked process clients. No native package, live service,
physical hardware or performance result is established by these tests. The
architecture-independent recipe is a declaration; native ARM build/CLI and actual
Asahi user-session checks remain separate validation work.
