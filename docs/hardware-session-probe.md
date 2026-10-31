# Read-only session probe

Run `scripts/hardware/session_probe.py` as the ordinary user inside the affected
Hyprland session before beginning the physical checks in
[hardware-validation.md](hardware-validation.md). It prints a small JSON report
to stdout and never writes a report or configuration itself. Capture stdout to
a new private local file if needed. There are no required nonstandard Python
modules, package changes, privilege helpers, daemon launches or network calls.
Use installed optional tools when present; absence remains visible.

```sh
umask 077
python -B scripts/hardware/session_probe.py > session-before.json
```

Optional identity arguments are `--model-id apple,j413` (13-inch M2 Air) or
`apple,j415` (15-inch M2 Air), `--source-revision` with a full lowercase Git
object ID, `--baseline-sha256` with the SHA256 of the separately retained
baseline, and `--execution-context physical|virtual|emulated|unknown`.
Omitted identities remain null/unknown. These arguments preserve operator
declarations without inferring that they match the running system. The report
also carries the probe's own exact source SHA256, architecture, kernel, actual
page size, and independently observed known Apple compatible ID when available
on aarch64. A device-tree ID does not authenticate physical execution. A
declared/observed model mismatch is reported, never silently corrected.

This complements `capture-baseline.py` and Doctor2 rather than replacing them.
Keep the baseline, exact package/platform set, probe and Doctor2 reports
together. This tool does not re-query package inventories, authenticate a source
checkout, certify a baseline, or assign acceptance results.

## Observations

| Report check | Fixed read-only query and meaning |
| --- | --- |
| `hyprland/version` | `hyprctl -j version`: current compositor version and commit only |
| `hyprland/displays` | `hyprctl -j monitors`: dimensions, refresh, scaling, transform and optional DPMS/disabled/focus booleans; local array indices only |
| `hyprland/compositor-renderer` | Explicit unknown: selected privacy-limited IPC queries do not expose the compositor's renderer |
| `renderer/wayland-gles-client` | `eglinfo -B -p wayland -a gles`: vendor/renderer/version of a brief GLES context connected to this session; software renderer hint |
| Four current-user units | `systemctl --user ... show`: `graphical-session.target`, `pipewire.service`, `wireplumber.service`, `xdg-desktop-portal-hyprland.service` |
| Two system units | Same Doctor2 properties for `speakersafetyd.service` and `asahi-audio.service` |
| `session/logind` | `loginctl ... show-session self`: Type, Class, State, Active, Remote, LockedHint only |
| `audio/graph` | `pw-dump -r pipewire-0`: audio sink/source class counts, node/link state counts, exact known j413/j415 graph node names only |
| Suspend capabilities | `busctl ... CanSuspend` plus bounded `/sys/power/state` and `mem_sleep` reads |

Service queries request only Doctor2's stable `LoadState,ActiveState,SubState`
properties. A service can be observed as not found, inactive or failed. Such
an observation is `checked`, which means obtained, not healthy. The same applies
to `CanSuspend=no` or `challenge`. The tool never requests sleep, lock/unlock,
volume/routing, brightness, service or inhibitor changes.

The GLES query creates a short graphics context using default system driver
selection; it is not a benchmark, window presentation test or proof that the
compositor uses that renderer. Inherited GPU offload/loader overrides are
discarded. Hyprland's broad `systeminfo`, rolling logs, client/window lists,
process inspection and full environment are not requested. Unsupported output
formats remain unknown rather than being guessed. No X11 or offscreen fallback
is substituted for an unavailable Wayland renderer observation.

PipeWire's installed client briefly reads the current graph. Raw graph data,
including names/properties returned by the server, stays in bounded process
memory and is discarded after filtering. Only the table's summary is emitted;
no raw stdout/stderr, client/application names, process IDs, node/link IDs,
device names, routes, host/network identifiers or monitor serials are retained.
Do not save raw `pw-dump` output as a substitute. Counts include the observation
client's possible transient presence and are not a stable graph fingerprint.
Exact known Asahi node presence is useful context but cannot prove signal flow,
active protection algorithms, calibration, audible output or speaker safety.
`speaker_protection` therefore remains `NOT TESTED` even with active services
and known graph nodes. Run Doctor2 separately for default volume/mute.

## Bounds and failures

There are at most twelve commands, each with fixed argv, absolute `/usr/bin`
paths, no shell, no stdin, a two-second whole-command deadline and a combined
stdout/stderr limit of 512 KiB. The shared query allowance is twenty seconds;
later queries become `total-deadline` when it expires. Each command's process
group is signalled only while its unreaped leader reservation is verified;
direct-child reaping has up to one additional second for cleanup. The deadline
includes children holding output pipes after the
leader exits and leaders remaining alive after closing their pipes. Fixed
kernel/device-tree reads are at most 4096 bytes each. Linux uninterruptible
kernel I/O and process creation are not hard real-time guarantees.

Reports distinguish `checked`, `unavailable` and `unknown`, with fixed reasons
for absent executables, missing local endpoints, denied queries, nonzero exits,
stderr warnings, malformed/unsupported output, timeout, output overflow,
observed endpoint replacement, incompatible reaping policy and lost/unverified
child ownership. Partial, truncated or warning-bearing command
output cannot become a checked value. Exit 0 means report collection completed,
including unknown/unavailable observations. Exit 2 is CLI usage failure; an
interruption exits 130 and may leave partial stdout, which is not a valid report.

The standalone CLI requires a single main Python thread and default SIGCHLD
disposition for command queries. An inherited SIG_IGN or custom SIGCHLD handler
is incompatible: commands are skipped before launch and remain unknown with
`reaping-policy-incompatible`. The probe does not silently replace those handlers.
An apparently default disposition is explicitly set to SIG_DFL before launch,
clearing Linux SA_NOCLDWAIT automatic reaping. The existing signal mask is left
unchanged. This is not an embedded API for processes with independent/native
child reapers or concurrent disposition changes.

WNOWAIT observations never reap the leader. Cleanup rechecks ownership directly
before the last possible group signal and reaps only afterward using waitpid,
without Popen's ECHILD-to-zero status fallback. ECHILD, a cached reaped status or
another ownership-query failure disables all subsequent group signals. The
report uses `child-reservation-lost` or `child-reservation-unverified`, no observed
exit status, and an unknown result; leader/descendant retirement is then unverified.
Such a report does not promise cleanup of children after ownership was lost.
The own-process signal policy setup changes no host/session setting.

Clients receive a fresh restricted environment. Current-user IPC is allowed
only through owned sockets under `/run/user/<uid>` with a private mode0700
runtime directory, ordinary directory ancestry and no symlinks. Hyprland and
Wayland environment selectors are validated, used internally and never emitted.
Inherited remote D-Bus, PipeWire, runtime, HOME and loader/config overrides are
discarded. System IPC is pinned to the ordinary root-owned local system bus.
Socket/ancestry identities are checked before and after each client query.
These checks detect observed replacement, not hostile same-UID races or server
authentication. Installed client binaries and system configuration are trusted.
Shader caches are disabled for the renderer query; reading interfaces can
still cause normal IPC, graphics or service bookkeeping.

Every physical check remains `NOT RUN`: login/acceleration, input/brightness,
protected audible audio, headset/microphone, lock/unlock, repeated lid sleep/wake,
preserved applications, external displays and performance/power/thermals.
Complete those checks on each exact M2 model using the existing validation
procedure. Report generation establishes no native ARM build, installed target,
physical M2, performance, release or maintenance acceptance.

## Focused checks

```sh
python -B -Werror::ResourceWarning scripts/hardware/test_session_probe.py
```

Fixtures exercise sanitization, formats, model separation, absent/denied
queries, fixed argv, aggregate deadlines and endpoint replacement. Disposable
real Python children exercise natural retirement, denial/nonzero status,
whole-command timeout with open/closed/inherited pipes, combined-stream overflow,
restricted environments and SIGTERM cleanup. Real temporary Unix sockets test
ordinary ancestry, ownership, symlink rejection and replacement. These are
host controls; they do not establish PipeWire playback, speaker safety or M2
behavior. Execute the live probe separately to observe available host interfaces.

Ten added ownership regressions retain all original 25 controls and cover real
kernel ECHILD after external reaping, cleanup-only loss, cached reaped status,
unverified ownership, last-signal/reap order, ECHILD during final reaping, ignored
and custom SIGCHLD handlers, threaded callers, policy setup failure and actual
Linux SA_NOCLDWAIT normalization. The latter compiles a tiny disposable C fixture
when a C compiler is available; it does not compile or qualify a native ARM tool.
