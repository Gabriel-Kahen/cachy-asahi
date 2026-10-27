# Selected desktop application execution

`scripts/workflows/desktop_application_runtime.py` executes one explicitly selected
application from a fresh `desktop_applications.Audit`. Supply the selected desktop
file SHA256, staged environment JSON, and runtime context JSON. The staged tree
and actual execution tree must be trusted and quiescent throughout the call.
This workflow is for reviewed applications; it does not sandbox arbitrary code.

The command uses the existing desktop parser's no-file-input behavior: `%f`, `%F`,
`%u`, `%U` disappear, `%c` expands the localized name, `%k` is the actual selected
desktop pathname, `%i` emits two arguments when an icon exists, and `%%` is a
literal percent. Unknown fields, undefined quoted fields and unsafe Exec syntax
are refused by the existing parser. No file/URL input API is supplied yet. Arguments
are passed directly to Popen, with no shell expansion. Direct `env` and shell
launchers are unsupported; audited application scripts with bound absolute
interpreters are supported. DBusActivatable entries require `--exec-fallback`;
this chooses Exec rather than activating D-Bus. TryExec must resolve and match
actual executable bytes. Hidden and desktop-excluded entries cannot launch.

Runtime executable, interpreter, TryExec and desktop bytes must match the staged
pins. Symlinked executable invocation names are preserved. In fixture mode the
primary program, PATH, data/config directories and entry Path map below the
staged root. Absolute kernel interpreters still run in the host namespace and
must match their audited bytes. Absolute arguments are not rewritten. This is
why staged execution is supported only for deliberately harmless fixture programs.
Installed modes compare staged pins against `/` instead of treating a staged
root as an installed system. Runtime libraries and arbitrary application behavior
remain outside the static audit's coverage.

Example after integration, with explicit absolute paths and a recorded entry hash:

```sh
python3 -B scripts/workflows/desktop_application_runtime.py \
  --root /private/application-snapshot \
  --environment /private/audit-environment.json \
  --context /private/runtime-context.json \
  --select example.desktop --entry-sha256 HASH_FROM_SELECTED_DESKTOP_FILE \
  --ready-marker READY --ready-seconds 2 --run-seconds 5
```

The environment JSON follows `desktop_applications.py`. A context is:

```json
{"mode":"fixture","work":"/private/fresh-work","display":"none"}
```

`work` must be an existing owned mode-0700 directory with no symlink ancestry.
The workflow creates private home/config/data/cache/runtime/tmp subdirectories.
For headless runs the runtime directory must be empty. Disabled bus/audio endpoint
paths must not exist. Child environment variables come from a closed list; live
user display, bus, audio, preload, credential and shell variables are not inherited.
Session/system D-Bus and audio addresses point to absent private endpoints. No
connection to the user's desktop or bus is made by the workflow.

`Terminal=true` requires explicit `terminal_argv` in the audit environment, ending
in a reviewed `--` or `-e` separator. It is a launcher-specific contract; choose
that separator according to the selected terminal's actual CLI. The application
argv is appended without interpolation. A missing terminal is `NOT_RUN`.

Supported installed-context entrypoints for later coordinator-owned trials:

- `mode: guest` requires ordinary-user aarch64 execution, the existing
  `CACHY_ASAHI_VIRTUAL_GUEST=1` marker and `cachy_asahi_virtual_proof=1` kernel token.
- `mode: native-container` reuses `scripts/integration/desktop.py`'s full disposable
  ARM container guard (read-only root/inputs/runner, isolated loopback, dropped
  capabilities, no-new-privileges, immutable image ID/nonce, no inherited live
  connections/devices). Its guard module must resolve to `/runner/desktop.py`;
  deploy that exact file there and provide a read-only
  `/runner/scripts/integration/desktop.py` symlink to it alongside the workflow
  and virtual helper. Ordinary repository-layout native-container calls refuse.
- For either installed mode, `display: wayland` and `wayland_display: wayland-test`
  select an existing owned Unix socket below the context's private runtime
  directory. The coordinator provisions that private compositor first. The
  workflow does not start a compositor or D-Bus daemon. Fixture GUI requests and
  missing private displays are `NOT_RUN`. The mode gates prevent running this
  installed application path against the live developer desktop.

`owned_process.prepare()` runs before launch. A new session leader and its pipes
transfer directly to the existing `owned_process.supervise()` API, which owns all
waits and signals. An observation-only log consumer timestamps a configured UTF-8
marker in bounded combined stdout/stderr. Readiness must be observed by the
specified deadline; it never proves a mapped window, renderer or usable UI. The
existing guest `mapped_client/query_clients/private_ipc` APIs need a separate
observation/close adapter before window checks can be claimed. Actual apps may
exit naturally, or a separately authorized private-session operator can close
them. A supervisor timeout/kill is never a successful normal-close result.

Run budget is 0.05–30 seconds plus one fixed retirement second. Readiness budget
cannot exceed run budget. Combined output is capped at 128 KiB. Cancellation via
SIGINT/SIGTERM is recorded without adding a second process-control owner; the
frozen run deadline bounds cancellation latency (at most 31 seconds). The sole
supervisor performs retirement. Cancellation does not renew deadlines. Normal
zero exit, an observed marker, complete output and the supervisor's empty-group
observations are all required for `PASS_EXEC_WORKFLOW`. Empty-group observations
do not prove absence of escaped/daemonized descendants; such applications are
outside this workflow's supported lifecycle.

Reports preserve underlying exit, signals, output completeness, ownership,
group census, diagnostics, audit pins and retirement status. Failure states
include `START_FAILED`, `READINESS_NOT_OBSERVED`, `RUN_TIMEOUT`, `OUTPUT_LIMIT`,
`CANCELLED`, `RETIREMENT_UNKNOWN`, `SUPERVISOR_FAILED`, `REFUSED`, and `NOT_RUN`.
An output-overflow cause can coexist with unknown retirement; consult both
fields. CLI exit codes are 0 for workflow success, 1 for executed failure and 2
for refusal/unrun. Output is application diagnostics and can contain sensitive
application data; retain reports inside the private trial's evidence area.

Focused checks after integration:

```sh
python3 -B -m unittest discover -s scripts/workflows \
  -p 'test_desktop_application*.py' -v
```

The development packet includes a retained source view, exact test logs and real
CLI demonstrations using only short-lived private fixture programs. These prove
host workflow mechanics. Installed native ARM apps, actual GUI/window behavior,
physical M2 compatibility, performance and release acceptance remain NOT_RUN.
