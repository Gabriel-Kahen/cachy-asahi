# Selected desktop application execution

`scripts/workflows/desktop_application_runtime.py` executes one explicitly selected
application from a fresh `desktop_applications.Audit`. Supply the selected desktop
file SHA256, staged environment JSON, and runtime context JSON. The staged tree
and actual execution tree must be trusted and quiescent throughout the call.
This workflow is for reviewed applications; it does not sandbox arbitrary code.

The original desktop parser validates Exec syntax before runtime input expansion.
`%f`/`%u` accept zero or one input in one invocation; `%F`/`%U` expand an ordered
list into separate arguments. An empty selection removes these fields.
`%c`, `%k`, `%i` and `%%` retain their existing behavior. Repeated/mixed input
fields, unknown fields, undefined quoted fields and embedded list fields are
refused. Input text is inserted only after command parsing and is never parsed
again as quoting, fields or shell code. These rules follow the
[freedesktop Exec specification](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html).
This CLI deliberately refuses multi-item selections for scalar fields instead
of launching multiple instances. It does not download remote inputs for file
fields; use local files with `%f`/`%F` and URI-capable applications for remote URIs.

Direct `env` and shell launchers are unsupported; audited application scripts
with bound absolute interpreters are supported. DBusActivatable entries require
`--exec-fallback`; this chooses Exec rather than activating D-Bus. TryExec must
resolve and match actual executable bytes. Hidden and desktop-excluded entries
cannot launch.

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

Explicit file/URI selections are optional. Repeat `--file /absolute/path` and
`--uri URI` in the desired argument order; they can be interleaved for `%U`.
Selections without a matching field are refused, preventing silent input loss.
A maximum of 64 inputs is accepted. `%f`/`%F` accept local files and approved local
file URIs. `%u`/`%U` convert `--file` inputs to canonical file URIs and pass accepted
`--uri` values exactly. A literal percent, whitespace, Unicode or shell punctuation
inside an input remains data in one argv element.

```sh
# The selected entry contains Exec=example %F
python3 -B scripts/workflows/desktop_application_runtime.py \
  --root /private/application-snapshot --environment /private/audit-environment.json \
  --context /private/runtime-context.json --select example.desktop \
  --entry-sha256 HASH_FROM_SELECTED_DESKTOP_FILE --ready-marker READY \
  --file '/private/input one.txt' --file '/private/second "quoted" file.txt'

# The selected entry contains Exec=example %U; the application may access its URI.
# Tests use harmless argv-only fixture programs and example.invalid addresses.
python3 -B scripts/workflows/desktop_application_runtime.py \
  --root /private/application-snapshot --environment /private/audit-environment.json \
  --context /private/runtime-context.json --select example.desktop \
  --entry-sha256 HASH_FROM_SELECTED_DESKTOP_FILE --ready-marker READY \
  --file '/private/input one.txt' --allow-uri-scheme https \
  --uri 'https://example.invalid/document?q=one%20two&literal=%25f'
```

Every `--uri` scheme requires explicit `--allow-uri-scheme file`, `http` or `https`.
No other schemes are supported. `--file` itself grants local-file selection,
including conversion for URI fields, without requiring the URI flag. URI policy
rejects raw controls/spaces/backslashes, malformed percent escapes, credentials,
invalid ports, malformed authorities and encoded authorities. HTTP(S) scheme
matching is case-insensitive while the supplied URI spelling is preserved. HTTP(S) must have a hostname. File URIs
must be canonical local `file:///...` values without authority, query or fragment;
`localhost`, network shares and ambiguous spellings are refused. The launcher
never fetches URIs, resolves DNS or opens a browser; an actual selected application
may act on an explicitly supplied remote URI. HTTP(S) input receipts say
`URI_PASSED_WITHOUT_FETCH` and carry no invented remote content hash.

Local files must have normalized absolute UTF-8 paths with no symlink component.
Only regular files are read. Each is capped at 16 MiB and each verification pass reads at most 64 MiB.
A successful selection must leave one byte of budget for an EOF check, so its
combined file size must be below 64 MiB; zero-length pseudo-files with hidden
content are refused. Reads that later fail identity checks still consume budget.
Descriptor and pathname identity are checked during hashing; byte hashes and
metadata are checked again immediately before launch and recorded after it.
These checks assume trusted quiescent paths and do not prove which bytes an
arbitrary application consumed. File contents are never copied into reports.
Local identity/byte changes or disappearance retain the process result and input
receipts; an otherwise successful workflow becomes `INPUT_CHANGED`, with its
original result in `application_status`. An editor's intentional save therefore
needs separate acceptance rather than becoming an unchanged-input PASS.

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
`CANCELLED`, `RETIREMENT_UNKNOWN`, `SUPERVISOR_FAILED`, `INPUT_CHANGED`, `REFUSED`, and `NOT_RUN`.
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
