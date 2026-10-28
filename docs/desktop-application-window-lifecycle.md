# Private application window lifecycle

`desktop_application_window_lifecycle.py` adds opt-in window mapping and normal
close observation to the selected application runtime. It requires an existing
private managed Source607/desktop574 ARM guest. It never starts a VM, compositor,
user manager or bus, installs packages, changes services or takes over a GPU.
The ordinary host is refused before bus/socket access.

Adopt the frozen file/URI input packet first. This packet's runtime delta adds
`run(args, launcher=None)`, uses that explicit launcher when supplied, and retains
a launcher-provided GUI result. Default launch, context, output readiness and
input handling remain unchanged. All original supervisor/helper bytes are held.

## Process and window identity

The main thread calls `owned_process.prepare()` before Popen, launches a fresh
session leader and retains exclusive unreaped custody during all window control.
WNOWAIT and PID/group/session/start-tick checks bind the window to that exact
launch. Captured pipes are drained nonblocking under the existing 128-KiB limit.
There is no second thread waiting for or signaling the application.

Only a direct Wayland, single mapped window with PID exactly equal to the owned
leader is supported. The existing virtual guest mapped-client predicate checks
visibility and positive size. Address, class/title and their initial values are
bound too. Detached apps, forwarding launchers, child-PID windows, Xwayland and
multiple mapped windows are refused; no other client is attached or closed.

The retained Hyprland Lua API provides a weak window object. The adapter:

1. Queries clients and, in a protected eval, looks up the selected address,
   validates its complete identity and stores the object under a random nonce.
2. In one non-yielding eval, retrieves the same retained object, checks that it
   remains live and unchanged, invokes
   `hl.dispatch(hl.dsp.window.close({window=w}))`, requires `result.ok == true`,
   and clears its nonce. Strings are Lua byte-escaped data, never interpolated
   code. Expired/nil/mismatched objects fail before dispatcher construction.
3. Observes that the selected owned window is absent/unmapped. An unrelated
   window reusing its address is ignored and never closed.
4. Stops all IPC control and transfers wait custody exactly once to the current
   `owned_process.supervise()`. Only that supervisor signals/reaps the group.

This avoids address-only query/close races, invented compound selectors and the
compositor's nil/focused-window fallback. Title/class changes conservatively
refuse close. The source-supported synchronous object guard is not native proof.
Source excerpts/hashes and exact line references are retained in the packet.

Normal success requires mapping, acknowledged legitimate close, observed
unmapping, natural zero process exit, complete output, no supervisor signals or
timeout/error, and its empty-group observations. Close acknowledgement alone
cannot pass. Prompts/refusal to close remain failures; TERM/KILL is never a
successful normal close. Escaped/daemonized descendants are unsupported.

Mapping/close/unmapping have fixed deadlines within the original run budget,
plus one reserved retirement second. SIGINT/SIGTERM stops window control and
joins bounded retirement. If scheduling or an operation exhausts even that
reserve while custody remains known, one separate one-second emergency cleanup
is attempted, `deadline_overrun` is recorded, and the workflow always fails.
It never renews application/window work. Only lost ownership forbids further
child PID/proc operations and supervision; then exit/retirement remain unknown.
There is no Popen poll/wait/reap or IPC control after custody transfer.

## Private managed admission

The entrypoint composes existing desktop574/virtual/managed guest guards and
managed `runtime_nodes/validate_user` checks. It requires actual aarch64,
UID/GID 23001, the existing guest environment and all desktop574/virtual/managed
kernel tokens, booted systemd without a container marker, dropped capabilities
and no-new-privileges. Readonly bus queries authenticate the exact private bus
owner and root-joined manager PID only after those guards pass.

A regular root-owned contract without symlink ancestry or group/world write is
opened once with nonblocking/no-follow flags. Ownership, mode and bounded bytes
are authenticated through that same descriptor; metadata and pathname identity
are rechecked. Duplicate keys, replacement and malformed contracts are refused.

```json
{
  "schema": 1,
  "api": "hyprland-lua-weak-window-v1",
  "compositor_pid": 1234,
  "compositor_start_ticks": 987654,
  "compositor_sha256": "ROOT_SELECTED_EXPECTED_INSTALLED_BINARY_SHA256",
  "instance": "ROOT_SELECTED_PRIVATE_INSTANCE",
  "wayland_display": "wayland-0"
}
```

These are placeholders. Root must bind the expected binary to the accepted
Source607 image and audited Lua API. The adapter compares actual bytes to that
expected pin; it does not learn trust from a running binary. Compositor start
ticks, private socket device/inode/owner and Unix peer credentials are rechecked
on every request. The peer must be the expected live managed compositor.

Only `/run/user/23001/hypr/<instance>/.socket.sock` and its managed Wayland socket
are used. Private managed bus/runtime/display values replace disconnected runtime
defaults only after admission. Application home/config remain private. No inherited
live connection is used. The new transport permits fixed clients queries and
internally generated bounded evals, with reply/request/count caps and a prelaunch
API check. It exposes no raw user IPC/script option. Unsupported Lua IPC remains
`NOT_RUN`; the existing virtual clients/exit-only allowlist is unchanged.

## Installed guest entrypoint

Use the standard audited snapshot/environment and an installed `mode: guest`
context with its private work area. `display: none` suffices initially; admitted
managed runtime/display values supply the real private compositor connection.

```sh
python3 -B scripts/workflows/desktop_application_window_lifecycle.py \
  --root /private/application-audit-snapshot \
  --environment /private/audit-environment.json \
  --context /private/application-context.json \
  --select supported.desktop --entry-sha256 EXPECTED_DESKTOP_SHA256 \
  --private-contract /root-provisioned/window-lifecycle.json \
  --ready-seconds 2 --close-seconds 2 --run-seconds 5
```

Readiness means observed window mapping. The compatibility `--ready-marker`
value is unused. Existing explicit file/URI selection and verification are
supported. File changes can still yield `INPUT_CHANGED` after an otherwise
successful application workflow. Reports retain launch start ticks, selected
window, mapping/close/unmapping facts, custody transfer and process retirement.

Actual success is `PASS_EXEC_WORKFLOW` with
`gui: PASS_PRIVATE_GUEST_WINDOW_LIFECYCLE`. Models produce
`PASS_MODEL_WINDOW_PROTOCOL`, `passed: false` and GUI `NOT_RUN`; their protocol
result is separate. Unsupported context/IPC is `NOT_RUN`, and startup, mapping,
close, deadline, ownership and retirement failures cannot pass.

## Prerequisite and evidence

This development host is x86_64 and fails admission. No actual application-window
trial, live compositor/bus connection, GPU takeover or system change was attempted.
Root must provide an existing isolated managed ARM guest, accepted compositor
binary with the audited Lua API, root contract, private sockets and a supported
direct foreground application. This packet supplies the runnable entrypoint.

Validation uses process/protocol models, private Unix socket fixtures and the
already-installed Lua interpreter with model window objects. It exercises object
expiry/address reuse, missing objects, title changes, peer/path mismatch, ECHILD,
output bounds, startup, deadlines, emergency retirement and cancellation. Mocked
root authority is unit-only; no privileged filesystem mutation occurs.

Actual native/guest GUI execution, physical M2 validation, performance and release
acceptance remain NOT_RUN/NOT_MEASURED/NOT_ADMITTED.
