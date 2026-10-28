# Native virtual IPC execution: run 38274341668

Status: actual broader run **FAIL**. Read-only diagnosis; guest,
adapter and controller code remain held. This review does not rerun the native
trial or establish a captured compositor frame, M2 compatibility, 16K-page
compatibility, graphics acceleration or performance.

## Actual execution and first failure

Run `38274341668` used committed source
`d1e489b8d2c5024e5d25a90231f45164ea08d574` and the 211-file packet
`8fa10f1acef68d3ddbe1e68ea9c11a20cbdb5e5b48f9901483879ee0b22e059b`.
The published aggregate and observed aggregate are byte-identical. Initial
integration passed with exit 0; ARM-C01, client and KSM stages passed, and
publication passed. The virtual stage failed. Its tooling image had 366
packages and preparation completed; all four QEMU capability checks passed.

The native aarch64 controller booted the generic aarch64 TCG guest with kernel
`7.2.10-1-aarch64-ARCH` and 4096-byte pages. Software GBM/EGL used llvmpipe and
verified 4096 pixels. The minimal-session probes then recorded:

| Attempt | Elapsed since readiness polling began | Return code | Error | Actual stdout |
| --- | --- | --- | --- | --- |
| 1 | 9679 ms | 6 | null | Exact previously observed IPC timeout reply |
| 2 | 15807 ms | 6 | null | Same exact IPC timeout reply |
| 3 | 21315 ms | 0 | null | JSON `[""]`, encoded as `[\n\t""\n]\n\n` |

All three probes had empty stderr. The existing readiness predicate requires
JSON `[]`, so the third response raised `runtime config errors`. No successful
ordinary `configerrors` command, frame-ready event, phase-pass event, or guest
pass was emitted. The guest failed after 134.311 seconds overall; this is a
different clock from the per-phase probe times. Both minimal startup logs were
retained. All five owner cleanup records verified absence and passed, and
private workspace cleanup passed. The owner and adapter correctly reported
failure; no frames were published.

There are exactly 13 events: boot, five successful setup/probe commands, GBM
pass, three IPC probes, two retained logs, and guest failure. The current
adapter accepts their closed diagnostic schema and refuses them as a successful
protocol with `guest-ipc-readiness-protocol-refused`. A returned IPC response is
evidence of request servicing; it does not establish mapped clients or frames.

## Hash-bound actual evidence

Source records are under `artifacts/ci/38274341668/development-decoded/`.
This review preserves exact copies and strict-base64/hash-verified log bytes
under `artifacts/reviews/virtual-empty-configerrors-diagnosis-20261012/actual/`.

| Record | Bytes | SHA-256 |
| --- | --- | --- |
| Owner result | 8494 | `085c7bfde34a99b9dc67509a173fc3e2f05dfaf91085a08055b80aa03de6fbde` |
| All 13 guest events | 76617 | `ab406dd9607b7039420dc89d39c037039abd65e273b72336f64805331dcc1422` |
| `minimal.log` | 2881 | `f4f972dece740f26dfba2f2bcc7c033a3b9956e2402c267c2e1daefc55192006` |
| `minimal-compositor.log` | 15139 | `57c3af6adb147ca0d7a6612540b95e8e37dd01ebbd4721efd445e1e0397b0825` |
| Aggregate and observed aggregate, each | See receipt | `caef7c071f422f29b1672f312b1335430d7170c42aaef52b9b1975c455d272c9` |

`actual-receipt.json` also records the public export-manifest hashes, the root's
33-bundle/1623-member strict decoder receipt, committed-source proof, source
holds before diagnosis, and the actual stage claims. `actual-validation.json`
records closed diagnostic validation and successful-protocol refusal. Neither
replaces the original actual data with synthetic events.

The stdout and compositor log identify the Lua configuration path
`/usr/local/share/virtual-proof/minimal.lua`. The runtime instance embeds
Hyprland revision `efb50993780079460b0cbed1363e2166a2de1d9f`. The actual pacman
inventory reports Hyprland `0.56.2-4`, Aquamarine `0.15.1-1`, and Mesa
`1:26.2.4-1`. The reviewed input lock binds the Hyprland package archive to
`4183f5212200625c278eefbbf70c912f1e8803df7ed99a8a2988beb4f4c74e04`.
These observations identify the source audit target; they do not independently
prove that the installed distribution binary is an unmodified build of that
source. Distribution patches and complete build lineage are not audited here.

## Configuration-error contract

The pinned
[Lua error accumulator](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/config/lua/ConfigManager.cpp#L1057)
joins stored error messages and returns an empty string when none are stored.
[HyprCtl's formatter](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/debug/HyprCtl.cpp#L725)
splits that text using `CVarList`, preserving empty entries, and quotes each
entry in its JSON array. The installed-version upstream hyprutils v0.14.2
resolves to `a21e87b878e72ee5dfd375899e8b2ad0d0c4c0e1`; its
[splitter](https://github.com/hyprwm/hyprutils/blob/a21e87b878e72ee5dfd375899e8b2ad0d0c4c0e1/src/string/VarList.cpp#L8)
inserts one empty entry for empty input. The client adds a newline when logging
the returned response. Empty error text therefore produces the exact bytes
observed in attempt 3, including the extra final newline.

A host C++23 harness compiles extracted upstream accumulator, formatter,
escaping and client logging bodies with the actual pinned hyprutils splitter
and string helper. It reproduces those actual bytes exactly. The current `[]`
predicate rejects that source-derived response; the following bounded candidate
accepts it while retaining `[]`:

```python
def no_reported_config_errors(value):
    return type(value) is list and (
        value == [] or
        len(value) == 1 and type(value[0]) is str and value[0] == ""
    )
```

This proposal applies only after successful JSON parsing. It refuses whitespace
entries, nonempty messages, mixed arrays, repeated empty entries, nested values,
null, boolean, numeric and non-list replies. Zero exit, null transport error,
empty stderr, combined UTF-8 byte caps, process liveness, 24-attempt/180-second
bounds, per-stage order and exact ordinary-command correlation remain required.
The original stdout must remain in both correlated events; the proposal does
not rewrite it to `[]`. Monitor, mapped-client, frame and cleanup gates remain
unchanged. Source, packet and guest/controller pin adoption would be separate
coordinator work after selecting an implementation.

The meaning of this predicate is limited to **no reported error text**. The
upstream API is lossy: `addError` can store an empty string, and `getErrors`
then produces the same empty text as an empty internal vector. The splitter
also trims each line, so a stored space-only or tab-only message produces the
same `[""]` wire value. The harness demonstrates all three ambiguities.
Refusing a received `[" "]` is possible; recovering an original whitespace
message already collapsed to `[""]` is impossible from this response alone.
Thus the actual reply is the expected empty-error-text representation and
provides no evidence of a reported nonempty config error, while internal-vector
emptiness remains unproven. This compatibility proposal must retain that
qualification. Stronger validation would need an independently justified parser
status signal rather than assuming the JSON array preserves that information.

The prepared minimal config is one `hl.monitor` call; its source literal is
bound in `actual/package-and-fixture.json`. The corresponding
[monitor binding error paths](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/config/lua/bindings/LuaBindingsConfigRules.cpp#L1104)
report fixed nonempty messages or add source/field prefixes. The source audit
scanned all 74 retained Lua CPP/HPP files. Initial syntax and protected-call
errors have separate loader/traceback paths; no empty or whitespace error path
was demonstrated for this minimal config. The audit does not prove absence
across all Lua internals, external callers, plugins or distribution patches.

The harness exercises nine formatter cases, including real and mixed errors,
and rejects 19 malformed or nonempty parsed payload cases. An independent
fresh-copy host replay passes the same cases and reproduces the actual bytes;
its result and log are held in `independent-replay.json` and
`independent-replay/replay.log`. Explicit predicate assertions return exit 1
for the held `[]` check and exit 0 for the exact two-shape candidate. It executes neither
the full Lua parser nor Hyprland, an ARM binary or a guest kernel. Exact source
bytes/URLs/SHA-256 values and extraction line references are retained under
`source-contract/`; the final receipt binds the source-derived harness results.
These checks diagnose the formatter contract; they do not convert the failed
actual native run into success.

## Renderer observations

The compositor log records virtio_gpu KMS discovery and a preferred 1024×768
mode, followed by repeated `EGL_BAD_PARAMETER`, no-matching-device and auxiliary
renderer-state errors. It also records fallback activity. These messages alone
do not establish fatal compositor graphics failure or a usable frame; the
actual guest stopped at the configuration-response predicate before monitor,
client and frame acceptance. The earlier standalone GBM result covers its
software buffer exercise, not compositor scanout or a complete software session.
Pinned Aquamarine v0.15.1 resolves to
`f31c47a1b9d300847d8fc3108ad959448103dfc1`. Its
[auxiliary renderer lookup](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/drm/Renderer.cpp#L233)
skips devices with no returned DRM filename and returns null when none match.
The warning path in
[DRM initialization](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/drm/DRM.cpp#L1534)
logs a missing auxiliary renderer and returns void;
[backend startup](https://github.com/hyprwm/aquamarine/blob/f31c47a1b9d300847d8fc3108ad959448103dfc1/src/backend/Backend.cpp#L124)
continues without converting that return to startup failure. The primary
same-GPU path can import a buffer to KMS without the secondary-GPU blit branch.
These are available source paths, not proof of an actual usable compositor frame.

Hyprland's separate
[main OpenGL initialization](https://github.com/hyprwm/Hyprland/blob/efb50993780079460b0cbed1363e2166a2de1d9f/src/render/OpenGL.cpp#L289)
already has a GBM fallback when matching an EGL device fails; fatal checks still
apply if that fallback cannot create its display/context. This initialization
precedes late IPC setup in the audited source. The returned actual IPC request
is consistent with startup progressing through that path, subject to the binary
lineage limits above. It does not prove a subsequent buffer import or scanout.
Exact source bytes, Git-blob checks, line references and report are held in
`renderer/source-fetch-index.json`, `renderer/receipt.json`, and
`renderer/report.md` under this review's evidence directory.

Retain the present generic software route for the first validated readiness/frame
attempt. An alternate route is not justified by these warnings alone. A later
actual buffer-import, blit or frame failure could justify a separately bounded
experiment. Headless-only is not an established drop-in route: this source still
needs a DRM-derived allocator and its QMP display-frame proof. Nested Wayland
would require a separately owned guest parent compositor. No backend or frame
gate is changed here.

The actual private log from historical run `38259350917` remains unavailable.
The newly retained log belongs only to run `38274341668` and cannot fill that
historical evidence gap.

## Remaining boundary

Root selects any implementation after this read-only diagnosis. No source,
shared pin, Git ref, native polling or dispatch is changed by this review.
The exact-M2/16K hardware and performance checks remain **NOT RUN**.
