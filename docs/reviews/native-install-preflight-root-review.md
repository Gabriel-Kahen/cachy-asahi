# Native installer P0 bridge independent review

**BLOCKED for source admission: inspected container policy is incomplete.** Actual P0, ABI16.0.1, native fixture26, real-four installation, hardware and M8 remain NOT RUN. The 72 passing source/data tests remain valid bounded evidence, not a live execution grant.

The author checkpoint authenticates as `f9f638d3c726ec1491fcc1be69c53f9225daa1f8f5fe019d6e6c55368f707b89` (9014 bytes, `0644`). Every indexed source/evidence row, the five receiver dependencies and retained prior controls authenticate. The bridge is `fe54490ee05421019d82c8f2b8eb52424fa93993f705ca1cdb95d9e225d47a2c` / 18039 bytes; tests `750409f9a5aa12163b17a7cbb58eaf00ec90ee725d147f8274518e589be97e83` / 19018 bytes; guide `caed0d42…` / 9399 bytes, all `0644`. The issuer capture is exact published `14aa7a9` / `7202c974…`. All five receiver source files match published `8e1b06b`; receiver `fe2becb4…` and embedded profile `b7fbd65e…` are exact. Prior `04813cfd…`/87 controls remain historical and unchanged.

The fresh isolated replay passes **72 tests** (35 bridge, 37 receiver), zero failures/errors/skips, zero forbidden actor attempts and no PYC. Thirteen additional independent control groups complete without actors. Actual published `Sources.module` methods successfully load the captured bridge and receiver; their `graph_namespace` and bridge namespace comparisons pass and refuse keyword-default poisoning. This is loader compatibility, not an admitted Session or native callback.

## Blocking finding: NIP-POLICY1

`container_binding` checks image/name/CID, user/entrypoint/arguments, environment, network, cgroup namespace, privilege/capabilities/devices, resource caps, tmpfs and three mounts. It omits host PID/IPC/UTS namespace and container lifecycle policy. Starting from the accepted container fixture, each independent metadata change remains accepted:

| Inspected HostConfig change | Actual pure inspector result |
| --- | --- |
| `PidMode: "host"` | ACCEPTED |
| `IpcMode: "host"` | ACCEPTED |
| `UTSMode: "host"` | ACCEPTED |
| `AutoRemove: true` | ACCEPTED |
| `RestartPolicy: {"Name": "always"}` | ACCEPTED |

The constructor remains restrictive and does not request these modes. `run` calls this inspector before `start --attach`, so the source/data gate does not reject these substitutions at that boundary. The coordinator confirms these policies are not intentionally permitted. Bind explicit closed/default Docker metadata values and refuse host/shared namespace or auto-removal/restart drift before start; retain the existing restrictive constructor. No broader normalization, privileged/unconfined/SYS_ADMIN or host-root retry is warranted.

These controls establish an inspection omission. They do not establish honest-run reachability, actual daemon substitution, host mutation, actual preflight PASS or a VM escape. No container was created or started by this review. Automatic removal could also cause later explicit removal failure; that possibility does not close the omitted pre-start check. The exact bounded controls are in `independent-controls.py` and `independent-controls.json` under the peer namespace.

## Verified boundaries and unresolved admission

The bridge's live path authenticates the published Session/Sources issuer, own module namespace and registered source graph, then requests actual `original_context`. That context binds the suspended original loader, view/modules, exact controller/image/commit and captured native `main`/Controller.run frames. The bridge additionally requires those observed frames still active and initial exit unset. Fake objects, same-name namespaces, prior receipts and post-return observations cannot supply the declared grant. Pipeline-model PASS tests explicitly replace live custody and daemon events; they are control-flow evidence only.

P0 uses one `min(existing deadline, entry+60)` cutoff, with ten seconds reserved for teardown; no renewed window is supplied. Selection is preflight-only, before fixture GPG/libalpm/ABI/matrix. The raw twelve Config fields are projected without broad coercion; only the receiver's empty-entrypoint sentinel and null-label normalization apply. Launcher zero exit, exact complete preflight scalar public/private agreement and owned cleanup are required. Independent child-disposal flag faults refuse; cleanup still targets the acquired immutable ID. An original KeyboardInterrupt remains the exact first object across a later cleanup error. An owner/source refusal creates no output or actor request.

The pinned transport/actor contract, ordinary ARM/Linux checks, image/input/inventory binding, CID reply agreement, inspect-before-start, owned-ID removal and successful empty ID-filtered listing remain distinct obligations. Missing or malformed CID supplies no safe removal authority. Expiry, drift, CLI close, removal or absence failure cannot promote a durable child PASS; enclosing owner safety cleanup remains necessary. No universal process/resource absence is inferred.

Registration of two bridge/test paths plus the five receiver paths, `sys.modules` installation, retained graph inclusion, existing callback wiring and exact current issuer rebind remain coordinator work. The immutable published issuer refuses concurrent unaccepted integration bytes. P0 can be invoked at the start of the actual native consumer callback before four broader stages; unrelated SVG/Zsh/full-repository PASS is not a prerequisite. No current SDK/source-graph composition or mutable integration handoff is admitted by this hold. A new source review and actual native P0 are required after the narrow correction and final composition.

This reviewer edited only the new review and peer evidence namespace. No source, shared map, workflow, Git, Docker/package/GPG/native/host/network/service/mount actor was changed or run. The exact checkpoint, fresh replay, published-source checks, finite counterexamples and limits are sealed in `artifacts/reviews/native-install-preflight-root-peer-20261012/receipt.json`.
