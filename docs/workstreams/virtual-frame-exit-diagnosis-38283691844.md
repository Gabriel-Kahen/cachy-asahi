# Pre-frame process exit diagnosis: run 38283691844

Status: actual native broader run **FAIL**. The guest advanced through IPC
readiness and monitor enumeration, then failed `client/compositor exited before
frame`. No frames or mapped proof client were recorded. This is read-only
source/evidence diagnosis; no guest, receiver, controller, source map, renderer
backend or native dispatch is changed.

## Actual execution

The run used accepted source `387217cac5264ab2494b7841bfcc42f636f4fe7a` and packet
`8fef8a03a58eafba992123690f758bc3e1405ae01a4ffeb26cce0b43ff4d170f`.
The root's public verifier authenticated 33 bundles, 1623 members, 27 export
manifests, 1180 accepted files and 31 summary bindings. Aggregate and observed
aggregate bytes match. Initial integration passed with exit 0; ARM-C01, client
and KSM stages passed, publication passed, and initial/virtual cleanup passed.
The virtual stage and overall aggregate remain failed.

The generic aarch64 TCG guest booted kernel `7.2.10-1-aarch64-ARCH` with 4096-byte
pages. Its standalone llvmpipe GBM/EGL probe verified 4096 pixels. Minimal IPC
attempts returned 6, 6, 6 and 0 at 9441, 15573, 21716 and 23097 milliseconds.
The successful reply was the previously audited empty-text form `[""]`, with
null transport error and empty stderr. Its immediately following ordinary
configerrors command retained the exact same response bytes.

The next successful command enumerated `Virtual-1`, 1024×768 at 74.993 Hz,
DPMS on and not disabled. Then **19** successful `hyprctl -j clients` commands
returned `[]`, each with return code 0, null transport error and empty stderr.
No frame-ready, phase-pass or guest-pass event exists. The joint process check
then failed. Guest elapsed time was 168.244 seconds overall, distinct from the
per-phase IPC clocks. All five owner cleanup records verified absence and
passed; private workspace cleanup passed. These observations establish IPC
request servicing and monitor state, not displayed pixels or a usable session.

## Exact retained data and source

There are 35 public events. Indices 7–10 are IPC probes, 11 their successful
command correlation, 12 monitors, 13–31 the empty client queries, 32–33 retained
logs and 34 guest failure. Earlier events are boot, five setup/probe commands
and GBM pass. Exact decoded snapshots and bindings are held under
`artifacts/reviews/virtual-frame-exit-diagnosis-38283691844/`.

| Record | Bytes | SHA-256 |
| --- | --- | --- |
| All 35 events | 89500 | `4bf9e9d66a1b5e5f7479aafefd1928e44d9743804ae79d02003cae561693a448` |
| Owner result | 8510 | `c87d9033e3c27e211242c7154968a080849f6d652df69af387bd476b80b55ee9` |
| `minimal.log` | 3776 | `51058f9c80eda6b24fa3a42ee12b75d6d00c30c37d8da7439d319f3be8179814` |
| `minimal-compositor.log` | 18968 | `5d246cd8c0478ffd75128e1fdf85934cedc6d17311d01b35f7b28a1e563e36b1` |

`committed-source-binding.json` binds Git blobs read from the actual accepted
commit to the owner receipt's source hashes. Guest SHA-256 is
`84b29d91c50ad7172009135283c05e405c9c1ecf08cfcad45ff3208d048834c3`;
common helper SHA-256 is
`b5099507b27fd9f86259c0096d0128b3a2480c546469312763a84438202fa4c3`.
The audit uses those committed bytes rather than attributing the run to the
checkout's later HEAD. Exact guest/common/controller/prepare/run snapshots and
the committed receiver are retained. Their corresponding working files match
at the start of this diagnosis.

## Process attribution gap

The committed liveness check is:

```python
require(client.poll() is None and compositor.poll() is None,
        'client/compositor exited before frame')
```

That error indicates at least one sampled process had exited. It gives no
return code, PID or role. Python short-circuits the expression: if the client
has exited, the compositor is not polled there. Every preceding successful
client query passed both polls before starting the command, but a process can
exit during or after the final query. The recorded sequence cannot identify
which process exited first, whether both exited, or an exit/signal code.

The client was launched as `wofi --normal-window --show dmenu` with the fixed
prompt and size, supplied two input lines and then EOF. `LoggedProcess`
merges stdout/stderr into a bounded private `minimal-client.log`, draining in a
thread. On the success path, the guest retains that file after client shutdown.
On this failure path, `finally` terminates surviving processes and drains the
collectors but retains only compositor stdout and the private compositor log.
**No `minimal-client.log` record exists in the actual public events.** Neither
its bytes nor its hash can be recovered from the provided result.

The common collector can also kill a process on logging overflow or drain
failure. Its status is not recorded at the failed predicate. The original
liveness error is preserved across later cleanup errors, so a secondary drain
error would not identify the original exited role in the public failure event.
No logging-error cause is established by the retained records.

## Cause analysis

The compositor remained responsive for the retained commands, including all
19 client queries. Its 185-line private log repeats auxiliary EGL-device and
renderer-state warnings, without a retained crash, abort or natural-exit cause.
The prior pinned source audit already established startup paths that continue
after those warnings and a separate main-OpenGL GBM fallback. Their recurrence
does not establish that a renderer failure caused this process exit or that
scanout works.

The stdout log ends with an XWayland disconnect. Because retention occurs after
`finally` may send TERM/KILL to the compositor process group, that line can be a
cleanup consequence. The retained files lack timestamps or a process-status
record tying it to the original failure. It cannot attribute the natural exit.
The standalone GBM probe and monitor response also do not establish a mapped
client or a captured frame.

Matching-version primary
[Wofi source](https://hg.sr.ht/~scoopta/wofi/archive/b85063f5d38b0082dbf4df8e9c4e9c39ab049ab0.tar.gz),
Mercurial revision `b85063f5d38b0082dbf4df8e9c4e9c39ab049ab0`, supports the
supplied normal-window, dmenu, prompt and dimensions options. Its dmenu path
consumes the supplied lines; EOF after two entries does not select the no-input
exit branch. Normal-window uses a GTK top-level rather than requiring its
layer-shell path. Exact primary source files, archive identity, line references
and hashes are held in `client-process/`. Installed version `wofi 1.5.3-1` is
from the actual pacman command, not a locally run client version command.
Distribution patches and binary equivalence were not independently verified.
No actual client CLI/stdin fault is established by this source audit.

A bounded host reproduction executes the exact committed `phase` with two
controlled scenarios: client exits with code 1 while compositor lives, and
compositor exits with code 1 while client lives. Both emit identical public
events and the same liveness exception after 19 empty client queries. Each
private client log exists with 36 diagnostic bytes, and each collector finishes
once, but neither public stream retains the client log. The corresponding
surviving process is then disposed of by cleanup, changing its later state.
An independent fresh-copy replay passes the same two scenarios with
ResourceWarning treated as errors and no PYC files. These are mocked transport,
process and clock scenarios with real temporary paths/sockets/log files; no
Wofi, Hyprland, Docker, QEMU or native guest is executed. They prove the
observation gap, not the actual runtime cause.

No backend replacement, client-argument change or relaxed mapping/frame
requirement is justified by the current evidence.

## Smallest next observation

Propose a diagnostics-only correction after coordinator selection:

1. Sample **both** client and compositor return states at the failed liveness
   boundary before termination; retain fixed role/stage and observed return
   codes separately from later cleanup return codes. A surviving process killed
   by cleanup must not be reported as naturally exited at the boundary.
2. Retain the bounded fixed `stage-client.log` after reaping/draining on failure
   as well as success, using its already allowed filename and existing base64,
   SHA-256, size and credential checks. Preserve the original liveness exception
   if retention fails and report unavailable bytes honestly.
3. Record whether a collector had already reported an output/drain failure,
   using a closed status rather than exporting arbitrary exception text.

The representation should be narrowly reviewed. A concrete minimal candidate
is one failure-only four-field event: `event` fixed to
`pre_frame_process_state`, `stage`, `client_returncode` and
`compositor_returncode`. Stage is minimal/overlay; each return state is null for
observed-running or an exact integer in the existing finite process-code range
-64–255, refusing booleans and extra keys. At least one state must be an exited
integer. Both samples precede cleanup. They record observed states at two sequential
polls, not an atomic snapshot or proof of exact exit ordering. Role is fixed by
field name; argv,
environment, arbitrary paths, exception text and runtime-tree export are
unnecessary. A subsequent cleanup exit code is separate evidence, never a
replacement for this boundary observation. The event remains diagnostic and
cannot grant frame/session success.

Existing collector overflow/drain classification could be added only if its
small closed enum is separately selected; it should not export arbitrary
collector exception strings. Keeping the existing client-log schema and
filename avoids a new log-path grant. The process event itself needs matching
controller projection and closed receiver-schema review before use. This
proposal specifies an observation, not an implemented or accepted event grant.
The original failure reason and all liveness, 45-second mapping, 15-second
capture, IPC, output, mapped-client, pixel-frame and cleanup gates should remain
unchanged. Do not retry an exited client, count output enumeration as a frame,
or switch generic renderer routes until the new evidence identifies a cause.

A subsequent bounded native run could then distinguish a client error/exit,
compositor exit, logging-induced kill or cleanup-only termination. The current
native result stays failed. A reproduction demonstrating a specific client
fault would justify a behavioral fix only after its actual evidence is retained.

## Historical and verification boundary

Run `38259350917` remains a failure at the initial IPC probe, with its private
compositor log unavailable. Run `38274341668` remains a failure at the empty-text
config response, with no frames. The accepted compatibility change explains why
this run advances further; it does not change either earlier actual outcome.

No new native trial is executed by this diagnosis. Generic software-frame,
exact M2/16K, Apple graphics and performance acceptance remain unestablished.
The final receipt binds committed source snapshots, actual evidence, matching
primary client/renderer source audits and both host diagnostic replays. All
production source holds remain unchanged. A first parent replay-summary check
assumed 35 client-log bytes; the actual mock result was 36, and the corrected
summary plus original assumption are retained. The reproduction itself passed.
Root's separate full-run peer review remains independent.
