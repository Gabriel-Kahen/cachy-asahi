# Guest IPC receiver integration

Status: receiver implementation and host fixture validation **PASS**. A corrected
native controller/QEMU guest trial is **NOT RUN**. Historical run `38259350917`
remains **FAIL**, with no captured frames; its actual private compositor log is
unavailable. See [guest diagnosis](virtual-guest-ipc-diagnosis.md) for the recorded
first failure, pinned upstream audit, and guest-side correction.

## Receiver grant

The controller adds only `ipc_probe` to its fixed event projection allowlist.
The adapter accepts exactly eight fields: `event`, `stage`, `attempt`,
`elapsed_ms`, `returncode`, `error`, `stdout`, and `stderr`. Stage is `minimal`
or `overlay`; attempts are exact integers 1–24, elapsed milliseconds exact
integers 0–600000, and return codes exact integers -64–255. Boolean and floating
point substitutes are refused. Error is null, `timeout`, or `output overflow`.
Both streams must be strings, with at most 1 MiB combined UTF-8 bytes. Raw and
ANSI/control-normalized streams must pass the existing credential filter.
Unknown fields and unknown event kinds remain refused.

Successful evidence requires minimal before overlay. Probes follow the stage's
preceding essential events, start at attempt 1, advance consecutively, and have
nondecreasing elapsed times strictly below 180000 ms. Only the exact observed
exit-6 timeout reply permits another attempt. Each stage ends in one READY
probe: return code 0, null error, empty stderr, and stdout parsing as JSON `[]`.
The immediately following event must be the ordinary command
`/usr/bin/hyprctl -j configerrors`, with identical return code, error, stdout and
stderr. That fixed command cannot appear as an additional readiness claim.
Frames and phase success require this correlation. Duplicate READY, probes
after READY, interleaving, missing probes, fatal retries and interrupted or
mismatched correlation cannot grant success or frame publication.

Failed outcomes can retain structurally valid fatal, late or partial probes,
including interruption before the successful command. They do not run the
successful protocol or count toward success. The historical ten-event failure,
which predates `ipc_probe`, remains a diagnostic record rather than a successful
protocol. Existing capability, source/image/receipt binding and cleanup gates
remain in place.

Only two log filename values are added: `minimal-compositor.log` and
`overlay-compositor.log`, each bound to its stage. The existing exact five-field
log schema, strict base64 decoding, SHA-256 binding, 1 MiB decoded limit and
private-content filter apply. No arbitrary path or runtime-tree export is
added. The adapter's aggregate 4 MiB event limit, controller projection 16 MiB
limit and UART bounds are unchanged. Guest snapshots require a reaped compositor;
unavailable bytes are reported as unavailable rather than claimed captured.

## Validation and integration boundary

Controller tests pass 22 cases; the adapter suite passes 94 cases, both with
ResourceWarning treated as errors. The 94-test adapter suite also passes from
a fresh copied source tree (11.340 seconds, no skips). A read-only peer check
accepts one synthetic complete protocol and refuses 25 malformed, private or
reordered variants. Six valid retry/recovery fixtures fail on the
pre-integration adapter with `unknown-guest-event-fields-refused` and pass on the
new source. Controller projection regressions likewise fail before the allowlist
addition and pass afterward. The first adapter test attempt exposed a dict-only
JSON helper used for list assertions; that harness error was corrected and its
log retained. Evidence is recorded under `/tmp/cachy-ipc-receiver-proof-hizlhgim/`
and `/tmp/virtual-controller-ipc-before-aezmdq1b/`.

Host tests use controlled mocked owners and guest subprocess/IPC fixtures. They
exercise valid immediate readiness and retry recovery, the 24-attempt and
179999-ms boundaries, failed diagnostic retention, malformed fields, fatal and
reordered success protocols, private content and encoded log bounds. These do
not execute the corrected Hyprland binary, generic ARM guest, or M2 hardware.

Shared pins remain coordinator-owned. The controller's guest CORE pin and the
accepted packet/controller/adapter source bindings must be refreshed to the
final reviewed source hashes before a corrected native retry. The receiver also replays the actual prior-run ten-event bytes through a mocked
owner: it retains byte-identical public events with SHA-256
`823e0909fec0644468ff781383b9949b7c12379829c409d7d29f3ac49124caf3`,
reports failure and publishes no frames. That is a receiver replay of historical
bytes, not execution of a corrected native guest.

A fresh copied virtual source tree passes all 61 guest/controller tests with
ResourceWarning treated as errors (1.413 seconds, no skips), including the five
new tests preserving the first phase/cleanup error when diagnostic writes fail.
The guest correction and its causal red/green evidence are recorded in the
linked diagnosis document. The adapter changes are confined to `read_events`,
`event_protocol`, and three fixed diagnostic codes; the existing acquisition,
publication, cleanup and cancellation implementation is unchanged.

No shared pins, Git refs or native dispatch are changed by this worker.
