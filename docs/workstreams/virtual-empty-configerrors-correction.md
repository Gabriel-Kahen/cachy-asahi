# Empty configerrors response compatibility correction

Status: selected implementation and host validation **PASS**. The actual native run
`38274341668` remains **FAIL**, with no frames. A native trial using this correction
is **NOT RUN**. The existing generic software route is unchanged; M2/16K hardware,
graphics acceleration and performance remain unvalidated.

## Source and actual trigger

The held [execution diagnosis](../reviews/native-virtual-ipc-execution-38274341668.md)
records the 13 actual events, both captured startup logs, source/binary lineage
limits and renderer control-flow audit. Review SHA-256 is
`a4c539fdad668b4bb27a5432312b70bd60bf315da256bf194d7b0c79aefe240b`;
its artifact receipt SHA-256 is
`350e1f3469bfd4ac8cf0f8b733403d7e9e4e6c8fb658cbedfad7188c609ea806`.
These records were completed and held before the selected correction.

Actual minimal IPC attempts returned 6, 6 and 0 at 9679, 15807 and 21315 ms.
The final response had null transport error, empty stderr and exact stdout
`[\n\t""\n]\n\n`, parsing as `[""]`. The held guest rejected it as runtime
config errors because it required `[]`; it emitted no successful correlated
command or frame event. Historical failure and cleanup records are preserved.

Pinned Hyprland `efb50993780079460b0cbed1363e2166a2de1d9f` joins Lua errors as
text; matching-version hyprutils
`a21e87b878e72ee5dfd375899e8b2ad0d0c4c0e1` preserves an empty split entry.
The JSON formatter therefore reports `[""]` for empty error text. A compiled
host extraction reproduced the actual reply bytes exactly. The formatter is
lossy: stored empty, space-only or tab-only messages can produce the same reply.
The limited acceptance claim is **no reported config error text**; this reply
cannot establish that the parser's internal error vector is empty. Full Lua
execution and distribution binary patch equivalence remain unverified.

## Selected correction

Guest and receiver each use the same bounded parsed-value predicate:

```python
def no_reported_config_error_text(value):
    return type(value) is list and (
        value == [] or
        len(value) == 1 and type(value[0]) is str and value[0] == ""
    )
```

Only `[]` and exactly one empty string are accepted. Received whitespace-only
entries, nonempty text, mixed or repeated entries, nested arrays, null, booleans,
numbers and non-list or malformed JSON values remain refused. There is no
trimming or general removal of empty entries in the correction. Upstream text
already lost before serialization cannot be recovered by the predicate.

A READY response still requires exact integer return code 0, null transport
error, empty stderr, bounded combined UTF-8 output, a living compositor and a
response before the 180-second deadline. Only the exact previously observed
exit-6 timeout reply retries; attempts remain capped at 24. The ordinary
`/usr/bin/hyprctl -j configerrors` event retains the original actual stdout
bytes, and the receiver requires immediate correlation with the same result.
Stage ordering and consecutive attempts, monitor/client/frame evidence,
publication privacy, cleanup and cancellation gates remain in place.

Source changes are confined to the helper and its readiness call in `guest.py`
and `virtual_stage.py`, with focused regressions in their respective test files.
Controller, shared maps, locks, workflow, renderer backend and Git/dispatch are
coordinator-owned and unchanged by this worker.

## Validation and hold

Evidence and fresh source captures are under
`artifacts/reviews/virtual-empty-configerrors-correction-20261012/`.
The baseline captures bind the pre-correction guest, receiver and tests, plus
the previously held diagnosis review/receipt. Causal host fixtures replay the
actual three probe values and times, preserve the exact successful stdout in
both correlated events, and exercise the ordinary success protocol with its
existing frame checks. These are controlled host fixtures, not completion of
the failed native trial or an actual new guest frame.

The working guest suite passes 43 tests and the working receiver suite passes
98 tests, with ResourceWarning treated as errors. The exact guest three-probe
replay fails on held source `3ca0e95e…` with `runtime config errors` and passes
on the correction. The held receiver rejects three combinations involving
`[""]`; its existing `[]`/`[]` combination passes. The correction accepts all
four minimal/overlay combinations while preserving exact reply/command bytes.
All 19 mandatory rejected payloads, transport/deadline/liveness conditions,
correlation changes and frame/monitor/client failures remain rejected.

A fresh 16-file source/dependency capture passes all 65 guest/controller tests
(1.448 seconds) and all 98 receiver tests (14.073 seconds), with ResourceWarning
as errors and no skips. The two helper return expressions have identical ASTs.
Removing each helper and reversing its one call in memory restores each full
module's prior AST exactly; all other source behavior is unchanged. The actual
13-event failed record also replays as failure with byte-identical public event
SHA-256 `ab406dd9607b7039420dc89d39c037039abd65e273b72336f64805331dcc1422`
and no frames under the corrected receiver.

Captured trees contain no PYC files. Checks use Python `-B`; one receiver outer
binding wrapper initially ran without `-B` and refreshed two shared ignored
cache files. The worker preserved those shared caches, and subsequent wrappers
and all captures use the bytecode-free path. The cache refresh changed no held
source or prior diagnosis artifact.

The bounded independent host peer accepts the actual three-probe sequence in
synthetic completion fixtures and refuses 19 parsed-value negatives in each
module, 10 guest transport and three guest deadline/liveness/log controls,
15 receiver transport/correlation/time/frame-protocol controls, and three
pixel-frame negatives. It also refuses the actual historical 13-event stream
as a successful protocol. Its positives use mocked transport and synthetic
completion/frame records; no new native guest runs.

Final hashes, exact source copies and test logs are bound in the correction
receipt. The coordinator's final independent acceptance, source/pin adoption
and a subsequent bounded native trial remain separate steps.
