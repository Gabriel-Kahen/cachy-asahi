# Finite synthetic preview supervisor

Source and controlled-fixture implementation only. No PipeWire/GStreamer actor backend, installed dependency grant or isolation authority is provided. The CLI prints `BLOCKED` and exits2 without launching anything:

```
python -I -B scripts/port/camera-preview/preview.py --contract
```

`supervise(backend, private, nonce, authority)` provides the reviewable integration contract. `RuntimeAuthority` must independently authenticate exact installed package/source/license closure, executable/plugin/library/config bytes and the actual isolated runtime. A backend's “verified” label and hash metadata cannot replace it. Its default methods refuse admission. A future reviewed backend supplies deadline-bounded actor reservation, start, cumulative output, exact private graph projection, stop and entire-tree reaping methods; no new command-selection interface or shell is accepted.

The fixed plan is private PipeWire, GStreamer `videotestsrc`, GStreamer `pipewiresrc` → `pngenc` → `filesink`, and one owned-port `pw-link`. Only `-q` is omitted from the original inert proposal because it suppresses the EOS message. Producer250-frame and consumer1-frame bounds are unchanged. Exit0 alone is insufficient; the consumer must return naturally with the pinned EOS message, before any cleanup request and without forced-EOS/interrupt/error diagnostics. Producer completion is not required after consumer disconnect. Stopped producer/daemon exits remain cleanup observations.

Limits:60s total,10s cleanup,20s consumer,30s daemon/producer,5s link;1MiB each stdout/stderr and registry snapshot;2MiB PNG. Final output is a closed4KiB JSON projection with hashes, geometry, finite lifecycle facts and independent first/cleanup failure. Terminal exits cannot change, known tree reaping cannot regress, cleanup continues through log/read/start failures and cancellation, and final frame bytes are rechecked. Only regular caller-owned mode0600 single-link output files under a mode0700 private directory are accepted. Runtime socket paths must fit a Linux Unix socket; private path text cannot inject GStreamer syntax.

Controlled fixtures yield `PASS_CONTROLLED_FIXTURE` with software transport, camera and hardware `NOT RUN`. A future authenticated backend plus independent authority may yield `PASS_SOFTWARE`; that still cannot establish physical camera, GUI preview,16K, M2, privacy indicator, installed target or performance acceptance. An actual stage must bind the receipt to the caller's successful process outcome and independently confirmed disposable-unit cleanup. Its parent-death enforcement and runtime containment are required admission inputs, not implemented by this source-only controller.

See [the software-preview workstream](../../../docs/workstreams/camera-software-preview.md) for exact unmet grants and primary-source evidence. The existing camera metadata receiver and route artifacts are unchanged.

Cancellation finalization blocks SIGINT/SIGTERM while restoring both handlers, records pending cancellation and drains each originally unblocked standard signal once with a zero-time wait, restores the caller's mask and checks cancellation again before returning. Direct KeyboardInterrupt/SystemExit from startup, cleanup or terminal projection independently latch cancellation. Earlier business and cleanup failures remain sticky. A CANCELLED first cause requires cancelled=true; a cancelled result cannot be PASS or BLOCKED.

This is finite catchable-cancellation behavior, not authority after the final unmask or receipt return. A default terminating signal after that cutoff can prevent any receipt; the actual caller/process outcome and independent disposable-unit cleanup remain mandatory. No runtime/backend grant is supplied by this correction.
