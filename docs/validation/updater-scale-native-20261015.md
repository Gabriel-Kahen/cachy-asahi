# Native updater scale fixture suite, 2026-10-15

[Actual run 38803000053](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38803000053)
succeeded: **106 tests, 106 PASS, zero failures/errors/skips**, native aarch64.
Product Source `6d24c3a647add2550f3612b79f14efb7e6b5a1a2` and workflow
`31472381d46444cd32d65ed724ca285bf1f26b7b` are recorded in checkout/result.
The selected Source adds Docker `--init` to the owned fixture container, retaining
its 128-process limit, isolation, original signature assertions and deadlines.
This is synthetic-scale/tiny-transaction evidence, not an update of the actual
587-package composition or a supported Apple system.

| Suite | Passed | Scope |
| --- | ---: | --- |
| Signed snapshot | 10 | Actual TEST-signed metadata/archive authentication and private copies |
| Platform policy | 10 | Synthetic protected-platform rules |
| Tiny bound transaction | 19 | Real libalpm signed tiny upgrades/refusals/checkpoint faults |
| Archive stream | 20 | Bounded synthetic archive decoding/corruption/path cases |
| Full-root observation | 12 | Temporary copied-root inventory/ownership observations |
| Capacity | 4 | Declared future byte/inode budget cases |
| Supervision | 6 | Owned worker lifetime/result/failure cases |
| Measure/copy | 5 | Temporary measurement/copy/reporting cases |
| Generic policy | 6 | Explicit generic-mode policy fixtures |
| Scale transaction | 14 | Synthetic 587-name roots with one changed data package |

These are 106 test methods, not 106 upgrades. The real signed gzip/xz/zstd scale
upgrade cases each assert one `fixture` package 0-1→1-1, exact intended prepared
addition, held other 586 synthetic versions and changed fixture payload. The
synthetic package records do not constitute the maintained 587-root composition.
The caller's builder is separately its signed 341-package base, inventory SHA256
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
Native libalpm SHA256 is
`94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902`.

## Intended scale-drift refusal

`test_scale_input_drift_after_prepare_refused` now reports PASS. Exact Source
rechecks a bound scale configuration in `Runtime.precommit`. This fixture's
patched callback appends one byte and calls the original precommit, whose hash
guard reports `scale configuration changed`. The callback sits after real signed
package load, add and transaction prepare, prepared-set checks, policy/trust/
protected-payload rechecks and snapshot validation; commit starts afterward.

The passing case requires the intended error substring and `status=FAIL`, with
`commit_started=false`, `checkpoint_changed=false`, original fixture payload,
empty checkpoint state, unchanged base trust, absent package-manager lock and
workspace reduced to the preserved root. This source-supported PASS establishes
the intended injected precommit refusal rather than the earlier signed-load
failure. The log exports its PASS identifier, not a separate callback Boolean,
returned error row or raw syscall trace. Exact original operands cannot be
independently reconstructed from that identifier.

The remaining passed cases retain their own source assertions for trust and
configuration preservation, active-lock refusal, signature failures, capacity,
archive/root limits, protected ownership, auxiliary-executable refusal, worker
failure/cancellation and truthful checkpoint/commit reporting. Some deliberately
model failures after a real tiny commit; they are not all no-mutation cases.
The [earlier 39-case evidence](updater-bound-native-20261015.md) explains those
shared tiny/snapshot/policy fixtures. Model names, kernel paths and protection
packages in these tests are synthetic inputs, not Apple hardware observations.

## Retention and cleanup

Root's once-collected [logs.zip](../../artifacts/development/updater-bound-scale-run38803000053/logs.zip)
is 22464 bytes, SHA256
`bff7028a934ade64ff8bd33ac7af4e1656c0d73f4dabc38085a46f9bc738d229`.
Its ZIP members pass read/CRC checks. 106 unique PASS identifiers independently
match the aggregate counts. Readable [result](../../artifacts/development/updater-scale-drift-diagnostic-20261015/followup/actual-run38803000053/result.json)
and [test identifiers](../../artifacts/development/updater-scale-drift-diagnostic-20261015/followup/actual-run38803000053/tests.log)
were derived only from that retained log; no collection, test replay or actor ran
for this review. Raw per-case state, private TEST keys and a page-size/CPU probe
are not retained. Behavioral conclusions join identifiers to exact Source.

The final cleanup-only step reports PASS: absence of owned container
`cachy-asahi-bound-8d969c51e5491b2469623c7da80baf3d`, absence of recorded image
`sha256:9c09999a53588db32585b13aa97da06385434dd1d54b2a475ae501e2968440b7`,
and `private_data_removed=true`. This is scoped owner-reported retirement;
it does not certify all host processes, Docker cache/layers or acquisition-cache
removal. The runtime uses network-none/private IPC, read-only root/source,
private/tmp, explicit writable workspace and the existing clean environment.

The earlier failure's text matched the published ENOTTY class. This success
after adding a container reaper does **not** measure or prove earlier PID-limit
exhaustion, zombie counts, a failed second fork or actual stale errno. The
successful Source still includes temporary TEST diagnostics; their later
artifact-only removal proposal is not validated by this run.

Full supported-root updates, installed end-user integration, coordinated actual
Asahi changes, production/release trust, physical 16K behaviour, boot/session
recovery, both M2 Air sizes and performance remain NOT RUN/unestablished here.
