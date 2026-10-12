# Desktop publication correction independent review

October 12, 2026. **DESKTOP-PUB-1 is closed on the tested source snapshot;
no remaining blocker was found for this focused publication correction.**
This signoff covers the projection and its controller wiring; the coordinator
owns the complete initial source freeze and actual workflow acceptance. Read the current roadmap/package
inventories first. Reviewed source and temporary data only; no Docker, ARM
program, native compositor, workflow, source/shared-lock or Git mutation.
The sixth native run's raw config/parser PASS remains evidence for that run;
corrected native publication and a new whole-job PASS are NOT RUN here.

## DESKTOP-PUB-1: reproduced and closed receipt drift

The initial in-flight wiring validated the desktop receipt in
`desktop_projection.project()`, then reread `desktop/desktop.json` in
`integration.safe_public()` without comparing those later bytes with the
projection index's original receipt hash. Within-read identity protection
alone did not bind that later copy to the checked receipt.

Independent temporary-data reproduction used the actual sixth-run receipt and
both reconstructed, hash-matching raw stdout logs. A wrapper called the actual
projector, then changed only `hardware_validation` to `PASS` before returning.
The actual `safe_public()` and unchanged generic exporter returned PASS and
published the changed receipt, while the projection index retained NOT RUN and
the earlier hash. This reproduces source-controlled receipt/acceptance drift;
it does not establish actual hardware acceptance or a Docker attack.

The current wiring checks the copied receipt's exact byte length and SHA-256
against the validated index immediately before staging; it stages that same
checked byte string. Independent reruns of the exact counterexample and
post-projection nonce/credential mutations now refuse publication before any
public receipt exists. Stable original bytes still publish successfully.
The owner added the after-projection replacement regression. The binding gap
is closed on the snapshot below; original receipt/result flags are unchanged.

## Actual producer-shaped success and scope

The archived sixth-run logs 19/20 were rejected by its generic exporter but their
complete stdout is retained inside `desktop.json`. Independently reconstructed
both files into a temporary producer-shaped raw tree and verified raw hashes:

| Command | Raw SHA-256 |
| --- | --- |
| 19, default Lua config | `6eb6aeeff4fe9770851e25252b70b8dcaabffccbe8e2eb6d28e7836f3bce248d` |
| 20, optional startup config | `040c8b52c64a471ec581a259592459a36165c7a8f4251a642051e7e8dff9a7f6` |

Both actual logs project successfully through `safe_public()` and the generic
exporter. The projected logs contain 341 and 358 bytes respectively and no ESC
bytes; the original receipt remained byte-identical in this stable-input case.
Previously generated exporter/control metadata was excluded from this temporary
producer tree; it is not original component output.

The projector requires the complete known receipt shape, exactly 22 successful
commands in producer order, default/optional executable/config argv, complete
seven-file payload-map shape, archive/runtime-lock hashes and exact image/nonce
bindings. It checks aarch64/nonroot/cap0/no-new-privileges/loopback isolation and
required mounts. Runtime/hardware/optimization flags must retain their declared
NOT RUN/BLOCKED values. It does not grant new runtime acceptance or strip ANSI
from arbitrary files.

The source commit in the public index is **external controller authority**. The
legacy producer receipt has no source-commit field: changing a valid externally
supplied source value is accepted by design and explicitly tested. Its source
binding therefore relies on the accepted frozen controller/copied runner and
nonce context, not intrinsic source attestation inside the legacy receipt.

Only numeric/semicolon CSI sequences ending in `m`, with bounded parameter
length, are removed from the two exact verification logs. Other escape sequences,
OSC/cursor controls, DEL, invalid UTF-8, Unicode formatting/control characters
and missing config-success text are refused. Line structure is preserved.
Credential checks examine raw and SGR-free text plus bounded percent/HTML and
literal Unicode/hex escape decoding views; data is refused, never redacted.
Unknown logs remain unprojected and face the unchanged generic exporter. That
exporter is defense in depth, not a universal arbitrary-encoding secret detector.

## Current tests and snapshot

Independent projector suite: **19 PASS**. Covered actual logs, all 22 command
statuses/order, isolation/bindings, refusal flags, raw/full-stdout/hash mismatch,
credential encodings, unknown controls/logs, strict JSON, symlink/hardlink/FIFO,
bounded reads and replacement during opening.

Independent integration suite: **57 PASS**, zero skips. The temporary in-flight
undefined-`report` test error was corrected before this checkpoint. The combined
focused result is **76 PASS**, plus the independent actual producer-shaped
stable/drift schedules described above. Whitespace checks passed. No corrected
native publication or overall integration execution occurred.

| Tested reviewed source | SHA-256 |
| --- | --- |
| `scripts/ci/desktop_projection.py` | `d2eab5230e2979e3cb9a39cd985c84018c5d38f430ed9c923e0577d3672d9203` |
| `scripts/ci/test_desktop_projection.py` | `4871d91ecec77cfb38ec2f1350d4b7a33689186c46017161528156400b44ae48` |
| `scripts/ci/integration.py` | `3633427707da0f93f9f3900cc1036596815f85000bf53e7ea2c6fbd22bbb3be2` |
| `scripts/ci/integration_export.py` | `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c` |
| `scripts/ci/test_integration.py` | `dde5c23742fe8a06d753adc54402e4956c31e74f482d87f55d28b3d8bebdca56` |
