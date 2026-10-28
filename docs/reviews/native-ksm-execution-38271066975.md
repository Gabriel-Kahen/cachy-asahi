# Native KSM execution 38271066975

The [reviewed startup retry](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38271066975)
completed October12 at15:33:24 UTC with FAIL. Source was
`aef8836ffe931ae34e930e5654054d27ebd84da8`,152-file packet
`65a7ab50f5e9b085278a1f2094771d2f705a2e768ab74300698ce451b858d24e`,
and unchanged workflow `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`.
Checkout succeeded; the source/executor step failed at15:33:22 and upload was skipped.

The newly finite diagnostics identify the actual first refused predicate:
`source_gate=daemon-image-baseline`,
`source_failure_reason=daemon-image-baseline-refused`. The image-list command
returned actual exit0 and six nonempty output lines. The source contract required
an empty image inventory. IDs and image metadata were deliberately not exported;
the six lines are an observation, not proof of six distinct accepted images.
Container baseline was not reached, and cannot be called empty.

Producer, both builds, comparison, lifecycle, cleanup and public export remain
NOT RUN. Status is FAIL/ValueError, cancellation and ownership uncertainty false,
publication false, and legacy build-cache absence NOT ESTABLISHED. This establishes
progress beyond the corrected captured-stage import boundary, without retroactively
identifying the original38262440852 failure or granting a native package result.

Root retained the exact emitted JSON and workflow-log hash
`5dd322654efb611c67e4b7f67330fbf5a2aa1a065afb09314bc71936e85fded4`
in `artifacts/ci/38271066975/root-source-failure-verification.json`.
No Docker or package actor was replayed during that read-only verification.

The coordinator selected a bounded cooperative pre-existing-image baseline
contract, preserving every accepted image/reference and continuing to require
empty containers. That correction is in development; no deletion, pruning,
relabeling, changed packet or successful successor outcome is inferred here.
Native lifecycle/installation, M2/16K, management and performance remain unaccepted.
