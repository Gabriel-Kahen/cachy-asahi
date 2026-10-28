# Native KSM execution 38262440852

The [first finite native KSM job](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38262440852)
ran October12, 14:22:31–14:22:44 UTC and failed before producer launch. It used
source `b918c7c68a7c7dee12ec0b2dee0cca14f703b431`, the152-file packet
`631df29044c624ef0c6d0d2d0c178e7cff489e2395071a679125a1fa7adb80a5`,
and registered workflow `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae`.

Checkout succeeded. The source/executor step returned exit1 at14:22:42,
after emitting the executor's finite JSON: `phase=source`, `status=FAIL`,
`failure_category=ValueError`, no cancellation and no ownership uncertainty.
Original producer, both KSM builds, comparison, lifecycle, cleanup and public
export are explicitly NOT RUN. Publication is false and legacy build-cache
absence is NOT ESTABLISHED. Upload was skipped; no package or encoded evidence
bundle was produced. The JSON establishes entry into the executor, rather than
a failure of the inline bootstrap before execution.

The retained JSON does not identify its first source predicate. Source loading,
host/daemon checks and scoped setup precede producer launch. No daemon counts or
identifiers were exported, so neither occupied images nor a specific import
refusal can be asserted as this native run's cause. Cleanup NOT RUN is preserved;
it is not a positive disposal claim.

A subsequent deterministic152-source copied-byte test exposes a separate actual
source defect: nested execution of the pinned BASE helper inherits an importer
that refuses its `contextlib` import. A narrow explicit pinned stdlib closure
and finite source-gate diagnostics are under review. That reproducer explains a
real source defect but cannot replace the absent native first-failure record.
A reviewed, rebound successor trial is required.

Root read-only verification retains the exact emitted JSON and archive/log hashes
in `artifacts/ci/38262440852/root-source-failure-verification.json`.
No Docker, native package actor, installation or hardware operation was replayed
by this verification. KSM installation/status/remove/reinstall and M2/16K,
management, performance and supported-release acceptance remain NOT RUN.
