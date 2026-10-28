# Independent retained Topmem02 review: run 38458434811

The retained v2 caller result is FAIL with first cause `signing-failed` and
closed diagnostic `io-failed / start`. Baseline public metadata reports
ACCEPTED8/4/249, receipt
`3995d8c436c32b20d57331311a79a1d5d1fcb48f5158d651db5876a4603a1491`.
The addon is NOT ACCEPTED with all counters zero; cancelled is false and
owned-image absence is true. These are Source-gated public observations;
package archives and all individual baseline journals are not independently
retained by this review.

The validated signer projection before recovery is OBSERVED/failed,
launch_attempted true, agent_bound false, sticky_uncertain false. After recovery
the first four fields are unchanged and sticky_uncertain is true. Recovery is
FAIL/refused, agent_absent false, keyhome_absent false and cancelled false.
Signer absence is not proved. Launch-attempt metadata and lack of a bound
agent do not establish an unlaunched or exited agent. Image absence does not
establish signer cleanup or virtual-machine disposal. No independent live
cleanup replay is performed.

The authenticated Source classifier maps an OSError to `io-failed`; stage
`start` identifies the parent `signing.start` boundary before handoff save/pin
and child launch. The exact errno and syscall remain UNKNOWN. The full raw
signer journal is not exported; only its validated closed projection is
retained. Key generation, library work and repository producer execution are
not inferred. Root's separate Source-cause worker owns I/O diagnosis; this
review supplies no correction or backfilled cause.

Completion SHA256
`1d216d0982f507c666c6e404197bffdcfa6eb743f67b7d7bdf1e179b79fdf378`
authenticates six files, 60,612 bytes. The unique raw-log markers reconstruct
the exact 824/553-byte gzip streams and exact 1,689/1,037-byte caller/prefetch
JSON bodies. Decompression is bounded and executes no archive contents.
Retained source-proof and prefetch steps succeed; public prefetch counts are
501 PASS, zero failed/pending, signature authentication NOT RUN.

Root registration binds Source
`1014a1964d30b110e7b1fe9baf890fb7b0ba15bf`, proof
`b13788511d2b5af145f98aa474fb441856ae011f935ba23f3dfe4d9e94606b6a`.
Independent Git object SHA1, SHA256/bytes and tree-declared mode checks pass
for all 125 retained blobs: 123 Source, one policy and one workflow. Nested
Source96/18/6 manifests bind the union. Profile is `topmem-v1`, caller manifest
`6ca00cefac43850ce56a793a3962bb51caad284182a752aa0ed0dd151fbc425b`,
caller
`16a84d23e88b2dcc69282ca1ea4c40045a3f1db64d9fd2e362371f82ad15dcb8`.
Signer and producer source pins remain unchanged. Candidate-adoption's three
changed rows match; its author c4a44 and peer b7ef pins are retained declarations,
without independent authentication of those raw receipts in this task.

Clock
`8e903fc26bd6c8e7be264933e0b174e4877bc44afcce52ce162935883b90d0e9`
matches caller, prefetch and log cross-pins; raw clock is absent. Commit/tree
membership and ancestry lack independent raw DAG/tree-object proof. External
Source-variable readback is retained without a fresh API query. This review
selects no tool policy and grants no execution authority.

Nineteen coordinator corruption controls exercise the pure extracted v2
caller/diagnostic/journal/recovery validators, observed projection binding,
counter/profile/clock checks and gzip/JSON framing. Twelve independent binding
corruptions are refused. No source module/providers, original tests, native
actors, GPG/library operations, package installation, raw archive contents or
live cleanup run here. The observed-instance sticky-state check binds this
record, without imposing a broader rule on all schema-valid failed runs.

The frozen receipt/index are under
`artifacts/reviews/topmem-corrected-caller-38458434811-root-peer-20261013/`.
Passing review authenticates a failed native result with uncertain signer
recovery. Native addon acceptance, hardware/performance, production trust,
release selection and full R1–R5 completion remain unestablished. Prior review
3926 is preserved; shared source, Git and the active Root goal are unchanged.
