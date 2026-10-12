# FDK consumer HOME and guide follow-up

**PASS for the coordinator's bounded workflow/guide correction.** The two
curated workflow environments preserve inherited HOME's exact value or absence,
and the guide now makes review/commit a prerequisite. No new consumer logic
finding was identified. This closes the selected two-workflow-environment and
guide items from the [prior held review](fdk-diagnostics-consumer-root-review.md).
Its receipt `b54041689ba1962e1868dd3bdf28116315753c002796768e8a8be817c78ae806`
and captured sources remain unchanged.

The corrected workflow is 47,336 bytes, SHA256
`4e1f13bdab87cba0ae94e554e7d393f9dad23d0fe41e750ea4ceeda4e0e284dc`.
The corrected guide is 5,218 bytes, SHA256
`720eb2bd96f919080331af476bd858997831e134a6445a3f36657e4f7febf5fb`.
Both retain mode 0644. The retained old workflow/guide match the prior review.

The workflow's non-Python text is unchanged. Both Python blocks parse; removing
exactly the old HOME dictionary entry and the new inherited-HOME conditional
from the respective function ASTs leaves the old and new block ASTs identical.
Only first-block `git()` and second-block `main()` have these environment
changes. Private Git configuration isolation stays explicit. The guide differs
by exactly one phrase: “is separately reviewed and committed” becomes “must be
separately reviewed and committed.”

Six environment cases passed: present nonempty HOME, present empty HOME and
absent HOME in each block. The first calls the exact captured `git()` with a
mocked subprocess. The second calls captured `main()` through its real
environment construction, captures the same environment passed to both
authenticated helper/consumer gates and stops there with a controlled fixture
exception. No Git process, encoder, native prerequisite probe or system actor
runs. Each observed environment preserves HOME's value/presence and the explicit
`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` settings.

The six cases form one test method; **15 tests passed, zero failures, errors or
skips**: that method plus all 14 held loader/bootstrap/public consumer tests.
These preserve authenticated private imports, source-poison refusal, one-time
capture, strict schema-2/vector gates, outer FAIL truthfulness and exact
historical schema-1 replay/current rejection. Python ran isolated with bytecode
disabled and ResourceWarning as an error. Captured files stayed hash-identical
and zero PYC files existed afterward. An initial reviewer harness assertion
omitted multiline regex flags before any tests ran; it was corrected and its
log retained. Held source was not changed by the reviewer.

The new project-owned capture includes all prior consumer inputs with only the
two corrected files substituted. Every primary packet129 row, job/test source,
stage40 lock, seven accepted stage sources and separate historical inputs still
matches the prior hold. Packet129 remains
`b91331eb4799718bf0700d8b9a81bbf39c99d5dad4a4f06f777e54d08392ac9d`,
stage40 remains
`4db538d6292c6580c1eb1cc0d330fc84b9c27ae7b570dbfea5a0cdda6f403e3c`.
The coordinator selected this follow-up for the two curated workflow
environments; the retained native job environment and executed packet remain
unchanged. This result does not expand that edit scope.

Source readiness for the selected combined consumer correction now passes.
Fresh committed Git/copy/bootstrap proof and a new native run remain
coordinator-owned gates. Actual run 38277573107 remains FAIL; compiler invocation
is not established. No new Docker/compiler/GPG/namespace/install/hardware or
performance result was produced. The previous sealed stage and installer reviews
remain unchanged.

Evidence is retained in
`artifacts/reviews/fdk-diagnostics-consumer-root-peer-20261012/home-followup/`:
fresh captures, reproducible controls, logs, `results.json` and `review-receipt.json`.
