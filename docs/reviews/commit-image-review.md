# Docker commit metadata independent review

October 12, 2026. **CI-COMMIT-1 is closed at the reviewed source checkpoint; no
remaining source blocker was found for the controlled initial workflow rerun.**
Reviewed the roadmap and package inventories before the original review and
rechecked the current correction. This signoff covers the initial controller
and its narrow optional consumer interface, not broad future workflow acceptance.

No Docker socket was opened, no container/image was created or started, no ARM
program or package ran, and no workflow, shared source, Git or host system state
was changed. Tests used temporary files, mocks and host-command/socket tripwires.
This review does not establish an accepted installed 345-package image, native
integration PASS, compositor operation or M2 compatibility. R1–R5 and the exact
M2 hardware acceptance remain separate and incomplete.

## CI-COMMIT-1 correction independently verified

The prior source created an untagged image before returning a validated API
response, and its lifecycle finally removed only the handoff container. The
original independent mocked reproductions confirmed that malformed responses
or subsequent Cmd/config rejection left the derivative untracked. That finding
is now corrected in both API and caller:

- The owned random handoff nonce defines a private recovery tag. The API checks
  that exact tag is absent using a bounded, strictly parsed 404 response. Existing
  tags, unsuccessful queries or invalid absence responses prevent ownership and
  POST. The callback records tag ownership after the precheck and before POST.
- The commit request includes that exact private repository/tag and returns only
  an exact schema-valid immutable image ID. Lifecycle registers the valid,
  nonbaseline ID before derived inspection, Config checks or the fresh verifier.
  Tag ownership survives malformed, delayed, failed or interrupted replies,
  callback failures and HTTP connection-close failures.
- Lifecycle failure, container-cleanup failure and cancellation remove the
  registered derivative. Cleanup resolves only the exact owned tag/ID, refuses
  the baseline or conflicting identities, removes only that derivative without
  prune/force, and queries both image IDs and the private tag to verify absence.
  Repeated cleanup accepts an already absent known derivative. Unknown API
  outcomes retain `cleanup_uncertain=true` and FAIL even after observed absence.
- Successful derivatives are retained only through onboarding, desktop and
  optional same-job consumers. Controller finally performs owned cleanup before
  sealing the authoritative summary, then clears its usable installed-image
  pointer. Cleanup failure, consumer exception or cancellation prevents PASS.
  The summary's existing late-cancellation handling remains in place.

The GET/POST precheck is not an atomic reservation against another writer with
exactly the same newly generated nonce. A socket timeout is per operation, not
an absolute request deadline. Observed absence after an uncertain response does
not attest that a delayed daemon mutation is impossible; the uncertainty remains
explicit failure. These limits are accurately stated and do not produce cleanup
or native acceptance on ambiguous evidence.

## Metadata, socket and executable boundaries

The [pinned Moby 28.0.4 merge rule](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
can inherit runtime Cmd when both requested execution arrays are empty. The
exact `Entrypoint: [""]` sentinel blocks that branch; its
[container-create rule](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go)
resets precisely that sentinel before selecting an executable. The correction
therefore has a primary-source basis. The API preserves full Env content/order,
nonempty commands, entrypoints and portable metadata. Comparison normalizes the
exact sentinel and null Labels; changed nonempty execution fields, labels and
Env still fail equality. Lifecycle test identity in image Env remains refused.

The fresh read-only verifier explicitly uses
`--entrypoint=/usr/bin/python3`, `-B` and its pinned script arguments. It cannot
inherit the handoff process or try to execute the empty sentinel. Accepted
handoff inventory, original payloads, sanitized private state, immutable image
identity and Config equality remain required before that image is usable.

The API refuses Docker environment overrides and arbitrary, remote or rootless
socket endpoints. Only the two default rootful UNIX paths are accepted, with a
point-in-time root-owned socket check. Transport uses AF_UNIX and fixed API1.48;
requests/responses have explicit size limits, strict duplicate/nonfinite JSON
checks, content type/length checks, exact success status and immutable-ID schema.
Interrupted connects close the not-yet-assigned socket; interrupted requests
close HTTP and propagate cancellation. Reviewed errors exclude raw Config,
private transport text and daemon response bodies. No socket enters a container.

`native_arm.main(argv=None, integration_consumers=None)` keeps the unchanged CLI
modes and defaults. The optional in-process consumer is forwarded only through
integration mode. `Controller.run(consumers=None)` calls it before final owned
cleanup, catches consumer failures into failed controller acceptance, and cleans
up on cancellation. The unchanged CLI supplies no consumer; none is installed
by this review. Separate future source directories remain outside the initial
source scanner.

## Repository acceptance binding

The generated repository manifest now pins the copied runner's script hash and
requires its actual source hash at the component guard. Both repository PASS
acceptance and public semantic projection validate the source commit plus exact
nonce, immutable image ID, daemon architecture, runner SHA-256 and explicitly
synthetic upgrade kind. Missing, extra or changed binding fields fail before
projection. Duplicate/nonfinite JSON and incorrect schema/purpose remain refused.

Only a complete base inventory equal to the authoritative accepted package lock
is transformed into package/version rows. All other result fields survive for
the unchanged generic exporter's credential checks. Wrong source/image/nonce,
script/daemon/upgrade values and unknown credentials cannot gain acceptance from
that projection. No filtered or truncated inventory is represented as complete.

The earlier local metadata probe receipt was read, not rerun:
`/tmp/cachy-config-probe-receipt-4qbp04gs/result.json`. Its execution label says
API1.51 while its server `api_version` field says 1.56; current workstream prose
separately states the observed server API1.56 and probe requests pinned to
API1.51, distinct from the production correction's fixed API1.48. The receipt's
execution label therefore identifies the request version; it is not native
Docker28 or package
installation evidence.

## Actual tests and reviewed snapshot

Independent focused checks: **150 PASS, zero skips**:

- `test_commit_image.py`: 33 tests, including precheck/ownership/POST ordering,
  occupied tags, response/transport/close failure, connection cancellation and
  strict command/config wire behavior.
- `test_integration.py`: 54 tests, including actual lifecycle config/fresh-verifier
  refusals with registered derivative cleanup, ambiguous response ownership,
  exact image/tag absence, baseline preservation, idempotence, consumer lifetime,
  callback/cancellation/final-cleanup failure, and failed summary acceptance.
- `test_repository_projection.py`: 14 tests covering exact generated-contract
  binding, full inventory authority, strict JSON and unchanged credential refusal.
- `test_native_arm.py`: 49 tests covering original native/pin/trust/build boundaries.

`git diff --check` passed. These tests are source/mock evidence only. The
controlled standard workflow's real results remain the authority for native
build/integration acceptance; this review creates no runtime PASS.

| Reviewed source | SHA-256 |
| --- | --- |
| `scripts/ci/commit_image.py` | `716e9aac5bd472e58da53e5def54a169f01b2c8bc7ac1fbae849f68532cf8a5c` |
| `scripts/ci/integration.py` | `f2607b2e49173cc48ae7c674421702ac89efb5285ec579d81133482fb166a6a5` |
| `scripts/ci/native_arm.py` | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| `scripts/ci/repository_projection.py` | `05c581300ba807f9e38495863054e159ae7464ea7becc496da15806a60b4404b` |
| `scripts/ci/test_commit_image.py` | `8b9a18f758b5cf99b3eb2e6f7a6315797b7d1f34154527e384b4254e7d5a5a91` |
| `scripts/ci/test_integration.py` | `db6ce47b5027a9d3d2a2e366495155c09220057baa9d76c870bf01e3a39b073e` |
| `scripts/ci/test_repository_projection.py` | `6b6f0076ed297b6d152a8b0dc434725e320318a576ac745a995a6dcd9f8c3c50` |
| `scripts/ci/test_native_arm.py` | `34f0e7873d3a9ff4b69abeb9bdb8d7a86b0e9a16fdcf5bcfb7f000eb6b9cc9ae` |
