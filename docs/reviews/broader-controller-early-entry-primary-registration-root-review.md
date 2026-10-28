# Controller early-entry source registration

Root adopted the independently reviewed controller and test sources into the
primary tree, plus the explicit258/265 composition packets. The launcher can
now pass its retained pre-checkout monotonic entry with
`--controller-entry-monotonic`. After clock authentication, the controller
requires a finite float between clock issuance and actual child entry, then
uses `min(workflow_end - 120, supplied_entry + 10080)` for every stage.
The publication reserve retains its existing separate cutoff.

Root authenticated282 author artifacts and288 independent peer artifacts,
compiled the exact primary sources, and verified every265 current source
hash/mode and all12 metadata pins. Only the controller/test source rows changed;
original159 sources, generated125 fixtures and the legacy packet remain exact.
The peer cold93 tests and27 independent vectors pass; these overlapping counts
are not added to the author's controls. Root registration is
`artifacts/reviews/broader-controller-early-entry-primary-registration-20261013/registration.json`,
SHA256 `2e5f611acdefd77c0ba34697f4e0014bcc10855d150540cd94465b2c2c95ec88`.

This closes the source-level early-entry handoff. The actual trusted launcher
must supply that flag. Absent it, the documented local-entry behavior remains.
Workflow/bootstrap registration, final code/data selection, actual per-run
clock/grant/runtime delivery, native frames and installer P0 are still NOT RUN.
No installation, ABI, complete-port, performance or hardware acceptance follows.

The installer registration at `84c43a0b1e3ea150477246c79c6c43a9760717e6`
already has a committed265-source proof:530 Git byte/mode queries,
5,887,033 source bytes, receipt
`artifacts/reviews/broader-installer-primary-registration-20261013/committed-source-proof.json`,
SHA256 `0cacbd0f91a10ac90dec101deb32dc7ab040997a3957d4693866e08bd17b042e`.
That proof precedes these two source changes. A new committed proof for the
current packet is recorded separately after this source registration is committed.

See the [independent peer review](broader-controller-early-entry-bridge-root-review.md)
and [source contract](../workstreams/broader-controller-early-entry-bridge.md).
