# Current client48 native stage source rebase

Implemented a bounded source rebase in exactly `scripts/client/stage.py` and
`scripts/client/test_stage.py`, assigned by Root after the no-skip workflow exposed
the stale freeze. Source is ready for fresh independent review. No Docker/native
actor, API, package install, production key, system trust or Git mutation was run
by this worker. Existing native37 captures and sealed history were not rewritten.

The adapter previously declared four old client/release hashes and 37 test IDs.
All four hashes differed from current primary Source. Its guard hash still
matched. It now declares the actual current client/release/test hashes and the
held `source_delivery.py` hash as an explicit fifth frozen dependency. The helper
is required by the current client's source lookup/export tests and was absent
from the old worker source copy. The existing copy loop consequently carries
seven exact roles: five frozen dependencies, the reviewed adapter self hash and
the unchanged guard. No helper, client, release or guard implementation was edited.

The literal accepted suite is derived from checksum-bound current
`test_client.py`: 48 unique IDs, comprising 19 PortableTests and 29 GPGTests.
Purpose changes explicitly to `frozen-48-client-native-source-tests`; worker test
count and receipt complete/unique outcome checks require exactly 48. A historical
37-purpose result cannot be relabeled as current success. The endpoint recipient's
20 tests remain a separate local/CI suite and are not silently admitted to native48.

All functions other than the two count-dependent functions, `run_tests` and
`validate_receipt`, have identical ASTs to the captured preimage. Changes in those
two functions only replace the literal old count with `TEST_COUNT = 48`.
GUARD_SHA, INPUTS_SHA, PACKAGES_SHA, complete341 inventory, immutable image,
bootstrap and package locks, explicit local daemon endpoint binding, read-only
mounts/network/privilege/resource limits, controlled environment, clock/deadline,
cancellation, process ownership/reaping, private diagnostics, cleanup, conditional
failure receipts and source-contract checks remain held. Execution admission and
any actual new native trial remain Root's separate responsibility.

Actual local portable stage tests pass 41, with no skips. The 39 existing tests
retain their semantics with the new freeze; two new controls check explicit
helper custody (present, changed and missing) and refusal of historical purpose,
missing outcomes and failed outcomes. Count37/47/49/boolean, duplicate IDs,
invented IDs, absent GPG identity coverage, errors/skips and private diagnostic
leakage still refuse current PASS. Mock daemon controls preserve endpoint binding,
isolation, cancellation, uncertain receipts and confirmed cleanup. These controls
prove source behavior, not an actual daemon or native run.

The exact reviewed workflow inline runner also passes locally: release82 and
client109, no skips. Client109 is client48 + endpoint20 + stage41. Signatures and
filesystem checks use actual disposable TEST keys; positive stable admission is
modeled only in the endpoint/exporter test fixtures, while the real stable gate
still refuses synthetic evidence. No hosted Ubuntu tool provisioning or CI run
is claimed by these local results.

Capsule `artifacts/reviews/client-stage-current-source-rebase-20261014/` contains
the preimages, explicit proposal and literal ID set, final Source/test snapshots,
held-function/constant proof, local logs and receipt. Root owns independent review,
feature commit/publication and later native admission. New native48 execution,
production trust, M2 installation/recovery and full-port acceptance remain NOT RUN.
