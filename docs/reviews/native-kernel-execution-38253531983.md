# First finite kernel trial 38253531983

Actual hosted ARM trial completed **FAIL** at 13:08:06 UTC on2026-10-12,
commit `dcc170af543f3238f33efc0c623811d6620affaa`, packet
`afdb5a4947acf71e511fe1266921d68149561aedb4ec5b030e841112e827d9e2`,
stage lock `e47d873cd1f8ff542ec1ffd3a5de4b51db4d890f28bc6f1dddbc27d989db0d5a`,
workflow `40a16f84d2a52f0574b71bb1baffdc6069429b2e27345870795f0351c34d0e4c`.
The inline committed-source/native bootstrap passes. The job refuses
`DAEMON_OCCUPIED` at its source/readiness phase before producer or acquisition
launch; both child exit records are NOT_RUN. Kernel probe/builds/runtime,
installation, binary publication and hardware remain NOT RUN; performance is
NOT MEASURED. Cleanup reports FAIL rather than attesting an empty daemon.

Recorded physical memory is16,722,006,016 bytes, available memory15,229,763,584,
initial available disk115,214,491,648. These satisfy the declared15GiB total,
14GiB available and30GiB initial disk guards. The pre-kernel disk observation is
null because that phase did not run. The finite refusal does not publish the
initial image/container inventories or counts; which inventory was nonempty
is not independently recoverable from the public record.

GitHub's dispatch endpoint returned HTTP500 despite actually creating this
run. The coordinator checked the matching workflow/branch/event run list before
retrying, found this exact run, and created no duplicate. Checkout, bootstrap,
execution and public steps have actual job records; this is not merely a failed
dispatch request. The public step succeeds and emits one schema2 bounded status.

The coordinator captures that line from the actual public-step log and
revalidates it with the exact authenticated public-helper bytes and actual
native outcome. Source/packet bindings, complete closed fields, finite reasons,
NOT_RUN child states and bounded resource scalars pass. The captured line and
`root-public-verification.json` are retained under `artifacts/ci/38253531983/`.
The original private status is not exported and is not reconstructed from the
projected line. Public failure acceptance establishes neither compilation nor
cleanup of resources outside the owned scope.

Next software task: review an explicit baseline-preserving Docker inventory
policy or narrowly scoped producer interface for the standard builder. Existing
images/containers must not be removed to satisfy the check. Preserve positive
owned-identity cleanup and uncertain asynchronous producer failures; do not
introduce global prune, privileged nested Docker, host service configuration or
a claim of build-cache absence. A source-audited policy change and finite
counterexamples must precede another trial.
