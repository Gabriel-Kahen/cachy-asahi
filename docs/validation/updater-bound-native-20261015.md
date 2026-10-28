# Bound updater native fixture execution, 2026-10-15

[Run 38783834038](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38783834038)
succeeded with product Source `498d6c90b65b0282c13e2c730f34a470449a8cd3` and
workflow `f2c969793efb294d6c0c41b9ba5c74a2b5555e5c`. Its retained sanitized
result reports **39 tests, zero failures, errors or skips**, executing on generic
native `aarch64`. This is acceptance of the finite disposable fixture cases
below; full587 updates, production updater delivery and Apple hardware remain
**NOT RUN**.

The 39 unique retained PASS identifiers exactly match the test methods in the
selected Source. They divide into distinct kinds of evidence:

| Selected suite | Cases | Actual scope |
| --- | ---: | --- |
| `test_bound_update.ActualTransactions` | 19 | Real signed tiny-root libalpm prepare/commit behavior and refusal/failure cases |
| `test_snapshot.SnapshotTests` | 10 | Real TEST signatures, authenticated private bundle snapshots and drift/semantic rejection |
| `test_platform_policy.PlatformPolicyTests` | 10 | Pure policy decisions over synthetic observations; no package transactions or hardware actions |

This count is **not 39 completed upgrades**. Several cases intentionally refuse
before commit; some test methods contain multiple invocations/subcases.

## Actual tiny transactions and signed snapshots

The bound-transaction suite creates a tiny local package database with synthetic
protected platform packages and one `arch=any` data package. It uses the real
native libalpm, whose retained SHA-256 is
`94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902`.
The selected worker checks that pin before execution. The recorded builder
inventory digest is
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`
for the caller's fixed 341-package base. These tiny roots are separate from that
builder inventory and from the full587 composition.

The successful upgrade case asserts actual installed `fixture` version **0-1 →
1-1**, replacement of `BASE TEST ONLY` payload bytes with `TEST ONLY`, a matching
prepared-add set, and a second invocation that completes with no package commit
or prepared additions. Source assertions also check unchanged base configuration/
trust, release of the package lock and removal of private per-call workspace.

Other passed transaction cases exercise invalid signatures, modified archives,
real dependency preparation failure, existing lock preservation, missing or
changed configuration/policy, archive drift after preparation, downgrade refusal,
protected/new/old payload ownership and alias routes into platform/trust paths,
an auxiliary `ldconfig` executable, and unsupported operations. These retain the
requirement that refusal leaves the original fixture payload/checkpoint intact.
Checkpoint-failure cases deliberately inject failures around a **real package
commit**, asserting the distinction between packages committed and checkpoint
changed. The lock-release failure case performs the actual release and injects
a failed return status; it is a modeled error, not an observed real lock leak.

The ten snapshot cases use generated private TEST signing keys and actual signed
metadata/package/database fixtures. They cover a valid private copy/recheck/
cleanup without advancing a checkpoint, custom payload/baseline semantics,
invalid metadata/package signatures, a signed semantically wrong database,
additional public primary keys, undeclared members, original input/bundle drift,
and changed private snapshot/result state. They do not contact a release server
or install a package.

The ten policy cases exercise protected-version/inventory/kernel-file ownership
rules, policy pins and malformed policy, release/transition evidence bindings,
unknown or ambiguous transitions, allowed operation/phase/context, and required
platform/audio roles. Model identifiers, kernel paths and observations are test
data. Their PASS results provide no Apple device observations or speaker-safety
acceptance.

## Retained output and cleanup boundary

The once-collected
[logs.zip](../../artifacts/development/updater-bound-run38783834038/logs.zip)
is **18342 bytes**, SHA-256
`a9c241984b6a4bf3a466f7ab09eca034c7ed6e8ea316578dac5f4461710a6ce8`;
ZIP CRC checks pass. The review parses that existing log and reads exact Git
Source files as data; it performs no download, rebuild, test replay or additional
dispatch. Readable [result](../../artifacts/development/updater-bound-run38783834038/review/result.json),
[identifiers](../../artifacts/development/updater-bound-run38783834038/review/tests.log)
and [local review details](../../artifacts/development/updater-bound-run38783834038/review/local-review.json)
are bounded derivatives.

The selected caller runs a root ARM container with network `none`, private IPC,
a read-only root/source, private `/tmp`, a separate writable workspace, bounded
resources and a clean environment. Its worker checks that only loopback is
present and checks the selected mount/environment shape. The retained result
reports local Docker endpoint `unix:///var/run/docker.sock` and builder image
`sha256:c9481b48c2564643b032531bb60c4e75be3bd3d987f48bd077415b900fd4795c`.

Only fixed result fields and test identifiers are exported. Raw per-case package
databases, before/after maps, checkpoints, GPG output, private TEST keys, bootstrap
audit logs and a page-size/CPU probe are not retained in this public output.
Behavioral conclusions therefore join the exported PASS identifiers to their
exact source assertions; this review does not independently reconstruct each
transaction from raw operands or reverify its signatures.

The final cleanup-only step reports PASS, absence of container
`cachy-asahi-bound-5d42ed92c86a6886469cbbc75b501599`, absence of the recorded
builder image, and `private_data_removed=true`. TEST keys live only in disposable
fixture directories/container storage; the selected tests stop their own GPG
agents and remove temporary roots, and container/private-tree removal closes
that scope. No TEST signing material is exported. This does not establish deletion
of retained acquisition caches, Docker daemon shutdown or removal of every host
image/layer/process.

The bound caller accepts only explicitly disposable release settings. This run
does not exercise an installed end-user updater command, full supported-package
updates, coordinated real Asahi platform changes, a production endpoint/key,
release freshness/revocation operations, reboot/session recovery, either M2 Air,
physical 16K pages, or performance. The separate packaged updater
[real Check trial](updater-real-check-native-20261015.md) and the full587 lifecycle
retain their own evidence boundaries.
