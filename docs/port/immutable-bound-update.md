# Immutable update transaction increment

`scripts/update/bound_update.py` commits a signed development release into an
explicit disposable copied root. This is an implemented, locally tested increment;
it does not provide the production updater or close the full 587-package update gap.

The caller reuses `scripts/client/client.py`, `scripts/release/release.py`, the
existing Apple policy evaluator, and `scripts/install/local_transaction.py`'s
pinned libalpm adapter. It introduces no repository format or trust protocol.
It never performs a rolling `pacman -Syu` or synchronizes ambient repositories.

## Transaction behavior

1. Require pinned release configuration and a separately pinned platform policy.
   Configuration names the release, namespace, signer, sequence floor, immutable
   metadata/release/keyring digests, base trust digest and synthetic platform context.
2. Snapshot the complete declared bundle, metadata/signature and public certificate
   into a private workspace. Verify signatures, existing release semantics and
   existing rollback/freshness rules; require a synthetic development release.
3. Exclusively lock the existing client checkpoint directory, then acquire the
   actual libalpm package-manager lock before observing package and file state.
4. Require actual package versions to match the authenticated base or already
   installed candidate. Reject downgrades and every protected package transition.
   Check both old and new paths, resolved aliases, actual protected ownership and
   pinned base pacman configuration/trust before preparing the transaction.
5. Load authenticated local packages with libalpm signature verification, prepare,
   and compare the actual add/remove sets. Use actual protected versions and
   kernel-owned module paths with the existing platform evaluator.
6. Recheck source and private input identities/bytes, configuration/policy pins,
   protected files, base trust and metadata expiry immediately before commit.
   Commit through the same prepared handle with the lock retained.
7. Observe actual package versions and payload, protected ownership/modules and
   trust afterward. Advance the existing checkpoint only after these checks.
   Hold both locks through checkpoint writing; check libalpm release results.

A failed commit can leave package state uncertain. Results report
`packages_committed: "UNKNOWN"` when commit began but did not return success;
post-commit or checkpoint failure keeps the successful package-commit fact.
Checkpoint exceptions use readback to distinguish applied, unchanged and unknown
state. The caller does not claim automatic rollback or boot recovery.

## Invocation and scope

Run one CLI process per transaction; libalpm retains a process-global signing
context. The command requires all of:

```
--root --workspace --settings --settings-sha256 --policy --policy-sha256
--bundle --metadata --signature --public-keyring --state-dir
```

`root` must be `workspace/root` and contain an existing local pacman database.
The workspace must be private, owned and canonical. The caller requires mapped
root in a user namespace, or an explicitly marked disposable Docker container,
with only loopback networking and a clean command environment. `--operation`
accepts only `repository-update`.

The schema-1 settings object has these exact keys:
`schema_version`, `purpose` (`disposable-generic-bound-update`), `namespace`,
`signer`, `minimum_sequence`, `release_id`, `repo_name`, `metadata_sha256`,
`release_sha256`, `public_keyring_sha256`, `base_trust_sha256`, `model`,
`running_kernel_release`, and `operations` (`["repository-update"]`).
The model and running release are synthetic test context, not hardware evidence.
There is no built-in production policy or bypass for missing configuration.

Base pacman configuration and keyring files are preserved. Package verification
uses a separate temporary public-only keyring, scoped to the configured signer;
no host keyring, repository configuration, service or user session is changed.
AUR, Flatpak, orphan/cache cleanup, restarts and coordinated Apple upgrades are
explicitly refused/outside this increment.

## Local verification

The owned development runner stages the proposed modules alongside current
read-only dependencies and runs checks in a rootless user/mount/network namespace.
It binds an owned disk-backed directory over `/tmp` only inside that namespace.
No host `/tmp` cleanup or host package transaction occurs.

- 10 authenticated snapshot/signature/semantic/drift checks passed.
- 10 pure platform observation/evidence checks passed.
- 19 transaction checks passed using actual x86_64 libalpm 16.0.1 and TEST signatures.
  The successful case upgrades an inert fixture from `0-1` to `1-1`, reads actual
  post-state and repeats as a no-op. Baseline local DB records/files are synthetic,
  not a claim of a previously installed supported platform.
- Failure coverage includes actual dependency prepare refusal, package lock
  contention, signatures/archive tampering, post-prepare source/configuration
  drift, protected direct/alias paths and ownership, downgrade, unsafe auxiliary
  executable, missing configuration/policy, unsupported operations, and failures
  before/after checkpoint replacement. Release-error status is injected after
  releasing the real test lock; checkpoint failure points are injected around
  otherwise real package commits.

## Remaining production and scale work

These restrictions are deliberate and must not be weakened globally in the
installer merely to run a full-system fixture:

| Restriction | Current bound / implication |
| --- | --- |
| Actual inventory | At most 128 packages; the 587-package composition is refused |
| Selected archives | At most 128, each at most 8 MiB compressed |
| Aggregate archive/signature inputs | At most 32 MiB |
| Decoded archives and root/projected tree | At most 128 MiB and 20,000 nodes |
| Archive formats | Bounded gzip/xz; common production zstd archives are refused |
| libalpm lists / ownership lists | 4,096 list entries / 20,000 files per protected package |
| Authentication | Existing client/release limits remain: 256 release packages, 4,096 declared files, 512 MiB per file and 2 GiB total |
| Native ABI | Exact libalpm 16.0.1 binary pins; local actual test used the existing x86_64 pin |
| Execution | NOHOOKS and NOSCRIPTLET; any present/aliased ldconfig is refused |
| Root | Entire small copied tree is observed; this is unsuitable for a live full root |
| Trust/platform | Development-only, synthetic release and external pinned synthetic policy/context |
| Supervision | CLI has no whole-transaction process supervisor; subprocess checks have individual timeouts |

A production caller needs release-defined capacities, supported compressed archive
handling, scalable actual observations and protected-path comparisons, explicit
safe hook/scriptlet/auxiliary behavior, cancellation/recovery supervision, durable
enrollment/configuration hookup, and native ARM integration tests against the full
supported composition. Live-root update/recovery and coordinated Apple transitions
require separate implementation and exact-machine validation. Native ARM, M2 Air,
full 587-package update, boot, session, hardware and recovery validation: **NOT RUN**.
