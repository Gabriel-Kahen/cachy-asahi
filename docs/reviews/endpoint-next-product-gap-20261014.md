# Endpoint recipient software gap

Implemented one R1 gap: a read-only consumer for the concrete local generation
layout produced by the endpoint exporter. The existing development client could
not consume stable promotion/withdrawal records. The new command is separate and
does not widen that client's development scope.

Owned product files are `scripts/client/endpoint.py`,
`scripts/client/test_endpoint.py` and `docs/release/endpoint-client.md`. Root
assigned these exact new files before implementation. Existing implementation,
manifests, status and CI files were not edited by this worker. Root owns feature
review, commit/publication and any static CI integration.

The implementation reuses the accepted exporter for canonical paths, managed
tree inventories, generation checks and full stable verification; this continues
through existing release semantics and opted source-delivery associations. It
requires a copied concrete generation, an expected generation identity and an
independently authenticated signer/public binary keyring. Signed contents are
verified in an isolated temporary GPG home. It verifies filename-bound signed
withdrawal records, refuses withdrawn selections and supports signed
withdrawal-only generations. Full inventory and directory identity are rechecked
after verification and temporary cleanup. The unsigned generation identity is
not authentication, freshness or an installation grant.

Actual local validation passes 20 recipient tests and 48 unchanged development
client tests, with no skips. Tests exercise real ephemeral TEST signatures,
exporter materialization, copied source sidecars, API/CLI withdrawal consumption,
wrong signer, unsigned-inventory rehashes concealing signed-payload tampering,
cross-release promotion and withdrawal bindings, missing/altered signatures,
unsafe paths/aliases/hardlinks/writable directories, locks, input/keyring bounds,
isolated GPG environment and drift after signed verification. Positive stable
tests model only promotion/hardware admission. Separate API and CLI checks use
the unchanged real gate and refuse the synthetic stable fixture.

First local attempts failed because test tampering omitted the explicit owner
permission change needed for exported mode0444 files, and because the recipient
initially expected development-envelope timestamps rather than the existing
release CLI's ISO UTC withdrawal timestamps. Corrections align the controls and
consumer with the existing contracts. Failed attempt logs are retained; final
tests bind the final Source. The sandbox-only initial key-creation failure ran
zero tests; the actual final suite used disposable TEST-only agent permissions.
No production key, network, system trust or package-manager operation was used.

CI discovery can skip crypto tests when binaries are absent. Recipient fixture
tests require GPG, gpgconf, repo-add, bsdtar and vercmp; existing development-client
tests require GPG/gpgconf. Local execution had all prerequisites and no skips.
CI SUCCESS alone does not establish those suites ran. Root will inspect/provision
CI separately, without this worker mutating the host package manager.

This source is ready for fresh independent review. It establishes no hosted
endpoint, freshness/newest-release protection, key rotation/custody, installation
authority, native ARM/M2 execution, recovery or full-port acceptance. Same-owner
hostile filesystem changes outside cooperative locks remain outside its storage
model. Old valid generations can omit newer withdrawals or revocations. See the
product guide for exact arguments, bounds and result flags, and the new capsule
`artifacts/reviews/endpoint-next-product-gap-20261014/` for sealed Source, test logs,
input hashes and read-only authentication.
