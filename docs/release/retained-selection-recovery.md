# Retained stable endpoint recovery

`scripts/release/recover_repository.py` prepares and verifies a signed recovery
authorization, then optionally builds/selects a local endpoint generation from a
retained stable bundle. It reuses `export_repository.py`'s copy, verification,
locking, generation-retention and atomic-selection engine. The production code
has no modeled-gate mode and cannot admit a synthetic release to stable.

This operation changes **only the endpoint's `current` selection**. It leaves
source `stable/current`, signing trust, installed packages, user configuration
and the Asahi platform untouched. Selecting repository metadata does not restore
an installed package/database/base combination, boot or session.

## Supported recovery

Both the currently advertised bundle and the retained target must pass the
existing real signed release/promotion verifier, including all native/M2 gates.
Both must use the same explicitly pinned signing fingerprint, repository name,
architecture, complete base inventory digest, selected/protected package names,
supported model set and coordinated compatibility sets. The target must have an
earlier signed promotion timestamp and no package version newer than current.
Version comparisons use the existing ALPM `vercmp` tool. This first version
intentionally refuses recovery across changed bases or compatibility policy.

The current endpoint bundle may have since been withdrawn in source storage:
its intact cached signatures/promotion still authenticate its identity for the
expected-current check. The target must remain unwithdrawn. Every current source
withdrawal is authenticated and included in the new generation, and a withdrawal
already advertised in the old generation may not disappear or change. A partial,
forged or changed withdrawal, late withdrawal after signing the plan, or target
withdrawal refuses recovery. Sign a newly reviewed plan after an authorized
source-state change.

A corrupt/incomplete current endpoint is refused. This command handles an
intact authenticated selection with a regression/withdrawal, not repair of a
corrupt metadata store. Corrupt/incomplete target bundles or promotion records,
expired/revoked/unavailable signer state in the supplied verification home,
stale selection pins and unsafe storage/input ownership are also refused.

## Review, sign and execute

All paths must be canonical absolute paths without symlink components. Source
and endpoint must be separate existing caller-owned directories without
group/world writes. Use the externally supplied explicit GPG home required by
the existing release tool; no default home, production identity generation,
key import, trust change or network lookup is performed by this command.

First prepare a read-only unsigned proposal, supplying the independently
observed current `generations/<SHA256>` value and retained release ID:

```sh
python3 -I -B scripts/release/recover_repository.py \
  --root /srv/local-repository --endpoint /srv/local-endpoint \
  --gpg-home /secure/verification-home --key "$RELEASE_FINGERPRINT" \
  plan --expected-current "generations/$CURRENT_GENERATION_SHA256" \
  --target-release-id rc-previous --reason 'Reviewed endpoint regression recovery' \
  > /srv/review/recovery.json
```

The proposal binds the expected current generation/release digest, retained
target release/promotion digests, identical base digest, complete current
withdrawal-file map, signer and bounded reason. Review its canonical bytes and
have the existing authorized signing process produce `recovery.json.sig` with
the same pinned fingerprint. The CLI never signs a recovery authorization.
Keep both single-link files caller-owned, non-writable by group/world, and
outside source/endpoint storage. No factual custodian identity is invented by
this tool; the signing operator's existing authority remains required.

Verify and preview first, then use the same arguments with `--apply`:

```sh
python3 -I -B scripts/release/recover_repository.py \
  --root /srv/local-repository --endpoint /srv/local-endpoint \
  --gpg-home /secure/verification-home --key "$RELEASE_FINGERPRINT" \
  recover --plan /srv/review/recovery.json
```

The default preview changes neither source nor endpoint. Applying creates a
fresh content-addressed generation containing the authenticated target release,
its signed promotion, all latest withdrawals, and the exact signed recovery
authorization. It retains all earlier generations and source bundles. The plan
contains no output generation digest, avoiding a circular hash/signature binding.

The expected-current pin rejects use after the endpoint changes. It is not a
permanently consumed nonce or a public anti-replay protocol: restoring precisely
the same expected source/endpoint state can make the same authorization usable
again. No installed-client freshness or one-use authorization claim is made.

## Concurrency and failure semantics

Planning and application take the existing nonblocking shared `.release.lock`
and exclusive endpoint-directory lock. Existing release writers and exporters
use these same locks. Authorization bytes/signature, current generation and
target source state are reverified during materialization and immediately before
selection; reused retained generations receive the same final checks.

Before the existing atomic symlink replacement commits visibility, a failure
preserves the selected generation. Temporary partial copies are cleaned. A
complete verified inactive generation may remain after a later failure; retry
reverifies it and retains all prior generations. After visibility commits, a
directory-sync failure reports `durability_uncertain: true`; inspect the actual
selection rather than assuming it rolled back. No cross-host transaction or
power-loss durability guarantee is added. Locking coordinates cooperating
writers; it does not control unrelated processes that ignore those locks.

Source `stable/current` remains independent. A later ordinary export can select
the source's current release again, or export a withdrawal-only generation if
the source current was withdrawn. Coordinate ordinary export scheduling for the
recovery window. This CLI does not install a persistent publication hold.

## Validation boundary

Run `python3 -I -B scripts/release/test_recover_repository.py`, plus the existing
release and exporter suites. Tests use real small changed package archives,
TEST keys, signatures, metadata, withdrawal records, file copies and symlink
replacements in temporary directories. Only existing stable factual gates are
explicitly modeled in test adapters. A separate unmodified-validator CLI test
requires synthetic stable refusal and unchanged endpoint state.

These are local source/filesystem checks, not native ARM, generic ARM/16K, M2,
production trust/custody, public publication, installed downgrade or actual
boot/session recovery evidence. Existing A06/A08/A12/A15 gates remain separate.
