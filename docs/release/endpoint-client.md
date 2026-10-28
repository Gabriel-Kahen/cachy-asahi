# Read-only local endpoint recipient

`scripts/client/endpoint.py` verifies one locally copied generation from the
[endpoint exporter](../repository-endpoint.md). It is a recipient check for R1,
implemented and tested with ephemeral TEST keys on local Linux. It fetches
nothing and never installs packages, configures pacman, changes trust or commits
a checkpoint. The existing development client and its development-only envelope
scope remain unchanged.

Supply a canonical absolute directory without symlink components, the expected
full generation SHA256, an authenticated full primary signer fingerprint and an
externally provisioned binary public keyring. Copy a concrete generation into
caller-owned storage; the maintainer's `current` symlink is not an input to this
command. The copied directory can have any basename. The keyring is a binary
public certificate export understood by GPG, not an armored certificate or a
keybox database. Provision and authenticate it separately.

```sh
python3 -B scripts/client/endpoint.py \
  --generation /absolute/downloaded-generation \
  --expected-generation FULL_LOWERCASE_GENERATION_SHA256 \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer FULL_AUTHENTICATED_PRIMARY_FINGERPRINT
```

The generation digest binds exact canonical `export.json` bytes. That inventory
is unsigned; its hash identifies a snapshot and does not authenticate a signer,
establish freshness or discover the latest release. The caller authenticates the
signer independently. The verifier checks complete inventory, hashes, repository
aliases, managed directory ownership/permissions and regular single-link files.
It rejects unknown members, incomplete withdrawal pairs, a selected withdrawn
release and noncanonical paths, including double-leading-slash aliases.

For a selected release it reuses the exporter and existing release verifier:
release/package/database signatures, signed promotion binding, full package and
database semantics, dependency/platform policy, provenance, opted source
associations and the actual promotion/hardware gates all remain required. The
CLI has no gate override. A synthetic fixture remains refused by the real gate.
Signed withdrawals must match their filenames and the pinned signer; their
records retain the release CLI's UTC timestamp form. A withdrawal-only generation
is valid and returns no package repository route or stable-contract check.

The binary keyring is copied into a private temporary GPG home under `/tmp`.
Caller GPG configuration and home are not used; automatic key retrieval/import,
key discovery, agents and dirmngr startup are disabled. Only temporary verifier
files are written and removed. The original keyring, generation, trust database
and client state are not written. A shared nonblocking lock covers the copied
directory, and a final complete inventory and directory identity recheck occurs
after signed checks and temporary-home cleanup. The same owner can ignore that
lock; use controlled storage, not a concurrently hostile filesystem.

Exit 0 emits one `verified-local-endpoint` JSON record with observed selection,
signer, generation identity, withdrawal IDs and `repository_relative_path`.
`stable_contract_checked` reports whether the selected signed release passed
the existing stable contract. `freshness_established`, `installation_authorized`,
`production_accepted`, `network_used`, `trust_changed` and `state_changed` remain
false. Exit 1 emits a refusal and no success record. The repository route is a
description of observed bytes; paths can change later and the result confers no
installation authority on them.

Limits reuse the exporter: 16,384 members and 8 GiB per examined tree. This
recipient additionally bounds inventory/withdrawal JSON and binary public keyring
to 4 MiB and every detached signature to 64 KiB. Python 3.11+, Linux flock,
GnuPG, bsdtar and vercmp must already be installed. Nothing is downloaded.

There is no network transport, authenticated key rotation, production custody,
expiry/sequence checkpoint or newest-release discovery here. An older valid
generation can omit newer withdrawals, and offline certificates can omit newer
revocations. Supplying a known generation hash does not solve those problems.
This command cannot establish real M2 execution, installation/recovery, public
endpoint availability or full-port acceptance. Those remain release and operator
work.

Run `python3 -B scripts/client/test_endpoint.py`. Its 20 tests use actual TEST
signatures, exporter materialization and filesystem operations. Positive stable
cases explicitly model only promotion/hardware gate admission; signature,
release semantics and opted source association checks remain real. Separate API
and CLI tests use the unchanged real gate and refuse the synthetic release.
Withdrawal-only API and CLI consumption succeeds without a hardware seam.
