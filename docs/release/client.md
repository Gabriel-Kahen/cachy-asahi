# Offline development release client

Status: implemented and tested locally with synthetic bundles and ephemeral TEST keys; native ARM client execution and production deployment **NOT RUN**. This wrapper adds a signed, expiring, sequenced metadata envelope around an existing release bundle. It is a foundation for R1/R5 repository and maintenance work toward the complete port, not completion of M3/M5/M8/M9 or A06/A08/A12/A15. Envelope schema1 and its target set remain unchanged. The optional source-delivery path below uses the companion release helper and existing evidence transport. Only `scope: development` is supported; stable/production scope is rejected with no override. It never installs packages, fetches a network resource, creates a key, imports a key, changes trust, publishes or satisfies hardware/promotion gates.

## Finite interface

`python3 scripts/client/client.py build` reads an existing bundle and writes a new **unsigned** JSON envelope to an explicitly chosen, previously absent output file. Required arguments: `--bundle`, `--output`, `--namespace`, `--sequence`, `--issued-utc`, `--expires-utc`, `--signer`. The caller signs the exact resulting bytes separately with an explicitly selected external key; the source CLI supplies no signing command or identity.

`python3 scripts/client/client.py verify` requires `--bundle`, `--metadata`, `--signature`, `--public-keyring`, `--signer`, `--namespace`, and an existing private `--state-dir`. Verification is read-only with respect to that directory. `--apply` explicitly enables committing its checkpoint after all checks. `--minimum-sequence` optionally supplies an independently known sequence floor; default 1 is only a cold-start floor, not discovery of the latest release.

All supplied paths are absolute and must have no symlink components. Inputs are regular files with a single hard link; the existing bundle's ordinary repo-add aliases are not dereferenced as targets. The state directory must belong to the invoking user with mode 0700. The client takes a nonblocking cooperative flock on that directory inode, validates a private regular checkpoint, and atomically replaces it with a mode-0600 checkpoint only on explicit apply. No default home/keyring/package-manager paths are used. GPG works with a copied binary public keyring and private temporary home; neither the caller keyring nor its trust database is modified. Trust comes from the separately authenticated full primary fingerprint, not a Web-of-Trust assertion. GPG, Python 3.11+ and Linux directory flock/fsync behavior are required; nothing is downloaded or installed.

Example development verification, with all inputs provisioned separately:

```sh
python3 scripts/client/client.py verify \
  --bundle /absolute/local-storage/staging/ID \
  --metadata /absolute/reviewed/envelope.json \
  --signature /absolute/reviewed/envelope.json.sig \
  --public-keyring /absolute/authenticated/TEST-public.gpg \
  --signer FULL_AUTHENTICATED_PRIMARY_FINGERPRINT \
  --namespace dev.example --state-dir /absolute/private-checkpoint \
  --minimum-sequence INDEPENDENTLY_KNOWN_POSITIVE_INTEGER
```

Add `--apply` to commit only the private checkpoint. Exit 0 emits one JSON result; exit 1 emits a refusal/error. `build` emits `unsigned-development-envelope`; `verify` emits `verified-development` or `applied-development`, always with `stable_accepted: false`. These examples do not configure an endpoint or production trust.

## Recipient source lookup and private export

For an opted-in development bundle, `sources` uses the same required verification arguments and optional `--minimum-sequence` as `verify`. Also supply exact `--package`, `--version`, `--arch` (`any` or `aarch64`) and `--artifact-sha256`. It verifies the existing signatures, namespace, expiry and checkpoint/sequence rules before returning the package's typed source-delivery record. The record identifies the selected source bundle, notices, source map, recipe, existing review artifact and supplied review-status label. No source or notice file is executed or extracted.

```sh
python3 scripts/client/client.py sources \
  --bundle /absolute/local-storage/staging/ID \
  --metadata /absolute/reviewed/envelope.json \
  --signature /absolute/reviewed/envelope.json.sig \
  --public-keyring /absolute/authenticated/TEST-public.gpg \
  --signer FULL_AUTHENTICATED_PRIMARY_FINGERPRINT \
  --namespace dev.example --state-dir /absolute/private-checkpoint \
  --minimum-sequence INDEPENDENTLY_KNOWN_POSITIVE_INTEGER \
  --package EXACT_PACKAGE --version EXACT_VERSION_REL --arch any \
  --artifact-sha256 EXACT_BINARY_SHA256
```

Add `--output /absolute/previously-absent-export` to copy only that package's selected material files into a new caller-owned mode0700 directory, with mode0600 files and `source-delivery-receipt.json`. Parent directories must already exist and meet the helper's ownership/path rules. Existing outputs, noncanonical/symlink paths, and destinations within the bundle or checkpoint directory are refused. The receipt binds the actual selected release digest, binary identity and exported file hashes. Package-specific reconstruction programs such as FDK's remain separate explicit recipient operations; this client does not introduce generic reconstruction or run any source program.

The command has no `--apply` flag and never changes the checkpoint, including through its Python API. Successful lookup/export reports `source-delivery-lookup-development` or `source-delivery-export-development`. Stable, source-completeness, legal, native, hardware and public-delivery acceptance all remain false. The supplied `review_status` is reported verbatim. The historical `authorization` material role names an existing opaque review artifact bound to selected bytes; it is not a new approval schema, required PASS label or proof of source completeness or legal permission.

The optional spec entry is `source_delivery: {schema_version: 1, index: {id, path, sha256}}`; its typed package index is documented in the [release interface](interface.md). For opted-in bundles, the complete selected package set and each actual binary identity must match. Every sidecar/material evidence ID must occur uniquely in `spec.evidence`, have that same hash in the enclosing signed `release.files` payload map, and match the actual bytes. The recipe also joins checksum-bound per-package provenance in that map. Input-relative publisher paths in descriptors do not authorize recipient reads outside `evidence/ID`.

The client loads the helper only from its explicit sibling `scripts/release/source_delivery.py`, using the actual regular Source bytes rather than a CWD/sys.path module or cached bytecode. After cryptographic verification, lookup reopens and describes the bundle, requires the same release-record digest, and rechecks the sidecar and materials. Export reads those materials again before creating the output. A changed release, missing/altered material or foreign package/provenance association refuses the operation. These checks transfer only selected observed source bytes; they confer no installation authority on a later pathname.

Generic bundles without `source_delivery` retain the original `build`/`verify` behavior. They have no declared source-delivery association, so `sources` refuses lookup/export. An optional sidecar does not establish source delivery for a release that never opted in. Required release selection, actual source/grant correspondence, maintained public availability and all promotion/hardware gates remain the release owner's separate obligations.

## Envelope schema 1

The signed bytes contain exactly `schema_version: 1`, `type: cachy-asahi-offline-development-envelope`, `scope: development`, caller-selected canonical `namespace`, a positive 63-bit integer `sequence`, `issued_utc`, `expires_utc`, full uppercase primary `signer`, `synthetic`, `release_id`, `repo_name`, and `targets`. UTC times have exact `YYYY-MM-DDTHH:MM:SSZ` form. No floats, duplicate JSON keys or unknown fields are accepted. Issuance may not be in the future; expiry must be after issuance, no more than seven days later, and after the client's fixed check-start time. The CLI has no clock override.

`targets` contains the exact release-record and spec references, both repository database references, and one reference per package. References bind canonical bundle-relative regular paths to SHA-256. Package references additionally bind name, version and architecture. The client derives this description from observed `release.json`, `spec.json`, repository/database/package bytes and the release record's declared payload-hash map; it compares the resulting description to the signed envelope. It also verifies the detached envelope, release-record, database and package signatures against the exact pinned primary (or its cryptographically bound signing subkey), rejecting invalid/expired/revoked/missing keys and weak digests. Consumed package/database signature bytes must match their hashes in the release map even if replaced by another valid signature. GPG exit zero alone is insufficient.

`targets` is `{release_record: FILE_REF, spec: FILE_REF, databases: [FILE_REF, FILE_REF], packages: [PACKAGE_REF, ...]}`. `FILE_REF` is `{path, sha256}`; `PACKAGE_REF` also has `name`, `version`, `arch`. Primary fingerprints have 40 or 64 hex characters. Namespace is an exact opaque lower-case identifier with letters/digits/`.`/`_`/`-`, at most 128 characters; it is not a discovered DNS identity. Limits are 4 MiB JSON/public keyring, 64 KiB detached signature, 256 packages, 4096 declared payload files, 512 MiB per payload file and 2 GiB total declared payload. Rejected inputs are never silently truncated.

A checkpoint binds namespace, development scope, signer, highest sequence, exact envelope SHA-256, release-record SHA-256, issued time and last applied check time. Lower sequence, same-sequence altered bytes, namespace/signer replay and clock movement behind that checkpoint fail. The same still-fresh envelope is idempotently verifiable. A higher sequence must not move issuance backwards. Verification errors and failures before the atomic replace leave prior checkpoint bytes unchanged. The replace is the commit point; an inability to sync the directory afterwards is reported as applied with durability uncertainty, not as a failed verification or an undone commit.

## Limits and source basis

This is a development experiment, not a publicly safe updater or a TUF implementation. A caller must authenticate the namespace, keyring/fingerprint and initial sequence floor out of band. A signing key compromise can authorize arbitrary content or a disruptive sequence jump. No threshold roles, authenticated key rotation, withdrawals, network transport, endpoint, installer integration, replay-resistant hardware state or production custody is supplied. Existing `release.py verify --channel stable` and all actual hardware/promotion checks remain independent and mandatory for any eventual stable release; this wrapper cannot approve one.

The existing release semantic verifier remains a separate required gate for every bundle. Run the existing [release CLI](interface.md) verification for the corresponding staging/stable record. This client checks hashes and cryptographic signatures of consumed targets and the declared payload map; it does **not** repeat `release.py`'s exact complete-directory/symlink inventory, `.PKGINFO`, repository description, general provenance semantics (beyond opted-in source/binary/recipe bindings), dependency/coordinated-set, protected-platform or promotion/hardware-gate validation. Extra files and aliases outside consumed/declared target paths are ignored by this wrapper. Its `verified-development` result is not complete bundle reverification, semantic acceptance or installation approval. The unsigned builder likewise only describes observed bytes; the external signer must finish the separate review gates before signing.

Time checks trust the local wall clock. Recording applied time catches some later backward movement, but cannot authenticate first-use time or defeat a consistently wrong/frozen clock. A local user can delete/reset/copy the state directory and roll back its history. Missing state is explicitly reported as a cold start. Repeated fresh verification does not prove the envelope is the newest published sequence. A withheld newer envelope can remain undetected until the current envelope expires. Offline key material may omit a new revocation; the client cannot learn it without an authenticated update outside this tool. Input paths may change after the observed bytes are verified; this client transfers no installation authority to those paths.

The checks are informed by TUF's documented rollback/freeze threats, expiration/version checks and fixed update-start time; this reduced single-signer prototype omits its role/key lifecycle guarantees. [TUF specification](https://theupdateframework.github.io/specification/latest/). GPG status parsing follows the full `VALIDSIG` primary/subkey, digest and invalid-key status records. [GnuPG status definitions](https://github.com/gpg/gnupg/blob/master/doc/DETAILS).

Run `python3 -B scripts/client/test_client.py`. Actual results and source hashes are recorded in [the workstream](../workstreams/release-client.md). Tests use temporary synthetic archives and explicit ephemeral TEST homes; the CLI itself never creates/imports keys. Native execution is deferred until after initial virtual-integration stages; no pipeline files are owned by this work.
