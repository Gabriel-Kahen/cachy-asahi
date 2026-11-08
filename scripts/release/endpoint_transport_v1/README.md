# Portable repository endpoint archive

This source-only tool transports one concrete endpoint generation as one file.
It fills the transfer step between the existing endpoint exporter/local copier
and recipient verification. It neither installs release-tools nor changes its
version, the inventory, repository activation or trust configuration.

```sh
python3 -I -B scripts/release/endpoint_transport_v1/transport.py pack \
  --generation /absolute/verified-generation \
  --expected-generation "$GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/transfer/endpoint.tar

python3 -I -B scripts/release/endpoint_transport_v1/transport.py unpack \
  --archive /absolute/transfer/endpoint.tar \
  --archive-sha256 "$AUTHENTICATED_ARCHIVE_SHA256" \
  --expected-generation "$GENERATION_SHA256" \
  --public-keyring /absolute/authenticated-public.gpg \
  --signer "$AUTHENTICATED_PRIMARY_FINGERPRINT" \
  --output /absolute/private-storage/fresh-generation
```

Supply the archive/generation hashes, signer fingerprint and binary public
certificate through independently authenticated selection channels. A checksum
calculated from an untrusted transfer does not authenticate it. The unsigned
container adds no freshness, revocation, newest-release or signing authority.
Current GPG, signed withdrawal, complete release/source, promotion and actual
hardware gates remain mandatory. Synthetic stable fixtures cannot pass the
unmodified real CLI. Withdrawal-only generations retain a null repository route.

`dependencies.json` pins the exact seven existing verifier/copy helper files,
their revision, byte counts and SHA-256 values. Helpers are checked before import;
drift refuses rather than silently selecting a different API. No central helper,
existing package or frozen/native Source is modified. The strict USTAR validation
pattern comes from `release_source_mirror.canonical_files`; it is adapted to
streaming rather than buffering an entire endpoint.

The format is plain, deterministic USTAR: `export.json` first, then sorted
inventory files. Every member is a regular file with mode `0644`, zero uid/gid
and timestamp, and empty owner/group/link fields. Header bytes must equal their
canonical regeneration. There are no directory, symlink, hardlink, device,
sparse, PAX or GNU extension entries. Padding is zero and termination is exactly
two zero blocks; extra members, trailing bytes and concatenated archives refuse.
This is a specific producer/consumer format, not a generic tar extractor. Paths
or sizes unrepresentable in USTAR refuse; no permissive extension fallback exists.

Repository aliases are not tar links. They are reconstructed only from the
caller-hash-bound `export.json`, after its complete regular-file set is checked.
Aliases must point to retained sibling files under the existing verifier policy.
The restored endpoint is freshly verified before atomic no-replace publication
and again afterward. The source generation/archive is locked and held by file
descriptors, checked for replacement/mutation, and never written. Filesystem
input symlinks, hardlinked archive/files and path aliases refuse.

Both operations require absent, disjoint outputs with an existing caller-owned
parent without group/world writes. Output archive files are `0444`; restored
directories are `0700` and regular files `0444`. Existing destinations are never
replaced. Private staging is removed on pre-publication failure. A post-rename
I/O/custody/verification failure can leave a complete output requiring inspection;
the tool does not delete that published output or claim rollback.

Limits retain the endpoint's 16,384-member and 8 GiB payload ceilings, counting
`export.json`. Tar overhead has a separate bounded allowance. File bodies and
archive hashing use 64 KiB reads; only bounded inventory JSON (at most 4 MiB) is
retained in memory. Monotonic deadline checks occur between I/O operations for a
30-minute operation budget; this does not interrupt a blocked kernel I/O call.
Use controlled local storage: shared locks are cooperative and final checks do
not prevent later changes by the same owner.

Success exits 0 with `packed-endpoint-archive` or `unpacked-endpoint-archive`,
outer SHA-256, `archive_bytes`, regular payload `bytes`, `files` including the
inventory, `aliases`, and `output_created: true`. The existing verification flags
remain unchanged. Refusal exits 1 with JSON stderr and no success stdout;
argument errors exit 2. Python 3.11+, Linux flock/renameat2, GnuPG, bsdtar and
vercmp must already be available. No network, signing, installation, activation,
trust/checkpoint modification, native/M2 execution or release acceptance occurs.

```sh
python3 -I -B -Werror::ResourceWarning scripts/release/endpoint_transport_v1/test_transport.py -v
```

Focused tests use actual TEST signatures and filesystem transfers. Positive
synthetic stable API cases model only the existing hardware gate; the real CLI
withdrawal route and stable refusal keep all current verification checks.
