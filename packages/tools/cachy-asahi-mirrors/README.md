# cachy-asahi mirrors

Original MIT development candidate 0.2.0 for ARM mirror checking and explicit
candidate activation/restoration. `check` and `rank` keep their existing behavior.
`rank` samples exact selected repository database bytes and publishes a separate
0600 candidate. Only explicit `activate` and `restore` mutate a caller-selected
target; there is no default target, `/etc` write, service, hook or automatic
activation. No `rate-mirrors` or CachyOS wrapper source is reused.

```sh
cachy-asahi-mirrors check catalog.json
cachy-asahi-mirrors rank catalog.json --output ./core-mirrors.candidate
cachy-asahi-mirrors activate "$PWD/catalog.json" \
  --candidate "$PWD/core-mirrors.candidate" --repository core \
  --target "$PWD/mirrorlist" --state "$PWD/activation.json"
cachy-asahi-mirrors restore --repository core \
  --target "$PWD/mirrorlist" --state "$PWD/activation.json"
```

The caller supplies a catalog from an independently verified compatible release/
base snapshot. The tool does not establish catalog trust, authorize a different
base/repository, validate a release signature or refresh stale snapshot pins.
This example has placeholders and is not a working catalog:

```json
{
  "schema_version": 1,
  "architecture": "aarch64",
  "base": "asahi-alarm",
  "repository": "core",
  "database": {"bytes": 100, "sha256": "REPLACE_WITH_VERIFIED_DATABASE_SHA256"},
  "mirrors": [{"id": "selected", "server": "https://mirror.example/$arch/$repo"}]
}
```

Only HTTPS templates containing complete `$arch`/`$repo` path segments qualify.
Credentials, query strings, fragments, redirects, encoded responses, duplicates
and non-aarch64/asahi-alarm catalogs fail. Rank uses certificate-verified HTTPS,
bypasses environment proxies, permits at most 16 mirrors / 32 MiB per database,
10s socket waits and 120s sequential sample deadline (at most one final socket
wait beyond it). It reports failures; no exact match means no candidate. Candidate
publication is atomic and does not replace an existing file/symlink. This single
request sample is not a sustained bandwidth, performance or hardware benchmark.

Activation is offline. It freshly validates catalog syntax/platform/repository,
its raw SHA256, the exact candidate header, and a unique subset of catalog server
lines. It never infers fresh network availability or signed provenance from that
binding. The caller must explicitly repeat the named repository. Absolute catalog,
candidate, target, state paths are required for activation; target/state paths are
also required for restoration. This validates selected metadata, not host hardware
or installation compatibility. The candidate must still be caller-owned 0600.

Mutable parent directories must be caller-owned without group/world write access.
Every path component is opened without following symlinks. All input/target/state
files must be bounded caller-owned single-link regular files; symlinks, hardlinks,
foreign owners and aliases fail. Targets may initially be absent. Existing targets
up to 64 KiB retain exact original bytes and POSIX mode/UID/GID through restoration;
activation retains that same mode/UID/GID. An initially absent target is created
0600 and removed on restore only if unchanged. ACLs, extended attributes and
original timestamps are outside this POSIX metadata contract; use ordinary files.
There is no privilege escalation. The caller must have the matching ownership
and permissions for its deliberately chosen target and journal.

The two explicit paths reserve empty 0600 sidecars `<target>.caa-lock` and
`<state>.caa-lock`, plus random `.caa-mirrors-<nonce>.tmp` files in those same
parents. These are the only auxiliary mutations. Separate nonblocking advisory
locks serialize tool operations even across different journals for one target.
Stop external editors/writers during each operation: these locks coordinate
cooperating callers, not arbitrary concurrent filesystem writers. Stable read
fingerprints and checks immediately before replacement refuse observed edits;
standard rename does not provide a compare-and-swap against an uncooperative
writer racing that final check. No claim of such kernel-level exclusion is made.

The 0600 JSON journal stores bounded exact prior/candidate bytes, hashes, POSIX
metadata and file identity. File and parent-directory fsync precede durable state
transitions. Target publication/restoration uses same-directory atomic replacement.
Journal states describe intent and completion:

- PREPARED: the prior state and proposed replacement are durable; publication may
  still be pending. Retry activates only the exact original or recognizes the
  exact recorded published inode. Restore can cancel an unpublished preparation.
- ACTIVE: the exact installed inode/content/metadata/timestamps are recorded.
  Retry is idempotent; restore refuses user edits or a replacement inode.
- RESTORING: restoration intent is durable; retry finishes only if the target is
  still the recorded active file or the exact recorded restored inode.
- RESTORED: prior bytes/metadata (or absence) are restored. Retry refuses later
  user changes; a new activation needs a fresh explicit state path.

A conflict never overwrites the observed user version or deletes its journal.
It leaves the pending state for explicit reconciliation; do not edit the journal
or its private temporary files. A killed process before its first journal write
can leave one unreferenced private temporary file; the tool never scans/deletes
unrelated files. Abrupt interruption after journaling is recoverable at the tested
prepared/publication/restoration boundaries. Storage failure may leave durable
intent without completion; no completed state is reported until its fsync succeeds.
Keep the journal until restoration is no longer needed. It contains the original
file, so protect its ownership and 0600 mode.

Development controls exercise real temporary-file CLI activation/restoration,
mode/UID/GID preservation, exact candidate/catalog binding, edit conflicts,
symlink/hardlink refusal, serialized operations and real SIGKILL interruption at
four durable transaction boundaries. No live configuration is exercised. Live
catalog authority/currentness, actual Asahi base/pacman integration, native package
pair/install/remove checks, filesystem power-loss behavior, both M2 models and
release admission remain separate gates. No production trust, network performance
improvement or hardware acceptance is claimed.
