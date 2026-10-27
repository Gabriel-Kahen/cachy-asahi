# Retaining release source mirrors across updates

The source-mirror `update` operation accepts a verified previous mirror and
complete caller-pinned next-release/source inputs. It writes a fresh portable
history containing every previous release plus the next one. Content objects
shared by releases are stored once. Existing recovery maps, source bytes,
package archives, notices, license evidence, dependency locks and provenance are
retained; update never prunes a retained release.

```sh
python -I -B scripts/release/release_source_mirror.py update \
  --previous-bundle /absolute/path/previous/mirror.tar \
  --previous-sha256 "$previous_mirror_sha256" \
  --previous-release-sha256 "$previous_head_release_sha256" \
  --release-dir /absolute/path/next-release \
  --release-sha256 "$next_release_sha256" \
  --output /absolute/path/fresh-successor
```

For retained HTTPS source plans, supply the existing `--retained-inputs`,
`--inputs-sha256` and `--retained-root` options described in
[source-mirror.md](source-mirror.md). Every next-release input is independently
validated by the existing exporter. Reuse applies to verified portable content
storage: a missing next-release source or cache receipt still refuses update.
No network, retained code execution, package installation or source acquisition
is performed.

The previous input may be a single-release mirror or an earlier complete
history. Its entire byte pin and all retained release/object joins are checked
before next-release validation or reuse. For a previous history, the
`--previous-release-sha256` pin must identify its current head; a retained older
release cannot stand in for that pin. Repeating an existing release digest or
reusing a release ID with different bytes refuses. Fresh directory creation
never overwrites an existing export. Validation refusals create no output; an
I/O failure during fresh output writing may retain a partial directory.

The output remains `mirror.tar`, `verify.py` and `mirror-receipt.json`. A history
TAR uses `history.json`, the trusted portable verifier and SHA-256-addressed
objects. Each retained release has its complete original mirror manifest and
inert original verifier bytes. Verification reconstructs each canonical
individual mirror and checks its original mirror digest with the current
trusted verifier. Archived Python/PKGBUILD files, including old verifiers, are
always data; they are never loaded or executed.

## Object accounting

The receipt and history report these deterministic counts over each individual
mirror's content-object set. Content objects include source/archive bytes,
licenses, maps, build provenance and reports. The per-release mirror manifests
and verifier blobs used to reconstruct individual mirrors are excluded from
these delta counts; they still count toward storage limits and the union's
`unique_objects` count.

| Field | Meaning |
| --- | --- |
| `new_objects` | Next release objects absent from the entire previous history |
| `reused_objects` | Next release objects already present in that verified history |
| `retired_objects` | Previous head objects absent from the next head |
| `retained_recovery_objects` | Earlier-history objects absent from the next head, still retained |
| `pruned_objects` | Always zero |

An object retired from the active head remains addressable through its previous
release. If a later release uses it again, it is reused from history. No deletion
or permission decision is implied by these counts. The predecessor bundle digest
is recorded as an export receipt reference; verification independently checks
each retained release, rather than asserting a signed ancestry chain.

## Verify any retained release after relocation

Authenticate the new mirror digest and the external verifier digest through
your trusted export channel, as for a single-release mirror. With the original
repository, release directories and caches unavailable, run:

```sh
python -I -B /new/location/verify.py verify \
  --bundle /new/location/mirror.tar --sha256 "$history_mirror_sha256" \
  --release-sha256 "$previous_head_release_sha256"

python -I -B /new/location/verify.py verify \
  --bundle /new/location/mirror.tar --sha256 "$history_mirror_sha256" \
  --release-sha256 "$next_release_sha256"
```

Both commands verify the entire retained history. The requested release must be
present; the result also identifies the current head and all retained release
digests. Existing single-release `export` and `verify` remain supported. The
HTTPS single-release verification receipt now returns the input mirror digest
correctly; the earlier implementation could report a notice digest due to local
variable reuse. Its underlying pinned TAR checks were unaffected.

## Limits and evidence

The supported recipe/source types and existing caps remain unchanged: 64 MiB
per object, 512 MiB unique object bytes and 16,384 objects. A history additionally
allows at most 256 retained releases. The sum of per-release referenced object
bytes and counts must also stay within 512 MiB and 16,384, bounding reconstruction
work even when many releases reuse large objects. Aggregate metadata/verifier
objects count toward physical caps. A history exceeding these limits refuses;
this operation provides no implicit pruning or cap override.

The complete-mirror authenticity model and source-export caveats still apply.
The caller authenticates release and mirror pins; no signature verification,
source rebuild, native build, installation, hardware/performance measurement,
legal completeness or redistribution-permission conclusion is added. Release
admission, publication and native trials remain with the coordinator.
