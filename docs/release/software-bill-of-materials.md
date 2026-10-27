# Offline release source and license inventory

`scripts/release/release_sbom.py` exports deterministic SPDX 2.3 JSON and a
machine-readable coverage report for the **exact existing `release.json` package
set**. It consumes the release/spec file maps, package archives, release build
provenance, `.PKGINFO`, `.BUILDINFO` installed-package locks, and the existing
`source_delivery.py` associations and `recipe_source_delivery.py` profiles.
It does not select packages from the development inventory or edit manifests.

Authenticate the release through the existing release workflow first. Pass the
authenticated manifest SHA-256 explicitly; this exporter checks that digest and
every consumed file's manifest hash but does not verify signatures or establish
a trust root.

```sh
/usr/bin/python3 -I -B scripts/release/release_sbom.py \
  --release-dir /absolute/path/to/release \
  --release-sha256 <authenticated-release.json-sha256> \
  --output /absolute/path/to/fresh-sbom-directory
```

The output directory must be new and its parent must already exist. The command
creates `sbom.spdx.json` and `coverage.json` with private directory/file modes
0700/0600. Successful export returns 0, including when coverage is unresolved.
Unsafe, corrupt, conflicting or mismatched inputs return 1 with a JSON `REFUSED`
reason. Consumers must inspect `unresolved_package_count` and each package's
`unresolved` array; a successful export is not an acceptance gate.

## SPDX semantics

The SPDX document uses `SPDX-2.3`, document data license `CC0-1.0`, a content-based
namespace, valid stable SPDX identifiers, and `DESCRIBES` relationships for every
release package. Each package names its exact archive, version and SHA-256.
Architecture, pinned source references and retained source bundle descriptors are
carried in `sourceInfo` and expanded in coverage.

`licenseDeclared` reproduces a single supported SPDX identifier only when archive,
release and provenance declarations agree, and any explicit source-bundle license
declaration agrees too. Missing declarations, multiple license tags without an
explicit expression, legacy names and unsupported identifiers produce
`NOASSERTION`; all raw declarations remain in coverage. The deliberately small
identifier set is visible in `LICENSE_IDS`. The tool does not invent `AND`/`OR`
relationships or synthesize legal grants from text files. `licenseConcluded` and
`copyrightText` are always `NOASSERTION`. Document `CC0-1.0` describes the SPDX
metadata, not the software's license.

`filesAnalyzed` is false: the exporter does not produce a complete SPDX file and
file-license analysis or a package verification code. Package checksums identify
the actual compressed archives. It separately reads archive members without
extracting them and records exact bundled license text hashes in coverage.
Creation time comes from `release.json`; output bytes do not include wall-clock
time, input absolute paths, or output location.

These choices follow [SPDX 2.3 package information](https://spdx.github.io/spdx-spec/v2.3.1/package-information/)
and [relationships](https://spdx.github.io/spdx-spec/v2.3.1/relationships-between-SPDX-elements/).
The format is the [SPDX 2.3 JSON schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json).
The focused suite checks the emitted fields and relationships; an independent
full SPDX validator has not been run for this development packet.

## Coverage and integrity

`coverage.json` includes the manifest pin, SPDX hash, exact package identities,
archive sizes/hashes, provenance descriptors, recipe hashes, declared and raw
licenses, bundled license member paths/hashes, source URLs/pins, retained source
bundle/map/recipe/notice descriptors, reviewer labels, and unresolved reason codes.
The full `.BUILDINFO` installed list and its canonical newline-list SHA-256 retain
the build environment lock. These dependencies are build context, not additional
selected release packages. Optional `actual_native_build_record` data is checked
against the archive/recipe when its recognized binding fields exist, with its
reported status retained as data. Execution is not revalidated.

Existing source indexes may cover a subset of the release; missing packages stay
in both outputs as unresolved. Foreign or duplicate associations, mismatching
archive hashes/versions/architectures, recipe inconsistencies, changed material
bytes, unsafe paths and duplicate JSON keys refuse export. Source maps are checked
against actual retained tar members. Reviewed original recipe profiles receive
the existing canonical `unpacked` validation plus exact archive payload-set,
byte, mode and metadata-binding checks. Their internal `context-source:` reference
is resolved only when its commit, package path and recipe hash match the retained
profile. Additional unresolved references remain visible.

Unknown profiles and opaque bundle formats remain unresolved. Recognized source
bundles still do not establish complete corresponding-source delivery, legal
approval or license obligations satisfied. Source and package notice hashes are
linked; the tool does not decide whether a notice is a sufficient grant. Pinned
HTTPS references remain `NOT_CHECKED_OFFLINE` for remote retrievability. A URL or
recipe alone cannot resolve retained source delivery.

The script performs no network or subprocess calls and never executes a recipe.
It rejects symlinked input ancestors/leaves, hardlinked input files, FIFOs,
unregistered evidence and credential-bearing source URLs. Archive links remain
opaque; no archive path is extracted or followed. Input limits are 256 packages,
4 MiB JSON/retained license text, 64 MiB compressed archive, 128 MiB decoded tar,
32 MiB member, 32,768 physical headers, 64 KiB extension header, and 512 MiB total
consumed release bytes. Compressed decoding uses the existing bounded
`scripts/update/archive_stream.py` decoder with a 30-second per-archive deadline.
Gzip/xz require Python 3.12 or later; zstd requires the Python 3.14
`compression.zstd` module. Absence is a concrete refusal, with no subprocess fallback.

## Focused verification

```sh
/usr/bin/python3 -I -B -Werror::ResourceWarning scripts/release/test_release_sbom.py
```

Tests use original inert fixtures and private temporary directories. CLI children
use `scripts/virtual/owned_process.py` for bounded exclusive-child supervision.
The development handoff retains a bounded export of already local real package
and source evidence, repeated byte comparison, refusal controls and exact hashes.
Host fixtures and offline export provide no new native build, physical M2,
performance, production trust, M5/M9 acceptance or release/publication credit.
