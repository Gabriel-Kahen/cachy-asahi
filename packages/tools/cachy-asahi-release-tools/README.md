# cachy-asahi-release-tools

Original MIT package, version 0.1.0-1. Four offline commands use frozen project
helpers from a private runtime. Python 3.14 or newer supplies bounded in-process
zstd decoding for SBOMs; `zstd` supplies the existing recipe archive inspector's
`.zst` decoding command. gzip/xz decoding uses Python's standard library.

```
cachy-asahi-release-tools --help
cachy-asahi-release-tools --version
cachy-asahi-release-tools sbom --release-dir /data/release \
  --release-sha256 HASH --output /data/new-sbom
cachy-asahi-release-tools source-export --release-dir /data/release \
  --release-sha256 HASH --package cachy-asahi-topmem --output /data/new-source
cachy-asahi-release-tools recipe-pack --recipe /data/topmem-recipe \
  --package cachy-asahi-topmem --source-revision FULL_GIT_SHA1 \
  --output /data/new-bundle
cachy-asahi-release-tools recipe-unpack --bundle /data/new-bundle/source.tar \
  --sha256 HASH --output /data/new-recipe
```

Supply a trusted SHA-256 independently; computing a hash of untrusted material
only establishes which bytes were processed. Every output directory must be
fresh and its parent must exist. Inputs, source bundles and output ancestors
must have no symbolic links. Existing outputs are refused, including symlinks.
Errors exit 2; successful operations emit one JSON object and exit 0. Help and
version exit 0. The executable resolves its own prefix; checkout, current
directory and Python import environment are not runtime dependencies.

`sbom` consumes an existing `release.json`, `spec.json`, exact package archives,
provenance and any registered source evidence. It writes `sbom.spdx.json` and
`coverage.json`. Missing source/license evidence remains unresolved; integrity
or identity errors refuse the export. SPDX license conclusions remain
`NOASSERTION`. A successful export is not legal or release acceptance.

`source-export` first applies the same exact release/archive checks, then uses
the existing source transport to verify the full release source association
set and export one package's materials unchanged, named by evidence ID, with
`source-delivery-receipt.json`. Missing or partial associations refuse export.
Opaque bundles stay opaque; this command never extracts or executes them.

`recipe-pack` accepts only the frozen reviewed original recipe/SRCINFO pairs
and declared local source bytes. It never evaluates the PKGBUILD. Add
`--archive /data/package.pkg.tar.zst` to bind exact archive metadata and payload.
Without it, the manifest explicitly records `UNBOUND_NO_ARCHIVE_SUPPLIED`.
For a release association, additionally provide `--review /data/existing-review`
and `--review-status TEXT`; both require a matching archive. Use `--synthetic`
for synthetic associations. Review text is opaque and confers no approval.
`recipe-unpack` checks exact canonical tar bytes, source checksums and profile
before writing inert source files. Rebuild commands in the manifest are data.

All four commands accept `--profile-set v1|v2` (default v2). Both helpers are
preserved byte-for-byte, including historical profiles. v2 adds the existing
Orphans3 profiles and corrected Setup8 payload handling. Select v1 when a
historical consumer specifically requires it. This package does not introduce
a profile for itself, change standalone tools, compare SBOMs, sign, fetch,
select packages, or invoke package installation.

Build in a separately provisioned environment with declared dependencies:

```
makepkg --verifysource
makepkg --cleanbuild
```

`check()` checks exact source/runtime/payload metadata and exercises moved-prefix
commands on small synthetic release/archive inputs. The topmem recipe fixture
contains exact project bytes and is used to construct synthetic archives; no
fixture executable or recipe build command is run. `fixtures.json` labels this
evidence. `source-provenance.json` pins the six runtime modules, their original
paths/revisions and MIT license. `payload-map.json` freezes all installed files.
Fixtures and tests are build inputs and are not installed.

The package installs one command, six private modules, this documentation,
provenance/payload maps and MIT notices. No hooks, services or configuration
files are installed. Removal deletes only those package-owned paths; exported
operator data lives outside the package. Native ARM builds, ALPM lifecycle,
16K execution, physical M2 behavior, performance and release admission require
separate actual runs.
