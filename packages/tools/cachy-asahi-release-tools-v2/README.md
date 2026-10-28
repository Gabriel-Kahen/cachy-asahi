# cachy-asahi-release-tools 0.2.0

Original MIT candidate, package version 0.2.0-1, with a fifth command:
`cachy-asahi-release-tools sbom-compare`. The versioned recipe and private runtime
preserve the frozen 0.1 sources and historical recipe profiles. Runtime requires
Python >=3.14 and zstd; no new dependency is introduced by comparison.

```
cachy-asahi-release-tools --version
cachy-asahi-release-tools --help
cachy-asahi-release-tools sbom-compare --help
```

`sbom-compare` reads two explicitly selected export directories, each containing
`sbom.spdx.json` and `coverage.json`. Supply each release ID and independently
authenticated SHA-256 for its release, SPDX document and coverage document.
It writes deterministic JSON or a human summary to stdout without creating files.
See `comparing-sboms.md` for complete arguments and evidence limits. Comparison
success exits 0 even when changes or unknowns exist. Refusal exits 1 with JSON on
stderr and no report on stdout; argument errors exit 2. Caller redirection owns
any saved report. No archive, checkout, source payload or package database is read.

The first four commands retain the 0.1 interface:

```
cachy-asahi-release-tools sbom --release-dir /data/release \
  --release-sha256 HASH --output /data/new-sbom
cachy-asahi-release-tools source-export --release-dir /data/release \
  --release-sha256 HASH --package cachy-asahi-topmem --output /data/new-source
cachy-asahi-release-tools recipe-pack --recipe /data/topmem-recipe \
  --package cachy-asahi-topmem --source-revision FULL_GIT_SHA1 --output /data/new-bundle
cachy-asahi-release-tools recipe-unpack --bundle /data/new-bundle/source.tar \
  --sha256 HASH --output /data/new-recipe
```

These four accept `--profile-set v1|v2`, default v2, and require fresh output
directories with existing parents. Inputs and ancestors must have no symlinks.
Existing output is never replaced; operation errors exit 2. SBOM export preserves
unresolved source/license evidence and `NOASSERTION` conclusions. Source export
validates the full association set before copying one package's exact materials
and original receipt; missing/partial associations refuse. Recipe packing accepts
only frozen reviewed recipe/SRCINFO pairs and declared source bytes. Optional
`--archive` binds exact metadata/payload; without it the archive status remains
`UNBOUND_NO_ARCHIVE_SUPPLIED`. Release association additionally needs `--review`
and `--review-status`; `--synthetic` labels synthetic associations. Review text
confers no legal approval. Unpacking verifies canonical tar bytes and profile,
then writes inert files; no recipe or bundle code is executed.

The launcher uses isolated Python and its own prefix. Private runtime is installed
under `usr/lib/cachy-asahi/release-tools-v2/scripts/`, with seven unchanged project
modules. `source-provenance.json` pins exact bytes/license/origins;
`payload-map.json` fixes all 15 installed files; `export-v2.json` gives the finite
versioned source/runtime export list. PKGBUILD and SRCINFO pin every source file.
`check()` runs only the seven new comparison integration tests plus exact source
checks. The previous delivery and portability controls remain independently frozen.

A separately provisioned builder may run `makepkg --verifysource` and
`makepkg --cleanbuild`; neither is automatically installed. There are no hooks,
services, configuration changes or signing actions. Same package name 0.2.0
upgrades 0.1.0 using ordinary package ownership; downgrading to retained 0.1
restores its launcher/private modules. Operator exports are outside package-owned
paths. Retained private staging/inverse checks are not ALPM lifecycle evidence.

This candidate adds evidence comparison only. Unknown/null/NOASSERTION data stays
unknown, and a valid image/provider-context difference is a reported observation.
The command does not determine compatibility, dependencies, security, source
completeness, native execution, hardware behavior, promotion or release acceptance.
Native ARM/16K, ALPM, installed-target and physical M2 runs remain separate.
