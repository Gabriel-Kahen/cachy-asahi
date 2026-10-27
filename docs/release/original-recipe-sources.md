# Original recipe source delivery

`scripts/release/recipe_source_delivery.py` adapts exactly these reviewed local
recipes to the existing `source_delivery.py` transport:

| Recipe | Version | Declared sources | Staged files |
| --- | --- | ---: | ---: |
| cachy-asahi-maintenance (current) | 0.1.0-2 | 18 | 16 |
| cachy-asahi-maintenance (retained) | 0.1.0-1 | 18 | 16 |
| cachy-asahi-session-diagnostics (current) | 0.1.0-3 | 10 | 7 |
| cachy-asahi-session-diagnostics (retained) | 0.1.0-2 | 10 | 7 |

No package, source-cache interface, release schema or default selection changes.
The adapter reads source data; it never executes recipes, fetches sources,
installs dependencies, installs packages or changes system configuration.

## Deterministic offline bundles

From the repository root, with a fresh output directory:

```bash
python -I -B scripts/release/recipe_source_delivery.py pack \
  --recipe packages/tools/cachy-asahi-maintenance \
  --package cachy-asahi-maintenance \
  --source-revision ab57e41b60d08e564bc0fe7e9a0c9a9c0706c283 \
  --output /absolute/private/fresh-maintenance-source
```

Use `cachy-asahi-session-diagnostics` for both recipe and package to create the
other bundle. The adapter allowlist pins the reviewed PKGBUILD and `.SRCINFO`
hashes. It then reads their complete literal local source list and validates
every source checksum. Recipe changes require explicit review and a new adapter
profile. Files outside that source list are excluded; original `LICENSE`,
`NOTICE` and `source-provenance.json` remain byte-exact.

The finite registry selects each version by its exact PKGBUILD/SRCINFO hash pair.
The current reviewed pairs are from `ab57e41b60d08e564bc0fe7e9a0c9a9c0706c283`;
the two historical pairs remain admitted for their existing source bundles.
Packing and unpacking derive the version and archive-binding recipe from those
source bytes. A version label, a mixed old/new pair or an unreviewed revision of
either file cannot select a profile. The observed Git revision remains a label,
as before. No bundle schema or retained bundle bytes change.

The output contains `source.tar`, `source-map.json`, `bundle.json`, `PKGBUILD`,
`LICENSE` and `NOTICE`. `source.tar` contains every declared source, PKGBUILD,
`.SRCINFO` and the generated manifest. Its flat regular-file USTAR headers have
sorted names, mode 0644, zero UID/GID/mtime and no host paths. Identical inputs,
revision label and archive binding produce identical output bytes.

`bundle.json` records source hashes/sizes, version, observed revision, dependency
declarations, original check commands and rebuild/staging instructions. The
revision is a supplied observation; exact reviewed hashes bind the inputs. It
does not embed the builder's dependencies or promise binary reproducibility.
Actual rebuilding requires a separately provisioned native aarch64 environment
with the declared dependencies and retained toolchain/environment evidence.

The previously produced historical bundles are retained unchanged under
`artifacts/source-delivery/original-recipes-20261027/`:

| Bundle | SHA-256 |
| --- | --- |
| maintenance 0.1.0-1/source.tar | `f84ca37ccee0f00f9fd0bbaace405e0fc71be8b8819755c8d498d19ae96dac5a` |
| session diagnostics 0.1.0-2/source.tar | `0c504f7c8a479e7d99f7bc4d507adbbe9dc6718dfb7b3377929317a6dac14860` |

The hashes in this table are checked against the retained artifacts before
handoff. Both concrete bundles say `UNBOUND_NO_ARCHIVE_SUPPLIED`; neither has a
release-source index or a placeholder binary hash.

## Relocation, checks and staging

```bash
python -I -B scripts/release/recipe_source_delivery.py unpack \
  --bundle /absolute/path/source.tar --sha256 ACTUAL_SHA256 \
  --output /absolute/private/fresh-relocated-recipe
```

Unpacking checks the supplied bundle digest, exact original source pins,
complete source set, manifest and canonical tar bytes before writing a fresh
private directory. It rejects links, traversal, duplicate entries and added or
changed members. Existing output paths are never overwritten. Unpacking runs
no code.

Run each manifest's `host_check_commands` explicitly from the relocated source
directory. These execute the original package checks, including isolated private
CLI staging tests. The diagnostics test's real socket ancestry control requires
a directory below caller-owned or root-owned, non-group/world-writable parents;
it correctly fails beneath `/tmp`. The test does not require a live desktop or
audio session.

To stage the reviewed package function into a separate **fresh, absolute**
directory, run this command from an unrelated working directory, supplying the
two absolute paths as arguments:

```bash
bash --noprofile --norc -c \
  'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$1; pkgdir=$2; package' \
  stage /absolute/relocated-recipe /absolute/fresh-private-stage
```

Then run the recipe's `check_source.py` (maintenance) or `check_package.py`
(diagnostics) with `--recipe-root /absolute/relocated-recipe --stage
/absolute/fresh-private-stage`. This checks every staged filename, byte and
mode. Staging is not installation. No ALPM lifecycle, native build, live session,
physical M2, performance or release qualification follows from these host checks.

## Binding an existing package archive

Add `--archive /absolute/package.pkg.tar.zst` when a package archive is already
available locally. The adapter snapshots its bytes and reuses the existing
read-only `package_checks.py` inspector. It requires matching `.PKGINFO` name,
version, architecture, license and dependency/replacement declarations; matching
format-2 `.BUILDINFO` identity and PKGBUILD SHA-256; and the complete declared
payload's bytes/modes. Wrong recipes, wrong versions, extra/modified files,
duplicate metadata, hooks and protected paths refuse before output creation.
Zstandard archives require the existing `zstd` program. No archive is extracted
or fetched. The binding records archive and metadata hashes, with
`native_execution: NOT_ESTABLISHED`: metadata correspondence is not independent
proof of how the archive was built.

To produce a source index for the existing release transport, also provide
`--review /absolute/existing-review --review-status 'EXISTING STATUS'`.
The review is retained as opaque, checksum-bound data. `--synthetic` explicitly
labels synthetic association fixtures. A missing actual matching archive
refuses this operation; unbound source bundles cannot enter the binary-bound
source index schema.

The resulting `source-delivery.json` has the existing one-package index shape.
Its descriptor paths are relative to its output directory; the recipe key is
`PKGBUILD`. Before signing a multi-package release, the release coordinator must
place the finite materials beneath one publisher input root, prefix each
descriptor's `path` with its package directory, retain the unique package-prefixed
IDs, and combine package rows into one index covering the exact selected set.
Existing `source_delivery.assemble` joins the actual package SHA-256 and release
provenance `recipe_sha256`. Existing client export preserves these materials.
Exported `PACKAGE-source.tar` can be fed to the same `unpack` command using its
verified material digest. No source completeness, license acceptance, signing,
publication, build or install authority is manufactured by this adapter.

Run the focused controls with:

```bash
python -I -B -Werror::ResourceWarning scripts/release/test_recipe_source_delivery.py
```

The suite uses both real original recipes, runs their original checks after
relocation, stages their actual package functions, verifies source transport
assembly/export/reconstruction using explicitly synthetic package fixtures, and
tests checksum, source-list, recipe, archive identity/payload and path refusals.
It performs no network access, host installation or hardware test.
The historical compatibility controls use the original two bundle bytes retained
as gzip fixtures under `scripts/release/fixtures/recipe-source-legacy/`, checked
against their original TAR hashes above. They do not depend on untracked local
artifacts or Git history in a CI checkout.
