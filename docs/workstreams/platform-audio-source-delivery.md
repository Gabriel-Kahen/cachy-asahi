# Finite platform/audio source delivery

`scripts/release/platform_audio_source_delivery.py` is a separate, offline adapter
for asahi-audio 4.1-2, alsa-ucm-conf-asahi 10-2, speakersafetyd 2.0.1-3,
bankstown 1.1.0-4 and triforce-lv2 0.3.2-3. It does not extend or change
`recipe_source_delivery.py`, selected packages or platform integration policy.

It hashes every retained recipe input against a versioned profile whose SHA256
is embedded in the adapter. It exports each unchanged PKGBUILD, every declared
source archive, the complete shared 117-crate vendor archive, Speakersafetyd's
J504 patch, the whole notice archive, retained `.SRCINFO` where present,
packaging license and environment binary-input lock. It copies the actual
upstream license and package-specific notice texts out for convenient review.
`UPSTREAM.json` preserves the retained acquisition receipt; `COMPONENTS.json`
records audited Cargo-lock-to-vendor package checksum joins. Source archives
remain opaque bytes, including legitimate original relative symlinks.

Each deterministic USTAR bundle has sorted members, fixed ownership/modes and
zero timestamps. Its manifest records input hashes/lengths, source order,
recipe/package identity, dependency metadata, observed checkout label and limits.
The exact recipe/input hashes are authoritative. The checkout revision label is
not proof of clean source or authenticated build provenance. Verification checks
the full input set, copied license bytes, generated instructions and manifest,
and rejects noncanonical tar metadata, extra files, links, duplicate names,
traversal, changed inputs and missing inputs. It never extracts original archives
or executes recipe/build code.

`pack-all` exports the remaining packages after an individual input failure and
returns a nonzero exit code with `PARTIAL_INPUT_EXPORT`. Each failure retains its
package name and exact input error. A failed new output directory may remain for
inspection. Existing destinations are refused and preserved. Exported files use
private mode0600 inside a new mode0700 directory; tar members use mode0644.

From the repository root, with the unchanged transport module available:

```sh
python3 -I -B scripts/release/platform_audio_source_delivery.py pack-all \
  --root "$PWD" --source-revision "$(git rev-parse HEAD)" \
  --output /absolute/path/to/new-audio-sources

python3 -I -B scripts/release/platform_audio_source_delivery.py verify \
  --bundle /absolute/path/to/new-audio-sources/bankstown/source.tar \
  --sha256 CHECKSUM_FROM_REPORT

python3 -I -B scripts/release/platform_audio_source_delivery.py unpack \
  --bundle /absolute/path/to/new-audio-sources/bankstown/source.tar \
  --sha256 CHECKSUM_FROM_REPORT --output /absolute/path/to/new-source-tree
```

A checksum from the same untrusted download is not authentication. Obtain bundle
checksums from the coordinator's authenticated release/provenance process before
recipient use. `unpack` writes flat verified inputs, `bundle.json`, and its
companion transport-format `source-map.json`; it does not run makepkg, unpack the
original sources, install packages or enable services. `REBUILD.txt` describes an
ordinary-user native aarch64 build in a separately provisioned disposable
environment, the historical build-only `--nodeps` exception, Cargo's frozen/offline
configuration, and required environment/provenance capture. Binary environment
locks identify inputs; they do not deliver the toolchain's corresponding source,
guarantee future URL availability or prove a byte-reproducible rebuild.

To make a static package association, supply an existing local package archive:

```sh
python3 -I -B scripts/release/platform_audio_source_delivery.py pack \
  --root "$PWD" --package alsa-ucm-conf-asahi \
  --source-revision "$(git rev-parse HEAD)" \
  --archive /absolute/path/to/alsa-ucm-conf-asahi-10-2-any.pkg.tar.zst \
  --output /absolute/path/to/new-bound-source

python3 -I -B scripts/release/platform_audio_source_delivery.py verify \
  --bundle /absolute/path/to/new-bound-source/source.tar \
  --sha256 AUTHENTICATED_BUNDLE_CHECKSUM \
  --archive /absolute/path/to/alsa-ucm-conf-asahi-10-2-any.pkg.tar.zst
```

This checks exact package name/version/arch/dependency/license metadata,
BUILDINFO's PKGBUILD hash, exact payload coverage/types/modes, fixed data and
notice hashes, and AArch64 ELF structure where the reviewed profile has a compiled
file. The receipt hashes the actual archive and observed compiled payload. It
labels the result `METADATA_FIXED_DATA_AND_ELF_STRUCTURE_BOUND`. Compiled bytes
are not independently pinned by these profiles; a structurally valid ELF with
matching metadata does not establish it was compiled from this source. A saved
receipt is not an authenticated compiler attestation. `verify --archive` recomputes
the receipt; without that option only the embedded receipt's shape is checked.
The generic inspector's protected-stack errors and installation-review warnings
remain in the receipt; this adapter does not waive that gate. `.zst` package
inspection uses the existing read-only inspector and installed `zstd` executable.

The companion files are compatible with `source_delivery.record_check`'s opaque
`bundle`, `source_map`, `recipe` and notice descriptors. The adapter deliberately
does not create a release authorization, source-delivery publication index or
signature. A coordinator may construct that existing transport record only with
the actual archive hash, its existing review record, the source-map/recipe/notices
and an explicit review status. No shared transport hook is required.

## Boundaries and independent blockers

The two data packages have all finite data/packaging inputs and actual grants
retained. Their source-only exports have no additional identified term blocker
in this finite adapter. This is not an all-dependency or release legal signoff.

All three Rust packages retain complete exact recipe/vendor/patch/notice inputs.
An offline audit of all 117 `.cargo-checksum.json` manifests verifies their exact
file sets/hashes (4,409 regular files; 57,569,078 expanded bytes). The
Speakersafetyd/Bankstown/Triforce locks join 75/17/38 registry dependencies to that
vendor inventory, with no missing locked Git/path dependency. Triforce's unused
`.gitmodules` entry does not become a required Cargo dependency. The bundle
preserves the full vendor superset, not just that per-lock subset.

Publication blockers remain separate for each package:

- All Rust packages: historical compiler/linker source correspondence, exact
  flags and complete runtime dependency source closure are unresolved. Binary
  environment locks do not satisfy those source obligations.
- Bankstown and Triforce: wmidi 3.1.0's aggregate MIT text comes from an identified
  later 2023 upstream version; explicit retrospective association is limited.
- Triforce: nalgebra-macros 0.2.2's supplemental Apache workspace text retains
  published dev-dependency differences and missing whole-crate VCS association.

Speakersafetyd's notices expressly select configparser's MIT option and retain
colored's MPL-2.0 term and exact unmodified source. Triforce preserves its original
GPL-2.0-or-later source declaration and the existing proposed GPLv3 combined
packaging choice and component terms. This adapter does not invent a grant,
replace terms with a root license, resolve that proposal, or assert a relinking
obligation is satisfied. `complete_corresponding_source_accepted` and
`legal_acceptance` remain false in every bundle.

The retained acquisition receipt and primary tag object identify Speakersafetyd's
revision as `63a92658a4daec170c6472e38162374206e593fb`. The shared manifest and audio
README currently contain a `...170f6472...` typo. The profile uses the retained
receipt's `c` revision, preserving all recipe/archive bytes. Coordinator correction
of canonical documentation is separate from this adapter.

This lane has 32 host-side controls and real retained-source exports. Package
binding controls use an explicitly synthetic ALSA archive with exact retained
payload bytes. Actual produced package-archive binding, native rebuild,
installation, VM execution, audio runtime, speaker protection, physical M2,
performance, publication and release admission remain NOT_RUN/NOT_ADMITTED here.
Existing results elsewhere do not transfer automatically.

```sh
python3 -I -B -Werror::ResourceWarning \
  scripts/release/test_platform_audio_source_delivery.py
```
