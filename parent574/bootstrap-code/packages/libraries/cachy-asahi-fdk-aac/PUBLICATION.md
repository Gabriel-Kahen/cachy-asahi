# Selected corresponding-source reconstruction

This source distribution selects the complete implementations of the two
libraries built by this project, preserving all 898 original implementation/
header files and their complete recorded grants. The classic and xHE full
NOTICES are included. All remaining build/package/test/reconstruction inputs
are original project MIT work. No original Makefile.am, configure.ac, ChangeLog,
Rust Cargo.toml/build.rs, other scaffolds, examples, unlicensed vectors or PDFs
are copied into the selected codec archive or executed by the build.

Project-authored build/packaging dated 2026-10-12; codec source bytes unchanged.
No binary publication, native build, patent clearance, legal approval or hardware
result is claimed. Source audit found no needed GNU Linux aarch64 implementation
file without an established grant. Native compilation is the next completeness
check. Release owners must retain the full notices, supply this complete source
and all modifications free to binary recipients, charge no codec copyright
license fee and make no endorsement claim. The grants do not convey patent rights.

## Producer selection

With the fixed private upstream audit packet, or the pinned selected archive:

```sh
python -B select-source.py --input "$SOURCE_INPUT" --output "$NEW_CODEC_ARCHIVE"
```

On a fresh runner with no workstation/private input, use:

```sh
python -B select-source.py --fetch-upstream --output "$NEW_CODEC_ARCHIVE"
```

This bounded HTTPS data-only stage fetches the exact full-commit codeload archive
into memory, checks its fixed 4,707,099-byte/SHA256 identity, selects only the
900 grant-scoped files and writes the same pinned codec packet. It neither
retains the broad upstream archive nor extracts or executes upstream content.
The upstream archive digest is
`ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806`.
Networking ends before the network-disabled native build containers.

The producer verifies exact byte pins and individual grant markers for every
selected file, adds the two unmodified full notices, and serializes sorted
regular files with fixed ownership/mode/timestamp in uncompressed USTAR. It refuses
an output whose generated digest differs from the fixed selected archive:
`1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4`,
17,387,520 bytes, 900 files. The selected filename is
`fdk-aac-3.0.0-selected-source.tar`; exact raw bytes are checked before parsing.
Only this selected packet has a 20 MiB read/storage ceiling. Upstream acquisition
and individual source members retain 8 MiB caps, with 32 MiB expanded content
and 4,096 members. No gzip fallback is accepted for the selected packet. The private full archive is not redistributed.

Materialize the clean archive with the independent template review map:

```sh
python -B materialize.py --archive "$NEW_CODEC_ARCHIVE" --output "$NEW_RECIPE" \
  --reviewed-template "$TEMPLATE_MAP" --reviewed-template-sha256 "$TEMPLATE_MAP_SHA"
```

Save the returned `input_sha256` object outside the recipe, independently review
all inputs and freeze the map bytes/hash. Then produce the complete source bundle:

```sh
python -B publication.py pack --recipe "$NEW_RECIPE" --output "$NEW_SOURCE_BUNDLE" \
  --reviewed-inputs "$RECIPE_MAP" --reviewed-inputs-sha256 "$RECIPE_MAP_SHA"
```

The bundle contains `cachy-asahi-fdk-aac-3.0.0-source/recipe/` with every recipe
input, including the clean codec archive, and `SOURCE-MAP.json` beside that
directory. Keeping the map outside the recipe avoids recursive self-hashing.
The outer corresponding-source bundle remains gzip-compressed and is bound by
its own recorded digest, not a cross-compressor fixed digest. Only the exact
selected member may reach 20 MiB; each other member and their combined content
remain limited to 8 MiB. Total content is at most 28 MiB, plus at most 128 USTAR
headers and one 10 KiB tar record of serialization padding. Compressed outer
input/output remains capped at 8 MiB. The receipt reports bundle/map SHA256 and counts. Retain those trusted digests
with the release. Actual public upload/source delivery is coordinator-owned.

## Recipient reconstruction and next native stage

Use the original project `publication.py` with trusted release digests:

```sh
python -B publication.py reconstruct --archive "$SOURCE_BUNDLE" --output "$NEW_RECIPE" \
  --archive-sha256 "$TRUSTED_BUNDLE_SHA" --map-sha256 "$TRUSTED_MAP_SHA"
```

This checks the bounded archive and full hash-bound map, writes only exact
regular files to a new external recipe, verifies every local source binding and
the complete 900-file codec archive, and executes no upstream program, compiler
or installer. The source bundle includes this reconstruction program; it is
also retained in the project recipe so recipients can obtain the trusted checker
separately. The private full archive is not required. The clean selected archive
can regenerate itself through `select-source.py` for a deterministic byte check.

Build the reconstructed recipe only with the existing native container builder:

```sh
python -B scripts/build/build.py "$NEW_RECIPE" --image "$NATIVE_IMAGE" \
  --output "$NEW_BUILD_EVIDENCE" --mode native --network none \
  --source-date-epoch 1791748800 --expected-packages "$ACCEPTED_341_LOCK" \
  --reviewed-inputs "$TRUSTED_RECIPE_MAP"
```

The immutable native image/actual inventory must come from an accepted bootstrap
receipt; recreate a hosted image after its job is torn down. Two fresh builds,
archive/metadata/payload comparison, actual codec/consumer ABI and lifecycle
checks remain required. No host compiler or installer is invoked by source
selection, bundle creation or reconstruction.
