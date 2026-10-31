# Opt-in Orphans0.3 source and build path

The explicit-removal implementation is available at
`packages/tools/cachy-asahi-orphans03/`. These are the exact20 product files from
Source73 `4c64ddbb5cf7c018365287583df3d0efb8cfe686`, package0.3.0-2, with18
recipe inputs and12 runtime files. The existing
`packages/tools/cachy-asahi-orphans/` and original source exporter retain their
0.1.0-2 read-only defaults. Select the03 path explicitly.

Both recipes build package name `cachy-asahi-orphans` and install the same command.
They are source alternatives. Installing0.3 replaces the old installed command;
it does not create a second co-installable package. No installation is automated
by these source/export commands.

## Source CLI

Run the qualified implementation directly from this checkout:

```sh
python3 -I -B packages/tools/cachy-asahi-orphans03/orphans3 --version
python3 -I -B packages/tools/cachy-asahi-orphans03/orphans3 --help
python3 -I -B packages/tools/cachy-asahi-orphans03/orphans3 live assess --help
python3 -I -B packages/tools/cachy-asahi-orphans03/orphans3 live plan --help
python3 -I -B packages/tools/cachy-asahi-orphans03/orphans3 live remove --help
python3 -I -B packages/tools/cachy-asahi-orphans03/check_source.py
```

The `orphans3` filename is the checkout entrypoint; the recipe installs it as
`/usr/bin/cachy-asahi-orphans`. Live operations require an explicit target root,
DB path, checked policy and exact policy hash. Removal also requires the reviewed
plan hash, exact selected names, explicit authorization and a fresh result path.
There is no automatic sudo or retry. Read `live remove --help` and the package's
README/READONLY before preparing an actual target. No live operation runs in the
examples above.

## Deterministic source export

Use the explicit v2 exporter with the03 recipe. Outputs must be fresh paths under
an existing caller-owned directory with no writable-by-others ancestors:

```sh
mkdir -m700 /absolute/private/orphans-development
python3 -I -B scripts/release/recipe_source_delivery_v2.py pack \
  --package cachy-asahi-orphans \
  --recipe packages/tools/cachy-asahi-orphans03 \
  --source-revision 4c64ddbb5cf7c018365287583df3d0efb8cfe686 \
  --output /absolute/private/orphans-development/source
```

Record the printed `bundle_sha256`, then pass it explicitly to `unpack`:

```sh
python3 -I -B scripts/release/recipe_source_delivery_v2.py unpack \
  --bundle /absolute/private/orphans-development/source/source.tar \
  --sha256 RECORDED_BUNDLE_SHA256 \
  --output /absolute/private/orphans-development/unpacked
```

Selection binds the exact PKGBUILD/SRCINFO hash pair and every source checksum.
A revision string labels the export; it does not establish checkout identity.
No archive supplied means `UNBOUND_NO_ARCHIVE_SUPPLIED`. Export and unpack execute
no package code and grant no additional qualification. The original exporter
remains on its finite historical profiles and refuses this03 recipe.

## Explicit build inputs

`scripts/build/orphans03-inputs.json` is the reviewed map of all20 product files,
including PKGBUILD and SRCINFO. Its exact recipe SHA256 is
`a023ae04c6ad73ef592df339aebc240860cfdd532a6977be695a05ba6b6f21d2`.
The original generic builder remains unchanged and accepts this explicit path:

```sh
python3 -I -B scripts/build/build.py packages/tools/cachy-asahi-orphans03 \
  --reviewed-inputs scripts/build/orphans03-inputs.json \
  --image sha256:REVIEWED_LOCAL_ARM64_IMAGE_ID \
  --expected-packages /absolute/reviewed/sorted-packages.lock \
  --source-date-epoch REVIEWED_SOURCE_EPOCH \
  --mode native --network none \
  --output /absolute/private/orphans-development/build-a
```

The image, sorted package lock and epoch must come from the separately reviewed
build environment. Tags and guessed identities are invalid. A second fresh
build directory and `scripts/build/compare.py --require-bytes` provide the normal
pair path. The versioned `build_v2.py` also accepts this recipe/map without source
options; neither invocation runs as part of adoption. Running a general builder
is a new execution and does not reproduce the complete published native trial's
fixture, authority and retirement checks. The tool package requires Python>=3.11
and pacman/libalpm for actual assessment/removal; source help/export works without
loading ALPM. No dependency provisioning is automated.

## Qualification boundary

Root qualified the exact0.3.0-2 component on generic native aarch64/4096-byte pages:
two equal packages,109 recipe controls per build, full574 BUILDINFO tuples and
13 private-target lifecycle cases. The recorded trial is run40597289861,
job122516317572. This adoption reuses its bytes and admission; no native execution,
original acquisition or semantic replay occurs during adoption.

Retain `descendant_exit=UNKNOWN_NOT_DIRECTLY_REAPED` and
`interruption_or_fatal_parent_cleanup=NOT_PROVEN`. The private positive removal
does not establish live-host removal. Native16K, either M2 Air, full606 GUI,
performance, production trust and release acceptance remain open. The package's
byte-held source-preparation README/provenance is historical; Root's finite
admission supplies the later native scope without rewriting those recipe inputs.

No default inventory, release selection, SBOM consumer or historical CI caller
switches to03 automatically. `release_sbom.py` still uses the original exporter.
Root owns any further inventory and consumer adoption.
