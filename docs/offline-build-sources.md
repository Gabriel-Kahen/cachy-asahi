# Offline source-cache bridge

`scripts/build/build_v2.py` can opt into `scripts/maintenance/source_cache.py` through
an independently reviewed source plan. Use `scripts/build/compare_v2.py` for its
paired evidence. The versioned builder selects `container-entry-v2.sh`; the
original `build.py`, `compare.py` and `container-entry.sh` retain their existing
bytes for pinned historical consumers. Package selections are unchanged. The
v2 interface also accepts ordinary builds without the four source options. This interface stages HTTPS archives only; Git/VCS mirrors and
source snapshots need a separate explicit interface and are refused here.

The catalog retains the existing source-cache schema, material byte/hash pins,
HTTPS URL, revision label and notice descriptors. The new plan binds that catalog
to **every** recipe input digest and binds every remote source, in effective recipe
order (generic followed by aarch64 sources), to one unique catalog ID and revision:

```json
{
  "schema_version": 1,
  "purpose": "offline-build-sources",
  "recipe_inputs": {"PKGBUILD": "REVIEWED_SHA256", "local.patch": "REVIEWED_SHA256"},
  "catalog_sha256": "REVIEWED_CATALOG_SHA256",
  "sources": [
    {
      "source": "upstream.tar.gz::https://example.invalid/pinned-release.tar.gz",
      "id": "upstream-release",
      "revision": "EXACT_REVIEWED_CATALOG_REVISION_LABEL"
    }
  ]
}
```

Use actual 64-digit lowercase SHA256 values. `recipe_inputs` is the complete
`input_sha256` object from the independent static recipe review. Hold the plan's
SHA256 separately; a plan supplied alongside untrusted bytes does not authenticate
them. Revision verification means equality with that reviewed catalog label; it
does not verify a Git commit, upstream signature or release publisher identity.
Notice bytes are checked and retained; descriptors do not establish license
clearance, sufficient notices, redistribution rights or complete source delivery.

Add all four options to an otherwise normal clean-build invocation:

```sh
python -B scripts/build/build_v2.py /absolute/reviewed/recipe \
  --image 'sha256:ACTUAL_PINNED_ARM64_IMAGE_ID' \
  --mode native --source-date-epoch ACTUAL_SOURCE_EPOCH \
  --expected-packages /absolute/reviewed/packages.lock \
  --reviewed-inputs /absolute/reviewed/recipe-inputs.json \
  --source-plan /absolute/reviewed/source-plan.json \
  --source-plan-sha256 ACTUAL_REVIEWED_PLAN_SHA256 \
  --source-catalog /absolute/reviewed/source-inputs.json \
  --source-cache /absolute/private/existing-source-cache \
  --network none --output /absolute/new/evidence
```

The source cache must already contain each object's exact bytes and provenance
receipt. This build interface never acquires, repairs or updates cache entries.
Absent objects/receipts/notices, mismatched catalog/recipe pins or revision labels,
incomplete/duplicate mappings, unsupported VCS sources, unsafe filenames and source
basename collisions fail before Docker is invoked. Alias names (`name::URL`) and
plain HTTPS source basenames are supported. URL and SHA256 must match the reviewed
recipe metadata exactly. The existing 128-source, 512 MiB-per-file and 2 GiB-total
cache bounds apply. All four options are required together; an explicit bridge
network is refused when staging is enabled.

After preflight, the build creates a fresh mode-0700 evidence directory, snapshots
the reviewed recipe and rechecks it, then creates `source-material/`. It rehashes
each streamed object from private, held, no-follow cache descriptors into ordinary
mode-0400 staging files. Receipts are checked again. No archive is extracted by
the host staging helper. The only new container mount is
`source-material/srcdest/` at `/offline-sources`, read-only. The cache, catalog,
receipts and host notice paths are not mounted.

Makepkg requires a writable `SRCDEST`, so `container-entry-v2.sh` seeds a private
mode-0700 `/tmp/offline-sources` in the existing container tmpfs from that mount
and exports it as `SRCDEST`. It still runs `--verifysource` and the ordinary clean
build without skipped checksums, dependency installation or host installation.
Source extraction/execution remains inside the reviewed isolated build. Networking
stays `none`; unexpected additional downloads in recipe code cannot use an external
network. This does not sandbox arbitrary recipe code beyond the existing OCI
boundary or prove the image's contents independently.

`provenance.json` records `source_material` with the selected source strings,
destination basenames, full catalog records, revision/byte/hash pins, recipe map
and plan/catalog hashes. `source-material/` retains the exact plan, catalog,
selected receipts, notice contents keyed by SHA256, selected archive bytes and
`selection.json`. Its file hashes remain in `files` alongside existing build
evidence. Failed container attempts retain this provenance. A staging failure
retains an explicitly failed attempt and may contain incomplete staging files;
those are not usable inputs. `compare_v2.py` checks retained file hashes and refuses
different source selections between builds, including a staged/non-staged pair.

This is source/host integration tooling. A mocked container result demonstrates
runner behavior only; it cannot establish an ARM build, reproducibility, installed
behavior, M2/16K compatibility, legal approval or release admission.

References: [makepkg.conf SRCDEST](https://man.archlinux.org/man/makepkg.conf.5.en),
existing [clean builder](build-system.md) and [source cache](source-cache.md).

Run the versioned controls without Docker or acquisition:

```sh
python -B -Werror::ResourceWarning tests/test_offline_sources.py
python -B -Werror::ResourceWarning tests/test_build_v2_validation.py
bash -n scripts/build/container-entry-v2.sh
```

The second suite applies the existing clean-builder validation contract and
synthetic inputs to the v2 imports, comparison CLI and shell helper. The original
validation suite continues to exercise the original entrypoints.
