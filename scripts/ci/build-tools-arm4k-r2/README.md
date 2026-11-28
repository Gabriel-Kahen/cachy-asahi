# Build Tools ARM 4 KiB source seals

This factory takes both corrected Build Tools recipe sets from
`78c44877d4966fd85a8112cd33daeee3d80137a0`. It uses the qualified
`97a44c4c7cb206704bf76e9fd1f1afb2266278c2` Source as its predecessor.
The earlier run qualifies `0.2.0-1`. See the
[original native evidence](../../../docs/validation/build-tools02-native-20261108.md).

Each successor contains the same 200-file namespace and a fresh 199-row
nonrecursive source map. The actor, installed probe, projection and matching
passive reader bind the exact version, complete package source and payload, and
ordered package test names. The hosted proof and positive image-stage and
reader paths require 4,096-byte pages.

| Release | Recipe files | Payload files | Checks per build | Installed and moved commands and observations, each |
| --- | ---: | ---: | ---: | --- |
| 0.1.1-2 | 15 | 11 | 8 | 5 commands, 6 observations |
| 0.2.0-2 | 16 | 12 | 11 | 6 commands, 9 observations |

Run the source controls and assemble each release into a fresh absolute
directory outside the repository.

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/build-tools-arm4k-r2/test_source.py
python3 -I -B scripts/ci/build-tools-arm4k-r2/prepare.py \
  --release 0.1.1-2 --output "$PRIVATE_ROOT/source-0.1.1-2"
python3 -I -B scripts/ci/build-tools-arm4k-r2/prepare.py \
  --release 0.2.0-2 --output "$PRIVATE_ROOT/source-0.2.0-2"
```

The factory reads exact local Git objects, verifies the old map and package
source pins, then renders both closed sources without constructing an image.
The source test verifies original-member preservation, both complete maps,
per-release actor and reader agreement, and cross-release refusal.

Publish each closed Source on its own `codex/` branch. The workflow is
`.github/workflows/native-arm-build.yml` (registry ID `381664314`) on
`ubuntu-24.04-arm`. Use the exact published commit and map digest for one
first-attempt dispatch per release after the coordinator clears the reservation.

```sh
gh workflow run 381664314 --repo Gabriel-Kahen/cachy-asahi \
  --ref "$RELEASE_SOURCE_REF" \
  -f source_sha="$RELEASE_SOURCE_SHA" \
  -f source_map_sha256="$RELEASE_MAP_SHA256" \
  -f operation=build-tools-alpm-v2
```

After retaining the original artifact, invoke the reader from the corresponding
verified Source tree without Git metadata. Bind the original capsule to the
genuine source, full ref, run and map digest.

```sh
python3 -I -B "$VERIFIED_SOURCE/native/build_tools_reader_v2.py" \
  --capsule "$ORIGINAL_PUBLIC_TREE_TAR" --binding "$ACTUAL_BINDING_JSON"
```

Positive acceptance requires two clean, equal native builds with matching
package metadata and payload. The disposable ALPM lifecycle requires the
original Required/Required TEST-signing policy, unknown-key and tamper
refusals, 349 → 350 → 349 inventory, installed and moved probe results, and
verified retirement. Current native build and installed lifecycle are **NOT
RUN** until those original results pass readback.
