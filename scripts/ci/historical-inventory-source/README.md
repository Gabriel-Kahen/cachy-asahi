# Historical inventory source views

Fourteen existing factory/guard routes bind seventeen manifest sections to the exact historical development inventory: 41,394 bytes, SHA256 `19a8bdb45916e5dffef7a4c1496ebbc489792795ea2906a3d705a67e3906b880`. Updating today's package metadata must not rewrite those historical sources or imply they used the new inventory.

This source-only stager selects an immutable baseline explicitly and writes a fresh closed input view. It substitutes the inventory snapshot and, only for the three explicit shared build roles below, frozen baseline helpers. All other source bytes, including every original emitter, test, dependency map and authority policy, remain unchanged. It verifies every selected ordinary single-link input before output. Current inventory/helper hashes are recorded separately in the compact stdout receipt and never passed off as historical inputs. There is no fallback that accepts arbitrary historical bytes, no pin bump, no package operation, Git/network access or native acceptance.

The fixed `FROZEN_BUILD` map selects only `scripts/build/build.py`, `compare.py` and `container-entry.sh` from `shared-build-v1/`. Those are exact bytes from source `dc01063ab4fd2d8c36a1e4c453811ffa8c27bb06`, already pinned by the unchanged historical profile's Apps6 role. Every snapshot is checked against that original profile; today's build helpers may evolve without entering the historical view. Current role files must still be bounded ordinary single-link inputs without writable group/world modes. All nonselected source drift still refuses. Historical views require no `source_materials.py` or source-cache bridge dependency. No original expected hash, emitter or family manifest is updated to new helper code.

```sh
python3 -I -B scripts/ci/historical-inventory-source/prepare.py \
  --source "$PWD" --factory apps-full574-repair-native \
  --baseline inventory-19a8bdb45916e5dffef7a4c1496ebbc489792795ea2906a3d705a67e3906b880 \
  --output /OWNED/FRESH/historical-source
python3 -I -B /OWNED/FRESH/historical-source/scripts/ci/apps-full574-repair-native/prepare.py \
  --source /OWNED/FRESH/historical-source --output /OWNED/FRESH/generated
```

Choose one fixed name from `profile.json`, repeat `--factory` for a distinct finite union, or use `--factory all` for the exact364-file union. Output must be fresh under an ordinary caller-owned parent and disjoint from every immutable input leaf. No unrelated source tree, `.git`, development artifacts, package cache or private data is copied. Unknown/duplicate/conflicting selectors, a changed snapshot, missing/drifted nonselected bytes, aliases and hardlinks refuse before output. Failed views are not installation or release inputs.

Static validation retains current product and inventory checks in the current checkout. Only the historical source checks run from this explicit view; external public-input checkouts still refer to their original separate canonical paths. Original emitters and their default bytes remain unchanged. Manual historical reproduction should use the view before invoking those original emitters; directly supplying evolved inventory remains an intentional original refusal.

The scoped read-only ten-minute CI matrix runs Python3.12/3.14. Eight portable controls exercise all fourteen closed views/seventeen original maps after synthetic current inventory/build-helper changes, compare full byte-identical output from four unchanged real emitter families, preserve original direct refusal, test missing/drift/alias/hardlink/snapshot/selector failures before output, and invoke the actual isolated CLI. They also prove unrelated drift still refuses alongside evolving build helpers, each damaged frozen helper refuses, and current helper paths retain ordinary-file guards. These checks execute no native or historical positive reader replay. Existing static source/control bodies still run unchanged from their selected historical context. Source-only reproduction cannot transfer historical native, hardware or release authority to current metadata.
