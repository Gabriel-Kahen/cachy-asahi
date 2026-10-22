# Historical inventory source views

Fourteen existing factory/guard routes bind seventeen manifest sections to the exact historical development inventory: 41,394 bytes, SHA256 `19a8bdb45916e5dffef7a4c1496ebbc489792795ea2906a3d705a67e3906b880`. Updating today's package metadata must not rewrite those historical sources or imply they used the new inventory.

This source-only stager selects an immutable baseline explicitly and writes a fresh closed input view. All other source bytes, including every original emitter, test, dependency map and authority policy, remain unchanged. It verifies every selected ordinary single-link input before output. The snapshot is the only substitution; current inventory bytes are recorded separately in the compact stdout receipt and never passed off as historical inputs. There is no fallback that accepts arbitrary inventory bytes, no pin bump, no package operation, Git/network access or native acceptance.

```sh
python3 -I -B scripts/ci/historical-inventory-source/prepare.py \
  --source "$PWD" --factory apps-full574-repair-native \
  --baseline inventory-19a8bdb45916e5dffef7a4c1496ebbc489792795ea2906a3d705a67e3906b880 \
  --output /OWNED/FRESH/historical-source
python3 -I -B /OWNED/FRESH/historical-source/scripts/ci/apps-full574-repair-native/prepare.py \
  --source /OWNED/FRESH/historical-source --output /OWNED/FRESH/generated
```

Choose one fixed name from `profile.json`, repeat `--factory` for a distinct finite union, or use `--factory all` for the exact364-file union. Output must be fresh under an ordinary caller-owned parent and disjoint from every immutable input leaf. No unrelated source tree, `.git`, development artifacts, package cache or private data is copied. Unknown/duplicate/conflicting selectors, a changed snapshot, missing/drifted noninventory bytes, aliases and hardlinks refuse before output. Failed views are not installation or release inputs.

Static validation retains current product and inventory checks in the current checkout. Only the historical source checks run from this explicit view; external public-input checkouts still refer to their original separate canonical paths. Original emitters and their default bytes remain unchanged. Manual historical reproduction should use the view before invoking those original emitters; directly supplying evolved inventory remains an intentional original refusal.

The scoped read-only ten-minute CI matrix runs Python3.12/3.14. Five portable controls exercise all fourteen closed views/seventeen original maps after a synthetic current-metadata change, compare full byte-identical output from four unchanged real emitter families, preserve original direct refusal, test missing/drift/alias/hardlink/snapshot/selector failures before output, and invoke the actual isolated CLI. These checks execute no native or historical positive reader replay. Existing static source/control bodies still run unchanged from their selected historical context. Source-only reproduction cannot transfer historical native, hardware or release authority to current metadata.
