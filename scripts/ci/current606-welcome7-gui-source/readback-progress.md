# Apps16 installed606 readback diagnostics

The original Apps16 service1800 trial `40202454241` reached the post-session readback and timed out in `installed606.py verify` at 600 seconds. The instrumented 607 run `40370390415` measured 821.214 seconds in payload traversal. That run already used the descriptor `statx` mount query and the literal-root traversal shortcut. Its timing does not isolate hashing, descriptor work or capabilities in the 606 guest.

This successor keeps every original readback and the 600-second deadline. It reports monotonic inventory, database metadata, payload and recheck boundaries, plus cumulative nodes, bytes and package ordinal every 2,048 payload nodes. The existing owned log drain forwards bounded diagnostic records from just the exact post-session verify child. The original stdout receipt, stderr log, retirement and acceptance checks remain authoritative.

Pass an ordinary retained checkout of the exact service1800 source tree `b069c4d77b6880b34c0ddbc4e128b95ab7efb8d4` to the source-only constructor. It emits a new, unissued source tree and runs no guest.

```sh
python3 -I -B -Werror scripts/ci/current606-welcome7-gui-source/apps16_readback_progress.py \
  --predecessor-root /absolute/retained-service1800-source --output /absolute/fresh-diagnostic-source
python3 -I -B -Werror /absolute/fresh-diagnostic-source/native.py preflight
python3 -I -B -Werror scripts/ci/current606-welcome7-gui-source/test_apps16_readback_progress.py \
  --repo /absolute/retained-git-repository --source /absolute/retained-service1800-source \
  --generated-guest /absolute/retained-service1800-generated/base_guest.py
```

The paired host control uses five exact frozen package archives and synthetic local ALPM records. It compares complete snapshots and runs the original content-drift and foreign-xattr refusals. The drain control verifies forwarding before EOF while preserving the raw log. The corpus supplies host equivalence and instrumentation cost only. A fresh source-bound trial is required to measure the 606 path on ARM16K.
