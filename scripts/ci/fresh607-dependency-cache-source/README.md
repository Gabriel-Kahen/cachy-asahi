# Exact retained dependency-cache source factory

This factory reproduces public1203 source `ddfc78e30552356baa94fa123f17fd33efc2aedc` from the complete unchanged diagnostic parent `15eed0d72b793117e0a44e670567acea63c2819c`. It changes eight files and holds1195. Supply a closed ordinary source export, without `.git` or unrelated files. The constructor reads DATA only; it never imports or executes supplied source, acquires artifacts, authenticates packages or mutates the host.

```sh
python3 -I -B -Werror scripts/ci/fresh607-dependency-cache-source/prepare.py \
  --source /absolute/diagnostic-parent-source \
  --output /absolute/fresh-cache-source --context known
```

`--context null` emits the same exact bytes with a NULL source/ref receipt. Both contexts keep all actual selectors and acceptance NULL. Existing outputs, aliases, noncanonical paths, source/operand changes, hardlinks and foreign namespace members refuse before writes. All emitted files are0644 and the output root is0700.

The runtime correction seeds eight missing retained archive/signature leaves and checks the two already-retained xdg-utils leaves. All ten still pass the original acquisition/GPG/signer/hash/PKGINFO checks; preparation does not authenticate or accept them. Original six-copy preparation and added copies share one240-second deadline; acquisition180 and all VM/security/cleanup clocks remain held. Default4K and emitted16K runtime bodies are unchanged. Full source and guard inverses remain mandatory, without vendoring a historical source tree.

Portable factory controls require `FRESH_CACHE_INPUT` for the exact parent and `FRESH_CACHE_EXPECTED` for the public child export:

```sh
python3 -I -B -Werror scripts/ci/fresh607-dependency-cache-source/test_factory.py
```

The frozen runtime author qualification is separate from this factory. Current generic16K execution, installed behavior, physical Asahi/M2, performance and release require their own results. This source factory grants no new acceptance.
