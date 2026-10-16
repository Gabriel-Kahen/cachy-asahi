# GNU provider lifecycle input materializer

`prepare.py` only reads and copies data. It neither builds nor installs anything,
executes exported code, calls Git, starts actors, changes the owner policy, nor
creates Root decisions. It is bounded to native run `38960150458`, source
`0056a7c1b83ff325f1368d3659cfeb8e5a5c8358`. A running/failed run or absent explicit
Root acceptance refuses before output creation.

After Root collects and accepts the actual successful run, invoke from the
repository root with actual decision paths and a fresh output directory:

```sh
python3 -I -B scripts/ci/glibc-gnu-provider-packet/prepare.py \
  --collection ACTUAL_ORIGINAL_COLLECTION_DIRECTORY \
  --pair-decision ACTUAL_ROOT_PAIR_DECISION_JSON \
  --normal-decision ACTUAL_ROOT_NORMAL_COMPILATION_DECISION_JSON \
  --private16k artifacts/development/glibc16k-run38941180852/root-verification.json \
  --private-runtime artifacts/development/glibc16k-run38941180852/runtime.json \
  --runtime-sources scripts/ci/glibc-owned-runtime \
  --held artifacts/platform/baseline-acquisition-20261012/cache/glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz \
  --output FRESH_PACKET_DIRECTORY
```

The collection must retain original `collection.json`, `run.json`, `artifacts.json`,
`artifact.zip` and `logs.zip`. The archive digest joins the API artifact object,
collection receipt and both explicit decisions. The source proof joins the
actual run/source/attempt and both distinct build containers. Both packages,
embedded and retained BUILDINFO, recipe/SRCINFO, full upstream result rows,
normal compiler receipts and original command outputs, normal ELF interpreters,
source/license bytes and ordered consumer/producer absence must join.

The source bundle contains the nine frozen recipe files, three original GNU
inputs and source authentication, with no generated `.SRCINFO`. Literal byte
pins bind those recipe files and `build-harness/expected.SRCINFO` to the exact
source commit above. Both retained native `evidence/generated.SRCINFO` records
must match that expected metadata. Runtime source records carry observed inode
and device details; their byte counts and hashes must match normal compilation
source identities, while all original records remain unchanged.

Both Root decisions must contain `run_id` (integer), `source_sha`,
`artifact_sha256` and `retention_sha256`, binding the actual collected export.
The pair decision additionally contains `status=ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR`,
`hardware=NOT_RUN`, actual `archive_sha256` and `provider_pkgbuild_sha256`.
The normal decision contains `status=ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES`,
`normal_source_sha256=a766bc7cd31cce18fe7e564432de4e4b63db49763608ae70ef8fab61cd29116c`,
`files` with exactly the three names below, and `compile_receipts` with `a`/`b`.
All ordinary refs have exactly `path`, `bytes` and `sha256`:

- Normal `files` paths: `runtime/a/normal-clients/bin/smoke-normal`,
  `runtime/a/normal-clients/bin/exec-child`, `runtime/a/normal-clients/bin/plugin.so`.
- Compile receipt paths: `runtime/a/normal-clients/receipt.json` and
  `runtime/b/normal-clients/receipt.json`.

No template acceptance receipt or archive digest is supplied. Root writes these
decisions from the actual result; the materializer preserves them verbatim.

The result is the adopted outer owner's `packet.json` interface, including both
archives, selected normal probes, exact held rollback archive and all decisions.
The original ZIP/API/collection files remain in `collected/`, so every source-map
origin can be checked without another retrieval. Nonempty original members are
also copied at their unchanged export paths; zero-byte outputs remain in the ZIP
and source map because the owner's ordinary refs require positive byte counts.
The immutable original runtime sources, license and exact single-edit normal C
source are retained in `normal-source/`. File count (256), per-file (256MiB) and
aggregate (512MiB) limits match the owner. An over-limit export is refused.

All validation precedes temporary staging. Publication reserves a fresh output
name exclusively, then renames the complete staging directory. Failed staging
is removed; existing outputs and all inputs are preserved. Root subsequently
freezes the actual packet revision/hash and binds the owner policy. Prepared
inputs confer no installed, M2, security, performance or release acceptance.

Run inert controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ci/glibc-gnu-provider-packet/test_prepare.py
```

The controls use temporary synthetic archives and explicit synthetic decisions,
reuse frozen recipe bytes but mock fixture held/GNU identities, block subprocess actors and exercise
the real owner data gate. They never create a real accepted-input payload.
