# Native FDK trial 38268251114: source-stage diagnosis

**Actual trial FAIL; FDK compiler invocation NOT ESTABLISHED.** The original producer boundary now passes. A concrete selected-packet serialization portability defect was independently reproduced, but the retained native evidence does not prove it caused this hosted failure. Proposed correction: pin the already identical uncompressed selected USTAR bytes and retain every source/content/license and recipe checksum gate. No implementation or pin change was made here.

## Actual retained evidence

Run `38268251114` completed at 15:16:17 UTC against commit **a50d53f7a8ccd7f6fee39b7501f2320113e60207**, packet **0329598c3d7777b9ed2234bf2bfdb366d1bec1ddf07871154f2c3c2c95ec1ab2**, stage39 **b83ddb865d7651c748258ac570e64fb824caf5bced8b1f415694dff7f5c187f5**, workflow **6df06b24cba7d55f26a8941b515f234a9ad4a24e11b164b8615cf3357dd9faa9**. Independently rehashed all eight regular public files against `root-public-verification.json`. The coordinator's strict decoding/public guard PASS is distinct from execution status FAIL.

The actual producer boundary records accepted/PASS, worker zero without cancellation, positive cleanup absence, native delegate zero, four completed original comparisons and final compare zero. Public acquisition records **501 PASS / zero pending / zero FAIL**; signatures record PASS for 249 payloads, including 248 signed packages. The producer summary records 341 builder packages and all four original package pairs passing bytes, installed contents and metadata comparisons. This review verifies these retained receipts and their hashes; it does not independently reconstruct their unexported private attempt/compare bytes or reauthenticate downloaded payloads.

FDK public status is FAIL, `phase: source`, `error_code: fdk-stage-failed`, `owned_container_absence: true`, native build NOT ACCEPTED and hardware/installation/publication NOT RUN. At the exact committed source, `source` is assigned after successful accepted/live base checks and before these predicates:

1. Run selected-source CLI with `--fetch-upstream` and require exit zero.
2. Run materializer CLI against the pinned template map and require exit zero.
3. Read the pinned reviewed map, enumerate/hash the recipe and require exactly 23 matching files.

Any exception at these points collapses to the same public phase/code. Private FDK command logs, raw receipt and runtime versions were not exported. The first failed source predicate and hosted cause therefore remain **UNPROVEN**. The source-phase failure does not attest a compiler invocation, codec build or AAC integration.

## Exact committed data-only replay

Read the current roadmap/inventory and source/workstream contracts. Captured all **39 stage closure files** from the actual commit with read-only Git blob/mode verification, plus the exact stage lock, into an owned private `/tmp` fixture. Imported only captured authenticated runtime/template helpers. Used the exact stage command arguments, a 120-second aggregate runner and the same cleared private environment: PATH `/usr/bin:/bin`, LANG `C.UTF-8`, LC_ALL `C`, temporary HOME and DOCKER_CONFIG. No native guards, Docker, compiler, upstream build scripts, installer or real-home operations ran.

The first sandbox attempt stopped at DNS failure; its receipt is preserved as an environment-limited result. A retry initially encountered the harness's existing exclusive log file before child execution; that harness result is also preserved, then corrected with a fresh owned log directory. Authorized pinned data-only acquisition subsequently passed in **1.371 seconds**:

- Selector `--fetch-upstream`: actual exit zero; fixed upstream archive SHA256 `ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806` validated; selected 900 files.
- Selected gzip packet: **2,701,495 bytes**, SHA256 `1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7`.
- Materializer: actual exit zero; exact **23-file** recipe map equals reviewed map `4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b`.

This successful replay uses local Python **3.14.7 / zlib 1.3.1.zlib-ng**, not the unknown hosted runtime. It does not repair or reinterpret the actual failed trial.

## Reproduced portability defect

The exact captured selector's `build_archive` uses `gzip.GzipFile` with its default compression and pins the resulting compressed digest. Rebuilt the same authenticated 900 selected file bytes in two actual available runtimes:

| Runtime | Generated gzip bytes | SHA256 | Pinned digest |
| --- | ---: | --- | --- |
| Python 3.14.7 / zlib 1.3.1.zlib-ng | 2,701,495 | `1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7` | matches |
| Bundled Python 3.12.14 / standard zlib 1.3.2 | 2,692,991 | `988fb524a385fd41a851090696858084640a065be66fbb779bf46efccba97262` | refuses |

Both use compression level **9** and identical gzip header `1f8b08000000000002ff`. Both produce the exact same **17,387,520-byte USTAR**, SHA256 **1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4**, and identical selected-byte aggregate `ed13dd9a9bf1f5712f2d7c04325cc63ddf966ff3071da8dfe3a66fd5b73c4373`. Independently constructed USTAR also matches. A direct single-call raw-DEFLATE compressor with explicit level9/window/memory/strategy reproduces each runtime's respective complete gzip bytes: buffering, tar headers, compression defaults and filename/mtime/OS header drift do not explain this pair. The difference lies in compressor serialization.

The [CPython 3.12 constructor](https://github.com/python/cpython/blob/v3.12.12/Lib/gzip.py) and [3.14 constructor](https://github.com/python/cpython/blob/v3.14.0/Lib/gzip.py) both default to level9, consistent with the actual probes. These primary sources support the API comparison; they are not evidence of the hosted runtime version.

The actual Python3.12 selector CLI, given the authenticated existing selected packet as `--input`, exits **one** with its fixed error `reconstructed packet differs from pinned selected digest` and leaves no output. This is a causal source portability reproducer without network or upstream-code execution. Standard zlib 1.3.2 is the tested implementation; the actual trial's Python/zlib and failure message remain unavailable, so this review does not label the reproduction as its proven first cause. Specifying compression level9 alone would not fix it, nor would rebinding the pin to another compressed implementation's output establish portability.

## Proposed portable content contract — coordinator selection required

Prefer an **uncompressed canonical selected USTAR** (`fdk-aac-3.0.0-selected-source.tar`) pinned to exact length **17,387,520** and digest **1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4**. The two tested serializers already agree on these bytes. Use the existing sorted names, USTAR format, prefix, epoch1791748800, regular-file mode0644, uid/gid0 and zero/default names; validate exact bytes before parsing. This removes host compression from generation while preserving an ordinary fixed source checksum in PKGBUILD and generated `.SRCINFO`.

Retain all of the following without fallback or skipped checksums:

- Exact upstream commit/archive digest and its existing 8 MiB acquisition cap.
- Exact 898 implementation files plus two grants, unchanged per-file sizes/hashes and selected implementation license-header checks; unchanged notice digests and no copied unselected upstream scaffolding/assets.
- Existing rooted regular-member/name/duplicate/inventory rules, 8 MiB per-member cap, 32 MiB expanded-content cap and 4,096-member ceiling. No extraction or build before verification.
- Independently reviewed template map and exact **23-file** materialized map, literal new selected-tar checksum/filename in both PKGBUILD and `.SRCINFO`, and static/generated/artifact recipe bindings.
- Ordinary source-file ownership/path and private output rules, command deadlines/resource ceilings, native-only builder guards and all install/hardware/publication exclusions.

The proposed selected raw packet exceeds the old 8 MiB compressed-container cap. Raise **only reads/storage specifically for this exact selected packet** to a finite **20 MiB** ceiling, with exact length/digest enforced. Upstream acquisition and unrelated template/member/JSON limits remain unchanged. A zero-compression gzip wrapper would similarly exceed the old cap and still require a deliberately canonical wrapper implementation; raw USTAR avoids that additional serializer. This is a specific format/cap correction, not a blanket archive-hash exception.

Coordinator-authorized implementation would have to update the selector/parser/materializer and relevant names/caps, recipe/.SRCINFO checksums, packet provenance/manifest metadata and frozen template/materialized maps. Preserve all 900 per-file rows and grant facts while rebinding any surrounding metadata hashes. Revalidate stage source closure, job packet and dependent workflow pins/Git/copy proof after the owner's source hold. The old selected gzip/recipe history remains accurate historical evidence. None of these edits or map changes was performed here.

A bounded **nine-case proposed-data-contract probe passed** using the unchanged current `audit_members` over the canonical raw USTAR. It admits exactly the 900 files / 16,686,087 content bytes and rejects truncation, trailing data, selected-container overflow, gzip wrapping, altered member bytes, symlink/missing inventory and notice drift. This validates the proposal's finite data boundary, not an implemented production format or native package build.

An alternative algorithm-independent decompressed-content acceptance policy would need to bind each actual compressed archive checksum into the generated recipe and freeze an explicitly reviewed generation policy for the resulting `.SRCINFO`/23-map. It introduces more receiver/recipe-policy changes than the single fixed canonical tar. Merely accepting arbitrary compressed hashes, ignoring the final archive digest, using `SKIP` or silently rebinding to standard-zlib output is not an acceptable proposal.

## Proposed finite source diagnostics

Keep diagnostics independent of the serializer correction. Before/after each actual source predicate, persist a closed source-bound record; preserve the first observed failure through cleanup. Suggested fixed predicates: `NONE`, `SELECTOR_COMMAND`, `SELECTOR_EXIT`, `MATERIALIZER_COMMAND`, `MATERIALIZER_EXIT`, `REVIEWED_MAP_READ`, `RECIPE_MAP_OBSERVATION`, `MATERIALIZED_23_MAP`. Command returns are separate typed records: `NOT_RUN`/`UNOBSERVED` with null code, or actual `EXIT_ZERO`/`EXIT_NONZERO`/`EXIT_SIGNAL` with a real bounded integer, rejecting booleans and invented zero after launch/timeout/cancellation failure.

A finite failure category may distinguish exact known runner deadline/timeout/output-bound errors, cancellation, process/filesystem errors, invalid data and other unclassified failure. Do not copy exception names/messages, paths, logs, URLs, response bodies or arbitrary child stderr into public fields. Map only trusted exact internal errors to known categories. A source command's nonzero return establishes that command failed, not its unexported internal fetch/selection/serialization predicate. Recipe count/equality observations remain null until actually measured. A PASS source record requires both observed exits zero and actual complete23-map equality; neither successful cleanup nor recovery can promote a failed/unobserved predicate. Validate the same finite projection in stage, outer job/public receiver and root-owned workflow before a rerun.

These diagnostics are proposed, not implemented. The coordinator must select the authorized format/cap and source scopes before any edits, then preserve explicit native outcome gates.

## Evidence and limits

Owned evidence: `artifacts/reviews/fdk-stage-source-diagnosis-20261012/` contains committed capture, exact replay scripts/receipts, both serializer receipts, actual Python3.12 CLI refusal, final data verification and nine-case canonical-tar proposal receipt. The private temporary source/recipe path and exact command environment are recorded in `capture.json`/`source-replay.json`. Review artifacts contain hashes/finite results, not upstream implementation payloads. After all checks, immediately removed the owned selected packet and 23-file materialized recipe (5,935,762 bytes); `raw-retention.json` records positive absence. The authenticated39 source snapshot and metadata-only command logs remain in the private temporary fixture. Replay must first reacquire the validated selected data with a fresh log label.

Actual corrected producer evidence is accepted at its own finite boundary. FDK trial remains FAIL. No FDK native compile, target dependency/provider substitution, AAC consumer integration, installation/removal, M2, 16K or performance result is established. The serializer portability bug is reproduced; the hosted first source predicate remains UNPROVEN. Shared implementation, maps, locks, Git, workflow and native dispatch were not modified by this reviewer.
