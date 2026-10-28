# Independent review: kernel resource diagnostics

Result: **PASS for the held source and bounded fixtures; no blocking findings.** This accepts an observation-only diagnostic change for review. It does not register a source closure or admit native execution.

The reviewed checkpoint is `artifacts/reviews/kernel-resource-diagnostics-20261012/checkpoint.json`, SHA-256 `b755f4057b5d8ac2905885d080b7350d3aa8f1231e2f99864eb7933bde451e01`. The independent evidence is in `artifacts/reviews/kernel-resource-diagnostics-root-peer-20261012/receipt.json`.

## Source custody and proposed maps

The checkpoint's 18 evidence artifacts, ten owned Python files and new guide were authenticated by SHA-256, byte count and mode. All 117 captured source rows were checked and copied into a fresh review directory. Read-only Git verification authenticated 118 baseline blobs and their modes at commit `215bd7b4f7e0ba3fa5d23e38d60a503b963c2ed0`: the original 117-row packet plus its excluded packet file. `215` denotes that commit prefix, not a file count.

The proposed capture changes exactly 12 of the 117 rows: ten owned Python files, a copied stage map and the copied `packet.py` stage-pin literal. The other 105 rows remain exact baseline bytes and modes. Pure captured-source `packet.preview` reproduces the proposed packet byte-exactly. The proposed 26-row stage pin is `92e6ae6348cef9a1032d77494554e581a2839ef4bd5ecc5fb14bb0112fde3ee4`; the proposed 117-row job pin is `5112e5b9f8078e84d9bde23db0ac53cf6931acf3f7329ff52f54fa22db2fd3e0`.

The registered stage map, job packet, primary `packet.py` and workflow remain exact baseline. The only admitted FDK dependency in this review is `scripts/port/fdk-native-stage/evidence.py`, SHA-256 `27d16ce1a89d949075b0fe85072575883de6e9021a4902747c4b8ed44ed71b27`. The moving FDK helper is excluded. No worker helper authority is inferred.

## Semantics and public boundary

Independent AST comparisons recover the entire original broker after removing exactly the post-refusal observer/rethrow, and the original stage/job after removing their schema-3 PASS guards. Resource predicates, Python equality semantics, ordering, ownership guards, actor queries, clocks, polling and cleanup behavior remain unchanged. The observer runs only after the original resource predicate refuses; it neither relaxes enforcement nor adds a query.

The optional observation is null or the closed `{field, kind}` pair. Independent controls cover all 15 required and seven forbidden field names, the build-role `CapAdd` refusal, and the original predicate's bool/int and empty-forbidden behavior. The four private/public validators and their constants match after the existing prefix mapping. Exact schemas, context restrictions and the 4096-byte bound reject raw values, unknown fields, poisoned types and oversized records.

Current observations reset at scope entry. The first failure and cleanup failure remain independently copied and sticky. Diagnostic labels cannot grant worker success, an actual child exit, cleanup success or a successful outer outcome. Strict legacy schema-1/2 records remain historical only; modern PASS requires schema 3 and every resource observation slot.

## Verification and limits

Fresh authenticated-copy verification passed **93 stage tests and 195 selected job tests**, with zero failures, errors or skips in the final runs. Fourteen job `BootstrapTests` methods were deliberately excluded because their setup writes temporary Git repositories. The author's authenticated 209-test job log is retained separately; this review does not claim a fresh full 209-test rerun. Two initial job failures were caused solely by the review runner's subprocess allowlist rejecting the harmless `/bin/true` fixture. The corrected runner passes; the initial runner and failed logs remain in the evidence directory.

Independent peers additionally passed 53 actual-inspector resource refusal cases and 51 focused validator methods, including 1,788 validator calls across the field/kind/slot matrix. Twelve added causal test methods were checked against the baseline. These are source, model and harmless local-process checks, not Docker or native builds.

Kernel5's actual schema-2 FAIL remains canonical byte-exact, SHA-256 `9363a4a311a892fc37138981674d5e5d458e7dab9cd986599b323172e000bd0a`. Its precise failed resource conjunct remains unknown; start remains `NOT_ATTEMPTED`, cleanup remains FAIL and owned absence remains unverified. No historical record was upgraded to schema 3 or given an invented resource label.

Docker, GPG, native compilation, installation, performance and M2/16K hardware checks were **NOT RUN**. This lane made no production, shared-map, workflow or Git writes. Prior seven-source handoff corrections remain frozen at checkpoint SHA-256 `7051b51c307ae574e0302bbb24b60c664821ee5e3462d65f9db15def690a1efa`. Integration and actor admission remain separate work.
