# ARM-C01 native failure correction: independent review

2026-10-12. **In-flight source review; final owner-held hashes and correction validation pending.** Reviewer owns only this document. No native ARM, 16K-page, M2, installation, release, or performance acceptance follows from the portable checks below.

## Actual retained native failure

Read the current roadmap, package inventory, and ARM experiment handoff/design. Inspected `artifacts/ci/38218102399/development-decoded/development-arm-c01-base-owner-public/public/` independently. The native result and launcher result are FAIL, with hardware/performance NOT RUN and release selection false. The retained contract binds source commit `108302cff3d7be59800747773017cad688489904`, original runner `b725639885740505a04fbdcab2e629e3201afb09cf948ac997c1309d91fe36cf`, and zlib source `bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.

There are 88 completed correctness records: the first producer's 84 positive cross-decodes and four CRC rejection records. Command 143, `baseline-1-reject-truncated-trailer-baseline-1`, ran the original `minigzip -d`, returned zero, and correctly failed its required rejection gate. It emitted 312 decoded bytes, SHA256 `a63114ad7013e439edaaeca1070536758567e78545e12daea16803d12201e0fa`, from the 327-byte truncated input, SHA256 `2cd5546291ea6525b873331a372f57a2a96b5c18b8a13d0542db63b366d2f2b4`. Its stderr log is empty. Native machine observation is aarch64; actual page size is 4096. This partial run cannot satisfy the full correctness matrix.

Independently verified all 143 retained projected command logs against their recorded bytes/SHA256, the environment and corpus manifest hashes, and all 84 positive decoded-hash records against the manifest. The projected command `log` paths are authoritative here; `producer_log` preserves the original names before public neutral-name projection. Public projection explicitly omits binary and corpus bytes, so this check does not independently rehash the earlier compiled binaries or replay their successful decoded outputs.

## ACN1: API resource failure falsely classified as invalid input

Reproduced against draft `scripts/experiments/arm_c01.py` SHA256 `a08a93d125a4bc1ad34341506d728f07bfe4057b4e02d35daadf34743974c83f`, strict C source SHA256 `13e4bb3550303aeec09cc17af62a0df32b079af075809a35acac44edb68da530`.

The driver's default status is 2. After `inflate()`, any result other than `Z_OK` or successful `Z_STREAM_END` breaks without distinguishing `Z_MEM_ERROR` or `Z_STREAM_ERROR`. Consequently a memory allocation failure can pass the corrupt-input acceptance criterion `(2,)`, while emitting the invalid-input diagnostic. This contradicts the driver's stated resource/I/O failure status 3.

Compiled the exact C source in an owned temporary directory on local x86, linked against the existing system libz. A linker `--wrap=inflate` shim returned `Z_MEM_ERROR` on the otherwise valid reference gzip. The process returned **2**, with `strict gzip: incomplete or invalid single gzip member`. This deterministic API fixture executes no installer, Docker, or host transaction. It is distinct from native ARM evidence. The ordinary local reference/CRC/truncated cases returned 0/2/2 respectively.

The verified pinned tarball's `zlib.h` distinguishes input corruption from memory and stream-state errors; `inflate.c` can return `Z_MEM_ERROR` during lazy window allocation after initialization. The [tagged upstream API](https://raw.githubusercontent.com/madler/zlib/v1.3.2/zlib.h) and [implementation](https://raw.githubusercontent.com/madler/zlib/v1.3.2/inflate.c) corroborate those semantics. Reported to the coordinator for owner correction: reserve exit 2 for invalid/incomplete input and fail the gate for resource/internal API errors, with an injected-error regression.

## Draft matrix and evidence review

The draft preserves all 336 positive cross-decodes and all 32 corrupt-input/decoder records. Strict drivers are linked separately against each retained baseline/LTO static archive with the corresponding reviewed flags. Four valid-reference strict decodes ensure the new API route also accepts and reproduces a valid payload. Original sample CLI CRC rejection remains a separate required observation; truncation exits 0/1 are retained as OBSERVED with rejection acceptance NOT CLAIMED. The receiver expects the complete exact ordered 505-command graph, four strict binaries and exact source, hash-bound corpus/log/dataflow, the existing four artifact sets and effective configuration flags, both rebuild comparisons, and AArch64 ELF/load-layout checks. Resource exit 3 cannot substitute for strict corruption exit 2 once the driver classification is corrected.

The C driver bounds input at 16 MiB and output at 32 MiB, requires gzip-only initialization (`31`), `Z_STREAM_END`, and no remaining input. Its declared contract is deliberately one member; concatenated members and trailing bytes are rejected rather than treated as a general gzip utility. The retained corpus consists of seven positive inputs and two corrupt fixtures; input generator and source-derived held-out bytes remain independently checked. Command/output/log bounds and cleanup remain in the producer; source, executable, configuration, and receipt hashes remain receiver-checked.

Independently ran the draft `test_arm_c01.py`: **61 tests PASS, zero skips**, 3.358 seconds. Exact test source SHA256 `ad336aeddbb81db9907c7cb876e88866647552b1d356e4fee2d017eefbcbd25f`; unchanged corpus source `dbaf951adbb91d6769f40f8fb18c13044a42a3b5db11b4ad7d1f44afbed9ad8c`. These mocked/temporary tests do not close ACN1 or prove an actual native build.

The cached pinned tarball was independently hash-verified without downloading or executing its build. Selected archive file SHA256 values: `zlib.h` `818667d6ab6a37fe7469cb06a7f0cb2c2cb2f2c948a03e5accf1a4a74bf3020a`, `inflate.c` `90221ea7d762e7044057f6ad5013e969086c6ba3d3051716b7aa786d7a6362ec`, `test/minigzip.c` `203b1a4623a11021f4b64c5f6b6a4addc1bcefac694cd48cac71ccce35d82c1d`. Tagged web files are supporting API sources; the verified archive supplies exact experiment bytes.

Final source readiness is withheld pending ACN1 correction and stable owner hashes. The historical native result remains FAIL regardless of subsequent source correction.

## ACN1 correction validation

The subsequent current runner is `12576d39e30c13b91c003713218615e4b9259776ba86994ebe9730af0050f044`, test source `8a4ad0713a3df8e29d1582ef6b353e7eb224c4eeeb57973e31f34bb912bd7b3e`, and embedded strict C source `369e4e0e3f7c79b5d892edf7476ade41d6647332fb78f95ad7de7d8449bbaca9`. Corpus source remains unchanged. The owner now classifies only `Z_DATA_ERROR`/`Z_BUF_ERROR` as invalid-input exits; other unexpected API errors return 3. `inflateEnd()` failure also forces exit 3.

Independently reran the exact original linker-wrapped `Z_MEM_ERROR` reproducer: **resolved**, exit 3. Wrapped `Z_STREAM_ERROR`, `Z_VERSION_ERROR`, `Z_NEED_DICT`, and an unknown API result also returned 3. The ordinary exact reference/CRC/truncated corpus cases still returned 0/2/2. All builds/probes were temporary local x86/system-libz fixtures, not pinned native zlib builds.

Fresh runner suite: **64 tests PASS, zero skips**, 3.443 seconds, including three actual compiled portable C/API regression tests that cover initialization and cleanup failures as well. No residual material defect reproduced against these current bytes. Final source signoff still awaits the owner's held checkpoint; the original native FAIL is unchanged and corrected native execution is pending.

## ACN2: new strict decoder artifacts omitted from development export

The current adapter `scripts/experiments/stage.py`, SHA256 `e6eaf7200d97c0ff65f1d652b85987e2c00a5c60745c870e996cf90fd9b62b70`, still builds its development archive only from the previous `libz.a`, `example`, `minigzip`, generated configuration and corpus allowlists. The new `build['strict_driver']` binaries and exact `strict-gzip.c` are omitted from both that archive and the named text projection. Thus local receiver validation can succeed while the published bundle cannot independently bind the bytes of the newly authoritative corruption decoders.

Reproduced using the bounded adapter unit fixture: added all four synthetic strict binaries, their strict-driver/source hash receipts, and the exact embedded C source. `export_artifacts()` succeeded with 38 archive members and **zero** strict binaries or source. This is a synthetic export completeness test, not native execution. Reported for a narrow explicitly hash-bound, size-bounded adapter allowlist extension; generic credential filtering must remain intact. Final correction readiness remains pending this export boundary and owner-held hashes.

## Final held-source closure: ACN1 and ACN2 resolved

The coordinator supplied the following held checkpoint, independently rehashed before final review:

| File | Held SHA256 |
| --- | --- |
| `scripts/experiments/arm_c01.py` | `12576d39e30c13b91c003713218615e4b9259776ba86994ebe9730af0050f044` |
| `scripts/experiments/test_arm_c01.py` | `8a4ad0713a3df8e29d1582ef6b353e7eb224c4eeeb57973e31f34bb912bd7b3e` |
| `scripts/experiments/stage.py` | `0ec75669e3bac0b4aab59f67cc56bcf0b2bb1a78c8b8bca2c7485a91d1fd9f91` |
| `scripts/experiments/test_stage.py` | `76eb8800948338462876d8bff3868defd241935541e72be22af68a5d4a78bd16` |

ACN1's corrected runner and API regressions remain unchanged from the independently validated correction above. ACN2's adapter now reruns the complete exact receiver verification immediately before selecting outputs and requires its result to equal the previously verified receipt. It adds only the exact strict C source, the four hash-bound strict binaries, and the 32 strict rejection partial-output / four strict valid-output files to the existing finite original-artifact/configuration/corpus allowlist.

Independently reran the original omission scenario with a complete synthetic receiver fixture: the corrected archive contains **79 regular members**, including `strict-gzip.c`, **four strict binaries** and **36 strict output files**. Independently hashed every archived member against the manifest. Driver entries bind source/license, archive, declared/effective flags, ELF record, and compile/ELF argv and command-log hashes. Output entries bind exact input, driver, stdout hash/size and command/exit. Executable members retain `0755`; all remaining members retain `0644`; deterministic member metadata and bundle comparisons pass in the suite.

Additional independent substitution checks replaced the C source, one strict binary and one valid-output file; changed the caller's strict-binary receipt hash; and changed a strict compile command to add `-O3`. **All five were refused before archive output creation.** The prescribed full experiment suite also checks missing/changed rejection outputs, transformed declared/effective flags and strict-valid records, compiler-log drift, forged corpus allowlists, and exclusion of private/image extras.

Independent final aggregate: **100 tests PASS, zero skips**, 5.638 seconds, retained `/tmp/cachy-arm-c01-final-independent-tests.log`. This includes the actual portable C/API fixtures, mocked core/receiver checks, and bounded synthetic adapter tests. No actual ARM build or execution follows from those tests.

The adapter retains per-member input/output bounds, 64 MiB total uncompressed and 8 MiB compressed archive limits, exact member counts, single regular files, fixed names and reproducible archive metadata. The generic credential exporter is unchanged at `1ae8aded5ab461b280ca1ff82047f6766d58efacf7a09c83dc84515ac7d2216c`, matching the historical lock's exporter pin; no private-state/root/image export or generic filter exception was introduced. Compile/ELF command logs remain in the separate public evidence archive. Successful cross-decode bytes remain unretained and are explicitly described as producer hash checks, not replayed evidence. Original sample CLI diagnostics remain separate observations.

**Final disposition: PASS for bounded held-source readiness; no remaining material defect reproduced.** The source lock `98617adc3dd70fb71a9734d7f38840f553b795ce05322d5b95598f20d5aec4a5` is historical and is not acceptance of the corrected bytes; the coordinator owns its refresh and the subsequent executed-source/Git binding. Actual run `38218102399` remains FAIL. Corrected native execution, 16K execution, M2 hardware, release selection and performance acceptance remain pending/NOT RUN.
