# Native updater run 38314402583: independent review

**Actual FAIL; Cargo return0 observed, compilation not accepted.** The bound worker diagnostic records controller validation, compiler launch attempt and observed natural return0, followed by `compile-elf/UNKNOWN ValueError`. Worker/container return1 and no OOM are exported. This is progress beyond the previous precompiler failure, but neither a compiled package nor a native build pair passes. The outer terminal's `native_compilation=NOT RUN` means an accepted pair was not established; it cannot negate the observed compiler invocation.

The exact committed source is `ea9ab8cc9a6501b5fe60cebad679c9fc152295c5`. Independent read-only Git object/blob, SHA256 and mode checks authenticated all 86 registered files, totaling 4,213,032 bytes. Key pins are ready `3b77173e49dc520017310a66025a3dc196917d6f785b9e1de3e23ef9f8ad7a69`, stage `046081956546a172471498e96792cbd287ce48e1034b2143e1a8fd9ea8b82412`, source `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb` and workflow `63a5296028c6ff78b81b5581c10e8cdddd35fe6a6b58400299499c097d255b14`.

The strict logs.zip index matches ten unique safe members and 279,145 decoded bytes. Three bounded logged gzip/tar bundles reproduce all eighteen public files byte-for-byte, including export manifests. Their exact captured workflow AST consumers pass closed projection/schema, byte/hash inventory and original/recovery terminal binding checks. The current root capture covers the sanitized compile-result record; no older-helper omission was found. Its five manifest/lock/audit/metadata/cfg hashes match the exported worker metadata and image binding. These records export ValueError and hashes, but no private ELF/header or raw failure string.

| Observation | Exported result |
| --- | --- |
| Worker controller | `2330f55a36de1c3f0d6e392c255d76d20636225aec44474691f16f123539234d` |
| Outer controller | `e86a7ed7dac412665310733ae2cad8cbdb4e7eba7e5754a18d90d368860fd502` |
| Compiler | Attempted true; observed return0; accepted false |
| First worker failure | `compile-elf`, predicate UNKNOWN, ValueError |
| Worker/container | Return1; exited; no OOM; owned container absence verified |
| Original terminal | FAIL, `native-pair`, runtime process-failed/1 |
| Cleanup/recovery | Scoped cleanup PASS; private data removed; recovery PASS |
| Time/storage | 399 seconds; peak growth 12,900,847,616 bytes; storage guard not latched |

The controller digests have separate roles and must not be equated. Raw controller bytes were not exported: this review authenticates the committed receiver and exported binding correspondence. Cleanup PASS concerns scoped resources; daemon-wide disposal is NOT ATTESTED. Recovery attests cleanup, not compilation. This partial run does not establish full two-build storage fit. Publication, installation and M2 hardware acceptance remain open.

The exact `compile-elf` scope includes importing the gate, the bounded no-symlink/single-link regular-file read, then `gate.elf(bytes)` delegating to `elf_gate`. The latter checks ELF64/little endian, aarch64, program-header shape/bounds, LOAD alignment/congruence, LOAD file/memory bounds and presence of LOAD headers. Regular-file custody/size/drift refusals are also possible in this scope. Neither an API mismatch nor a particular 16K failure is established. The source inserts the reviewed 16K linker RUSTFLAGS before Cargo, and `worker.run` forwards that environment directly to Popen. A captured AST spy proves that source path retains the flags; the actual effective child environment was not exported.

Six synthetic byte-only ELF refusals through the exact gate and real private Recorder independently reproduce the diagnostic loss: each distinct leaf becomes `compile-elf/UNKNOWN ValueError`. A valid synthetic header passes the static gate. These are source controls, not the missing actual binary or a loader test. The worker's current generic step and public compile projection deliberately omit raw errors; the review cannot recover the private leaf or raw compiler stderr and proposes no implementation fix for the actual ELF.

The reproduced gap supports one narrow follow-up: tag the existing read/ELF refusal sites with a fixed leaf enum, preserve the first error/cancellation, and extend the existing bounded diagnostic/projector/verifier schema. If header facts are retained, keep them to closed nullable numeric/enum facts such as class/endian/machine, header width/count, LOAD count and minimum alignment; export no addresses, paths, raw messages, logs or binary. This proposal changes observability only. Its exact enum/bounds are held in the peer artifact; root must select and review any source change separately.

Peer proof: `artifacts/reviews/native-updater-38314402583-root-peer/proof.json`, SHA256 `7cd9d1b0c121667776ba7991fed046eafa3e5521acf8fe0f80de8a63bebccd3f`. The receipt seals source86, workflow, replay, proposal and this review. The peer ran no Docker, compiler, native, installation, GPG, services or network actors; only read-only Git/source/artifact operations and byte/directory models ran. Historical failure evidence and held source remain unchanged.
