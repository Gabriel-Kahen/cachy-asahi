# Kernel ELF declared alignment — independent Root peer

Source-only PASS on2026-10-14. Frozen author receipt is eb695976512f6da9c721984db2005d7e8aae71b85f05963e9cb6de4677de99d4. Actual-review receipt532a6613b8bf78f54bc44750e08eb26e31112aa62f6d6f595bad86ff17f80093 remains separate. Full R1–R5/M5–M9, both M2 Air sizes, hardware16K/W/X and measured performance remain unfinished.

Authenticated25 author leaves and41 retained actual-review leaves, their indices/receipts, external pins, retained Root Source proof and current five worktree preimages. All five current bytes/modes/hash descriptors matched the frozen a311de55bf34df1a889dcfff101abb8fa2eb4358 preimages at review and final seal. Test Source is outside the124 runtime rows: its exact Git-blob SHA1 was recomputed from held bytes and matches92849a1b085db4bdaffe7f7cafbaa886ebc7834d; Root's later commit proof remains its authority. No Git query or mutation occurred.

The [ELF ABI](https://gabi.xinuos.com/elf/07-pheader.html) separately specifies page-size VA/file congruence and declared power-of-two alignment/congruence. The [GNU linker author patch](https://sourceware.org/pipermail/binutils/2021-December/118893.html) describes common-page p_align smaller than maximum-page segment layout. This supports the narrow distinction; it is not proof of the selected actual emitted operands or a hardware loader result. Pinned retained Asahi memory/linker/runtime mapping text was read without accessing its private source archive.

Thirty-one fresh focused groups pass. The exact old/new ELF parser class and cstring are AST-selected; complete synthetic ELF64LE/AArch64 ET_DYN bytes with genuine section-name/symbol tables run through bounded BytesIO seams. The fixture generator is a held pure Source definition, not native code. Declared4096 and8192 with16K-congruent VA/file and PA/file load geometry are old-red/new-green;16384 remains green. Floor0/1/2048, nonpower12288, VA-only4K, PA-only4K, malformed declared congruence, permission7/unknownbits, empty or invalid memory/file ranges, overflow, entry outside file-backed RX, section W/X/outside-load and executable stack remain refused. A relocatable module with no program headers remains accepted in its synthetic profile. Falsey/KeyboardInterrupt/SystemExit/GeneratorExit parser read faults retain the same exception and close the owned fake stream in both versions.

Reversing only the one changed predicate reproduces the entire old verifier byte-for-byte. Section/load/entry/symbol/Image/config/module validation, output bounds, Source checks, exception paths and all clocks remain held. The new conservative floor4096 is paired with explicit16K VA/file and PA/file congruence; it does not accept generic no-alignment0/1 profiles or loosen W/X acceptance.

Exact test reversal removes one added regression and restores the old invalid-floor literal2048→4096, yielding the entire original test AST. No existing method/assertion is removed. Retained author42-pass/one-existing-skip suite and internal68 paired cases were authenticated but not replayed. The author's three complete verify_outputs fixtures mock Source identity and remain separate from this peer's complete ELF parser fixtures; neither is a native output.

Stage membership stays29, changing only verifier. Runtime packet membership stays124: verifier, stage lock and packet loader change;121 rows remain held. Top-level policy metadata is identical and the loader changes only its stage hash. The five-copy map is exact:

- verify_build.py a71d95c329360e00b22694a8a41244c57f7747a3cd8551c54d843d914be10435/42523B/0755.
- test_verify_build.py55012cda9b235443431836307a28b3df78505dc68472d43ad48d6e76bf0a7fb5/36377B/0644.
- stage.lock.json b415aa06203b13dedebc0d1f2a7c3aeeec3e91bbf1c9d55e7fc79ddf61566253.
- packet.py934152feb3c8c112dbaa69efc54ac095c5e8cedb25ed0de241e11e624605c5bd.
- packet.lock.json99942af8f057cbabe8d56cc490b81c5437f13dc849872bab0c91a3e95bb544b3.

Actual38583969397 remains FAIL. Retained natural KERNEL return0 precedes OUTPUTS/DATA_REFUSAL, VERIFY_OUTPUTS/CHECK_001. That fact names a compound check and exposes no segment/alignment/permission/size operand; the actual failed term remains UNKNOWN_UNRETAINED. Local over-refusal proof does not backfill the historical cause, accept its unretained ELF or promise the next run will pass. Producer/cleanup/daemon preservation PASS and candidateNOTRUN retain their separate scopes.

One initial peer packet-mode schema error is recorded in attempts.json and corrected only in the harness. No actors, compiler/linker, private-output/archive reads, canonical/API/dispatch changes occurred. Root must recheck/apply the exact five copies, authenticate committed Source/full packet and register a new trial. Hardware/platform/runtime/recovery/performance/release acceptance requires its own actual evidence.
