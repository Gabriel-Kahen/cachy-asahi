# Platform static ELF audit independent review

Status: **held source review blocked by confirmed ELF-DYN-1; owner correction pending**. Independent fresh-copy 40 tests pass with zero failures/errors/skips. No actual624 ELF scan, package execution, installation, native build, ABI/import test, physical16K or M2 execution occurred. PASS in a parser fixture is not runtime acceptance.

Read the current roadmap, package inventory and held workstream. Only this review and `artifacts/platform/elf-audit-root-review-20261012/` were written; source, shared maps/locks, Git, system trust and package state remain unchanged by the reviewer.

## Held reviewed bytes

| Path | Bytes | Mode | SHA256 |
| --- | ---: | --- | --- |
| `scripts/platform/elf_audit.py` | 24,972 | 0644 | `9fa7a8681caeb66c114779f6f2af24e56e52629436ec5f947943b20695842d00` |
| `scripts/platform/test_elf_audit.py` | 23,921 | 0644 | `daed64b6b314bf15e1f37ab3c5210729698a34c0f7d8aacdc9551247b77e5c8b` |
| `docs/workstreams/platform-elf-audit.md` | 11,354 | 0644 | `d804bda3853c6d6c33c6b672b042cb3b49f90010abb229e4a4692faf4c259982` |

Author checkpoint `artifacts/platform/elf-audit-20261012/checkpoint.json` rehashed to `30daccc365d084cddbbf4de4dca8d014acec5332fca15b35d98032450b465707`. All three held files were captured into an independent new PYC-free tree before execution; captured bytes/modes match the hold. The owner has since been authorized to correct the blocker, so this disposition applies to these original held bytes rather than any later moving source.

## Confirmed ELF-DYN-1: dynamic virtual mapping ignored

`parse_elf` retains only `(p_offset,p_filesz)` for `PT_DYNAMIC`. It does not bind `p_vaddr` or `p_memsz` to the file-backed `PT_LOAD` mapping before reading the dynamic array. This differs from the existing correct treatment of `DT_STRTAB` virtual addresses. The [gABI program-header definitions](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html) distinguish file and virtual addresses; [glibc2.42 dl-load.c](https://raw.githubusercontent.com/bminor/glibc/glibc-2.42/elf/dl-load.c) records the dynamic address from `p_vaddr` and its entry extent from `p_memsz`, then applies the load bias. This is a format/source relationship, not a claim that the target uses this exact glibc revision.

Three independent 2,048-byte inert ELF64 fixtures have `PT_LOAD` at file/virtual offset0, dynamic file bytes at320, and valid string bytes at512. Mutating only the dynamic virtual address to **4096 (outside the load), 1024 (a different mapped all-zero table), or 2^64−1 (overflow)** leaves the parser's SONAME and `DT_NEEDED` output unchanged. All three are labeled `aarch64-loadable-elf` and enter the observed-provider/request machinery. Thus those loader observations can be derived from bytes that the declared memory mapping does not associate with the dynamic array. `runtime_load_verified=false` correctly prevents a runtime claim but does not repair the false structural relationship.

The complete evidence is `dynamic-mapping-counterexamples.json` and the three accompanying inert `.elf` fixtures in the review artifact directory. Root and source owner received this finding before finalization. A narrow correction should validate the complete dynamic interval/entry extent and address arithmetic, require an unambiguous file-backed virtual mapping consistent with its declared file offset, and refuse or explicitly exclude unresolved dynamic mapping from provider observations. Meaningful coherent nonzero-offset and relocated-load positive controls are needed alongside unmapped, mismatched, ambiguous, BSS, overflow and memory-extent negatives. Refusal under a documented conservative parser policy must not be described as proof that a real loader rejects a package.

## Other bounded checks and limits

Independent tests ran from the captured tree under `python -B -Werror::ResourceWarning -m unittest discover -s scripts/platform -p test_elf_audit.py -v`: **40 tests, 0.040 seconds, no failures/errors/skips**. `suite.log` retains the actual results. Additional direct probes refused all96 ELF32 header truncations across little and big endian, duplicate SONAME/RPATH/RUNPATH singleton tags, cross-package hardlinks and escaping symlinks; `boundary-probe-results.json`. These supplement the suite's file/table/segment bounds, ambiguous/BSS string mappings, string termination/control/duplicate checks, ET_REL/BPF/foreign/firmware roles, ordered needed names, 16K alignment/congruence distinction, namespace limits, archive-member correlation and output/input controls.

The proposed actual contract `17b5a1414fb7575fde9168fbf7378f310ddef2edabef8c8b24784fcc1648a418` was reviewed **as metadata only**. All four referenced JSON inputs were size/hash checked; actual payload/report/handoff associations agree. All624 names are unique and complete; package archive refs/status and declared-member mismatch fields agree. Archive cache paths received regular/single-link/size stat checks only, totaling1,323,663,952 compressed bytes. This check does not claim fresh archive hashing, repeated signatures or actual ELF inspection.

The parser otherwise distinguishes ET_DYN shared-object-or-PIE form from a proven library, keeps non-AArch64/relocatable and firmware data outside native provider identity, and conservatively reports global observed candidates, ambiguity and missing providers. RPATH/RUNPATH, environment/cache/hwcaps, secure execution, symbol versions, relocations and actual loader selection remain unverified. The [gABI dynamic-array/string definitions](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html), [string-table rules](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.strtab.html), [AAELF64 2025Q4](https://github.com/ARM-software/abi-aa/blob/2025Q4/aaelf64/aaelf64.rst) and [Linuxv6.19 loader source](https://github.com/torvalds/linux/blob/v6.19/fs/binfmt_elf.c) were consulted. Declared alignment and file/virtual congruence modulo16384 are observations; neither establishes actual16K behavior or certain runtime failure.

The reader consumes compressed SHA-bound captured bytes and correlates each streamed member against the old hash-bound report. Unsupported extended numbering and per-object/archive refusals remain visible failures/incomplete candidate inventory. Missing or ambiguous library candidates remain findings even when static byte inspection succeeds. The coordinator must enforce the documented external process/memory/retained-output envelope; internal read deadlines alone are not a hard syscall lifetime guarantee. Source digesting inside an executed helper cannot replace pre-execution byte/mode verification.

No additional concrete blocker was confirmed during this bounded original-source pass. ELF-DYN-1 must close against a new explicit source hold before source approval or an actual624 scan. The six recovered archives and prior624 payload PASS remain data evidence; installed image authentication, independent trust/custody, corresponding source/licenses, runtime ABI, platform transaction/recovery, production and hardware acceptance remain separate unfinished gates.
# Coordinator correction adoption

The original40-test source and its ELF-DYN-1 finding above remain historical.
The corrected held source is `c283d4c8091286156ed319bcdfb2860073322e16a6ed3f626edc6efd00db3c35`,
tests `a6ee66dda5fb313f64091a8a550f60ad0be037df87b8498a31f52958b433670f`,
and guide `14194206e07ab88fb3ff6ea789302a3bc9f4c1cd13af5cdbee47421902d0255c`,
all0644. Coordinator independent fresh-copy46 tests pass with zero skips.
All three retained inert reviewer fixtures now refuse the unmapped virtual
interval, wrong file offset, or overflowing address. PT_DYNAMIC's complete
memory extent must be file-backed, equal its declared file extent, and have
one matching PT_LOAD translation. Valid nonzero-offset/class/endian fixtures
remain passing. Source approval closes ELF-DYN-1 conservatively; it does not
claim complete Linux loader validation or16K/runtime/M2 compatibility.

The root receipt is `artifacts/reviews/platform-elf46-root-source-review-20261012.json`.
The exact624 input contract and existing read/resource limits are unchanged.
Actual624 ELF scanning remains NOT RUN at this source-adoption point; a fresh
committed/authenticated helper copy is required for the separate data execution.
