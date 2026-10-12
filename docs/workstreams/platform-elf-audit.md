# Static platform ELF and loader observations

Status, 2026-10-12: **DYNAMIC-MAPPING CORRECTION IMPLEMENTED; 46 LOCAL FIXTURE TESTS PASS. Corrected independent source review and actual 624-archive ELF audit NOT RUN.** Initial40-test source `9fa7a868…` was independently blocked by ELF-DYN-1; its source/checkpoint/test evidence remains historical. This is a bounded static-data follow-up to the actual 624-archive payload inspection. Neither a successful parser nor an observed library candidate establishes installation, runtime ABI, actual 16K execution or M2 compatibility. Coordinator owns source adoption, fresh authenticated execution and shared maps/Git; this owner changes only the two new ELF files, this record and private `artifacts/platform/elf-audit-20261012/` evidence.

Read the current roadmap and package inventory. The protected Asahi/platform transaction and coordinated Python proposal retain their prior acceptance status. The historical 406/618/623 payload failures remain unchanged. Existing platform helpers, contracts, source pins, package inventory and authentication data are not modified.

## Exact input proposal

The new contract is `artifacts/platform/elf-audit-20261012/proposed-inputs.json`, SHA256 `17b5a1414fb7575fde9168fbf7378f310ddef2edabef8c8b24784fcc1648a418`. It binds these actual retained inputs:

| 624 input | SHA256 |
| --- | --- |
| Payload contract | `e77ce4f77f8bef40e011b710cc1ffcef3d10a5d778454c00e9eaac4936f8bca6` |
| Complete inert payload report | `7df4b87a2d8d31455fa0e8cf30e2f53eed65cacbb2d2dbe7dd395b9484ecf314` |
| Payload handoff | `4d2e056c3812610efbc842a23b45560800e3d0e11a4e8e0ebb53e0f671686aad` |
| Authentication bindings | `beed7e78a57e121ee13922194882803f6eae1cd989293005250016ca81cd637f` |

Those reports were rehashed during proposal preparation. The old reader's source remains pinned to `a7cb3a1c469f88fdb37d17e2414eb283bc53e0ef7211d0723af2b9037fa7689c`, from committed `9140bcaf939bd15b82a2a8c3f020b842c9f03c48`. Its actual 624 PASS records 1,323,663,952 compressed bytes, 5,709,117,440 decoded bytes and 138,317 nodes. Reading that existing report finds 7,129 header-level ELF observations: 6,717 ELF64/EM_AARCH64, 350 ELF64/EM_NONE, nine ELF64/EM_BPF and other firmware/data machine/class identities. These are the old reader's bounded header observations; the new full static parser has **not** run on them.

## Initial source and format semantics (historical blocked snapshot)

| Initial source, mode0644, blocked by ELF-DYN-1 | SHA256 |
| --- | --- |
| `scripts/platform/elf_audit.py` | `9fa7a8681caeb66c114779f6f2af24e56e52629436ec5f947943b20695842d00` |
| `scripts/platform/test_elf_audit.py` | `daed64b6b314bf15e1f37ab3c5210729698a34c0f7d8aacdc9551247b77e5c8b` |

Implementation is original MIT source using only the Python standard library, with no local helper import, third-party parser, linker, `ldd`, `readelf`, package code or compiler dependency. It supports bounded ELF32/ELF64 headers and both byte orders. Numeric type/class/machine/OSABI/ABI-version/flags and entry point are retained. ET_EXEC is executable form; ET_DYN is shared-object-or-PIE form, without claiming that every ET_DYN object is a library. Provider identity is limited to observed ELF64/little-endian/EM_AARCH64, zero AArch64 flags, System V/GNU OSABI, ET_EXEC/ET_DYN and load segments. Relocatable objects, foreign/unknown identities and firmware paths are reported as data or unresolved runtime scope, rather than blanket foreign-runtime failures. Firmware-path objects cannot become native library candidates.

Primary format references are the [gABI ELF header](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html), [program headers](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html) and [dynamic linking](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html), plus [AAELF64 revision2025Q4](https://github.com/ARM-software/abi-aa/blob/2025Q4/aaelf64/aaelf64.rst). They define fixed header/table shapes, EM_AARCH64=183, byte order, file and memory segments, interpreter strings and dynamic string references. DT_STRTAB is a virtual address; the parser maps it through one unambiguous file-backed PT_LOAD interval. It does not treat the value as a file offset or read a zero-filled BSS tail as a string table. [String-table rules](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.strtab.html) also bind first/last null bytes; even unreferenced declared tables are checked, and a genuinely empty table is allowed when it has no string requests. Ordered repeated DT_NEEDED entries remain ordered; relevant singleton tags, interpreter and dynamic segment duplication refuse. Offsets, table sizes, string termination and file-backed ranges are checked before use.

[Linuxv6.19 binfmt_elf.c](https://github.com/torvalds/linux/blob/v6.19/fs/binfmt_elf.c) provides the pinned kernel-loader reference for page rounding and load alignment; this reference revision is not a claim about the shipped target kernel. Each PT_LOAD records its declared alignment, congruence at that alignment, and file-offset/virtual-address congruence modulo16384. Congruence and declared alignment are separate observations. Alignment below16384 is recorded as insufficient declared16K alignment even when the modulo16384 relation holds. Neither observation predicts certain load failure or proves runtime eligibility: segment interactions, kernel configuration, relocations, libraries and execution remain untested. Section/symbol relocations and symbol-version ABI are outside this parser.

[glibc2.42 dl-load.c](https://github.com/bminor/glibc/blob/glibc-2.42/elf/dl-load.c) is the pinned userspace-loader source reference. The audit retains RPATH/RUNPATH and DT_NEEDED names, but does not reproduce environment/cache/hwcaps, secure-execution rules, token substitution, search order or symbol/relocation resolution. The reference is not a shipped-glibc assertion. GNU/Linux source licenses remain those of their upstream references (GPL-2.0-only and LGPL-2.1-or-later); their runtime implementation is not copied or executed by this original data parser.

## Reader and provider scope

Every archive reference receives strict exact schema, positive nonboolean size, per-file and aggregate accounting before payload capture. A no-follow regular single-link file is captured, with before/after identity/stat and whole compressed SHA256 checks. Parsing consumes the captured bytes after the source descriptor closes. The new stream must match every old report member's path, type, mode, size, target and regular-file SHA256, including controls; duplicate/traversing paths, sparse/special members and missing/extra members refuse. Only ELF regular-file bytes are retained transiently for parsing. Other bytes are streamed and hashed. No member is extracted to a filesystem or executed. Archive errors and per-object parser refusals stay visible; they cannot produce a static inspection PASS.

Interpreter paths are resolved only in the observed archive namespace. The resolver has bounded expansion and refuses cycles, root escape and non-directory ancestors. Hardlink aliases require a same-package observed regular target. Library candidates come from qualifying ET_DYN objects without an interpreter, their SONAME/basename, and verified archive aliases. Distinct locations remain ambiguous even with similar names; absent candidates are labeled missing from this observed inventory. Absolute DT_NEEDED names receive path lookup; relative slash-containing names and dynamic tokens remain unresolved. A single global candidate is only an observation and is not proof that a target loader selects it. Parser/archive refusal marks the candidate inventory incomplete. Missing and ambiguous requests remain findings even if static byte inspection itself succeeds.

| Preserved reader/output bound | Value |
| --- | ---: |
| Compressed per archive / aggregate | 300,000,000 bytes / 2 GiB |
| Decoded per archive / aggregate | 1 GiB / 8 GiB |
| Member / per-archive nodes / aggregate nodes | 512 MiB / 100,000 / 500,000 |
| Per-archive deadline / outer trial envelope | 300 seconds / 20 minutes |
| Process memory / private retained data | 2 GiB / 256 MiB |
| JSON input/output | 64 MiB each |
| Program headers / section headers | 256 / 65,534 |
| Dynamic entries / each string / loader requests | 4,096 / 4,096 bytes / 500,000 |
| Archive path / link expansion | 4,096 bytes / 40 |

The 20-minute outer lifetime, 2 GiB memory and256MiB retained-data bounds must be enforced by the coordinator's disposable execution wrapper, just as for the preceding payload audit. Internal streaming deadlines cover reads and final processing; bounded filesystem syscalls are not an independent hard lifetime guarantee. The new parser adds finite table/string/request limits, without raising old archive/decoded/node limits. Extended ELF numbering is explicitly unsupported and produces a recorded parser refusal. A refusal due to this strict parser's unsupported/noncanonical shape is not a claim that a real kernel rejects the object. The output writer requires fresh mode0600 output beneath an owned0700 artifact directory and refuses symlink ancestors or overwrite. A source snapshot's guarded output can be copied and rehashed into the assigned private evidence directory.

## Actual fixture verification and next action

**The initial40 fixture tests passed, zero skips**, under `python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/platform -p 'test_elf_audit.py' -q`. Fixtures construct inert ELF and xz/tar bytes only. They exercise ELF32/both byte orders, non-native/BPF/firmware roles, DT_NEEDED order, SONAME/interpreter/search strings, every ELF64 header truncation, table/segment range errors, extended numbering, BSS and ambiguous string mappings, malformed/duplicate dynamic tags, control/unbounded/unterminated strings, alignment versus16K congruence, symlink cycles/escapes/depth and same-package hardlinks. Actual owned file snapshots survive source-path replacement; symlink/hardlink inputs, node/hash drift and output freshness/caps refuse. Full synthetic pipeline fixtures retain missing-provider findings and failed archive correlation. Complete input/report/handoff bindings, bad reference accounting and duplicate/control-path/node budgets refuse before archive reads. Exact2GiB aggregate accounting admits while2GiB+1 refuses without allocating large payloads; the synthetic count and archive consumer are explicitly mocked only for that accounting fixture.

The initial checkpoint and copied source/test replay (now historical BLOCKED source, not acceptance) under `artifacts/platform/elf-audit-20261012/` are source evidence, not a new624 package inspection. Next: independent source review, coordinator adoption/fresh authenticated snapshot, then an explicitly authorized bounded run using the proposed contract. External byte/mode verification must precede executing the captured CLI with `-I -B`; an in-process digest is not a substitute. Example contract arguments after authorization are `--contract <captured proposed-inputs.json> --contract-sha256 17b5a141… --output <fresh private report path>`; the full digest is in the input table above.

No actual624 ELF scan, source-package execution, install, native build, host keys/trust change, mount, ABI/import test,16K runtime or hardware/performance acceptance occurred in this proposal. Existing catalog authentication, independent owner trust/custody, corresponding-source/license grants, installed-image correlation, target transaction, recovery and production release gaps remain open.


## ELF-DYN-1 correction

The independent reviewer demonstrated a material error in the initial `9fa7a868…` source: PT_DYNAMIC read its `p_offset` table without correlating `p_vaddr` and `p_memsz`. Three actual inert ELF fixtures kept apparent dynamic bytes at file offset320 while specifying virtual address4096 (unmapped),1024 (a different zero table) or2^64-1 (overflow). The old parser accepted a fabricated needed name and SONAME from bytes a loader would not use. This blocks the initial proposal despite all40 fixture tests passing. The initial source, checkpoint and reviewer proof remain unchanged; actual624 ELF scanning was never authorized or run against that source.

The corrective implementation follows the pinned [glibc2.42 loader](https://github.com/bminor/glibc/blob/glibc-2.42/elf/dl-load.c), which locates dynamic metadata using its virtual address and memory extent. It requires the entire PT_DYNAMIC interval to map through exactly one file-backed PT_LOAD interval, with address overflow checked and mapped file offset equal to `p_offset`. The strict reader policy requires `p_memsz == p_filesz`, a nonempty integral bounded number of dynamic entries and full file backing. Unequal/BSS/noncanonical extents are explicit parser refusals, not assertions of certain kernel failure. The output records the correlated dynamic interval. DT_NULL ends interpreted metadata: later entries are counted as ignored padding/data and cannot become needed names or SONAME evidence. A physically present terminator beyond the declared interval does not terminate that interval.

| Corrected source, mode0644 | SHA256 |
| --- | --- |
| `scripts/platform/elf_audit.py` | `c283d4c8091286156ed319bcdfb2860073322e16a6ed3f626edc6efd00db3c35` |
| `scripts/platform/test_elf_audit.py` | `a6ee66dda5fb313f64091a8a550f60ad0be037df87b8498a31f52958b433670f` |

**46 local fixture tests PASS, zero skips.** New tests cover the three causal wrong-address cases, memory/file extent disagreement, a missing terminator within the declared extent, fractional/trailing entry boundaries, BSS and ambiguous load mappings, and ignored post-DT_NULL entries. A coherent nonzero-offset control uses load file offset256/virtual address16640 and dynamic file offset768/virtual address17152; it retains the correct names in ELF32/ELF64 and both byte orders. The prior16K comparison now moves PT_DYNAMIC and DT_STRTAB consistently with the changed PT_LOAD virtual address, preserving a meaningful positive control. The string-table ambiguity fixture separately overlaps only its string interval, keeping its intended coverage. A full synthetic archive/contract case refuses the wrong dynamic interval, returns overall static FAIL, marks the provider inventory incomplete and emits no fabricated dependency request.

The owner independently replayed the reviewer's three actual inert files against captured historical `9fa7a868…` bytes and the corrected parser. All old false interpretations reproduce; corrected results are exactly `elf-dynamic-mapping`, `elf-dynamic-offset-disagreement` and `elf-dynamic-overflow`, with no provider requests. Proof `artifacts/platform/elf-audit-20261012/dynamic-correction-proof.json` has SHA256 `7986acb14212e1ce1f27501066bdedc4b40142ab8d03657f1278e5d8e8b6b2b8`. These files are review fixtures, not package execution or an actual624 scan. The proposed input contract and all old platform contracts/helpers/pins/caps remain unchanged. Corrected held checkpoint and peer closure precede coordinator adoption and any actual624 execution; installed/runtime/16K/hardware acceptance remains open.
