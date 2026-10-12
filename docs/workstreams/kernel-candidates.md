# R3/M7 kernel candidate: KERNEL-C01

Source work completed on 2026-10-12. One eight-line correctness patch was
actually applied to a full private copy of the retained Asahi source. The
separate baseline tree remains identical to that archive. Kernel compilation,
native kernel execution, physical16K/M2 validation and measurements are NOT RUN.
This candidate is not selected for a release. The protected platform tuple and
reviewed ARM-C01 six-source lock were not edited.

## Pinned baseline and finite audit

Read `docs/roadmap.md`, `manifests/packages.toml`, platform capture and
`scripts/platform/kernel-correspondence.json` before implementation. This is
progress toward R3/M7, not satisfaction of its hardware/recovery acceptance.

| Input | Exact identity |
| --- | --- |
| Asahi kernel source | Commit `94fb23346d522edf53722357c426a3e58030beea`, tag `asahi-7.1.13-3`, package `7.1.13.asahi3-2` |
| Retained compressed archive | 262,965,559 bytes; SHA-256 `874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad` |
| Actual embedded config | SHA-256 `ae1d4ce855bd435b62c8fb213cbcf2d4eefd47b62274792c4a6bf299848b3876` |
| Historical supplied config | SHA-256 `a66145c1b93002e47ae6a9ab09698b4ae4f202cdad09da5e87a6abad080a66aa`; pahole131 versus embedded132, other lines identical |
| Cachy patch inventory | `CachyOS/kernel-patches` at `17bb0bb818d283d0dc6e0280a2e9d5b95e66808b` |
| Cachy kernel recipe/defaults | `CachyOS/linux-cachyos` at `59f65f1b18e642888ec3415d01aec86c0c15bf0e` |
| Cachy7.1 fixes branch | `eeb430fda7ca459865df848512a165b4e5d99f57` |

The actual embedded config is pinned rather than claiming reproduction of its
historical generator. It preserves ARM64_16K_PAGES, ARCH_APPLE, DRM_ASAHI,
Apple DART with strict DMA, Rust, MCA/MACAUDIO/AOP audio, HZ1000 and full preempt.
It leaves THP and LRU_GEN disabled. See the exact source URLs, notices and hashes
in [`audit.json`](../../scripts/port/kernel-candidates/audit.json).

| Audited candidate | Decision and platform interaction |
| --- | --- |
| BIO slab fallback, Cachy `0d61333f6e03e8fa4620e33e1bac4c644a9412c6` | Sole selected source experiment. Common block allocation reaches Apple NVMe; storage/memory pressure can indirectly affect graphics and audio. No new config or page geometry. |
| USB descriptor control-character truncation, `63f0e52c5da93e5199320037c242984b55401f3f` | Not selected. Generic USB identity changes require peripheral matching, USB audio, reconnect and resume checks despite untouched Apple controller drivers. |
| UDMABUF scatterlist change, `f9490d6abf76e99efc8f8435181d5f7f7871cd19` | Excluded from this experiment: UDMABUF disabled. Enabling it adds a variable; DMA buffers, PAGE_SHIFT and DART mappings need physical16K checks. |
| Reclaim/writeback change, `6f80b5c9567fe190f6b17efd4c998907f9fdb778` | Deferred. Shared reclaim paths remain relevant with LRU_GEN disabled; broader NVMe, AGX memory pressure, audio, power and suspend regressions need a dedicated experiment. |
| Cachy tick/preempt/compiler/THP defaults | No change. HZ1000/preempt already present; no gain established. THP, O3/LTO, tickless and scheduler substitutions are unreviewed variables. |

Exclude x86 CPU/native/v3/v4/Zen flags, AMD/Intel PC power/drivers, NVIDIA,
DMI/ACPI/WMI hardware detection, IntelMac/T2 apple-bce assumptions, scheduler
replacement, kernel-manager and PC boot integration from this experiment.
Apple m1n1/U-Boot/firmware, DCP/AGX, DART/SART, RTKit, PMGR, device trees, audio
and speaker protection remain baseline inputs. Asahi's [platform report](https://asahilinux.org/2025/08/progress-report-6-16/)
explains why boot, graphics, audio and power integration must be tracked together.

## Selected change, notices and actual results

[Cachy commit0d61333](https://github.com/CachyOS/linux/commit/0d61333f6e03e8fa4620e33e1bac4c644a9412c6)
has the same hunk as [primary Linux commit447cfed6](https://github.com/torvalds/linux/commit/447cfed6d700bfbd5a7120f8ea5821a0e1191667).
When a per-CPU BIO cache is empty, the existing code skips its slab allocation.
Without DIRECT_RECLAIM it can returnNULL unnecessarily. The hunk shares the
existing slab attempt with this cache-miss path. Cache-hit and flag handling,
bvec cleanup and mempool fallback bodies stay unchanged. Source correspondence
does not demonstrate runtime behavior or performance.

The full patch is 2,249 bytes, SHA-256
`d6564155f9cb9cabc2c281b39c92c8231086a6fce855aa685c9f3709e1f04674`.
`block/bio.c` changes from
`ee6bf72d442a263fc8c86db6048c4476775a860971ba42e1c7cba1e1d693dd27`
to `be44b4dcbf65d05c43447f5a37a20a322ed2bf9e06a0f41d9a496bc8ab274dd4`.
Both GNU patch dry-run and application returned0 with fuzz0, no offsets or
rejects. The complete archive has100,117 members,93,861 regular files,
99 symlinks and1,589,202,874 declared file bytes. Full comparison verified every
regular-file hash and link target; only `block/bio.c` differs in the candidate.
Baseline verification found no changed member.

Keep `block/bio.c`'s GPL-2.0 SPDX and Jens Axboe copyright, Joseph Qi authorship
and signoff, and Christoph Hellwig suggestion/review in the original patch.
The source root COPYING is GPL-2.0-only WITH Linux-syscall-note. The harness
retains COPYING, GPL-2.0, Linux-syscall-note and license-rules text unchanged.
This selected-file audit does not close all kernel/firmware redistribution
licenses. The Cachy recipe declares GPL2 while its repository LICENSE is GPL3;
no recipe implementation or broad unreviewed upstream source is published here.

Ignored evidence under `artifacts/kernel-candidates/`:

- `full-baseline-20261012/result.json`: full unchanged baseline and command-free materialization.
- `full-candidate-20261012-b/result.json`: actual full-tree patch application and both command/log hashes.
- `source-audit-20261012/application.lock.json`: exact original application lock, SHA-256 `611da0b6104baa3a2c444ce7637b0296a6fe97c88a098f0980a9faf1a0e1751d`.
- `source-audit-20261012/final-verification.json`: explicit revalidation binds current plan lock to the preserved application receipts; source fields are identical.
- `upstream-audit/`: finite upstream metadata, original patches, source notices and independent single-file application.
- `independent-review/`: bounded independent source/harness review and adversarial probes.
- `final-plan-20261012/result.json`: current plan lock actually validated; command list empty.

The current [`candidate.json`](../../scripts/port/kernel-candidates/candidate.json)
hash is `d26f691006a24f76db11f2f353e0ec10d93425ce2b6f8970a446b7bd34c98617`.
It adds future build quota/headroom requirements to the original build plan;
source/archive/config/patch/license pins are identical. Old receipts were not
rewritten. The first full attempt retainedFAIL because Python normalized a
symlink spelling; its owned failed tree was removed, while failure logs and
receipt remain. Exact safe link spelling and resolved target checks now pass.

## Executable source and future native build plan

[`harness.py`](../../scripts/port/kernel-candidates/harness.py) has `plan`,
`baseline` and `apply` modes. Validation reads pinned data; application invokes
only GNU patch, never a kernel Makefile, recipe or helper. It rejects changed
input/member hashes, duplicate/path-traversal members, special files, escaping
links, new patch targets, binary/rename/mode changes and any fuzzy/rejected
application. New outputs must be canonical paths below the owned ignored
directory. Each full tree is capped at2GiB declared content plus a <=300MiB
compressed snapshot, with4GiB free-space prerequisite. Input snapshots are
hash-checked before extraction; the extraction pass enforces the budgets again.
Current owned retained evidence is approximately3.9GiB; this work used a6GiB
retention budget. Only owned failed work was cleaned; protected archive/config
inputs and other workstreams were untouched.

From the repository root, use a new absolute output for a repeat:

```sh
python3 -B scripts/port/kernel-candidates/harness.py apply --full-source \
  --lock scripts/port/kernel-candidates/candidate.json \
  --lock-sha256 d26f691006a24f76db11f2f353e0ec10d93425ce2b6f8970a446b7bd34c98617 \
  --archive artifacts/platform/kernel-history-20261012/linux-asahi-7.1.13-3.tar.gz \
  --config artifacts/platform/kernel-history-20261012/embedded-config \
  --patch artifacts/kernel-candidates/upstream-audit/0d61333f6e03e8fa4620e33e1bac4c644a9412c6.patch \
  --output /absolute/checkout/artifacts/kernel-candidates/new-candidate
```

Use `baseline --full-source` for the unchanged full tree, or `plan` for a small
source slice without command execution. Failed post-validation work writesFAIL
and preserves bounded diagnostics; inputs refused before materialization do
not create output. Follow the6GiB retention budget before another full pair.

[`native-build.sh`](../../scripts/port/kernel-candidates/native-build.sh) is an
executable future plan, syntax-checked but NOT RUN. It requires native nonroot
aarch64 Linux, exact source tree/config/lock and a reviewed immutable builder
receipt with package-inventory hash, nine resolved tool executable pins and an
enforced <=24GiB writable-output quota. No such kernel builder receipt is yet
frozen or assigned; this remains the next native-build prerequisite.

```sh
bash scripts/port/kernel-candidates/native-build.sh \
  baseline ABSOLUTE_BASELINE_SOURCE NEW_ABSOLUTE_BUILD_OUTPUT \
  ARCHIVE EMBEDDED_CONFIG ORIGINAL_PATCH CANDIDATE_JSON CANDIDATE_SHA \
  REVIEWED_BUILDER_RECEIPT BUILDER_RECEIPT_SHA
```

Run the same interface for `candidate` with the separate verified candidate
tree. Both variants use the same toolchain, flags, timestamp and experimental
LOCALVERSION; only source hunk differs. Observed toolchain metadata is GCC16.1.1,
binutils2.46, Rust1.93.1, bindgen0.73.2 and pahole1.32. Dependencies come from the
historical recipe and are recorded in the plan. Exact generated configuration
equality is mandatory, including tool-version symbols; this has not yet passed
on a builder. The native wrapper clears build environment overrides, fixes
tool paths, limits jobs2 and per-process address space8GiB, config generation
to300seconds and full Image/modules/dtbs build to7,200seconds per variant with
30second kill grace. Its24GiB free-space check is a headroom prerequisite;
the reviewed builder must independently enforce the writable-output quota.
No install, modules_install, boot, sysctl or service target exists.

[`verify_build.py`](../../scripts/port/kernel-candidates/verify_build.py) now
requires `outputs --build BUILD --source VERIFIED_94FB_TREE` and optionally
`--expected-config APPROVED_GENERATED_CONFIG`. Its Python interface is
`verify_outputs(build, source, expected_config=None)`. The same-job caller must
first establish complete source/archive/patch and builder closure; the output
verifier independently authenticates nineteen unchanged source files by exact
SHA-256 before using their contents. Those pins include both M2 DTS files,
arm64 Image/link rules, EFI header, vermagic, module-generation rules and the
Apple audio module mapping and module-export namespace macros. `source_evidence_sha256` in its result records the
exact map and source commit. It reads no source Makefile as executable code.
The held original wrapper has not been edited: its old `outputs` invocation
omits the now-required `--source` and therefore refuses acceptance. The new
native stage must consume this interface after independent review.

The strengthened checks are:

- Full bounded [FDT format](https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html)
  parsing: version/backwards compatibility, block bounds/order/alignment,
  nonoverlapping reservation ranges and terminator, balanced nodes, unique
  nodes/properties, property-before-child ordering, padding, string references,
  and the single final END token. Root `compatible` and `model` bytes must equal
  the exact pinned J413/J415 DTS properties, including the ordered compatibility
  list. This does not establish DTB equality to a compiler-generated baseline
  or validation of every driver property.
- Real current-version ELF64 little-endian AArch64 headers and section/symbol
  tables, config-selected ET_DYN for RELOCATABLE or ET_EXEC otherwise, an entry
  inside executable file-backed load memory, >=16K load geometry, consistent
  allocated sections, bounded RELA indexes and no writable executable loads,
  sections or stack. The pinned source's zero-offset little-endian16K Image
  header has flags12, valid effective size, zero reserved fields and a branch;
  `_text`, `_end`, ELF entry and Image header bytes must correspond. The entire
  Image is also compared byte-for-byte to the pinned
  `arch/arm64/boot/Makefile` projection:
  `-O binary -R .note -R .note.gnu.build-id -R .comment -S`. Copied file-backed
  allocated ELF sections are mapped through their unique PT_LOAD physical load
  addresses (LMA), ordered, and compared in <=1MiB chunks. Explicitly removed
  sections, unallocated debug/metadata and NOBITS memory are excluded; gaps must
  be zero, ranges must not overlap, and EOF must follow the last copied byte.
  The header effective size `_end - _text` may exceed this file extent because
  it includes zero-initialized memory. Ambiguous/compressed/excluded allocated
  layouts are refused. `image_elf_relation` records section extents, zero-gap
  count and verified Image SHA-256. This establishes agreement between the
  supplied binary files, not proof of compiler execution or source semantics.
  EFI-enabled
  Images additionally require bounded source-shaped ARM64 PE32+ headers and
  sections. These file geometries do not establish physical page-table behavior.
- Every generated `.config` setting is compared when an expected configuration
  is supplied. Both Image and vmlinux must contain exactly one complete bounded
  gzip IKCONFIG member whose uncompressed bytes equal the actual generated
  `.config`, with its SHA-256 recorded. Generated `kernel.release` must name
  version7.1.13 and exactly match `include/generated/utsrelease.h`.
- Nonempty unique Kbuild `.o` paths in `modules.order` must exactly match actual
  uncompressed `.ko` files. Configured MCA, MACAUDIO and AOP audio modules are
  mandatory. Every module requires valid relocatable AArch64 ELF, code, module
  descriptor, defined exported symbols and `.modinfo` name/license/dependencies;
  exact vermagic derives from generated kernelrelease, SMP/preempt/unload/version
  config and the pinned arm64 rule. `Module.symvers` requires five tab-separated
  fields, valid CRC/export/namespace/owner fields and nonduplicate symbols
  actually defined in their declared ELF owner. The pinned modpost grammar
  accepts `module:btrfs`, comma-separated module lists and optional tail-globs;
  malformed, empty or oversized lists are refused. This is structural/export
  plausibility checking, not loader or ABI acceptance.

Bounds include vmlinux4GiB, Image256MiB, each DTB4MiB, config1MiB, at most4096
modules/12GiB combined (1GiB per module), <=250,000 output inventory entries,
<=8,192 ELF sections and <=2,000,000 symbols per ELF. Gzip decoding is bounded
before materializing config output; no external command or upstream code runs
in output verification. Native preflight authenticates one descriptor snapshot
of the builder receipt before parsing that same byte buffer, rejects duplicate
JSON keys. Both native preflight and output verification enumerate at most
110,000 source entries and256 symlinks, require strict existing-target
resolution inside the exact source root, and reject dangling or cyclic chains.
Enumeration errors propagate; unreadable subtrees cannot be silently skipped.
The held source harness was not edited; its existing escaping-link checks are
separate from this new native-consumer cycle/missing-target guard.

The revised local suite has62 passing tests:20 unchanged source-harness tests
and42 verifier tests. Synthetic valid files establish parser behavior only;
adversarial cases include the previous8-byte DTB false positive, malformed
FDT tables/tokens/identity, invalid ELF type/version/geometry/WX, missing/swapped
IKCONFIG, changed generated release, missing/extra/linked/compressed modules,
wrong module vermagic/descriptor/relocations, invented symvers exports, sparse
oversize files, gzip expansion and builder-receipt swaps, valid module namespaces, malformed namespace lists and
source-link cycles/budget exhaustion and unreadable enumeration subtrees.
New Image relation cases reject a byte64 body mutation with unchanged vmlinux,
mutated copied data or zero gaps, truncated/trailing data and LMA overlap.
Positive fixtures exercise removed build-ID notes, unallocated debug data,
NOBITS memory beyond EOF, shifted physical addresses and retained allocated
dynamic string/symbol/relocation data. Data-only x86 synthetic ELF probes with
the pinned objcopy flags matched normal, shifted-LMA and all three dynamic
section projections; these probes compile or execute no kernel. The
[GNU objcopy documentation](https://sourceware.org/binutils/docs/binutils/objcopy.html)
describes the binary output as starting at the lowest copied load address. The actual retained source passed all
nineteen source-file pins and all99 links resolved strictly inside its root. Kernel
compilation, kernel execution, hardware validation and measurements remain
NOT RUN. The original27-test historical receipt was not rewritten.

The historical independent **source/application** review is PASS. It pins harness SHA-256
`f2d6fc62d28b0c189469ca7cf8293f10c574ecd0459c33c013bf1a271b8a5ebf`;
`independent-review/review.json` SHA-256 is
`aa23a7b0cd9a3d6dc75564fffbbea8b9a0e960a3f854a9ec53c1676690735fe3`.
The reviewer separately verified both complete source trees, all99 candidate
symlink resolutions, historical/current lock correspondence,27 implementation
tests, its25 harness checks (including20 shared tests),4 original verifier probes and
shell syntax. Those original probes did not establish complete output
structure; the strengthened verifier above requires a fresh independent review.
These overlapping historical check counts are not summed as unique tests.

Before retention for a release, implement/run the native allocation regression
cases (cache hit; empty cache/slab success without reclaim; slab failure/no
reclaim; mempool and bvec paths), then compile both full kernels. Separately,
both exact M2Air sizes need a proven baseline recovery boot, physical16K boot,
storage integrity under allocation pressure, graphics, audio/speaker protection
during I/O, suspend/resume, and paired battery/thermal/performance measurements.
Keep the accepted Asahi recovery kernel/boot files intact; any experimental
package or boot entry needs its own later integration review. Performance and
compatibility remain unproven, and M7 acceptance remains incomplete.
