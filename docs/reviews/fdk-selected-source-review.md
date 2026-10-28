# Independent FDK selected-source review

2026-10-12. Review scope: the source selection and independently authored build,
packaging, checks and reconstruction inputs for `cachy-asahi-fdk-aac 3.0.0-1`.
This is a source/data review. No compiler, package installer, network request,
repository Git mutation or system configuration change was performed by this
reviewer. Temporary source reconstructions and synthetic fixtures were created.

**Result: PASS for the exact selected-source packet, recorded copyright grants,
complete project inputs and reconstruction below. No required default GNU Linux
aarch64 implementation file without an established grant was identified.**
Actual native compilation must still prove build completeness. Runtime,
binary/source delivery, installation and hardware acceptance remain NOT RUN.
The broad private packet is not approved for publication by this review.

## Immutable implementation and copyright evidence

The independently inspected private input has SHA256
`1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49`.
It is only an inspection input, not an approved recipient release. Its selected
codec implementation is pinned to upstream full commit
`a68a51aa45d86a43c7b228e3d45624af09dcdd8d` by `build-layout.json`.

All 898 selected `.c`, `.cpp` and `.h` files match the recorded sizes and SHA256
values. Their first complete copyright comment includes the explicit source
and binary redistribution grant and the no-patent-license clause. No codec
bytes are modified. All eight complete comment variants actually present in
the selected implementation occur verbatim in `COPYRIGHTS-and-LICENSES`.
That bundle additionally retains a ninth variant from the broader input.
The two original Latin-1 PPC comments retain their original raw bytes;
the complete block plus trailing LF has SHA256
`190c9775bc437c6500cec2bba176d1d0e79efdd70a9b8e6b4c61ec4834ccf642`.

The clean 900-file codec packet, SHA256
`1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7`,
was independently compared with the retained original upstream codeload archive,
4,707,099 bytes, SHA256
`ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806`.
Every selected file and both full notices match its original bytes exactly.
This comparison read local archive data and made no network request.

Both full grants exactly match the original pinned input:

| Material | SHA256 |
| --- | --- |
| `NOTICE.classic` | `95ec80da40b4af12ad4c4f3158c9cfb80f2479f3246e4260cb600827cc8c7836` |
| `NOTICE.xhe-aac` | `bf3e762249027586195def2b2e904901b42c8b7fab455fc66bf365f70d08de6d` |
| `COPYRIGHTS-and-LICENSES` | `a0a52a99bef6dea5c370711f17ed1c02e8b0989a4c167f4e54a36368987428c0` |

These are explicit copyright grants subject to their stated conditions.
They do not grant patent rights or establish legal patent clearance. Free
complete source delivery with binaries, complete notices, no codec copyright
license fee and no implied Fraunhofer endorsement remain release obligations.

## Source and build inventory closure

The reviewed layout plans 170 classic and 225 xHE translation units. Every
planned translation unit is in the selected inventory and appears as a factual
source path in the private upstream Makefile inventory, which was inspected
as data and never executed. All 225 selected xHE translation units are planned.
The six additional selected classic architecture fragments are retained as
source; they are not separately compiled by the plan. The independent build
uses the selected implementation and its include directories and executes no
upstream Makefile, configure script, Rust wrapper, example or test program.

An independent textual scan removed comments and resolved quoted include
directives against each file's parent and its library's recorded include paths.
All 2,648 resolvable directive occurrences remain in the selected inventory.
The only external quoted headers are C-runtime `assert.h`/`stdint.h`, Windows
`armintr.h` guarded by `_M_ARM`, MIPS `dsplib_util.h`/`dsplib_dsp.h` guarded by
`MIPS_DSP_LIB`, and Android `log/log.h` guarded by the Android branch. This is
textual source closure, not actual compiler preprocessing or build success.
The additional angle-bracket project header `iisutillib.h` resolves inside the
selected source. Remaining angle-bracket includes are runtime/compiler headers
or explicitly gated Android/Windows/x86 headers; no macro-computed include was
observed. No extra upstream scaffold input is referenced by the build plan.

The selected codec packet must contain exactly those 898 unchanged files plus
the two complete original grants. Ungranted scaffolding and unused wrappers,
restricted manuals and unlicensed vectors must remain excluded. The old
private packet's filename does not establish its distribution rights. No
missing grant for an excluded file is silently treated as a codec source grant.
In particular, explicit grants for the privately retained `Makefile.am`,
`configure.ac`, `ChangeLog`, `rust/Cargo.toml` and `rust/build.rs` remain
unestablished. None is included or executed by this selected-source recipe.
The restricted manuals and unlicensed Rust vector are also excluded. This
packet resolves the selected implementation scope by exclusion and independent
build logic; it does not grant permission to redistribute those private files.

## Frozen recipient packet and verification

The source worker's final retained directory is
`/tmp/cachy-asahi-fdk-publication-review-qjpi7wr4`. Independent inspection bound
all inputs to these exact bytes:

| Artifact in that directory | SHA256 |
| --- | --- |
| `template-inputs.json`, 22 project inputs | `b569ff9ae69eb56e9b9635c3ed0849eaebbfa516f48304ade1790f802532bb63` |
| `reviewed-inputs.json`, 23 complete recipe inputs | `4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b` |
| `cachy-asahi-fdk-aac-3.0.0-source.tar.gz`, 2,822,903 bytes | `717fd8fce8afb165e95e673f74385746f5511576c548f80c56e88a1752ba5356` |

The bundle contains exactly 24 regular files: the complete 23-input recipe
(including the clean codec archive) and its map beside it. All members have
mode 0644, UID/GID zero and epoch 1791748800. The map and every recipe byte match
the frozen map; the 22 project bytes also match the actual repository template.
Neither the broad private archive nor ungranted upstream scaffolding is present.
The selected codec archive has exactly 900 files and 16,686,087 expanded bytes.
Selection preserves original source bytes and both grants. Only archive layout
and project packaging/build inputs are independently authored.

This reviewer reconstructed a fresh recipient at
`/tmp/fdk-independent-publication-review-v2i4hfgx/recipient`. Its exact 23-file
map matches the frozen map before and after tests. `review-receipt.json` and
`static-review.json` in its parent retain the independent results. All 75
software tests passed with no skips from that reconstructed recipe: 54 source/
selection/transport/repository tests, nine planners and twelve publication
checks. Ten Python AST checks, shell syntax and explicit-path recipe inspection
passed. Independently parsed PKGBUILD constants match `.SRCINFO`, including all
source digests, package relationships, dependencies, architecture and options.
PKGBUILD was never sourced; no compiler or source program was executed.

A second source run denied private-source reads and network connections. All
53 required source checks passed, with only the optional historical private
comparison skipped; there were zero private-source read attempts. Together
with the nine planner and twelve bundle checks, this establishes 74 required
checks without the private broad source. The recipient includes its own selected
codec packet, so reconstruction/build planning does not depend on a workstation's
private archive. This is not a native compilation result.

The review found and reported an initial relocated-fixture failure caused by
an unrelated `/tmp/.git` marker. The corrected helper reads bounded Git
HEAD/gitdir/commondir and objects/refs structure without Git commands or hooks.
Independent fixtures verify that invalid markers remain unchanged and do not
block temporary output, while the actual project and valid synthetic worktrees
remain protected. The final full suite passes with the unrelated marker intact.
The earlier template map `70b71…` and broad 18/19-file handoff are superseded.
Any change to the final recipe/template requires a new full-map review.

The optional producer fetches only pinned upstream HTTPS bytes into memory and
writes only the selected archive. This reviewer inspected its bounded transport
and mocked transport tests, but did not invoke network fetching. The local
original-upstream/selected-byte comparison above is independent evidence.
Retention in `/tmp` is preparation, not durable free recipient source delivery
or actual publication.

## Required later acceptance

Compile and rebuild from the reviewed recipient source in the actual immutable
native ARM builder; retain complete commands and actual ELF/ABI/codec checks.
The proposed provider substitution still requires fresh resolution and ownership
checks for the 574-package graph. Signed installation, upgrade, removal and
recovery, PipeWire AAC consumer behavior, physical 16 KiB execution and both
M2 Air sizes remain unfinished. This review establishes no performance gain,
installed transaction, native runtime compatibility or complete-port acceptance.
