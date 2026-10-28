# FDK source-built replacement candidate

The selected-source checkpoint at the end is authoritative. The earlier private
packet, 18/19-file maps and tests below are historical development evidence and
are superseded for new native/source-delivery dispatch.

2026-10-12: source-audited private development recipe under
`packages/libraries/cachy-asahi-fdk-aac/`. Compilation, native build/rebuild,
codec runtime, installation/removal, publication, performance and hardware
validation are **NOT RUN**. Source/fixture checks are not build acceptance.
This work changes no shared manifest, CI, Git state, 341-package builder inventory
or Apple platform package.

## Publication correction and selected implementation

The original audit/proposal identified missing xHE binary notices and an
unmatched retained-binary recipe hash. Its prepared packet is privately retained
at `/tmp/cachy-fdk-redistributable-source-3.0.0.tar.gz` (historical filename, not
clearance), 3,861,432 bytes, SHA256
`1244e51941011bb63433b022f8bc247a28cf374749a2c3fb30f73fae42c88c49`.
It pins upstream 3.0.0 full commit
`a68a51aa45d86a43c7b228e3d45624af09dcdd8d`, preserves 1,190 upstream files
byte-for-byte and adds Apache's grant. Two restricted PDF manuals and an
unlicensed Rust vector are omitted. **Whole-packet redistribution is NOT CLEARED**:
explicit grants for upstream build scaffolding and unused Rust wrappers remain
unestablished. Earlier descriptions of this broad packet as redistributable
are superseded. No source or binary publication occurs here.

The recipe now uses independently authored MIT build/staging logic, executing
none of the upstream Makefile, configure, scripts, Rust, examples or tests.
`build-layout.json` records factual source/include/API inventories:

| Library | Translation units | Include directories | Public headers | Exports |
| --- | ---: | ---: | ---: | ---: |
| Classic | 170 | 13 | 6 | 18 |
| xHE | 225 | 37 | 1 | 63 |

The selected implementation inventory pins all 898 `.c`/`.cpp`/`.h` files in the
codec library trees, retaining original bytes and explicit Fraunhofer grants.
Independent review matched these facts to the pinned implementation. Quoted project
include directives, resolved with the preserved include order, stay inside that
selected set. Different reviews counted directive occurrences differently; no
exact include-edge count is used as an acceptance result here. C-runtime
`assert.h`/`stdint.h` come from the platform; Windows `armintr.h`, MIPS DSP and
Android logging headers are confined to inactive platform branches for the
default GNU Linux aarch64 build. No codec source is patched.

Before publication, prepare and independently review a new complete selected
source packet: all 898 implementation/header files, complete original grants,
project-authored build/layout/packaging/check sources and any modifications.
Exclude ungranted unused scaffolding/wrappers/docs, or establish their grants
from immutable primary evidence. Verify actual native build completeness from
that same recipient packet. Supply corresponding source free of charge with
binary releases, retain all notices, charge no codec copyright licence fee and
claim no Fraunhofer endorsement. Patent rights/legal approval are not asserted.
The current private broad packet is useful for bounded compilation preparation,
and cannot serve as the cleared recipient source release.

## Recipe, notices and package lifecycle

The independently written `cachy-asahi-fdk-aac 3.0.0-1` recipe declares aarch64,
runtime glibc and build GCC/Python/binutils from the existing builder. Its fixed
proposed providers are `libfdk-aac=3.0.0`, `libfdk-aac.so=2-64` and
`libfdk-xhe-aac.so=0-64`. It conflicts with `libfdk-aac` and has no replaces,
hooks, scriptlet, service, timer or platform configuration. One explicit provider
substitution proposes retaining the 574-package graph; actual libalpm resolution
and ownership checks remain required. No provider selection is adopted here.

Build logic inherits recorded builder C/C++/linker flags, uses PIC and the
codec-required C++ exception/RTTI restrictions, links two shared libraries with
explicit SONAMEs/public-export scripts, and authors pkg-config files. It does
not require a new toolchain package or invoke a host compiler. Native entry
points require the explicit aarch64 container contract. Full compiler/linker
commands are retained in `/out/fdk-build-commands.json` before the builder removes
temporary work. Four compiler workers are bounded by the existing container.

Expected payload: two real DSOs with their local SONAME/linker symlinks, seven
headers, two pkg-config files, both full codec notices, all nine complete
copyright/licence header variants, separate MIT grant and README/provenance.
No static archive, `.la`, example program or source-test executable is installed.
Removal deletes package-owned paths only; dependencies require an approved
replacement transaction. Do not force-remove a provider used by the PipeWire
AAC plugin or automatically replace audio/platform packages.

| Notice input | SHA256 |
| --- | --- |
| `NOTICE.classic` | `95ec80da40b4af12ad4c4f3158c9cfb80f2479f3246e4260cb600827cc8c7836` |
| `NOTICE.xhe-aac` | `bf3e762249027586195def2b2e904901b42c8b7fab455fc66bf365f70d08de6d` |
| `COPYRIGHTS-and-LICENSES` | `a0a52a99bef6dea5c370711f17ed1c02e8b0989a4c167f4e54a36368987428c0` |

Independent review found the earlier shared audit's `418b67…` notice bundle used
lossy UTF-8 replacement for two original Latin-1 PPC headers. The owned bundle
retains all nine complete comment blocks **byte-for-byte**, with an encoding
note; source bytes are unchanged. Its raw PPC block with trailing LF has SHA256
`190c9775bc437c6500cec2bba176d1d0e79efdd70a9b8e6b4c61ec4834ccf642`.
The coordinator must reconcile shared bundle/coverage/proposal evidence before
publication. Another shared generator gap remains: `prepare_source.py` records
prefixed included-file paths, whereas the retained manifest uses relative paths.
The packet's actual bytes/inventory verify; generator/manifest regeneration
needs coordinator reconciliation, not an implied reproducibility pass.

## Concrete private materialization and native interface

The repository template intentionally omits the private archive. Its full
18-file input map is retained outside the recipe at
`/tmp/cachy-asahi-fdk-review-nm9ej4eq/template-inputs.json`, SHA256
`943749ff6fa696b13a7fd2f8ee0457e962def1a100387d679a0c0b9e7f7a140f`.
Independent complete-map review precedes use; creating a map is not review.
`materialize.py` requires that map and approved SHA, checks every template file
including PKGBUILD/SRCINFO, verifies the fixed packet/manifest and all 1,191 file
bytes, and creates a new external recipe with 19 inputs. It performs no archive
extraction, network request, compiler invocation, installer or host system mutation.
It refuses existing/repository-contained outputs, unsafe/special input files,
archive links/path traversal and stale or incomplete reviewed maps.

From repository root, after packet review, with a new external `FDK_RECIPE`:

```sh
python -B packages/libraries/cachy-asahi-fdk-aac/materialize.py \
  --archive /tmp/cachy-fdk-redistributable-source-3.0.0.tar.gz \
  --output "$FDK_RECIPE" \
  --reviewed-template /tmp/cachy-asahi-fdk-review-nm9ej4eq/template-inputs.json \
  --reviewed-template-sha256 943749ff6fa696b13a7fd2f8ee0457e962def1a100387d679a0c0b9e7f7a140f \
  > "$FDK_OUTPUT/materialization.json"
```

The receipt's full `input_sha256` map must be saved outside that materialized
recipe as `FDK_REVIEW`, independently reviewed and frozen. Use the same accepted
refreshed native snapshot/341-row lock for both builds. `FDK_IMAGE` must be an
actually provisioned immutable ARM image; a hosted image ID after job teardown
is unavailable. Recreate the accepted snapshot in a later native job and retain
its actual bootstrap/image/lock receipt. Then, while that image exists:

```sh
python -B scripts/build/build.py "$FDK_RECIPE" --image "$FDK_IMAGE" \
  --output "$FDK_OUTPUT/build-1" --mode native --network none \
  --source-date-epoch 1791748800 --expected-packages "$FDK_LOCK" \
  --reviewed-inputs "$FDK_REVIEW"
python -B scripts/build/build.py "$FDK_RECIPE" --image "$FDK_IMAGE" \
  --output "$FDK_OUTPUT/build-2" --mode native --network none \
  --source-date-epoch 1791748800 --expected-packages "$FDK_LOCK" \
  --reviewed-inputs "$FDK_REVIEW"
python -B scripts/build/compare.py "$FDK_OUTPUT/build-1" \
  "$FDK_OUTPUT/build-2" --require-bytes > "$FDK_OUTPUT/compare.json"
```

Retain all source/materialization/build receipts, exact archives and comparisons
privately; job artifacts containing the broad private source packet must not be
published before source-distribution review.
Require byte, payload/type/mode/owner, `.PKGINFO` and separately reported
`.BUILDINFO` equality; report failures plainly. Default initial CI discovery
does not select libraries; root owns separate stage integration. No CI/shared
manifest edit is made here.

## Actual checks and unfinished acceptance

**42 software tests PASS, no skips**: 33 source/materializer tests and nine
planner/inventory tests. They cover special/nonblocking reads, archive members,
map binding/tampering, exact source copies and relocated immutable inputs while
the build working directory contains generated src/pkg/logs. Planner checks
verify 395 unique compile commands and two ABI links without invoking compilers;
all 898 selected source byte pins/grant markers match. Python AST and
`bash -n PKGBUILD` pass without executing PKGBUILD.

Native checks are implemented but **NOT RUN**: actual ELF64 AArch64, classic
SONAME 2/xHE 0, exact public export sets, glibc-only dependencies including its
ARM loader, 16 KiB load geometry, and bounded classic AAC-LC encode/decode of
original deterministic PCM. xHE smoke covers API version/configuration lifecycle
only. Neither suite is equivalent to upstream conformance/quality tests.
ELF geometry is not physical 16 KiB runtime execution. SONAME/export agreement
is not full ABI equivalence or proof the PipeWire consumer works.

Still required: native builds/ABI/smoke results, complete source publication
review and delivery, fresh private libalpm resolution of the 574-package provider
substitution, signed disposable and target install/upgrade/removal/recovery,
actual PipeWire AAC integration, exact 16 KiB execution and both M2 Air hardware
observations. No performance gain or complete ARM port is claimed.

## Retained private 19-file handoff

Copy-only materialization was actually executed after independent review of the
18-file template; it performed no extraction, compiler invocation or installation.
The concrete recipe is `/tmp/cachy-asahi-fdk-review-nm9ej4eq/recipe`.
`materialization.json` and `static-report.json` in its parent retain the copy
receipt and explicit-path package inspection. The final full 19-file input map
is `/tmp/cachy-asahi-fdk-review-nm9ej4eq/reviewed-inputs.json`, SHA256
`e68ccd838f352f3eeab7979f4fbcc1744e1ab7d3084384155e85fdf4fe9796d0`.
Independent full-map review passed before and after read-only verification:
the 18-file template plus pinned archive matches the 19-file recipe exactly.
Static inspection passes with every local source bound, and all 42 software
tests also pass from this actual relocated recipe. No test was skipped. Retain
this temporary evidence privately with the later native job; do not treat `/tmp`
as durable source delivery.

| Frozen implementation input | SHA256 |
| --- | --- |
| `PKGBUILD` | `d438b21d0353700e1aba1f4171a3e3a3976f631945b339c0faae3aa4d3d8ca13` |
| `.SRCINFO` | `3cd0d9d7619d7283e89931070ab2cc71df76f2fe4f2051e276369f2858b8b234` |
| `codec-smoke.c` | `70735f85644927e0427d12fbda21d6515fdab1bb9c19b5105abe654218b9af96` |
| `test_source.py` | `1230539cc6a343084c97277ecf9b4ffddbc84c35d2f5b711755d7038e5a99eab` |
| `test_build.py` | `36507bb9050d6df50206cddfdf87bf85e82bf7138122dc760a75d17aaf348d83` |

The complete map retains hashes for every other build/layout/staging/provenance
asset plus the exact private source archive. Any input change requires a new
full-map review and materialization handoff before native dispatch. Publication
remains blocked, independently of successful private fixture materialization.

## Selected corresponding-source checkpoint — 2026-10-12

This supersedes the preceding private-packet source-delivery blocker and all
18/19-file maps. The historical 1190-file packet remains private and is not
called redistributable. The current selected archive includes exactly 898
unchanged implementation/header files with recorded individual grants and both
complete original codec notices. It excludes all 293 other upstream files,
including the five ungranted scaffolds, unused wrappers/examples/scripts/docs
and test assets. The new source packet is complete for the two independently
built selected library implementations, rather than all upstream software.

No needed default GNU Linux aarch64 implementation source without an established
grant was found in the static include/build audit. All selected raw bytes and
complete headers/notices match the pinned upstream source. Platform SDK-only
branches remain inactive for the supported default build. Include review checks
actual directives and preserved search order; differing lexical occurrence
counts are not used as an acceptance result. Actual native compilation must still
prove build completeness and run the ABI/codec/consumer checks. The copyright
source-selection gate is addressed within this recorded grant scope; patent
authorization, legal approval and actual public delivery are not asserted.

The complete source bundle carries the selected codec archive, all original MIT
build/layout/package/test/check/selection/reconstruction inputs, complete grants
and its hash-bound map. It contains no private broad archive or copied upstream
scaffolding. `PUBLICATION.md` records the recipient reconstruction recipe and
source-delivery obligations: retain notices, provide complete source and all
modifications free to binary recipients, charge no codec copyright licence fee,
and claim no endorsement. No external publication occurred here.

| Concrete retained artifact | SHA256 |
| --- | --- |
| Selected codec `/tmp/fdk-aac-3.0.0-selected-source.tar.gz` (2,701,495 bytes; 900 files) | `1c4ade00f624c1e6f9e988cd17868a5e3faa78fea2522e9c302a89866d04cdd7` |
| 22-file template `/tmp/cachy-asahi-fdk-publication-review-qjpi7wr4/template-inputs.json` | `b569ff9ae69eb56e9b9635c3ed0849eaebbfa516f48304ade1790f802532bb63` |
| 23-file recipe map `/tmp/cachy-asahi-fdk-publication-review-qjpi7wr4/reviewed-inputs.json` | `4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b` |
| Complete bundle `/tmp/cachy-asahi-fdk-publication-review-qjpi7wr4/cachy-asahi-fdk-aac-3.0.0-source.tar.gz` (2,822,903 bytes; 24 regular members) | `717fd8fce8afb165e95e673f74385746f5511576c548f80c56e88a1752ba5356` |

The materialized recipe is `/tmp/cachy-asahi-fdk-publication-review-qjpi7wr4/recipe`;
the independently hash-verified reconstructed recipient copy is its sibling
`recipient`. Parent receipts are `materialization.json`, `static-report.json`,
`publication-receipt.json`, `reconstruction.json` and `software-validation.json`.
Retain the selected artifacts with the later job/release; `/tmp` is not durable
recipient delivery. The earlier selected-template map `70b71…` was invalidated
by runner-producer/repository-boundary corrections and must not be reused.

### Fresh runner regeneration and native handoff

With the reviewed project template checked out and a new external archive path:

```sh
python -B packages/libraries/cachy-asahi-fdk-aac/select-source.py \
  --fetch-upstream --output "$FDK_CODEC_ARCHIVE" > "$FDK_OUTPUT/selection.json"
python -B packages/libraries/cachy-asahi-fdk-aac/materialize.py \
  --archive "$FDK_CODEC_ARCHIVE" --output "$FDK_RECIPE" \
  --reviewed-template "$FDK_TEMPLATE_MAP" \
  --reviewed-template-sha256 b569ff9ae69eb56e9b9635c3ed0849eaebbfa516f48304ade1790f802532bb63 \
  > "$FDK_OUTPUT/materialization.json"
```

The network stage fetches only fixed full-commit data from codeload into memory,
caps input at 8 MiB, requires exactly 4,707,099 bytes/SHA256
`ac9682b35f6e5f75e1f008a5ba2636ba6c9c77c70b78377b53992559e8bda806`,
checks selected byte/grant pins and emits exactly the `1c4ade…` codec archive.
It retains no broad upstream source and executes no upstream code. This exact
network-to-selected reconstruction was actually run successfully here; a
separate reconstruction from the clean codec archive also reproduced the same
bytes. The selected producer needs no workstation-private archive or extra
builder package. Native build containers remain network-disabled.

The fresh materialized map must equal the frozen 23-file map above before the
existing explicit recipe builder runs twice against the same accepted original
341-package inventory. Root owns image recreation, pipeline integration and
actual native trials. Use the native command shape above with this new recipe,
new full map and actual accepted immutable image/lock. Recreate hosted images
after job teardown; no stale image ID or source-map substitution is accepted.

Recipient reconstruction is concrete:

```sh
python -B packages/libraries/cachy-asahi-fdk-aac/publication.py reconstruct \
  --archive "$FDK_SOURCE_BUNDLE" --output "$FDK_RECIPIENT_RECIPE" \
  --archive-sha256 717fd8fce8afb165e95e673f74385746f5511576c548f80c56e88a1752ba5356 \
  --map-sha256 4c9a6e04c964145fad2da64e627ca0f06f576aec40f443e701cad930d916c38b
```

This was executed with bounded regular-file/member checks and strict duplicate-
free map parsing, recreating all 23 inputs exactly without private full source,
upstream execution, compiler or installer. Bundle packing is deterministic and
the source map sits beside the recipe to avoid recursive self-hashing.

### Actual verification and remaining gates

The producer checkout passes **75 tests with no skips**: 54 source/selection/
transport/repository-boundary tests, nine planner tests and 12 bundle tests.
The reconstructed recipient copy passes **74 required tests**, with only one
historical private-input comparison intentionally skipped while reads of that
private path were explicitly denied. All clean selection, reconstruction and
build-planner checks run. Ten Python AST checks and PKGBUILD syntax pass; source
and complete metadata bindings are reviewed independently.

An independent reviewer found the earlier ancestor `.git` existence check could
mistake an unrelated invalid marker for a worktree. The shared helper now checks
bounded HEAD/gitdir/commondir and objects/refs structure without Git commands or
hooks, ignores invalid markers unchanged, and preserves real project/template
containment refusal. Regression fixtures cover both cases and relocated source
recipes. No unrelated marker was removed by this workstream.

Independent local final artifact review passed: all 23 producer/recipient inputs
and the 24-member bundle match their frozen maps, selected byte/grant scope is
unchanged, static recipe checks pass, and before/after hashes remain stable.

Remaining: the coordinator's release review and actual native compiler/
ABI/codec/consumer results, two-build comparison, provider transaction/lifecycle,
free public source delivery with releases, patent-use authorization and M2/16 KiB
hardware acceptance. No implementation grant blocker is presently identified;
these remaining execution/release gates are not silently treated as passed.
