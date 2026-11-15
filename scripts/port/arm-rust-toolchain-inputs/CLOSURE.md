# Qt closure and loader-model correction, 2026-11-14

All original 84 inputs and all 271 package descriptors/1,154 dependency joins
from `5f3e34579c77c68245616950f182d6dae8a5d747` remain unchanged. Their exact
locks and original finite results are retained under `history/`. The catalog
now enforces both preserved subsets before inspecting anything.

Four additional exact native ALARM archive/signature pairs authenticate under
the unchanged pinned ALARM key and have their complete payloads inspected:

| Package | Version | Archive bytes | Actual acquisition |
| --- | --- | ---: | --- |
| qt6-5compat | 6.12.0-1 | 521,852 | Official mirror, exact archive and signature |
| qt6-shadertools | 6.12.0-1 | 1,621,928 | Official mirror, exact archive and signature |
| qt6-declarative | 6.12.0-1 | 20,090,780 | Exact retained dependency cache, copied to `/tmp` |
| qt6-svg | 6.12.0-1 | 266,844 | Exact retained dependency cache, copied to `/tmp` |

Full Qt5compat payload inspection exposes its QML/Quick/ShaderTools requirements;
full Declarative inspection exposes SVG. Those modules are retained rather than
discarding optional plugins or commands. Their real `.PKGINFO` dependencies are
bound in the lock. All other declared dependencies of these four modules are
already in the preserved 271 set, except the exact pending Qt-base candidate.

`qt-frozen-inputs.json` pins all five Qt identities, frozen repository entry
hashes, archive/signature sizes and hashes, public key and exact-name routes.
`qt-acquisition-evidence.json` retains actual transfers, local-copy provenance,
required signature results, unavailable endpoints and resource preflight.

The new archive cache is **22,501,404 bytes**, below the enforced 512 MiB cap,
and is entirely under `/tmp`. Initial `/tmp` free space was 13,434,413,056 bytes
and available RAM was 19,070,824,448 bytes. The acquisition command checks fresh
space/RAM on each invocation, freezes its source/key descriptors, bounds each
file to 32 MiB and each HTTP transfer to explicit byte/time limits, rejects
redirects/hash changes, and records 429 availability as unknown without retrying
that host during the invocation. Payloads are never materialized as a root or
executed. No Docker, native/Source/Reader actor or compiled-payload execution is
used.

```sh
python3 -I -B scripts/port/arm-rust-toolchain-inputs/acquire_qt.py \
  --cache /tmp/owned-rust-qt/cache \
  --retained-cache /private/exact-retained-cache \
  --output /tmp/owned-rust-qt/acquisition
python3 -I -B scripts/port/arm-rust-toolchain-inputs/catalog.py \
  --cache /private/preserved-271/cache \
  --cache /tmp/owned-rust-qt/cache --output /tmp/owned-rust-qt/catalog
```

Both commands currently exit 2 honestly: acquisition lacks exact Qt-base, and
catalog verification lacks that archive/signature and its real metadata. The
catalog retains a clearly marked uninspected descriptor for that exact input.
Even if its bytes later appear, it refuses automatic admission until its actual
`.PKGINFO` and dependency closure are reconciled. `--prepare` refuses missing
inputs before creating output. This does not produce an accepted native profile.

## The empty RUNPATH was a catalog-model error

The unchanged VapourSynth 80-1 ELF is
`/usr/lib/python3.14/site-packages/vapoursynth/libvapoursynth.so.4`,
3,284,304 bytes/SHA256
`d946d71543f23536392e568268f59f5e1f83f7a2767bb2fc1bcbf7c192973111`.
Its `DT_RUNPATH` tag is present and its entire string is empty. It has no RPATH.

The [pinned glibc loader source](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=elf/dl-load.c;hb=8362e8ce10b24068bacc19552c128dd10e082fd9)
at `8362e8ce10b24068bacc19552c128dd10e082fd9`, corresponding to the recorded
package version suffix, explicitly ignores an entirely empty RPATH/RUNPATH in
`decompose_rpath` lines 595–600. Tag presence still suppresses RPATH at lines
763–777. Empty components inside nonempty lists such as `:` or `/usr/lib:` are
different and continue to require a current-directory policy hold.

The parser now records tag presence separately and models those distinctions.
It preserves the original ELF bytes. The frozen source file and its LGPL text
are retained under `loader-source/`, with exact hashes and source URLs in
`loader-semantics.json`; the catalog binds that model to the unchanged glibc
package version. This is a source-defined structural model, not proof of
source/binary correspondence or native loader execution.

Pinned VapourSynth R80 and meson-python 0.22.0 source facts also identify a
concrete empty-tag emission mechanism, but the original build causality remains
unproven: the exact ALARM recipe/build intermediates are unavailable. Removing
the tag would change RPATH precedence. No source/packaging or published-ELF
rewrite is appropriate for this wholly empty tag under the pinned model.

## Still unfinished

Exact `qt6-base-6.12.0-2-aarch64.pkg.tar.xz` remains missing: 15,176,004 bytes,
SHA256 `70f2bbce49fa82dee86074a7c96dcc1e43f54a1f82407bb8d855708932323abd`.
Its exact signature is also missing. Official and tested retained routes return
404; the separately tested October 15 route remains 429/unknown. The available
`-3` archive is not substituted. `remaining-inputs.json` retains the exact pins
and all observed unresolved edges.

The current inventory has 276 descriptors: 275 verified payloads and one
explicitly uninspected Qt-base descriptor. Inspection retains 223 unresolved
Qt-base-interface dependency edges across all original and added payloads.
The missing archive's actual contents and further dependencies remain unknown.
No commands/plugins or existing packages were dropped to reduce that count.

Thirty-eight focused controls pass, including tag-presence/precedence, wholly
empty versus colon-empty paths, preserved 271 descriptors/joins, pending metadata
refusal and `/tmp` cache restrictions. Two independent checks produce identical
19,520,403-byte catalogs, SHA256
`443c3954553360050aead33c0a7870c334abf644932b9d7e5ad04b812eda5821`.
All 275 available signatures verify under the unchanged primary key, alongside
the unchanged 137-file Rust association. The full read retains 65,313 members,
1,899,832,500 expanded file bytes, 2,220 AArch64 ELF records, nine pinned BPF
objects, 1,171 known package-expression joins and 8,563 direct ELF joins. The
uninspected Qt-base dependency list is not invented or counted as complete.

Complete corresponding source for compiler/Cargo/LLVM and runtime inputs,
historical recipe correspondence, source/legal/relinking acceptance, key
freshness, native build/runtime/profile admission, M2/16K/performance and release
remain held. Root retains all integration, publication and native-role authority.
