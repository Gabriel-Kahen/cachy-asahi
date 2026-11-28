# LLVM 23.1.1 private source reference

Original opt-in candidate, **source-only; build/install/native/16K/M2 NOT RUN**.
No original binary recipe has been recovered. All four correspondence mismatches,
license108/source delivery holds, production trust and release holds remain.
The example qualification is deliberately incomplete and refuses execution.

Fixed consumer contract:

- Prefix `/opt/cachy-asahi/llvm23-source-reference`; tools `bin/llvm-config`,
  `bin/clang`, `bin/clang++`, `bin/ld.lld`, `bin/llvm-ar`, `bin/llvm-ranlib`.
- Shared LLVM and libunwind under `lib` (upstream SONAME/symlink chain retained),
  LLVM CMake configuration `lib/cmake/llvm`, compiler-rt builtins/profile under
  `lib/clang/23/lib/linux`. No global aliases, providers, services, hooks or ldconfig.
- AArch64-only backend and native GNU/Linux default triple; GCC/libstdc++ bootstrap,
  RTTI/shared LLVM, no LTO/PGO/CPU tuning. Compiler-rt sanitizers/XRay/fuzzer/ORC
  are disabled: the current Rust199 configuration has `sanitizers=false` and
  `profiler=true`. This is not a full compiler-rt distribution.
- Tools/DSOs request `$ORIGIN/../lib;$ORIGIN` install RPATH and 16K maximum-page
  linker geometry. Static ELF inspection refuses other architectures or unsuitable
  PT_LOADs. Required tools must have a file-backed executable entry point. An
  `ET_DYN` tool must also declare an interpreter or `DF_1_PIE`. The required
  shared libraries must be `ET_DYN` and have neither marker. This policy covers
  the expected LLVM and libunwind outputs. Actual loading, native 16K behavior
  and M2 compatibility require separate execution evidence.

Root owns the Rust consumer join. It must select this llvm-config and LLD by
absolute path, explicitly link and load from this private `lib`, retain the exact
qualified image inventory, and update source pins. PATH alone does not establish
Rust's runtime loader linkage. No `/usr` symlinks are needed or supplied here.

## Inputs and execution

Run only later in an externally qualified **non-root native AArch64** environment:
local 179168672-byte archive matching `inputs.json`; a separate immutable build
image with the listed tools, GCC/C++/libc development files, binutils, Python,
CMake/Ninja, zlib/zstd headers and libraries; reviewed exact source inventory and
notices; authentication and qualification evidence; usable unprivileged bubblewrap
namespaces. Neither a declaration nor an invented digest is qualification.

The controller requires an already assigned cgroup v2 at the qualified path:
8 GiB RAM, swap 0, 2 CPUs and 512 PIDs. It writes no cgroup files. Admission also
requires 12 GiB currently available host memory and 64 GiB/600000 currently free
filesystem bytes/inodes (conservative remaining-space check before every command).
These budgets are proposed, unmeasured requirements, not proven LLVM resource
sufficiency. A command has a fixed one-hour limit and bounded logs. Resource
refusal, namespace failure, timeout, failed checks or unverified owned-child
retirement stop the candidate; no weaker retry. Large builds exceeding this bound
need a separately reviewed successor. There is no resource reservation or lease.

After creating a real qualification JSON derived from `admission.example.json`,
bind its exact bytes and set these environment variables for the normal package
phases. The example itself will refuse:

```sh
export CACHY_ASAHI_LLVM23_BUILD=1
export CACHY_ASAHI_LLVM23_ADMISSION=/absolute/qualified-admission.json
export CACHY_ASAHI_LLVM23_ADMISSION_SHA256=EXACT_SHA256_OF_THAT_FILE
# Local archive belongs beside the recipe, or in makepkg's local SRCDEST.
# On a future qualified builder, normal makepkg invokes prepare/build/check/package.
```

The controller copies and verifies the local archive, extracts only inside an
all-namespace bubblewrap sandbox, joins the extracted tree with the qualified
inventory, then mounts source and the driver read-only. Tools build first with
native GCC and stage through `DESTDIR=/work/dest`. Standalone `runtimes` CMake
then uses the staged Clang at its final private pathname through a read-only
sandbox mount; it stages compiler-rt and libunwind into the same DESTDIR.

`check()` requires staged tools/version/backend checks, static AArch64/16K ELF
geometry and real C/profile/exception compile/link/run probes, under the same
sandbox. `package()` accepts only the digest-bound checked stage, copies it into
an empty sibling package root, preserves symlinks and adds exact component
licenses plus original packaging provenance. No host installation command exists.
The recipe requires this repository's pinned read-only capacity and owned-child
helpers; it is not a standalone downloaded PKGBUILD.

Installation is a later explicit ALPM transaction after package review: inspect
`pacman -Qlp` for the one private prefix, use the signed qualified archive, inspect
ownership with `pacman -Ql cachy-asahi-llvm23-source-reference`, and remove with
`pacman -R cachy-asahi-llvm23-source-reference` after removing private consumers.
Removal should remove only package-owned files under that prefix. Signed
install/remove/reinstall, dependent Rust linking, version upgrades and target
lifecycle have **NOT RUN**. Do not manually delete the prefix as an uninstall.

## Source-only checks

```sh
python -m unittest discover -s packages/port/llvm23-source-reference -p 'test_*.py'
bash -n packages/port/llvm23-source-reference/{PKGBUILD,build.sh}
```

These tests use small synthetic files and refusal cases. No archive scan or
extraction, compiler, makepkg, container, namespace, lease or system mutation was
performed in this implementation task. `upstream-metadata.json` records bounded
primary metadata reads, including one 404; no source archives were downloaded.
