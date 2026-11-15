# LLVM23 source-reference candidate

Source-only original candidate at `packages/port/llvm23-source-reference`, based
on `origin/main` d93314d5223d7997f6499ef331a03a0d1cd317e9. It supplies a concrete,
opt-in two-stage native AArch64 CMake/Ninja plan for the original Rust199 reference;
it is not a reconstruction of any of the four held binary recipes.

Source pin: LLVM 23.1.1 archive **179168672 bytes**, SHA256
`ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6`, upstream
commit `6dfe1677ab8dffbc6ec13d53a1e0215d75147689`. Existing authenticated source
and archive-metadata evidence is joined by fixed hashes in `inputs.json`.
Primary pinned CMake metadata informed the plan; observations and failed requests
are recorded in `upstream-metadata.json`. The candidate applies no historical
PKGBUILD or libcxx patch; libcxx/libcxxabi are not enabled.

The frozen output is `/opt/cachy-asahi/llvm23-source-reference`, with shared LLVM
and libunwind in `lib`, tools in `bin`, LLVM CMake files in `lib/cmake/llvm`, and
compiler-rt builtins/profile in `lib/clang/23/lib/linux`. Upstream shared-library
SONAMEs and symlinks are preserved, no provider names or `/usr` aliases are added,
and no ldconfig or platform changes occur. Stage one uses admitted GCC/G++ to
build LLVM/Clang/LLD; stage two uses the staged Clang through its final private
pathname to build compiler-rt/libunwind. The Rust199 consumer's current disabled
sanitizers and enabled profiler determine the narrow runtime selection.

Root owns the consumer configuration and private loader/linker join; this task
does not modify Rust199, shared inventory, workflows or platform components.
Root should use the absolute `bin/llvm-config`/`bin/ld.lld`, explicit private
`lib` link search and runtime loader path, and refresh the exact environment and
candidate pins. No PATH-only runtime-linkage claim is made. See the package
README for precise build image, source, resource and qualification inputs and
reviewable staging/install/remove behavior.

Actual results: source/refusal tests and Bash syntax only, recorded in the
package `validation.json`. No archive download/extraction, makepkg, compiler,
build, package assembly, installation, native namespace or hardware execution.
The private package is not yet built or qualified. Native4K/native16K, both M2
Air sizes, resource sufficiency, full upstream tests, signed ALPM lifecycle,
Rust consumption, performance and release remain unestablished. All original
binary/source correspondence and existing source/license holds remain open.

## Concrete Rust consumer source findings for Root

`rust-consumer-metadata.json` retains finite excerpts/hashes from Rust commit
`b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`, without executing Rust/bootstrap:

- `bootstrap.example.toml` lines 1099–1106 supports target `llvm-config` with an
  absolute external path; `llvm.link-shared=true` selects shared LLVM (145–148).
  Set target `llvm-has-rust-patches=false` for this unpatched upstream LLVM.
- Target `rustflags` (1139–1143) applies to all stages. A concrete candidate is
  `rustflags = ["-Clink-arg=-L/opt/cachy-asahi/llvm23-source-reference/lib",
  "-Clink-arg=-Wl,-rpath,/opt/cachy-asahi/llvm23-source-reference/lib",
  "-Clink-arg=-Wl,-z,max-page-size=16384"]` under the native target table.
  This is supported configuration syntax/source inference, **not a tested join**.
- Bootstrap `core/builder/cargo.rs` lines 296–344 explains that `rpath=true`
  injects Rust's own `$ORIGIN/../lib` layout. That is insufficient by itself for
  a separate sibling LLVM prefix. Keep the absolute private LLVM runtime path
  on ELF objects that actually depend on libLLVM; verify their final DT_NEEDED
  and RUNPATH/RPATH plus actual installed execution without LD_LIBRARY_PATH.
- `compiler/rustc_llvm/build.rs` lines 185–188 uses `LLVM_CONFIG`; 334–340
  selects shared/static `llvm-config --libs`; 451–459 consumes its ldflags.
  The staged llvm-config must report private lib paths. Inspect actual results
  before treating this source plan as correct linkage.

Keep `bin/ld.lld` explicitly selected through the qualified consumer's linker
configuration/PATH and probe its version; this candidate makes no global compiler
or linker default change. The consumer's native GCC setting may remain distinct
from LLVM's private Clang. Root owns the final exact TOML, sandbox and image pins.
