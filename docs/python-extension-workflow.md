# Compiled CPython developer component

`scripts/workflows/python_extension.py` complements the existing Python and
CMake/Meson journeys with a tiny original MIT C extension. It uses real
CMake/Ninja and an explicitly selected C compiler, imports the compiled module
using the selected CPython interpreter, tests it through CTest, and installs it
into fresh private prefixes. It uses no wheel writer, packaging backend shim,
pip, network dependency or host package installation.

```sh
python3 -I -B scripts/workflows/python_extension.py \
  --python /usr/bin/python3 \
  --cmake /absolute/path/to/cmake \
  --ctest /absolute/path/to/ctest \
  --ninja /absolute/path/to/ninja \
  --cc /absolute/path/to/cc \
  --output /absolute/path/to/new-private-extension-workflow
```

All tools are selected explicitly by absolute path, resolved and hashed. The
fixture requires CMake >=3.24 and its `Python3_add_library(... WITH_SOABI ...)`
API. CTest is supplied separately. The C-only build needs no C++ compiler.
Commands reuse the existing pinned owned-process runner, finite time/output
budgets, scrubbed environment and private HOME/TMPDIR. No privileged changes or
existing desktop/session access are used.

The finite profile supports CPython on Linux x86_64 or aarch64, with a shared
include/platinclude tree containing `Python.h` and `pyconfig.h`, and a `.so`
extension ABI. The interpreter reports sysconfig paths, EXT_SUFFIX, SOABI,
compilation configuration, architecture and actual page size. Up to 512 ordinary
header files/8 MiB are copied into the private workspace and hashed. CMake gets
that copied header tree and the selected interpreter/compiler; the retained
compile database shows what was actually used. Missing headers, split layouts,
unsupported ABIs/interpreters and missing explicitly selected tools produce
named `NOT_RUN` results with exit 2. No extension is fabricated. Actual command
failures produce FAIL.

The fixed fixture contains no fetch/download/dependency hooks. This is an
offline local-project journey, not a network sandbox or arbitrary-project
executor. It uses installed compiler, linker, CMake modules, CPython runtime and
system development files. No transitive toolchain is downloaded.

The complete journey exercises:

- Initial configure, real object/shared-extension compilation, import and two
  Python unit checks invoked by CTest.
- A fresh private `cmake --install` prefix. The exact installed extension is
  imported and unit-tested with source/build directories temporarily renamed
  away. Both are restored in `finally` blocks.
- A real unchanged Ninja build leaving extension, object and recorded build
  graph artifacts untouched. A C edit changes object/extension bytes and output.
- A deliberate `#error INTENTIONAL_COMPILE_FAILURE`, refusal to import the old
  extension, and recovery by restoring/rebuilding the C source.
- An actual unittest mismatch through CTest, stale-import refusal, restored
  expectation, rebuilding/retesting and successful final installed-prefix tests.

Each prefix is fresh and retained. Its tree contains only the compiled extension
and original fixture license. The interpreter loads the exact extension path
through `ExtensionFileLoader`; tests verify the C method is a native builtin.
Import/test commands use `-I -S -B`, excluding user/system site startup and
bytecode writes. This is private CMake installation, not wheel or OS packaging.

Source, copied headers, sysconfig receipt, selected tools, build graph, compiled
object/extension and installed tree hashes govern custody. Changed inputs or
products and failed builds/tests revoke execution. Stale-refusal checks prove
zero import subprocess launches; old files remain inspectable on disk.

`result.json` retains commands, identities and scope. `commands.json` and numbered
logs bind combined output to owned-process outcomes. `project.json` binds
per-step artifacts, source snapshots and installed receipts. The copied header
tree, build, compile database and private prefixes remain available for review.

The existing `scripts/checks/package_checks.py::elf_check` inspects actual,
unchanged extension bytes. Its complete errors are retained. Its target profile
is AArch64/16K: an x86_64/4K extension can import successfully and still report
`FAIL_TARGET_PROFILE`. Layout alone never proves native16K execution, M2
behavior, performance or release acceptance. No ELF bytes or machine fields are
rewritten to obtain a pass.

Executable hashes and copied Python headers do not archive or fully pin stdlib,
libpython, compiler support binaries, assembler, linker, libc or other system
libraries. Reproduction needs the selected runtime/toolchain provisioned
separately. Absolute paths/debug metadata can affect bytes; no cross-workspace
bit reproducibility or performance claim is made. Copied CPython headers retain
their original upstream notices and are validation inputs, not project-authored
MIT fixture sources.

Focused controls:

```sh
python3 -I -B -m unittest discover -s tests/workflows -p test_python_extension.py -v
```

Host evidence does not qualify native ARM/16K, Asahi system installation,
independent onboarding, either physical M2 Air size, performance or a release.
Those remain separate coordinator-owned work.
