# llhttp original source-provider development candidate

This original recipe builds upstream llhttp 9.3.1 from the generated C release,
not the TypeScript/npm development tree. It is unselected. It is not an ALARM
recipe reconstruction and establishes no correspondence to the signed foreign
llhttp binary. Upstream release tag `release/v9.3.1` resolves to
`4fce8cac9433aa4728428bb3b26880d32ad05c88`; `source.json` records the exact
39,211-byte primary archive, URL and locally verified SHA-256. The Git tag and
HTTPS archive were consulted directly; no upstream source signature was verified.

The archive contains `src/{llhttp,http,api}.c`, `include/llhttp.h`, CMake and the
MIT license. CMake compiles these C files directly. It does not run npm or
regenerate the parser. Generator-to-C reproducibility has not been established.
This avoids adding Node/npm/generator dependencies to the finite native builder.
The MIT grant permits redistribution with its notice; package() retains
`LICENSE-MIT`. Recipe and smoke code are original MIT work.

The runtime dependency is glibc. Build dependencies are the base-devel C toolchain,
CMake >=3.25 and Ninja. The recipe preserves normal makepkg dependency resolution,
checksums and check(). It provides `llhttp=9.3.1` and the generated
`libllhttp.so` SONAME metadata, conflicts with the alternative `llhttp` package,
and does not replace it automatically. There are no install scripts, hooks,
services, boot changes or configuration files. Payload: shared library and links,
header, pkg-config/CMake metadata and license under `/usr`.

Build/check/package commands are explicit in PKGBUILD. The check compiles against
and loads the just-built library; byte-fragmented valid input must complete once,
and malformed Content-Length must be rejected. The upstream generated C release
has no standalone CTest suite; this is a focused API check, not upstream npm tests.

See the sibling [libgit2 candidate](../cachy-asahi-libgit2-reference/README.md)
for the shared finite native plan, source validator and host evidence. Native ARM
pairs, 16K/M2 execution, package transactions and project TEST signing are NOT RUN.

The recipe explicitly sets `PKGEXT='.pkg.tar.xz'` for the finite native
XZ-only archive reader. Normal makepkg XZ compression parameters are unchanged.
This packaging-format pin changes no build, check or package function; retained
host build evidence predates the pin and remains host evidence only. No XZ
package archive or native result is claimed.
