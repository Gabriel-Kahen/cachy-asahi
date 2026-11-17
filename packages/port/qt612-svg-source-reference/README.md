# QtSVG 6.12 independent source reference

`cachy-asahi-qt612-svg-source-reference 6.12.0-1` is an unselected source
candidate for a disposable TEST image. It supplies `qt6-svg=6.12.0`,
`libQt6Svg.so.6` and `libQt6SvgWidgets.so.6`, and conflicts with official
`qt6-svg`. It has no replaces, install script, service or hook. The virtual
version matches the SVG dependency of the QtWayland candidate at
`af714934d87849661dd1f1102287a4f3761cb600`; no downstream build is claimed.

## Pinned source and licensing

The [official Qt archive](https://download.qt.io/archive/qt/6.12/6.12.0/submodules/qtsvg-everywhere-src-6.12.0.tar.xz)
is 2,341,876 bytes, SHA256
`e4ab39534ec97987b1b9b60ef7f4d3253d5912a69f8c713a01753174a4029331`.
Its publisher SHA256 matches. Archive `.tag` matches the official `v6.12.0`
peeled commit `883a58532078d003cefef0a549bfe9f885ce41f5` (tag object
`0a753f450c4b4671cc97ef1c566512b9ab322382`). The original `.cmake.conf`
`alpha1` field is preserved; the actual module version is 6.12.0. Full archive
versus Git-tree equivalence and cryptographic signature verification are not
established by these checks. `upstream.DATA.json` records exact primary evidence.

The canonical notice policy contains **12 files / 95,646 bytes**: all seven
LICENSES bodies, three REUSE policies, license rules and W3C test-suite terms.
`package()` copies their original source-relative layout under its own license
`source/` directory. The USC Information Sciences Institute contribution to
`qsvghandler.cpp` additionally uses **HPND-sell-variant**; it is not covered by a
blanket LGPL label. Qt library licensing offers LGPL3/GPL2/GPL3 alternatives;
examples, tests, build code and documentation have separate grants. The source
audit retains exact embedded notice comments and whole-file pins for 186 test
assets, including font notices. Those test SVG/font assets are not binary payload.
Preserve the complete original source archive for those originals. No commercial
rights, legal clearance or official binary-recipe correspondence is claimed.

`SECURITY-RELEVANCE.DATA.json` records the inspected primary advisories and
source hardening. No direct QtSVG6.12 patch was selected from that inspected
publisher index. Qt identifies the SVG recursion and marker fixes as included
before/by this release; this is source evidence, not exploit testing or a claim
of no vulnerabilities. The existing four QtBase dependency security patches
remain required by the reference provider; this recipe does not modify QtBase.

## Complete build contract and dependency hold

Both public libraries, the SvgPrivate interface, SVG image-format plugin and SVG
icon-engine plugin stay required. SvgWidgets intentionally has no private module.
XML reader/writer, CSS parser, widgets, graphics view and system zlib are required
imported QtBase features; they are not disabled to fit this host. Upstream tests,
examples, docs and SBOM generation are off, while the independent normal package
`check()` remains mandatory.

Normal dependencies are glibc, libgcc, libstdc++, **`qt6-base=6.12.0`** and zlib.
The build additionally needs GCC, CMake>=3.25, Ninja, pkgconf, Python and Perl in an
ordinary Arch base-devel environment. `ABI-REFERENCE.DATA.json` records the
upstream QtBase dependency commit `025bdad181de241e81bf853c8a2d7bf3d19261a9`
and GUI18 reference `b05267833d497ef034576741bf31968019a526c3`. A compatible
separately reviewed QtBase successor can satisfy the same private/public API and
feature contract. The actual native provider, signed inventory and source-ABI
receipt remain unbound.

Before CMake or compiler probes, `source.py dependencies --prefix /usr` requires
exact 6.12.0 Core/Gui/Widgets version headers, public/private/build/tool metadata,
versioned private headers, AArch64 library/tool structures, executable build tools
and the offscreen platform. This is a structural read-only input check, not ABI
or execution qualification. `dependency_guard.cmake` then enforces exact prefix-
bound 6.12 discovery, imported library paths, private targets and required
features. `source.py configuration` checks the 21-setting cache profile;
`source.py targets` refuses missing generated metadata for either module or plugin.

The current host has **QtBase6.11.2**, and this preflight correctly refuses it
before CMake. The normal aarch64 makepkg architecture gate also refuses x86_64
(exit12); no architecture, dependency, check or signing bypass was used. No QtSVG
source configuration was attempted with the wrong host Qt. A standalone CMake
executable does not satisfy a missing normal package dependency.

After the complete compatible native image is separately bound, the normal build
command is:

```sh
MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 makepkg --cleanbuild --force
```

Unset job limits default to1; other explicit values fail before build/check tools.
Both CMake builds use `--parallel 1`, and autogen workers are fixed to1. These
scheduling settings are not memory/storage measurements or capacity acceptance.

## Smoke, staging and lifecycle

The smoke links Svg/SvgWidgets from the explicit own build tree and Core/Gui/
Widgets from the explicit dependency prefix, with exact6.12 versions and imported
library locations. It checks Core's numeric version and both SVG **version
strings**. The pinned QtBase syncqt source concatenates decimal version fields
in generated numeric module macros; comparing those module numbers directly to
`QT_VERSION_CHECK` is unsuitable for this release. No base-source patch is made.

The genuine future `check()` creates an offscreen QApplication, validates
renderer dimensions and colored/transparent pixels, generates SVG into a buffer
and renders it back, paints a real QSvgWidget, and tests image-reader and scalable
icon rendering. It requires the exact own plugin root, ordinary nonaliased plugin
files and explicit plugin instances/IIDs. After the base offscreen platform loads,
its library search path contains only the own SVG plugin root. Foreign installed
SVG plugins cannot satisfy these checks. The smoke has a60-second timeout and
proves no display, GPU, input, network, M2 or full SVG conformance behavior.

`package()` uses DESTDIR and a standalone nonexecuting stage checker. It requires
two AArch64 SONAME libraries and four exact internal links, public/development/
SvgPrivate headers and metadata, qmake metadata and both plugins. The SVG plugin
CMake files live under **Qt6Gui**, a source-audited finite ownership exception;
Qt6Gui's own config and other base files remain forbidden. The checker records
all file hashes/modes/links/ELFs/DT_NEEDED and enforces static16K PT_LOAD geometry.
That predicate is not native16K/M2 validation. Limits are32,768 entries,
64MiB/file and256MiB total payload; actual package size/fit is not measured.
Signed runtime dependency closure still needs review against actual staged ELFs.

Owned paths are the SVG libraries/headers/metadata, two plugins, and this
package's notices. No bootloader, kernel, Mesa, audio, device, system service,
`/etc` or user configuration is owned. Removal is ordinary package-owned file
removal. Restoring another provider requires a separate normal dependency-
resolving transaction. Installation, removal, rollback and target compatibility
are **NOT RUN**.

## Actual validation

The real source/tag and all12 notice hashes pass. Actual notice-only copying
inside fakeroot also preserves those12 files; it is not a staged Qt build.
Forty-seven SOURCE/MODEL controls pass on Python3.12.13 and3.14.6 under512MiB,
with ResourceWarnings treated as errors and zero skips. Each test file runs in a
separate interpreter because some install permanent actor fences. The tests use
labelled synthetic ELF, prefix and cache/configuration fixtures; the shell tests
stub every build operation. Smoke-source/XML checks do not evaluate CMake or Qt.

QtSVG configuration, compilation, real ELF staging, rendering, native build pair,
comparison, TEST key/signature, Root grant, installation/removal and hardware
acceptance remain **NOT RUN / UNBOUND**. No system package was installed and no
native actor, upload, signing or publication occurred. `BUILD-CONTRACT.json`
provides the source-only producer interface; `SOURCE-REUSE.DATA.json` records the
MIT helper/control reuse without editing the frozen original families.
