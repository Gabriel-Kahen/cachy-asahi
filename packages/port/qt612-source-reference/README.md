# Qt 6.12 independent source-reference provider

`cachy-asahi-qt612-base-source-reference 6.12.0-2` is a separate, unselected
project package for a disposable TEST image. It is not the source recipe for
the foreign `qt6-base 6.12.0-3` artifact. Correspondence to that artifact's
PKGBUILD SHA256 `0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272`
remains **HOLD**. No selectors, shared manifests or platform packages change.

## Source and licensing

The primary archive is `qtbase-everywhere-src-6.12.0.tar.xz`, 51,220,268 bytes,
SHA256 `a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307`,
from [Qt's archive](https://download.qt.io/archive/qt/6.12/6.12.0/submodules/).
Its `.tag` matches official `v6.12.0` commit
`025bdad181de241e81bf853c8a2d7bf3d19261a9`.
`upstream.DATA.json` records primary download/tag/configuration and patch pins.
The literal `alpha1` field in the release's `.cmake.conf` is preserved; its
module version is 6.12.0 and the file matches the official tagged source.

Four exact official patches apply with zero fuzz in this order:

1. `CVE-2026-116337-qtbase-6.12-0002.diff`
2. `CVE-2026-116337-qtbase-6.12-0001.diff`
3. `CVE-2026-105924-qtbase-6.12.diff`
4. `CVE-2026-105943-qtbase-6.12.diff`

The fourth patch affects Windows SSPI; retaining it records source parity,
not Linux runtime validation. The initial failed opposite ordering remains
in local audit evidence. The recipe stops on failed patch application.

`source-notices.json` pins 173 original source-relative notices, 636,122 bytes.
This includes all 38 LICENSES texts, 78 attribution files describing 90
components, their referenced license bodies, other LICENSE/COPYING/NOTICE/
AUTHORS files and the original reuse rules. `package()` preserves that layout
under `/usr/share/licenses/cachy-asahi-qt612-base-source-reference/source`.
Qt libraries, tools, documentation and bundled components have different
grants; the metadata label `LicenseRef-Qt-ThirdParty` points to these originals.
No commercial Qt rights are claimed. Packaging/helper code is MIT.

`recipe-inputs.DATA.json` and `recipe-inputs/` retain exact authentic ALARM and
Arch recipes, their explicit 0BSD grants, and the audited distro/Qt patch
inputs. These are comparative inputs. The new recipe does not blindly replay
their LTO, system-CFLAGS, qmake-strip or three cherry-pick changes. Their
foreign package identity, split package, translations, optional drivers and
groups are not adopted. The two original relative 0BSD license symlinks are
audit metadata, not makepkg source operands. Active source operands are the
flat files explicitly listed by `PKGBUILD` and `.SRCINFO`.

## Finite build API

The package is declared `aarch64`; native compatibility is **not tested**.
It provides `qt6-base=6.12.0` and `libQt6Core.so.6`, conflicts with `qt6-base`,
and declares no replaces, install script, service or package hook. Standard
`/usr` Qt6 paths allow normal dependency and loader checks in an independent
private image. Co-installing it with official qt6-base is unsupported.
Other Qt modules/plugins and existing binary consumers require explicit
image/ABI admission; this feature subset is not a qualified desktop upgrade.

`configure.cmake` fixes 91 cache settings and `source.py configuration` checks
the actual resulting cache before compilation. The expected public modules
are Core, Concurrent, DBus, Gui, Network, OpenGL, OpenGLWidgets, PrintSupport,
Sql, Test, Widgets and Xml. XCB/GLX and offscreen backends and SQLite are
required; Qt's built-in minimal QPA backend is also retained. Wayland, EGL/EGLFS, Linux framebuffer, KMS/DRM/GBM, evdev/mtdev,
libinput/udev/tslib, VNC, Vulkan, GTK3, AT-SPI bridge, CUPS, GSSAPI, proxy/
journald/liburing integration, deployment/Wayland scanner tools and non-SQLite
drivers are disabled. SBOM generation, examples, docs and upstream tests are
disabled; the Test library and the independent package smoke remain required.

System zlib, double-conversion, libb2, PCRE2, FreeType, HarfBuzz, JPEG, PNG,
MD4c and SQLite are required; OpenSSL and D-Bus are linked. Exact normal
runtime/build dependencies are in `.SRCINFO`. MD4c is deliberately bounded
`>=0.5.3,<0.6`: the release bundles 0.5.3 and its flag assumptions conflict with
0.6. A newer system MD4c needs a separate justified compatibility change.
There is no architecture or dependency bypass and no M2-specific tuning.

Normal native build command, only after a complete compatible image is bound:

```sh
MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 makepkg --cleanbuild --force
```

This successor defaults both `MAX_JOBS` and `CMAKE_BUILD_PARALLEL_LEVEL` to
literal `1`. `build()` and `check()` reject any other explicitly supplied value,
including an empty string, before configure/tool calls. Both builds pass explicit
`--parallel 1`; the Qt profile also sets `CMAKE_AUTOGEN_PARALLEL=1` for moc/uic.
The recipe has no `nproc` job override. These scheduling limits do not bound a compiler
or linker's memory use and do not establish that Qt fits any memory limit.

`RESOURCE-EXPERIMENT.json` proposes a new 4 GiB/one CPU inner builder, 6 GiB
daemon, 12 GiB owned storage, minimum 14 GiB available disk and 10 GiB available
RAM, with the selected Source93 controller/owner/guards unchanged. C must enforce
and measure those limits. The predecessor's 18 GiB RAM / 72 GiB disk proposal
remains immutable; neither proposal has a capacity PASS. `SCRATCH-RETENTION.md`
records disposable first-attempt work and evidence that must survive comparison.

No `--nodeps`, architecture override, `--nocheck` or signing bypass is needed.
The recipe emits an XZ package, with normal dependency checks retained.
`check()` compiles against the explicit own-built Qt tree, binds its libraries
and offscreen plugin, and runs a 60-second offline Core/Network/Widgets smoke.
It checks version, temporary file/hash operations, widget rendering and the
event loop; it makes no network request and proves no real display/M2 behavior.

## Staging and removal contract

`package()` installs only through DESTDIR, copies the pinned notices and then
runs `check_stage.py`. The checker reads every staged file without loading an
ELF. It requires AArch64 ELF64 little-endian libraries/tools, all 12 module
SONAMEs/development files, private XcbQpa library, qmake/moc/uic/rcc, offscreen/XCB/SQLite plugins,
internal nonescaping library links, the version header and exact notice corpus.
It refuses foreign ownership paths, special nodes, unsafe modes, disabled
backends and non-SQLite drivers, and records the complete byte/mode/link/ELF
inventory. Limits are 32,768 entries, 128 MiB/file and 1 GiB total payload.
`--host-only-x86_64` is an explicit separate inspection mode, not ARM credit.

Owned paths are Qt6 libraries, CMake/pkg-config metadata, headers, tools,
plugins, Qt data/docs and this package's license directory. No boot, kernel,
Mesa, audio, udev/systemd, `/etc` or user configuration is owned. Removal is
ordinary package-owned file removal; restoration of another provider is a
separate normal dependency-resolving transaction. Installation, removal,
rollback and compatibility with a supported Asahi/M2 image are NOT RUN.

## Actual checks and remaining holds

The exact source/tag/notices and zero-fuzz patch sequence were checked.
The predecessor at `7748d41315d7b2a0a79ddc18eab4e89fc4ef71e1` successfully
configured its 90-setting profile on this existing x86_64 host. The new
91-setting serial profile has not been configured against Qt. The predecessor
probe generated build files and compiler probes, not a Qt library/package build. Notice copying
inside real fakeroot preserved all 173 pinned files in a private DESTDIR.
Synthetic source/staging tests confer no native result.

Normal host dependency query reports missing **`cmake>=3.25`** as an Arch
package, despite an existing standalone CMake executable used for the configure
probe. `makepkg --verifysource` correctly refuses this host's x86_64 architecture
for the aarch64 recipe; no override was used. Native image/inventory and all
missing native build inputs remain unbound, not assumed available.

Full Qt compilation, package creation, own-built smoke, real ELF staging,
native build pair/comparison, TEST signature/key, Root selection, installation
and hardware acceptance are **NOT RUN / UNBOUND**. `BUILD-CONTRACT.json` gives
the frozen input API for an independent native producer. No host package
installation, service, native Actions/VM, signing or publication occurred.
