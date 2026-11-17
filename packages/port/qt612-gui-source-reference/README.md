# Qt 6.12 GUI source candidate

This independent TEST-only candidate adds five source-backed Qt **shared modules**
to the frozen serial bootstrap's thirteen. A genuine x86_64 host configure passed
all113 profile settings and generated exactly18 shared-library targets. Qt
compilation, real ELF staging, smoke execution, native builds, installation,
removal and M2 validation are **NOT RUN**. Nothing is installed by the audit or
test commands. This candidate does not establish sufficient memory/storage,
full72-module catalog coverage, or correspondence to the unrecovered official
`0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272` recipe.

## Exact scope

| Added module | Source-backed requirement | Required regular library |
| --- | --- | --- |
| EglFSDeviceIntegration | EGL and EGLFS | `usr/lib/libQt6EglFSDeviceIntegration.so.6.12.0` |
| EglFsKmsSupport | EGLFS GBM plus KMS/DRM | `usr/lib/libQt6EglFsKmsSupport.so.6.12.0` |
| EglFsKmsGbmSupport | EGLFS GBM, KMS and GBM | `usr/lib/libQt6EglFsKmsGbmSupport.so.6.12.0` |
| WaylandClient | Wayland client/scanner and own Qt6 scanner | `usr/lib/libQt6WaylandClient.so.6.12.0` |
| WlShellIntegration | Wayland client and wl-shell | `usr/lib/libQt6WlShellIntegration.so.6.12.0` |

Each library must provide `libQt6<MODULE>.so.6` with the expected relative links.
Private headers and normal Qt CMake configs are required. WaylandGlobal is a
header module; KmsSupport and other prerequisite support targets are static.
They do not add further shared modules. The other54 catalog modules belong to
other Qt components and remain outside this candidate. Their upstream
implementations exist; this is not a claim that they failed to build.

The source-backed GUI plugin set includes EGLFS/KMS and emulation, minimal EGL,
Wayland client/EGL, wl-shell, xdg-shell and bradient decoration. The stage checker
also requires the retained offscreen/XCB/SQLite plugins and own Qt6 tools.
Compositor/server and unrelated direct-device variants are disabled. Compiling
these payloads does not select a desktop backend or alter the Asahi platform.

## Pinned inputs and normal dependencies

`SOURCE-INPUTS.lock.json` records exact reuse from serial recipe commit
`69a02851b87ca29daf2e197101b66bf75ff61889`: Qt6.12 archive51220268 bytes/SHA256
`a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307`, upstream
revision `025bdad181de241e81bf853c8a2d7bf3d19261a9`, four ordered zero-fuzz security
patches and the unchanged173-notice policy. All173 source notices/636122 bytes
were verified against a fresh extraction with those patches applied. The source
helper changes only the package destination name; its complete inverse is checked.

The Qt licensing declarations and packaging/third-party notices are retained.
The original source provides the actual license files; `source.py` verifies them
and copies exact bytes only into the named private package DESTDIR. Byte checks
do not issue legal acceptance. `module-source-contract.DATA.json` pins39 audited
source files and28 bundled Wayland XML inputs. No external wayland-protocols
package is required by these audited generation sites. Qt builds its own Qt6
scanner; the host Qt5 scanner is not an input.

Normal runtime dependencies retain the bootstrap GUI/Widgets/OpenGL/PrintSupport
set and add `libdrm`, `libglvnd` for EGL, `mesa` for GBM and `wayland>=1.15`.
Ordinary makepkg dependency and version/provides resolution remains mandatory.
The host package query reports `cmake>=3.25` missing. The separately installed
local CMake4.3.3 enabled the recorded host configure; it does not satisfy that
package-database gate. An actual signed native image, complete provider inventory,
dependency transaction and current TEST key/signatures remain unavailable.

`SERIAL-POLICY.DATA.json` is a byte-identical copy of the frozen bootstrap resource
basis, whose package-version field describes that predecessor. The separately
named `RESOURCE-PROPOSAL.json` applies those **unmeasured, unaccepted** ceilings
to this GUI candidate:4GiB/1CPU/j1 builder,6GiB daemon,12GiB owned storage,
14GiB minimum available disk and10GiB RAM. The recipe enforces scheduling only.
Actual cgroup/storage enforcement, capacity observations and Root admission
belong to a separately selected C producer/runtime.

## Build, checks and lifecycle

The future ordinary native command is `makepkg --cleanbuild --force`, once Root
selects a suitable signed aarch64 image and inputs. Both build and check enforce
literal one-job settings. `check()` uses normal exact Qt6 CMake discovery from
the explicit own-built tree, checks all five added module configs and imported
library locations, builds the finite smoke and runs it with a60-second timeout.
The smoke renders a QWidget offscreen and checks OpenGL/PrintSupport/Wayland
public API linkage. It creates no GL context, contacts no compositor, activates
no direct-device plugin and sends no network request. These are future checks;
their compilation and execution have not happened.

`check_stage.py` reads the actual private DESTDIR. It requires exact18 Qt shared
providers, source-backed libraries/headers/configs/plugins/tools, complete173
notices and safe ordinary payload/alias/mode inventories. Every ELF must be
AArch64 with structurally16K-compatible load segments. It reports interpreter,
DT_NEEDED, SONAME and GNU version data, including absent metadata as unavailable.
Staged provider observations do not resolve the external signed transaction or
prove loader,16K hardware, native or M2 compatibility. Historical needed/version
metadata for the five modules is preserved in `ABI-REFERENCE.DATA.json`.

Package name is `cachy-asahi-qt612-gui-source-reference`, version6.12.0-1. It
provides `qt6-base=6.12.0` and the18 declared SONAMEs; actual providers must still
be observed. It explicitly conflicts with `qt6-base` and the bootstrap project
provider because their payloads overlap. It has no `replaces`, hooks or install
script and writes no system/user configuration. Future installation/removal
must use normal package transactions with complete dependency checks; removal
removes package-owned Qt paths. No install/remove operation is performed here.

C must bind this candidate explicitly after the bootstrap works. A native pair
must retain both complete ordinary clean attempts, all original provenance-file
operands, genuine checks, raw stage contracts before normal makepkg cleanup and
strict archive/payload/PKGINFO/BUILDINFO equality. No C producer integration or
artifact transport is modified here. Source79/final779 and the full catalog's
official acceptance remain unchanged.

## Evidence and focused controls

`evidence/` retains the genuine source audit, host configure command/log/cache/
summary, generated target declarations and normal host dependency query. These
are host source/configuration observations, not compiled package artifacts.
`BUILD-CONTRACT.json` states proposed outputs beside actual results;
`recipe-files.lock.json` is the complete candidate file/mode/hash map excluding
itself. The upstream source archive stays external under its whole pin.

Run each `test_*.py` separately using Python `-I -B -Werror`. Source/stage/smoke
controls fence actors and use conspicuous MODEL fixtures where appropriate.
`test_parallel.py` permits only its finite Bash process with all build/install/
compiler helpers stubbed and external command search disabled. No tests compile
Qt or authenticate real provider signatures. No native, hardware, performance,
capacity or release credit is claimed.
