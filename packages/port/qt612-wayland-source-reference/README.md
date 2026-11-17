# QtWayland 6.12 source candidate

This package contains a concrete full-feature recipe, source/dependency checks,
stage verifier, finite smoke and lifecycle contract. It is **source-audited and
configuration-blocked**, not built. The genuine host configure refused Qt6.11.2
where6.12.0 is required. Native build, actual stage, smoke, compositor/session,
installation/removal, capacity and M2 checks are NOT RUN.

## Actual component and desktop scope

Qt6.12's core WaylandClient library, QPA backend, wl-shell integration and scanner
are already source-backed by the separate qtbase GUI18 candidate. This QtWayland
archive does not recreate them. Its client feature module is header-only. It adds
ivi-shell, qt-shell and Adwaita client plugins, client texture sharing, and the
compositor/QML pipeline.

The declared desktop snapshots are distinct. The historical minimal-eight root
does not require Qt packages. The broader45-root desktop preview includes
hyprpolkitagent/hyprland-qt-support and therefore Qt Declarative. Hyprland is not
a QtWayland compositor. `inventory-closure.DATA.json` preserves exact roots,
versions, source conditions and the available evidence limits; it does not turn
the full72-module catalog into a requirement for every desktop application.

The full candidate requires six shared libraries: WaylandCompositor,
WaylandEglCompositorHwIntegration, WaylandCompositorXdgShell,
WaylandCompositorIviapplication, WaylandCompositorWLShell and
WaylandCompositorPresentationTime. Four are QML backing libraries, as confirmed
by the exact QtDeclarative6.12 build helpers. It also requires seven component
plugins and all eight QML imports:

- `QtWayland.Compositor`, plus XdgShell, IviApplication, WlShell, QtShell,
  PresentationTime and TextureSharingExtension below that URI.
- `QtWayland.Client.TextureSharing`.

Quick/QML, client extensions and SVG-dependent decoration remain enabled. The
VSP2 hardware layer is outside this Asahi-targeted profile. The conditional BRCM
source path has a recorded missing doubled `extensions/` reference and is not a
supported capability. No missing capability is patched around or counted passed.

## Compatible-provider prerequisites

Frozen GUI18 `b05267833d497ef034576741bf31968019a526c3` exports
`wayland_server=OFF`. Qt's imported private feature cache and generated C++ header
do not establish an independent compositor-server override. The dependency guard
therefore requires a separately selected compatible server-enabled Qtbase6.12
provider. It neither edits nor weakens that frozen recipe. C's forthcoming
provider must retain the18 intended GUI outputs and export server-ON consistently
in its package metadata, imported feature state and private header.

`COMPATIBLE-PROVIDER-INTERFACE.DATA.json` gives the exact provider/scanner/protocol
contract. Matching QtDeclarative6.12 Qml/Quick/public/private/build-internal tools
and QtSvg6.12 remain separate prerequisites. The recipe uses normal
`qt6-base=6.12.0`, `qt6-declarative=6.12.0`, `qt6-svg=6.12.0`, Wayland, EGL/GLVND,
XKB and DRM dependencies. Package version resolution is necessary but does not
replace the imported-feature/private-ABI checks or Root's signed provider review.
The host normal package query records these exact Qt versions and
`cmake>=3.25` missing. No version-bypass or provider-substitution flag is used.

The new package does not replace Mesa, select a GPU driver or change the Asahi
platform. It conflicts only with the overlapping official `qt6-wayland` package;
compatible qtbase/declarative/SVG providers remain installed. Actual compatible
native providers, keys, signatures, inventories and Root bindings are unselected.

## Source, licenses and security inputs

The retained official component archive is908828 bytes, SHA256
`ae14d9bcf1bb3c300a3ab2e6a53f50284e5c6c966a4ac4cc5aedcb1bc74e4d02`.
Its `.tag` is `c4f85cd060e3e80a7d71829defac9cf5a40e8ffa`, matched to the peeled
official `v6.12.0` tag. Download metadata, checksum, tag readback and bounded
acquisition are preserved under `upstream/`. No large Qt bundle was downloaded.
Only two small QtDeclarative helper files were fetched at its immutable dependency
revision `4332fbbb4c340463dc8cee36dda0c85d932122d8` for source auditing; they are
not a compiled QtDeclarative provider.

The unchanged upstream notices, REUSE data, third-party protocol inputs and
license texts are pinned in `source-notices.json`:16 files/128430 bytes. Source
SPDX headers and the full archive are retained. The compositor's GPLv3/commercial
alternatives and other files' LGPL/GPL/BSD/MIT terms remain distinct; no commercial
license or legal approval is issued. `source.py` verifies and stages actual bytes
only into the private named package DESTDIR.

QtWayland also generates code from Qtbase's installed protocol trees. The exact
52 protocol/attribution/license inputs,449254 bytes, are pinned separately in
`dependency-inputs.json`, verified against the selected dependency prefix and
copied into this package's dependency-notice tree. Their source and existing GUI
host-configure copy were checked; an actual native installation is unavailable.

`SECURITY-RELEVANCE.DATA.json` records the inspected public Qt6.12 patch index and
the four Qtbase dependency patches. No direct QtWayland patch was selected from
that index; Qtbase patches still belong on the compatible Qtbase provider. This
is a bounded component-relevance audit, not a vulnerability-free or freshness
acceptance claim. Other Qt components' security obligations are not waived.

## Build and acceptance behavior

The future ordinary command is `makepkg --cleanbuild --force` in a Root-selected
signed native aarch64 image. Normal dependencies/checks remain mandatory. Both
build and check enforce one job; the full-feature CMake profile retains required
server, Quick, dmabuf, client-shell and decoration functions. The guard requires
exact matching Qt6.12 public/private/scanner providers. After configure, the
source helper refuses empty or partial success without all six shared-library,
eight QML-plugin and three client-plugin target declarations.

The future smoke uses normal exact CMake imports, both real scanners and a tiny
generated server protocol. It compiles QML components and checks seven compositor
type registrations without creating a compositor, window, socket or GL context.
Client TextureSharing is packaged and source/stage checked; its initializer
accesses native QPA server-buffer integration and is explicitly **not executed by
the offscreen API smoke**. A genuine Wayland/Hyprland display test remains a
separate required runtime observation. No smoke compile or execution has occurred.

The stage verifier requires all six shared providers, eight complete QML trees,
seven fixed plugins, source QML bodies, exact own/dependency notices and safe
payload metadata without GUI18 overlap. Its AArch64/16K ELF parser is the exact
audited GUI checker algorithm and records needed libraries, interpreter and GNU
versions. Structural checks do not prove native loading or M2 compatibility.

`lifecycle.DATA.json` defines future normal signed install/reinstall/upgrade/
rollback/removal, dependency/overlap negatives, exact inventory/payload checks and
preservation of user/other-package configuration. It performs no transactions.
The inherited4GiB/j1 builder,6GiB daemon and12GiB owned-storage proposal remains
unmeasured/unaccepted; only recipe scheduling is enforced here. Heavy compilation
requires Root's scoped resource and execution selection.

## Evidence and controls

`BUILD-CONTRACT.json` separates source-backed requirements, genuine host failure
and unavailable native results. `evidence/` retains the original configure log,
failed cache, command/input pins, host dependency query and source/data joins.
The complete recipe-file map excludes only its own map file. No old GUI/base,
adapter, C producer or shared manifest is changed, and no original official
Qtbase `0bd04f` correspondence is claimed.

Run each `test_*.py` separately with Python `-I -B -Werror` and an explicit private
`TMPDIR`. Actor-fenced source/stage/smoke controls use labelled MODEL fixtures;
the scheduling controls permit only their stubbed Bash process with external
program search disabled. Genuine source/hash/tag evidence is checked separately.
Passing controls are not a successful Qt configure, build, native or hardware run.
