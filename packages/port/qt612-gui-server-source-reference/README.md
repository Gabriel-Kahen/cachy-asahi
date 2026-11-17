# Qt6.12 GUI18 server-enabled source candidate

This is a separate, unselected Qtbase provider derived from frozen GUI recipe
`b05267833d497ef034576741bf31968019a526c3`. The original GUI, base recipe,
producer, and manifests are unchanged. It preserves Qt6.12.0 revision
`025bdad181de241e81bf853c8a2d7bf3d19261a9`, the 51,220,268-byte upstream
archive SHA256 `a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307`,
all four security patches in their exact order with zero fuzz, all 173 source
notices (636,122 bytes), the serial scheduling guard, and all 18 GUI modules.

The only changed Qt feature setting is `FEATURE_wayland_server=ON`. Qtbase's
upstream condition for this private feature checks Wayland client/scanner
availability; it does not require a server library. The recipe additionally
requires normal `wayland>=1.15` and `libwayland-server.so=0-64` dependencies.
`SERVER_DEPENDENCY_GUARD.cmake`, invoked by the actual `QtBase` project hook,
requires `wayland-server>=1.15` through pkg-config and links a small server API
probe. It does not execute that probe or bypass normal package checks.

`source.py configuration` joins all 113 real configuration settings, both
server cache entries, the server prerequisite link result/version, the
generated `Qt6::Gui` enabled/disabled private feature lists, and the private
`QT_FEATURE_wayland_server 1` header. The stage checker preserves the complete
AArch64/ELF/16K structure, GUI plugin, development file and 173-notice checks.
It additionally requires the staged feature export/header and normal
WaylandGlobalPrivate/ScannerTools discovery files, recording their whole pins.
Its passive metadata parsing is not a consuming CMake import or native test.

The genuine future `check()` smoke uses the own built Qt tree, exact versions,
explicit private/support package paths, imported library/scanner locations,
and the enabled server feature property. It retains the offscreen widget/API
tests and links the normal server library. It allocates and destroys a local
`wl_display` without adding a socket, connecting a client, dispatching a server
event loop, creating a GL context, or claiming compositor/hardware behavior.
No production Qt library or this smoke has been built or run here.

`PROVIDER-INTERFACE.DATA.json` is the proposed contract for the separate full
QtWayland client/compositor/QML candidate. Qtbase supplies the existing 18
libraries, the enabled private server feature and its global/scanner helpers.
QtWayland must still require matching Qt6.12 Qt Declarative (QML/Quick/private
targets and build internals) and SVG. This recipe supplies neither a QtWayland
compositor library nor those separate modules. The unchanged upstream protocol
files remain subject to that consumer's exact input pins.

The package provides `qt6-base=6.12.0` and the same 18 SONAME aliases as GUI18.
It conflicts with official `qt6-base` and both independent base/GUI providers.
It has no automatic `replaces`, install script, hooks, backup entries, services,
or user configuration writes. It cannot coinstall with overlapping providers.
The normal disposable replacement/removal/rollback transaction is untested.
An exact `qt6-base=6.12.0-3` requirement remains unsatisfied; matching SONAMEs
alone do not establish private ABI or version compatibility. See
`lifecycle.DATA.json` for the complete proposed transaction boundary.

Licenses remain the retained per-file Qt/third-party grants and full 173 notice
inventory. The source/guard/checker additions are MIT. Packaging notices and
patches are retained byte-for-byte. Legal/release acceptance is not inferred
from source acquisition, the archive version, or configure success.

Actual local observations in `evidence/`:

- Fresh bounded extraction of the pinned archive and all four forward patches
  passed with zero fuzz/offset. The notices and exact release tag/version passed.
- A fresh x86_64 configure using local CMake 4.3.3 passed in 19.347 seconds under
  a 512 MiB address-space limit and 60 CPU seconds. Only ordinary configure/compiler
  probes ran. It records all 113 settings, the real server link probe, enabled
  feature exports and exactly 18 generated shared-library targets. These are
  declarations, not built Qt payloads. Local CMake is outside the host package
  database; a normal native dependency transaction is still required.
- The already retained aarch64 `wayland 1.26.0-1` archive and detached signature
  were whole-hashed. Its actual `.PKGINFO` provides the required server SONAME;
  its headers, pkg-config metadata, symlinks and AArch64 server ELF were read
  without extraction, loading or execution. GPG and provider resolution remain
  unrun; this byte audit is not native compatibility acceptance.

Build only in a separately authorized clean native image with the complete
normal signed dependency closure:

```sh
MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1 makepkg --cleanbuild --force
```

The old F69/GUI producers and transport are not bindings for this new tuple.
A new Root-selected producer must retain whole stage/configuration/check
receipts before normal makepkg cleanup, run two clean native attempts, compare
archive/payload/PKGINFO/BUILDINFO, and validate the normal transaction. No actor,
Root grant, image, signing operation, upload, installation, M2 check or
performance result is supplied here.

All 79 focused controls passed under 512 MiB per process. Run the source/MODEL controls individually (their audit fences are isolated):

```sh
python -B test_recipe.py
python -B test_source.py
python -B test_stage.py
python -B test_smoke.py
python -B test_parallel.py
```

Use an available owned `TMPDIR` when the host tmpfs is full. The stage fixtures
are inert synthetic ELF, not runnable Qt or native acceptance evidence.
