# Development host results — 2026-11-14

This new opt-in UI leaves Welcome8, first-login, Setup8, shared manifests and
default selectors unchanged. Runtime backends are explicitly constrained to
first-login 0.1.0-2 and Setup8 0.3.0-1. Their exact check-only fixture hashes are
recorded in source provenance; no fixture is installed by this package.

Observed on x86_64, Python 3.14.7, PyGObject 3.56.3 and GTK 4.22.5:

- **22 bridge controls PASS**, including real project helper inspect/preview/
  apply, interrupted transaction recovery, edited-file preservation, unchanged
  action labels with stale content, old recorded template roots, unavailable
  templates, conflicts, expiry/single use, migration-owned recovery refusal,
  symlink refusal, cancellation, protocol/size refusal and concurrent actions.
  Invalid/malformed helper responses are controlled test inputs, not native
  evidence. Ordinary-user program availability uses the host's existing files;
  no Fish/Zsh shell or compositor session is launched.
- **Five delivery controls PASS**: actual `package()` has eight owned files,
  moved isolated help resists ambient Python imports, missing runtime/backend
  has no checkout fallback, and the source-hidden moved bridge runs real helper
  activation in a private HOME. These run from a standalone source package too.
- **11 actual GTK window/button checks PASS**, using a private Xvfb display,
  private D-Bus/HOME/cache/runtime, hidden source checkout, moved installed
  prefix, private `/tmp`/`/dev`, and no network. Actual mapped window and button
  signals exercised read-only inspection/preview, disabled apply, stale apply
  refusal, explicit edit-preserving apply, selection invalidation, pending
  recovery preview/resume, completed-recovery gating and busy-window close/
  worker cancellation. The screenshot was visually inspected. This is host
  software GUI evidence; the user's desktop was not used.
- All 15 local sources passed makepkg SHA-256 verification. Required `check()`
  ran all 27 bridge/delivery controls. Static recipe checks report no errors.
- Ordinary `makepkg --nobuild --noconfirm` returned **8**, naming the two exact
  uninstalled backend packages. No host dependencies were installed. A separate
  `makepkg --nodeps --noconfirm` completed checks and package assembly; this is
  explicitly **not dependency-resolution or installation acceptance**.
- The final assembly emitted one `libfakeroot internal error: payload not
  recognized!` warning. It remains in the log. A separate bounded archive DATA
  read confirmed all tar UID/GID fields zero, exactly eight ordinary files
  across 19 payload nodes, intended modes and exact hashes matching every tested
  UI runtime/document/license source. No fixture, test, hook or autostart file
  is present in the archive. No archive was installed; GUI/helper checks used
  staged source files in private namespaces.

Retained final outputs:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `/tmp/cachy-asahi-first-login-ui-final-package-o40mrj1x/recipe/cachy-asahi-first-login-ui-0.1.0-1-any.pkg.tar.zst` | 23851 | `d848b5083600d2a1522d943bd29e72e15605e7f0f4503abb2418d02e9fb8f6d3` |
| `/tmp/cachy-asahi-first-login-ui-gui-delivery-20261114/gui.json` | 882 | `930dc1ba1509400d3bf1c68f94cdc8be398eaac6b045568d5164b1fa26e41573` |
| `/tmp/cachy-asahi-first-login-ui-gui-delivery-20261114/preview.png` | 61196 | `98f3820a25500ee940ec7efd676abb8a1a2d96e6758e3157d0da2663dfc08751` |
| `/tmp/cachy-asahi-first-login-ui-final-package-o40mrj1x/makepkg-assembly.log` | 2076 | `3f2f69275e894067d10389dc80cd58332e03f0d5eb2c0ff8d6c2c1d1d87af589` |

`archive-review.json` sits beside the final assembly log. GUI stderr and the
Xvfb log are empty in the final run. The first two attempts failed before any
GUI window because Xvfb's default GLX probe crashed in the host NVIDIA EGL
library while the namespace exposed no graphics devices. The first/second
failure directories remain `/tmp/cachy-asahi-first-login-ui-gui-{first,second}-20261114`.
The optional harness now disables Xvfb GLX, GTK GL/Vulkan/dmabuf and portals,
uses cairo, and disables core dumps. These are test-only settings, not product
defaults or graphics-acceleration evidence.

Reproduce from this source directory with `python3 -I -B test_bridge.py`,
`python3 -I -B test_delivery.py`, and optionally
`python3 -I -B test_gui.py --output /private/new-gui-result`.
For extracted makepkg sources, `FIRST_LOGIN_UI_RECIPE` selects the reviewed
absolute PKGBUILD for the actual `package()` delivery checks; `check()` supplies
it automatically. Build only in an owned workspace and preserve dependency
failures separately from any explicitly requested `--nodeps` assembly.

The underlying CLI does not supply an atomic preview compare-and-swap. Fresh
report/content checks block observed staleness; Setup8 remains the authority
for serialized final writes and edit preservation. Native ARM, signed package
lifecycle, integrated first graphical login, M2/hardware and release acceptance
remain NOT RUN. No shared selection or native actor was changed or invoked.
