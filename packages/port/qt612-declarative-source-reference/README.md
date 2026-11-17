# Qt6.12 Declarative source reference

This original aarch64 development recipe supplies the Qt6.12 Linux QML, Quick and Controls component required by the separate QtWayland compositor candidate. It is source-audited and unselected. It has not been compiled, packaged, installed, signed, admitted into frozen349, or tested on M2 hardware. No runtime/platform acceptance is implied.

Upstream component: `qt/qtdeclarative`, release tag `v6.12.0`, commit `4332fbbb4c340463dc8cee36dda0c85d932122d8`, tree `98324181f2eebf01e806603a01829a40b8683631`. The official component archive is39,221,652 bytes, SHA256 `311f3a2603e1973bb59baef9dfa740a376de713157d4782ee043681e889c9260`; both primary checksum endpoints agree. No monolithic Qt bundle was acquired. Upstream's tracked `.tag` is `$Format:%T$`: its exported value is the tree ID, not the commit. Retained primary Git ref/commit data joins that tree to the release commit. The exact tagged `.cmake.conf` retains an `alpha1` prerelease marker; this recipe does not rewrite it or infer a different source identity. Signature authentication remains unperformed.

The PKGBUILD requires the compatible `cachy-asahi-qt612-gui-server-source-reference=6.12.0`, `qt6-shadertools=6.12.0`, and `qt6-svg=6.12.0` packages through normal dependency resolution. Imported CMake versions and provider locations are checked. `qsb` is mandatory: the upstream `src/CMakeLists.txt` otherwise skips **every Quick module**. Required provider tuples are not available/accepted here. The normal host dependency probe naturally refuses Qt6.11.2; no compiler was invoked by that `project(... NONE)` probe.

All56 non-native-platform features declared by this component's QML/Quick/Controls configuration are explicitly ON and checked after configuration. This includes JIT on supported Linux/AArch64, network/SSL/WorkerScript/models, particles/shaders/shapes/vector images, dialogs/layouts, and portable Basic/Fusion/Imagine/Material/Universal/FluentWinUI3/StyleKit controls. macOS/iOS/Windows native styles have upstream platform conditions false on Linux; they are not claimed. The unrelated optional QML language server requires a separate matching Qt LanguageServer component and is not claimed by this runtime profile. The static internal Qt.test.controls helper is not falsely advertised as a runtime shared plugin.

The stage contract requires17 shared API modules, exact SONAME/AArch64/16KiB ELF geometry, private Qml/Quick headers and CMake targets, QmlBuildInternals/macros, pkg-config interfaces, normal tools,47 source-derived QML modules with qmldir/type/plugin checks, and all23 pinned notice files. Every staged ELF is inspected without loading it. ELF geometry is a static check, not native or M2 evidence. The retained ELF parser is an exact, whole-pinned function reused from the maintained QtWayland stage checker. All actual DT_NEEDED names are reported; unknown external Qt modules refuse the stage.

The finite60-second offscreen/software smoke imports all47 modules, instantiates Quick/Controls/Layout objects, evaluates JavaScript, and compiles a normal `qt6_add_qml_module` consumer. Software/offscreen execution will establish only that finite smoke, never Wayland/GPU/hardware correctness. `lifecycle.DATA.json` specifies separate normal signed install/remove checks for the maintained disposable lifecycle runner. No package hooks, services, automatic replaces, live install or removal are introduced.

Build procedure in a future admitted disposable builder: acquire all sources/signatures before the build; normal `makepkg` dependency checks; `prepare()` validates revision tree/notices; serial `build()` checks providers and all required features before compilation; `check()` builds/runs the finite consumer; `package()` installs only into DESTDIR and validates the complete payload. There is no network inside these functions and no nodeps/unsigned dependency bypass. The component keeps bundled JavaScriptCore macro assembler/Yoga code with original notices; dependencies and complete upstream source remain available at the pinned official source URL.

Source-only validation:

```sh
python3 -I -B test_recipe.py
makepkg --printsrcinfo
```

The retained actual `makepkg --verifysource --ignorearch` result verifies all13 source checksums only; `--ignorearch` on an x86 host is not a compile or ARM claim. Seventeen focused controls distinguish genuine source evidence from explicitly synthetic MODEL payload checks. `SECURITY-RELEVANCE.DATA.json` records the finite primary public patch-index check: no direct Declarative patch was selected; the matching base provider must retain its existing three security fixes. This is not a vulnerability-free or security-freshness claim.

Capacity remains a separate blocker: no peak RSS, elapsed time, native pair or resource fit is measured. Serial compilation alone is not proof of fit. Root must select and qualify a complete input/provider set and finite resource profile before a real build. Old Qt recipes, GUI variants, shared inventory and Asahi platform stack remain untouched.
