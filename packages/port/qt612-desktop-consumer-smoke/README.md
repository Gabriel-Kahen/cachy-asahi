# Qt 6.12 installed desktop consumers

Source-only candidate. **Not configured, compiled, installed, or executed.**
The three checks below must all succeed against one normally installed Qt
6.12.0 family. Missing providers, mismatched versions, missing plugins, failed
pixels, missing reflection, or a protocol timeout are failures; there are no
skips or fallback providers.

| Consumer | Actual behavior required at execution | Boundary |
| --- | --- | --- |
| `qt612-desktop-render` | Decode the fixed SVG through the image-format plugin; paint it through `QSvgRenderer`; load compositor QML imports; render the QML scene through Quick's software paint-device backend; compare interior pixel colors. | Offscreen software only; does not create a compositor or test a display/GPU. |
| `qt612-desktop-shader` | Build the fixed vertex shader with installed `qsb`, deserialize its embedded output and check SPIR-V, input/output locations/types and the uniform block layout. | Serialization/reflection only; does not execute a shader on a GPU. |
| `qt612-desktop-protocol` | Generate both Qt client/server wrappers, connect them through an anonymous socket pair, exchange a fixed serial and text, and verify the reply within a finite deadline. | In-process Wayland transport/codegen only; does not start an external compositor or desktop session. |

The render check intentionally does not initialize
`QtWayland.Client.TextureSharing`: its upstream initializer asks the platform
integration for a server-buffer interface. An offscreen paint-device check
cannot validate that API. Its installation and any actual texture-sharing
session remain separate provider and runtime checks. These consumers do not
claim complete module coverage, native ARM, 16K-page, Asahi/M2, lifecycle,
performance, or release acceptance.

In the separately granted native environment, install the five matching
providers first, then run from this directory:

```sh
cmake -S . -B /owned/qt612-desktop-consumer-build -G Ninja \
  -DQT612_INSTALLED_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build /owned/qt612-desktop-consumer-build --parallel 1
ctest --test-dir /owned/qt612-desktop-consumer-build --output-on-failure
```

Use a fresh owned build directory. No command installs packages, changes system
configuration, opens a public socket, or launches a physical desktop session.
CTest gives each executable ten seconds; the protocol's internal deadline is
shorter. Preserve full configure/build/test output, exit statuses, installed
package identities and loaded-provider evidence. A single printed marker does
not establish that the other consumers ran. No native runner, signing grant,
provider receipt, lease or Root acceptance is created here.

`INTERFACE.DATA.json` pins the source candidates expected by C's complete-family
adapter. This project only accepts installed `/usr` package discovery and exact
6.12.0 library/tool targets. It cannot authenticate package provenance or prove
which ELF objects the loader used: the native adapter must retain its existing
package ownership, signature and loaded-library checks. Do not substitute the
frozen server-OFF GUI candidate, Qt 6.11 host packages, a build-tree import path,
or an upstream architecture declaration.

The client and server generator macros both name their common C output
`wayland-desktop-probe-protocol.c`. Separate build directories prevent rule
collisions, and only the client copy is compiled. The server C source is marked
`HEADER_FILE_ONLY`; its Qt wrapper resolves the same interface definition.

Source/data controls (no CMake/compiler/scanner/qsb/render/protocol execution):

```sh
TMPDIR=/home/gabe/.cache prlimit --as=536870912 -- \
  python3 -I -B -Werror test_data.py
```

The controls validate the closed source map and fixed fixture semantics. They
do not simulate a successful consumer run. API references are pinned in
`SOURCE-AUDIT.DATA.json`; upstream documents describe the
[paint-device render target](https://doc.qt.io/qt-6/qquickrendertarget.html#fromPaintDevice)
and [build-time shader resource generation](https://doc.qt.io/qt-6/qt-add-shaders.html).

All files in this directory are original project code/data under MIT; no
upstream implementation or generated protocol code is vendored.
