# Qtbase 6.12.0-4 Asahi629 parity candidate

The earlier Asahi629 guest swapped the official and project Qtbase 6.12.0-3
packages, ran both providers' offscreen and Wayland software probes, and
restored the original 629-package inventory. Its independently read receipt
binds the comparison and both archives below.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| Official `qt6-base` 6.12.0-3 | 15,177,820 | `2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31` |
| Project 6.12.0-3 archive | 14,172,388 | `6420f8ee8d8ebc106072c9bedb111c6b2dd780eb4e4629bceec4dc71a2b774c4` |
| Official/project comparison | 252,319 | `44de3677704545315fc1955acebeb24e22c7d03829c371061369effbc6044171` |
| Scoped guest receipt | 7,056 | `8ee4c063ab5b34665b01fe56f5c1b5b9ff06eff44ea0cb261d2e53350e16f9a4` |
| Project 6.12.0-3 recipe receipt | | `b3b46a27d6bb5e93bf411de9a23bf238c36230f268206af09637c9d66f0ce41a` |

The new recipe projects 6.12.0-4 from that exact 6.12.0-3 recipe. It uses
Qtbase v6.12.0 revision `025bdad181de241e81bf853c8a2d7bf3d19261a9` and the
51,220,268-byte archive
`a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307`.
The [inherited recipe](README.md) supplies the ordered four security patches,
the Qt md4c cherry-pick, exact md4c and Vulkan header packages, and 173 source
notices. The generated `.SRCINFO` and `PARITY.UNISSUED.json` pin every
recipe source. Qt license metadata remains GPL-3.0-only, LGPL-3.0-only,
Qt-GPL-exception-1.0 and the retained Qt third-party notices under
LicenseRef-Qt-ThirdParty. The projection and checker are MIT-licensed.

| Feature | Change and dependency |
| --- | --- |
| AT-SPI | Enable `accessibility_atspi_bridge`. QtGui compiles the D-Bus bridge for use by Wayland and XCB. `at-spi2-core` supplies the build headers and pkg-config metadata. Qt uses its session bus and registry through D-Bus, so the package lists it as an optional runtime dependency. |
| Printing | Enable `cups`, which also enables Qt's CUPS job widget. `libcups` supplies headers and the printer plugin's hard runtime dependency, `libcups.so.2`. |
| XWayland EGL | Enable `xcb_egl_plugin` and `egl_x11`. The XCB plugin uses the existing GLVND and X11 dependencies. Qt can use its X11 EGL platform-display path and its legacy EGL display fallback. |

The exact ALARM dependency archives and original detached signatures are in
the recipe receipt. Both signatures verified offline with the held ALARM
key. Both packages already appear in the retained Q3 build lock and the
Asahi629 installed lock. The archive metadata records `libcups 2:2.4.20-1`
as Apache-2.0 WITH LLVM-exception AND BSD-3-Clause AND Zlib AND BSD-2-Clause,
and `at-spi2-core 2.62.1-1` as LGPL-2.1-or-later. The recipe keeps the 18
Qtbase libraries, bare `qt6-base` provision, GLX, Wayland server and Vulkan
configuration, and existing Asahi platform and service packages. Qt's separate
EGLFS X11 and VK_KHR_display platform plugins remain disabled.

## Expected package paths

A comparison of the two host-generated install graphs found 31 added file
paths and zero removed paths. The [stage checker](check_parity.py) defines the
exact paths. Its two plugin checks require executable shared objects with
`DT_NEEDED` entries for `libcups.so.2` and `libEGL.so.1`, respectively.

- 13 QtGui private AT-SPI headers, including five generated D-Bus headers.
- Two QtPrintSupport private CUPS headers.
- `usr/lib/qt6/plugins/printsupport/libcupsprintersupport.so` and
  `usr/lib/qt6/plugins/xcbglintegrations/libqxcb-egl-integration.so`.
- Seven CMake export files per plugin, with `Targets-release.cmake` corresponding
  to the official package's `Targets-relwithdebinfo.cmake`.

All 31 corresponding files are in the audited official-only inventory. The
CUPS plugin adds a `printsupport` directory, and the EGL plugin shares the
existing `xcbglintegrations` directory with GLX. Existing libraries, platform
plugins, feature headers, and CMake/qmake metadata may change bytes. The final
package comparison must measure those changes and confirm the path and ABI delta.

## Source checks and pending qualification

From this directory, project into an empty destination path and check the
recipe metadata.

```sh
python3 -I -B -Werror prepare_parity.py --output "$NEW_RECIPE"
python3 -I -B -Werror test_parity.py
cd "$NEW_RECIPE"
makepkg --printsrcinfo | cmp - .SRCINFO
```

The source-only `makepkg --nobuild --nodeps --ignorearch --holdver` check
used the held Qt archive, applied all five patches, and verified all 173
notices. Both profiles configured independently on x86_64 under a 768 MiB
per-process address-space limit and each passed the 114-setting check. The
new graph contains the QtGui bridge objects, both plugin targets, and normal
CUPS and EGL link inputs. All 40 projected runtime dependency expressions passed `pacman -T`
on the copied Asahi629 project database. The source checks did not compile Qt.

The build and replacement controllers currently bind 6.12.0-3. To schedule
6.12.0-4, bind the new recipe receipt, signed dependency pins, guest artifact
names, independent stage/archive checks, and updated replacement lock.
Build in a fresh offline AArch64 16 KiB guest with normal dependency resolution
and the existing serial makepkg policy. Compare the result to both audited
archives for package ownership, SONAMEs, dependency resolution, and the
retained Vulkan/md4c ABI. Confirm the QtGui AT-SPI bridge and both new plugins
in the actual archive before TEST signing.

In Asahi629, run the existing official/project software rendering checks,
then exercise the new paths as an ordinary user. Query real accessible roles
and keyboard focus via the AT-SPI bus while the Hyprland screen-sharing
picker runs through its portal. Enumerate and print through a disposable CUPS
queue with a private daemon fixture, since the baseline has only the CUPS
client library. Force `QT_XCB_GL_INTEGRATION=xcb_egl`
in XWayland and show a rendered frame using the EGL context and loaded plugin.
Check the automatic XCB selection with GLX still present. Restore the
official Qt package and recheck inventory, install reason, protected state,
and scoped runtime behavior. A headless Weston check alone cannot qualify
the Hyprland picker. Package build, candidate installation, runtime parity
and physical M2 qualification are pending.
