# Qtbase QtCore link preflight on emulated AArch64

This preflight reads the closed Q3 configure result and its exact 16 GiB
scratch image. It checks the whole scratch pin on a temporary same-filesystem
reflink and reads selected ext4 files with read-only Debugfs. It verifies that
the guest PKGBUILD equals the existing Qt-family `gui_server` projection,
including the serial autogen and server dependency guard, and checks the
actual CMake cache, Ninja manifest and rules. Ninja runs only its graph and
command-inspection tools.

## Replay the preflight

Pass the canonical paths to the Q3 terminal receipt and original scratch.
Select a writable probe directory on the scratch filesystem and outside the
Q3 attempt and receipts. The original scratch and receipt are opened without
updating access time. The probe directory holds a temporary reflink and
bounded tool outputs. The command emits an unissued JSON plan on stdout.

```sh
lane=scripts/integration/qt612_base_16k_link_preflight
python3 -I -B -Werror "$lane/test_preflight.py"
python3 -I -B -Werror "$lane/preflight.py" \
  --q3-terminal "$q3_terminal" --q3-scratch "$q3_scratch" --probe-dir "$probe_dir"
```

| Q3 Ninja target | Commands | C/C++ compile edges | Shared libraries linked |
| --- | ---: | ---: | --- |
| `lib/libQt6Core.so` | 321 | 303 | QtCore |
| `lib/libQt6Gui.so` | 639 | 597 | QtCore, QtDBus, QtGui |
| `all` | 1,855 | 1,385 | Full configured build graph |

The Core target includes the versioned `libQt6Core.so.6.12.0` link and
the SONAME symlink. The Gui closure includes the Markdown importer and the
exact system md4c library. The retained R4 importer object is a separate
compile result. The Q3 Gui link requires 260 direct object inputs and the
Core and DBus shared libraries. [Q3 configure validation](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md)

## Core checkpoint and resource limits

The plan selects the existing serial CMake build invocation with
`--target lib/libQt6Core.so`. The command belongs inside the exact Q3
356-package root at its original guest path, with UID and GID 1000. The
checkpoint keeps Q3's compiler, flags and generated rules. It uses the
existing owned QEMU continuation boundary for a future issued attempt.
The boot and Q3 backing images are read-only inputs. A fresh attempt owns
the writable QCOW2 overlay, separate result disk, scope, nonce and capacity
checks. Feed the returned file and allocation limits to the existing owned
runtime command observer. Recheck actual output filesystem capacity at entry.

The probe measured 12,484,247,552 free bytes inside the Q3 ext4 scratch.
The Core proposal keeps 4 vCPUs, 4 GiB guest memory, 6 GiB actor memory,
and a 64 MiB result disk. It proposes a 4 GiB overlay cap, 32 MiB for
reports, 2 GiB live host disk reserve, and 2 GiB host memory reserve. It
allows 6,900 seconds for the guest build, 7,200 for QEMU, and 7,500 for
the outer attach. These are stop limits. No completion budget has been
measured for Core. R4 measured 209.20 seconds and 349,966,336 allocated
overlay bytes for its importer run.

A future Core result needs natural command exit, original output custody,
and AArch64 ELF64 shared-library readback for `libQt6Core.so.6.12.0`, with
SONAME `libQt6Core.so.6` and 16 KiB-compatible load geometry. Retain the
elapsed time, peak memory and peak allocated storage with the owned cleanup
evidence. The Qt-family package checker already provides an ELF parser for
these binary checks.

Gui and the full Qtbase build and package stages remain pending. The
`all` graph excludes package staging, the recipe smoke check and XZ
compression, whose runtime and storage remain unmeasured. The existing
Qt-family packaging recipe and native runner gates continue to apply.
