# Python 3.14.8 source-authoritative candidate

This new original recipe produces `python 3.14.8-1.1` from a pinned official
CPython release and exact CPython patch. It does **not** reproduce or rebind the
historical ALARM `3.14.8-1` binary, whose BUILDINFO recipe remains unavailable.
The recipe is unselected; its aarch64 declaration is not an ARM build result.
The existing three-update proposal pins `3.14.8-1`, so it cannot silently adopt
this distinct candidate release or authorize a protected Python replacement.

Packaging, marker and check code are original MIT work. `CPython-LICENSE` is the
exact 13804-byte release LICENSE, SHA-256
`b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231`.
The POSIX 2024 patch retains its upstream author/header and CPython terms.
`source-provenance.json` records the exact URLs, revisions, digests and limits;
all eight makepkg source entries have SHA-256 pins. No ALARM recipe or its
externally-managed marker was copied. Upstream signature freshness and complete
third-party source/license/grant review remain held, including bundled upstream
materials such as ensurepip's wheel. Neither the notice nor a checksum is legal
acceptance.

## Build and runtime profile

The build follows CPython's documented configure/make/DESTDIR mechanism:
[configure options](https://docs.python.org/3.14/using/configure.html),
[Unix builds](https://docs.python.org/3.14/using/unix.html). It enables shared
libpython, uses system expat/mpdecimal, disables LTO and automatic ensurepip
bootstrapping, and uses the system timezone database. No PGO, performance gain,
Apple-specific optimization or historical compiler-flag correspondence is
claimed. Builder flags/dependency versions still need retained native evidence.

The runtime includes the standard cp314 ABI, `libpython3.14.so.1.0`, versioned
and ordinary Python/config/pydoc/IDLE frontends, stdlib, headers, pkg-config
files, manpages, a project-authored PEP 668 marker and exact notices/provenance.
Regression fixtures and IDLE test fixtures are removed from the runtime tree.
No pip frontend is bootstrapped. The runtime source/ensurepip module remains
available for explicitly created virtual environments.

Dependencies are explicit in PKGBUILD/.SRCINFO. In addition to core compression,
SSL, FFI, decimal and XML libraries, readline/ncurses/util-linux-libs cover
the built standard modules. SQLite and Tk are build requirements and optional
runtime features. BlueZ headers are an explicit build input. Full candidate
checks require `_tkinter` to be built; this check is not skipped when a builder
lacks Tk. The selected upstream checks cover ten core suites without claiming
GUI or the complete CPython suite.

With the declared dependencies already present in an owned **native aarch64**
builder, the intended commands are:

```sh
python3 -B test_source.py
python3 -B check_source.py --archive /absolute/Python-3.14.8.tar.xz
makepkg --verifysource --noconfirm
makepkg --cleanbuild --nosign --noconfirm
```

These commands do not install dependencies or the resulting package. The
source checker parses metadata as DATA and never sources shell or fetches.
`check()` runs functional interpreter checks plus ten selected upstream suites.
`package()` stages exclusively through DESTDIR, validates ownership/relative
links/notice/marker, then executes the staged interpreter with its own prefix
and full candidate profile. Thus `--nocheck` cannot turn a missing Tk profile
into a successful package stage. Native ELF/16K, full transaction, extension
consumers, rebuild comparison and recovery remain later acceptance gates.

## Actual host evidence and limits

November 14, 2026: four focused source controls pass, including tampered patch/
notice, metadata/dependency drift, foreign archive and symlink refusal. Exact
official tar/material/LICENSE correspondence passes. An owned recipe copy
passed `makepkg --ignorearch --verifysource` for all eight inputs; the architecture
override was used only for x86 source checking. Normal verification first
refused this host architecture, and that refusal is retained.

A bounded ordinary-user **x86_64 core probe** compiled the pinned source with
the recipe build function, two make jobs, `CFLAGS=-O2`, no LTO and private HOME/
XDG/TMPDIR. No dependencies were installed. This host lacks Tk: the build
reported 36 built-in/76 shared modules, one platform-inapplicable module,
`_tkinter` missing, zero failed imports. Ten selected upstream files pass:
2719 cases run, 116 skipped. This is not the full upstream suite.

Source-tree and relocated staged core functional checks pass under the explicit
`host-core-probe` profile, which deliberately returns 2/HOLD. The staged prefix
is private `stage/usr`; SOABI is `cpython-314-x86_64-linux-gnu`. Static inspection
shows the shared libpython SONAME and the interpreter's matching dependency.
The 3190-path layout/notice/link guard passes; real notice corruption and an
escaping frontend link refuse, then are restored. The final package function's
full-profile check **refuses with exit 1 for missing Tk**. No package archive was
assembled or accepted. The target check remains mandatory.

The probe began before BlueZ was added to the explicit build-dependency list;
BlueZ was already installed and build/configure/source bytes were unchanged.
The final package/stage guards use the final candidate snapshot. Early probe
working-directory setup failures are retained separately. This evidence is a
working core rebuild/staging route with an explicit missing prerequisite,
not a successful full-profile makepkg build.

Ignored evidence is under
`work/python3148-source-candidate-host-20261114/` in the implementation worktree.
`host-probe-report.json` binds the candidate source/check files, dependency
versions and build/source/upstream/runtime/stage logs. No host install, native
ARM execution, protected-policy change, production signing, supported-system
acceptance or M2 hardware test occurred.

## Install/remove ownership

This recipe intentionally owns the system Python paths under `/usr/bin`,
`/usr/include`, `/usr/lib` and `/usr/share`. It declares no install script,
backup files, hooks, services, trust/configuration changes or home-directory
writes. Package removal removes those package-owned files; selecting an older
Python requires separately supplied rollback assets and the supported package
transaction. This candidate provides no authority to change the existing Asahi
boot/kernel/Mesa/audio set or the original protected Python policy.
