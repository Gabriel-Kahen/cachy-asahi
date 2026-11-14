# Python 3.14.8 full Tk host build

This opt-in helper builds the unchanged Main432 `python3148-source-candidate`
recipe as an **x86_64 host diagnostic**. It does not replace the retained ALARM
Python package or qualify native ARM, GUI, Apple hardware, source delivery,
licensing or release policy. No package is installed on the host or target.

The official Arch image must already exist locally at
`archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`.
`inputs.json` binds every unchanged recipe file, including `.SRCINFO`, and the
24,130,644-byte Python source archive
`c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73`.
Missing or changed material fails before Docker is called. Source originals are
only read; the copied input namespace is mounted read-only.

From the repository root, with a retained exact source archive and a new output
directory:

```sh
python3 -I scripts/port/python314-tk-host-build/run.py \
  --source /private/materials/python-Python-3.14.8.tar.xz \
  --output /private/new-python314-tk-run
python3 -I scripts/port/python314-tk-host-build/inspect_archive.py \
  /private/new-python314-tk-run/export/python-3.14.8-1.1-x86_64.pkg.tar.zst \
  > /private/new-python314-tk-run/archive-review.json
python3 -I scripts/port/python314-tk-host-build/test_host_build.py
python3 -I scripts/port/python314-tk-host-build/test_archive_layout.py
python3 -I scripts/port/python314-tk-host-build/test_actual_archive.py \
  /private/new-python314-tk-run/export/python-3.14.8-1.1-x86_64.pkg.tar.zst \
  > /private/new-python314-tk-run/actual-controls.json
```

Only provisioning has network access (`host` networking works around the
observed rootless bridge HTTPS timeout). It downloads the frozen 2026/11/09
official core/extra DBs, checks their exact hashes, and installs the declared
runtime/build dependencies and `base-devel` inside its disposable image. Package
signatures remain Required; DB authentication here is the pinned SHA-256, not
a claim of a verified DB signature. The recorded pacman configuration, complete
installed package inventory and acquired archive/signature hashes are exported.
No host package installation, service startup or display/device access occurs.
Provisioning may emit package hooks which skip system-manager reload because
the container is not booted.

The source-build actor uses `--network=none`, two CPUs, 4 GiB memory/swap limit,
256 PIDs, read-only root, UID/GID 1000, all capabilities dropped,
`no-new-privileges`, an init process and only the input bind plus private work
volume. `/tmp` and `/run` are bounded noexec tmpfs mounts. The inspected actor
configuration must match before starting. The existing pinned FDK Runner gives
the controller a 2,700-second overall deadline; provisioning is at most 900
seconds, image commit 120 seconds, and source/check/package execution 1,500
seconds. A separate 120-second cleanup budget removes only the unique owned
containers, volume and derived image, including names whose create CLI was
interrupted. Missing owned names are distinguished from cleanup errors. Cleanup
errors leave HOLD and retain the first failure in the private report.

The build uses ordinary
`makepkg --ignorearch --cleanbuild --nosign --noconfirm`; dependency checks,
source checksums, `prepare()`, `build()`, `check()` and `package()` all run.
There is no `--nodeps`, `--nocheck`, prerequisite installation in this actor, or
network fallback. `MAKEFLAGS=-j2` and fixed `SOURCE_DATE_EPOCH=1791748800` are
explicit host diagnostic inputs. This recipe does not enable PGO/LTO. The
generated package is deliberately unsigned and is never installed.

The unchanged recipe tests the complete candidate runtime (including mandatory
`_tkinter`), ten upstream suites, private package layout, notices, frontends,
PEP 668 and staged runtime. An extra staged `tkinter.Tcl()` check evaluates
`6*7` without loading Tk or creating a window; `_tkinter` links to Tk, but
headless Tcl is not GUI validation. The separate archive command reuses the
pinned bounded DATA reader, recomputes every payload checksum, checks namespace,
required compiled Tk extension, relative frontends and exact notices/provenance,
and rejects missing/changed materials, privileged modes, hooks/services/pip and
upstream test fixtures. It never extracts or executes the archive.
The seven explicit retained-archive controls accept the real payload, reject
truncation/trailing compressed bytes, and reject mutations of its decoded DATA
map: omitted Tk, changed notice, extra service and material outside `/usr`.

The private output retains operation logs, exact helper/input identities,
failure context, resource configuration, makepkg exit/log, actual package,
`.PKGINFO`, `.BUILDINFO`, Tk result and cleanup outcomes. The first observed
bridge failure is retained separately; it is not hidden by a later success.
No reproducibility or historical-build equivalence is inferred.

Command semantics are documented by the official
[makepkg manual](https://man.archlinux.org/man/makepkg.8.en),
[Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/),
and [Python tkinter documentation](https://docs.python.org/3.14/library/tkinter.html).
