# md4c 0.5.3 source-reference provider

New project recipe for `md4c-0.5.3-1-aarch64.pkg.tar.xz`, intended for the
Qt 6.12 producer's `>=0.5.3,<0.6` dependency contract. This is a project-built
provider candidate. The separate search for an authenticated official ALARM
0.5.x binary remains **HOLD**. This recipe does not recover that binary or inherit
ALARM's signing authority. Root must separately admit project provenance and
trust before the producer can consume it.

## Source and installed contents

Upstream [release-0.5.3](https://github.com/mity/md4c/tree/472c417005c2c71b8617de4f7b8d6b30411d78f4)
resolves to commit `472c417005c2c71b8617de4f7b8d6b30411d78f4` (annotated tag object
`093c3f45ce44bd6661849982b1dd7f0e7f385621`). The full-commit codeload tarball is
244705 bytes, SHA256
`ecbd85292465df929839897e314d809b5c8b267e20c4e5e24d51a1602d16d99a`.
The archive hash and source version were checked; upstream signature
authentication was not established. `source.json` records these fixed inputs.

The unchanged C sources build shared `libmd4c.so.0.5.3` and
`libmd4c-html.so.0.5.3`, each with SONAME 0 and upstream symlink chains. The
package installs `usr/bin/md2html`, its man page, both headers, both libraries,
pkg-config metadata and CMake imported targets under `usr/lib`. It retains the
original MIT license at `usr/share/licenses/md4c/LICENSE.md`. Upstream test
software/specification notices remain in the source archive; tests are not
installed. Build dependencies are CMake/Ninja plus normal base-devel tools;
checks additionally need Python/pkgconf. Runtime dependency: `glibc` only.

No source patch, service, hook, install script, configuration backup, boot or
hardware-stack change is supplied. These `/usr` paths belong to a normal md4c
package, so this candidate must not be installed alongside another provider
owning the same paths. A later signed ALPM installation/removal must be reviewed
as a dependency transaction. Removing md4c while Qt depends on it is not an
independent uninstall test. This task did not install or remove any package.

## Native two-clean-build contract (NOT RUN)

Root selects two independently clean, non-root **native aarch64** build
environments with the same recorded package/toolchain inventory, source bytes,
recipe bytes, makepkg configuration and `SOURCE_DATE_EPOCH=1776685420`.
Retain each environment's actual inventory and full phase logs. With dependencies
already present, run the normal command in a fresh copy of this recipe directory:

```sh
SOURCE_DATE_EPOCH=1776685420 makepkg --cleanbuild --log
```

The recipe selects XZ package output. Do not use architecture, dependency or
check bypasses. `build()` uses Release shared-library CMake/Ninja; `check()` runs
all 652 upstream CommonMark and 65 regression examples, then stages through
`DESTDIR` and runs `smoke.sh`. Smoke checks exact CLI/version/output, both
SONAME/symlink chains, both pkg-config versions, a compiled parser/render API
consumer and a separately compiled CMake imported-target consumer. `package()`
stages the normal install and original license; no host installation occurs.

Both builds must pass. Inspect actual `.PKGINFO` for exactly `pkgname=md4c`,
`pkgver=0.5.3-1`, `arch=aarch64`, and the declared runtime dependency. Retain
`.BUILDINFO`, archive byte/hash pins and file inventories. Check actual ELF
machine is AArch64, dependency/loader closure, and 16K PT_LOAD suitability.
Compare complete archive bytes; if unequal, explain metadata and payload
differences rather than claiming reproducibility. Identical host-stage payloads
do not waive these native checks.

Only after native review may Root select a separately signed project package,
its detached signature and public trust evidence. C's future input object has
exact fields `name`, `version`, `arch`, `filename`, `archive`, `signature`; the
last two must each be actual whole-file `{path,bytes,sha256}` references.
Those references and all native/signing/acceptance results remain NULL in
`native-contract.json`. No archive, signature or `.PKGINFO` is fabricated here.

## Actual local verification

On x86_64, GCC 16.2.1, CMake 4.3.3, Ninja 1.13.2 and pkgconf 3.0.7:
two independently extracted source/build directories passed build, all
652+65 upstream examples (zero failures/errors/skips), the recipe's actual
`check()` and `package()` functions, and all staged smoke checks. Their complete
15-leaf installed payload inventories were byte/mode/symlink identical.
These were separate clean directories on one host, **not clean native builder
environments**. No makepkg package archive, signing, ARM, 16K runtime, complete
Qt transaction, M2 or release result is claimed. Bash syntax and generated
`.SRCINFO` were checked. The coordinator's ignored `work/` evidence retains the
commands, logs and payload comparison; `HOST-RESULT.json` summarizes them.
