# Native Fish and md4c build results

Both trials used clean, separate build containers on a hosted AArch64 runner
with 4,096-byte pages. Each trial ran the normal recipe checks, compared the
whole archives, and retired its build containers and private daemon. Root
verified the original GitHub job evidence.

| Package | Native source commit | Byte-identical archive | Hosted run |
| --- | --- | --- | --- |
| `md4c-0.5.3-1-aarch64.pkg.tar.xz` | `eed0513b957ef265b334a7762bdfba4f50afd500` | 74,076 bytes, SHA-256 `19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95` | [44241902162](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44241902162) |
| `cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz` | `19dea1cca35659ad7ab307dfea09c30a77362640` | 5,516 bytes, SHA-256 `6dee81130f3ba3e570791cf079d2152893461ec27fa6e2e34a3d614986f9a949` | [44243507361](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/44243507361) |

The md4c run verified the exact 349-package builder inventory and 257 detached
input signatures. Both builds passed 652 CommonMark cases, 65 regression cases,
and the staged command-line, C API, pkg-config, CMake and SONAME checks. The
corrected finisher verifies each direct dynamic dependency, including the
AArch64 glibc loader, and checks segment alignment. Both image and container
inventories were empty on two successive checks of the dedicated daemon.
Root rehashed all 930 exported evidence files and replayed the finisher against
the two original packages.

The Fish run verified the exact 341-package builder inventory and 249 detached
input signatures. Both builds passed the `caa_mcd` regression check with a
conflicting `CDPATH` directory. The exporter retained both exact raw logs,
named for the build host architecture. The package remains architecture
independent. Root rehashed all 878 exported evidence files.

The earlier md4c run exposed an ELF dependency check and a retained Docker
image ancestry. The earlier Fish run held on a check log filename mismatch.
Both earlier workflow results remain recorded with their original verdicts.

The project signed these two exact development packages with separate,
disposable TEST keys for offline Qt staging and the Fish guest rehearsal.
Production signing, Apple hardware acceptance, and performance measurement
remain open. The md4c package is a project source reference. Official ALARM
binary recovery remains open.

## Signed Fish upgrade and rollback

The disposable AArch64 QEMU guest used 16,384-byte pages and started with the
exact 583-package overlay. Pacman upgraded only `cachy-asahi-fish-config` from
0.1.0-1 to 0.1.0-2, then restored the original signed 0.1.0-1 archive. Each
phase matched its full 583-package inventory.

The ordinary user started a real interactive Fish shell in all three phases
with the same 294-byte config produced by Setup8. The original and restored
versions selected the conflicting `CDPATH` directory. The new version selected
the directory it had just created. The guest's normalized ALPM records matched
after rollback, with only the selected package install date normalized.

Root independently read back the original result disk and its 22 evidence
files. The VM shut down normally. The scope and both containers were absent on
two checks. The independent receipt has SHA-256
`6577eec735ad6e216f367e66c0140739156f320950a8a1cd7c03bf9f87add62c`.
[Fish upgrade runner](https://github.com/Gabriel-Kahen/cachy-asahi/pull/529)
