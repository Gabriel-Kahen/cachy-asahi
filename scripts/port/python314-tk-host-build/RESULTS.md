# Observed host diagnostic — 2026-11-14

The unchanged Main432 Python 3.14.8-1.1 recipe completed ordinary
dependency-checked `makepkg --ignorearch --cleanbuild --nosign --noconfirm`
twice in fresh disposable x86_64 containers. The final run exercised the
controller's registration of every cleanup name before Docker creation.
Subsequent entry-point/failure-reporting changes do not change successful build
commands; entry-point refusals are covered by focused controls. Exact executed
helper identities remain in each private report. These observations establish
host software checks only.

Final retained output directory:
`/tmp/cachy-asahi-python314-tk-full-final-20261114`.
Nothing from the output directory is installed or committed into the source
tree. Root owns any later retention, integration and native admission.

| Retained file | Bytes | SHA-256 |
| --- | ---: | --- |
| `export/python-3.14.8-1.1-x86_64.pkg.tar.zst` | 17308438 | `8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e` |
| `report.json` | 11117 | `bb235951ce668e1fc5730fb20e7fdfe6cca5be5015e29111107025734258073b` |
| `archive-review.json` | 581 | `d0ec2fc203d7998c61fe2820d54325b8fc5cec1cd9d4cb6e0cb1dee17b8d4c0b` |
| `actual-controls.json` | 1021 | `7ad4836c7d711d359eb401b122cb625a76da744766f990719761b74364bfa959` |
| `export/makepkg.log` | 882198 | `6194cf7e2ee5e43448585c7742c7e9509352cbb77fcc75cd7fa60733b4a5ab5b` |
| `export/BUILDINFO` | 7464 | `97fcfb0133882db15eee81ecbe189e772f6569a31c9ba44d65b73028a77fecc8` |
| `export/packages.txt` | 3429 | `ca820feead2c9053f5f010969c4c53674ef4354ab2059470454234b135349492` |

Actual results:

- Source/recipe checksums and dependency checks passed; original recipe and
  source bytes remained unchanged. The source-authority check still labels
  historical binary correspondence UNBOUND.
- Configure/build checked 114 modules: 36 built-in, 77 shared, one not applicable
  on Linux x86_64, zero disabled, missing or failed imports.
- Complete candidate runtime passed before and after staging, including required
  `_tkinter`, compression/zstd, SSL, decimal, ctypes, SQLite, GDBM and timezone.
- All ten selected upstream suites passed: 2,719 tests run, 120 skipped. This
  is the recipe's finite suite, not the entire CPython regression suite.
- `package()` layout check passed. Headless `tkinter.Tcl()` returned `42` and
  Tcl patchlevel `8.6.16`; compiled Tcl/Tk versions were `8.6`. No Tk commands
  were loaded, window created or display/device accessed.
- Bounded archive inspection hashed 3,051 ordinary files (75,320,276 bytes),
  3,191 payload nodes total. Required Tk extension, relative frontends, PEP 668
  marker and exact source notices/provenance passed.
- 30 focused controls and seven controls against the actual retained archive
  passed. Tampered/truncated/trailing input and missing/changed/unbound payload
  DATA were refused.
- Inspected build restrictions matched network-none, two CPUs, 4 GiB memory/swap,
  256 PIDs, read-only root, unprivileged user, init and dropped capabilities.
  All five cleanup actions returned zero. No owned actor, volume or derived
  image remains. The original cached official base was preserved.

The earlier successful full run remains separately at
`/tmp/cachy-asahi-python314-tk-full-second-20261114`; its archive has the same
observed bytes/hash. This finite host observation does not qualify native
reproducibility or any original ALARM build.

Real warnings remain in both successful logs: ten dynamic-loader warnings about
`libfakeroot.so` during upstream bytecode installation, and makepkg references
to its private `$srcdir` in six installed sysconfig/Makefile/bytecode paths.
Neither warning was suppressed or treated as a reason to edit the frozen
recipe. The archive reader confirmed root-owned metadata and package layout;
relocation/extension/embedding consumers remain separate checks.

The first attempt used rootless bridge networking and timed out on HTTPS after
90 seconds before any package installation. Its failed record remains at
`/tmp/cachy-asahi-python314-tk-full-first-20261114`; no native/source success is
inferred from that attempt. Provisioning-only host networking resolved the
observed acquisition issue. The installation worker's older missing-Tk
`host-core-probe` HOLD outputs remain separately unchanged.

Native ARM builds, original compiler/source correspondence, complete source and
legal/policy acceptance, GUI behavior and M2/hardware validation remain open.
