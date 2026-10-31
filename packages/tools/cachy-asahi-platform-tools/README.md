# cachy-asahi-platform-tools 0.1.0-1

Original MIT candidate for offline coordinated Apple-platform planning and
strict private metadata preparation. The sixteen runtime helpers retain their
exact source bytes and `scripts/...` layout from the Git revision and hashes in
`source-provenance.json`. The package adds one versioned launcher/runtime map;
existing checkout commands and frozen source profiles remain unchanged.

## Use

Create an owned mode-0700 directory for new mode-0600 reports. Supply explicit
absolute data paths and independently checked SHA256 values. Reports never
overwrite existing files. Inputs remain at their bound absolute paths; moving
the installation prefix does not relocate or rewrite evidence inputs.

```sh
mkdir -m700 /absolute/private-reports
cachy-asahi-platform-tools --help
cachy-asahi-platform-tools check
cachy-asahi-platform-tools plan --contract /absolute/transition.json \
  --contract-sha256 HEX --output /absolute/private-reports/plan.json
cachy-asahi-platform-tools check --contract /absolute/transition.json \
  --contract-sha256 HEX --report /absolute/private-reports/plan.json \
  --report-sha256 HEX --output /absolute/private-reports/check.json
cachy-asahi-platform-tools sources --output /absolute/private-reports/runtime.json
cachy-asahi-platform-tools prepare --contract /absolute/strict.json \
  --contract-sha256 HEX --output /absolute/private-reports/prepare.json
```

`plan` returns 0 for a complete offline data plan, 2 for retained data blockers,
1 for refused/malformed inputs. `check` verifies the entire runtime, performs
real libalpm/vercmp controls, and optionally recomputes and exactly compares a
retained plan. It records preparation prerequisites separately; READY means
prerequisites available, with transaction and authentication still NOT RUN.
`sources` emits the exact `private-platform-prepare-source-closure` document
required by the strict preparation contract. Bind that new file by absolute
path, size and SHA256 in `strict.json`; no source proof is bypassed.

`prepare` preserves the existing strict contract and proof requirements in
`private-platform-transition-prepare.md`. It freshly verifies all package
signatures with pinned supplied public certificates, recomputes the plan and
checks every provider/archive/provenance/source binding before ALPM. It uses a
fresh private root/database with NOLOCK|NOSCRIPTLET|NOHOOKS, denies questions,
requires an exact final inventory and never calls commit/download. Results
retain all input references and hashes. Return 0 means exact private metadata
preparation; 2 is a retained ALPM refusal; 1 is an input/authentication refusal.

The import closure includes recovery input, capture, build and lifecycle
helpers. Their fetch/build/install commands are not exposed by this launcher.
Only offline plan, verification, source proof and strict private prepare are
available. Archive inspection currently accepts XZ package archives.

## Dependencies, build, payload and removal

Runtime: Python >=3.12 with its standard ctypes/lzma/tarfile/resource modules;
Arch `pacman` supplies libalpm and `vercmp`; `gnupg` supplies `gpg`/`gpgv`; glibc
supplies the C runtime. Plan comparison needs real libalpm even when read-only.
The private transaction adapter deliberately permits only **libalpm16.0.1**;
an unreviewed ABI refuses rather than falling back. `--help` works without
loading these dependencies. No third-party source, certificate, package archive,
private key or installed package database is bundled. Build: `makepkg --nodeps`
in a disposable ordinary-user recipe copy with already installed dependencies.
No dependency installation occurs. `bubblewrap` is a check dependency for the
offline, checkout-hidden namespace controls. Standard makepkg dependencies
include bash/coreutils/bsdtar/gzip/zstd; `base-devel` supplies the normal build
environment. Native ARM/16K and installed ALPM lifecycle require separate work.

The package owns exactly the 23 files in the build-time `payload-map.json`: one
launcher, sixteen private Python sources, one runtime map, three documentation
files and two license notices. It installs no hooks, services, pacman config,
boot files, certificates or shared Python modules. The launcher derives its
private runtime from its real prefix, verifies source hashes before imports,
and uses a fresh bytecode namespace; subprocess helpers inherit it.

Removal deletes only package-owned files. Reports and supplied evidence live
outside the prefix and are retained. A file-level removal inverse is tested;
this does not establish a pacman install/remove lifecycle. Existing recovery,
platform boot/kernel/firmware/Mesa/audio/protection stack is preserved.

## Evidence limits

A synthetic complete plan can pass data checks while its fixture signatures
remain unauthenticated. The strict prepare command refuses such signatures.
Real private libalpm fixture controls establish metadata behavior only. No
complete real signed transition dataset is supplied with this candidate, so
authenticated end-to-end preparation remains NOT RUN. No native ARM build,
installation, 16K, physical M2, boot/recovery, performance or release acceptance
follows from source custody, host assembly or the test fixtures. Both M2 Air
sizes remain NOT RUN. Coordinator owns canonical adoption and manifest changes.
