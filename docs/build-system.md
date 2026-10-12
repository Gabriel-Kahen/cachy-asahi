# Clean ARM build system

Implementation status: portable tooling implemented and locally tested on x86_64. Native ARM package builds, OCI provisioning execution, clean ARM second builds, installation, and M2 hardware validation remain **NOT RUN**. `arch=any` package assembly on this development host is separate evidence and does not satisfy M1. No preselected builder image or repository snapshot is invented here.

## Contract

Use Python 3.11+, an existing Docker engine, and `zstd` for `.pkg.tar.zst` inspection. `vercmp` is needed only for versioned dependency checks. No tool installs these on the host. Run the build runner on the Docker daemon host: bind mounts refer to daemon-local paths, so remote Docker contexts cannot transparently use local evidence paths. Use a dedicated, audited builder image; do not repurpose application images.

The builder must be Linux/arm64, addressed by an immutable `repository@sha256:<64 hex>` digest or local `sha256:<64 hex>` image ID, and already present locally. It must contain `makepkg`, `base-devel`, `diffutils`, all declared build/check/runtime dependencies, trusted ALARM package-signing keys, and a non-root account matching the invoking UID/GID. The chosen Asahi ALARM repository snapshot, keyring provenance, dependency artifacts/signatures and package versions must be retained. An ARM userspace builder is not an Asahi installation image; no generic PC kernel/boot integration is installed onto a target by this workflow.

`build.py` verifies the image architecture and Docker server architecture. `--mode native` requires the observed Docker server to report arm64/aarch64; `--mode emulated` requires another server architecture. The container additionally checks `uname -m`. Record the actual emulator/kernel/CPU provenance externally when using emulation: these observations alone are not independent hardware attestation. Cross-compilation is not implemented and cannot masquerade as native evidence. Page size is captured; an ordinary ARM builder with 4K pages does not prove 16K-page execution.

The runner creates one fresh named container per attempt, copies a digest-reviewed recipe snapshot, mounts it read-only, gives the recipe only a new artifact directory for persistent writes, drops capabilities, uses a read-only root, forbids privilege escalation and limits CPU/memory/processes. It exposes no Docker socket, signing keys, host `/etc`, devices, or package database. Temporary build files live in a 4 GiB tmpfs. Timeout cleanup removes only its unique container. Existing Docker jobs are untouched. Recipe execution still requires independent review: an OCI container is an isolation boundary, not a proof that arbitrary code is safe. Network is disabled by default; `--network bridge` explicitly permits source acquisition and must be recorded/reviewed for remote sources.

## Offline builder provisioning

Obtain and verify a pinned ARM base image and a complete signed dependency cache from the coordinator's chosen base snapshot outside this tool. Include `base-devel`, `diffutils`, and the recipe dependencies, plus their full transitive closure. Supply a reviewed JSON map of **every package and detached signature filename to its SHA-256**. Provisioning accepts original `.pkg.tar.zst`, `.pkg.tar.xz` and `.pkg.tar.gz` archives with their same-basename `.sig` files; unsupported extensions, missing/mismatched signature pairs and unsafe filenames fail. It copies exact signed bytes and verifies their reviewed checksums, without recompressing an archive. A mixed-format cache is supported; only its explicit archive paths, never signature files or unmatched globs, are passed to pacman. Retain the image/rootfs source provenance and signing-key fingerprints.

```sh
python3 scripts/build/provision.py \
  --base-image 'registry.example/arm-base@sha256:<actual-64-hex-digest>' \
  --cache /absolute/verified-package-cache \
  --checksums /absolute/cache-checksums.json \
  --output /absolute/new-builder-context
```

Default execution only writes a Dockerfile, strict offline pacman signature configuration, copied input cache, and `provision.json`. No Docker command runs. Add `--execute` to build the image in Docker with networking disabled. `pacman -U` executes **inside that image only**, with `LocalFileSigLevel = Required`; no key is imported and no package is installed on the host. Missing dependency closure or untrusted/expired signatures fails provisioning and remains a blocker. A trusted base image must provide the keyring and non-root account; this tool does not bootstrap trust from an unauthenticated latest tarball. Output includes the resulting immutable image ID, log, and sorted `packages.lock`. The original base and every dependency/signature hash are recorded. Root provisioning can execute signed dependency package hooks inside the image, so review the cache before execution.

This provisioning path is implemented but not exercised on the present x86_64 host. Automatic binfmt/QEMU registration is intentionally absent because it mutates host execution state. An already configured emulator may be used with an honest emulated label; it cannot close the native ARM gate.

## Recipe inspection and review

```sh
python3 scripts/checks/package_checks.py recipes --require-recipes > /absolute/recipe-review.json
```

Discovery is recursive beneath `packages/desktop`, `packages/shells`, and `packages/settings`. The scanner reads `.SRCINFO` as data when available; otherwise it accepts only simple constant top-level assignments. It never runs `makepkg --printsrcinfo`, sources Bash, imports recipe code, or downloads sources. Dynamic metadata fails with a request for reviewed `.SRCINFO`. Split packages are unsupported and rejected. SHA-256 inputs include all regular files below each recipe, including notices and supplementary evidence; any change requires a new review snapshot. Symlink inputs are forbidden.

Review the recipe body, notices/licenses, source ownership, dependency snapshot, and installation behavior independently, then store that recipe's `input_sha256` object as a standalone JSON file. A metadata file can be stale; the isolated builder regenerates it and checks effective fields in both directions, including aarch64 dependencies/sources, hook declarations, epoch/version/release, provides/conflicts/replaces and source/checksum order. Existing `.SRCINFO` additionally receives an order-exact `diff` against generated output after removing only full-line comments and blank lines. Values, indentation, inline comment text and field order are not normalized; missing inputs fail the comparison. Complete effective-field binding remains enforced in both directions. Static-pass is a metadata/checksum result, not a license grant or a full package approval.

## Execute an attempt

```sh
python3 scripts/build/build.py packages/shells/cachy-asahi-fish-config \
  --image 'sha256:<actual-preprovisioned-image-ID>' \
  --mode native --source-date-epoch 1791748800 \
  --expected-packages /absolute/approved-packages.lock \
  --reviewed-inputs /absolute/reviewed-fish-inputs.json \
  --output /absolute/evidence/fish-attempt-1
```

Examples contain placeholders, not claims of existing image availability. Use a documented source epoch from the accepted recipe/source snapshot; both attempts must use the same value. The package inventory is checked before recipe execution and again after it. The script runs source verification and `makepkg --cleanbuild --clean --force --log --noconfirm`, without dependency-install or package-install switches. Missing dependencies stop the build. Source checksums are never skipped. A successful package must match reviewed name/base, exact epoch/version/release, architecture, license and runtime/build/check/optional dependencies, provides/conflicts/replaces/backup metadata; `.BUILDINFO` must identify the reviewed PKGBUILD digest. Unexpected installation hooks cannot enter a successful automated build.

An existing output directory is rejected to prevent stale artifacts being reused. Evidence includes `inputs/`, `artifacts/`, generated `.SRCINFO`, package inventory, makepkg/pacman config and checksums, runtime page size/tool versions, build log, validation JSON, unique clean-container ID, image identity, exact command, timestamps, exit result and artifact/evidence SHA-256. Failed invocations after snapshot creation retain a failed provenance record and logs. Preflight failures before directory creation are printed and produce no successful record.

## Dependency closure and rebuilds

Provide an explicit reviewed inventory JSON array containing `{name, version, arch, provides}` for each package available from the selected snapshot, then run:

```sh
python3 scripts/checks/dependencies.py /absolute/arm-snapshot-inventory.json
```

This checks declared build/runtime/check dependencies, versioned providers, declared conflicts/replacements, and overlay build ordering/cycles. It does not infer hidden runtime dependencies, download packages or prove the proposed transaction is installable. Use the separate release worker's complete target-transaction checks for base file ownership and coordinated desktop versions.

Repeat the build command into a different new output directory; the runner launches a new named container. Then:

```sh
python3 scripts/build/compare.py /absolute/evidence/fish-attempt-1 /absolute/evidence/fish-attempt-2
python3 scripts/build/compare.py /absolute/evidence/fish-attempt-1 /absolute/evidence/fish-attempt-2 --require-bytes
```

Comparison verifies recorded evidence and recipe/artifact hashes, rejects copied records reusing the same clean-container ID, requires the same image, mode, epoch, reviewed inputs, metadata, dependency-lock hash and entry-script hash, and re-inspects archives. Installed contents include file data, modes, owners, links, sizes and mtimes. Only known pacman root metadata files are separated from the installed tree; hidden payload files are not ignored. `.PKGINFO`, `.BUILDINFO`, and whole-archive byte equality are reported explicitly. Content identity cannot be reported as byte identity. Unique container IDs are local records, not cryptographic proof of independent machines or unforgeable execution evidence.

## Acceptance and release interface

`built-package-static-pass` means one isolated build plus automatic archive checks passed. It says nothing about installation, trusted signatures, resolved upstream licensing, rendering, speakers, recovery, or M2 behavior. M1 still requires all coordinator-selected recipes, second clean ARM build evidence, independent manual review, and documented dependency/base inputs. Every failed/deferred package stays in the coordinator's inventory. No script marks a milestone complete.

The release worker owns `scripts/release/`. Its per-artifact provenance and native-build/dependency-lock evidence schema is stricter than this runner's local multi-file build record (it also requires the accepted project commit, snapshot ID, retained dependency archives and hardware gates). No automatic adapter invents these fields. Preserve this evidence, then prepare release records against its schema after the coordinator freezes the committed sources and snapshot. A content-only comparison is insufficient for the current stable release byte-identity policy.

Primary specifications consulted October 11, 2026: [makepkg(8)](https://man.archlinux.org/man/makepkg.8), [.SRCINFO](https://wiki.archlinux.org/title/.SRCINFO), [BUILDINFO(5)](https://man.archlinux.org/man/BUILDINFO.5.en), [Docker container execution](https://docs.docker.com/engine/containers/run/), and [ALARM generic AArch64 userspace](https://archlinuxarm.org/platforms/armv8/generic). Generic installation documentation is background for a builder userspace, not an approved M2 base installation path.
