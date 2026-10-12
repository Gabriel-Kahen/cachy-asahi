# Native ARM CI candidate

Coordinator execution results are tracked in [the native execution record](validation/native-arm.md). The source-only handoff below predates dispatch; its NOT RUN labels describe that handoff, not the later coordinator results. The current recipe lock after the native metadata correction is `20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63`.

Source-audited and implemented October 11, 2026. **Native runner dispatch, image bootstrap, package builds, byte comparison, target installation and M2 validation: NOT RUN.** The local input audit ran on x86_64; it authenticated data without executing ARM programs or installing packages.

## Runner and cost

Read-only GitHub API inspection confirmed `Gabriel-Kahen/cachy-asahi` is public, its default branch is `main`, it is not archived, and Actions is enabled. Its local origin is `git@github.com:Gabriel-Kahen/cachy-asahi.git`; the canonical public URL is [the project repository](https://github.com/Gabriel-Kahen/cachy-asahi).

GitHub documents `ubuntu-24.04-arm` as a standard ARM64 Linux VM with 4 CPUs, 16 GB RAM and 14 GB storage. Standard runner compute is free for public repositories; larger runners are paid. The workflow uses only that fixed standard label and refuses a private repository. [Runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

No workflow was pushed, published, dispatched, or paid service enabled by this worker. There are no schedule, push, pull-request, paid-runner, release, signing, cache-upload or artifact-upload jobs. Small evidence bundles, including the original overlay artifacts, are encoded in workflow logs; GitHub documents logs as excluded from artifact storage allowance. Input rootfs/dependency binaries are excluded from those bundles. Coordinator downloads the logs promptly and retains the verified private inputs separately.

The only executable action is `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, verified through the upstream `v7.0.1` Git ref. Checkout is MIT-licensed and does not persist credentials. Python, GPG, Docker, `lscpu` and package-inspection `zstd` are expected preinstalled; no host package installation is attempted. Their observed versions/image metadata are recorded. GitHub's hosted VM image is maintained by GitHub and can change; it is not represented as an immutable VM image.

## Authenticated userspace and frozen transaction

The base is the official dated August release, not a moving latest URL or third-party OCI container:

| Input | SHA-256 |
| --- | --- |
| `ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz`, 829,367,415 bytes | `42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319` |
| Its detached signature, 566 bytes | `0157d8cd6261c85205931c766b754d6d56112b28800666fb64add1de192ebe11` |
| `archlinuxarm.gpg`, 3,098 bytes | `6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f` |
| `archlinuxarm-trusted`, 44 bytes | `f2a7250f2a2b77542f82f4219b2bae7895f27b3dcfdf350b497e2be306af776d` |
| Empty `archlinuxarm-revoked` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Rootfs: [dated HTTPS archive](https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz), [signature](https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz.sig). The same mirror hostname is listed in the authenticated rootfs's own `/etc/pacman.d/mirrorlist`; HTTPS certificate validation was left enabled. The `os.archlinuxarm.org` HTTPS hostname failed certificate-name validation locally, so it is not used as an insecure fallback.

Keys come from [ALARM PKGBUILDs commit `29432c01130efc4ad297dfe8f487d5b79cbaf8e9`](https://github.com/archlinuxarm/PKGBUILDs/tree/29432c01130efc4ad297dfe8f487d5b79cbaf8e9/core/archlinuxarm-keyring). This package recipe declares GPL. The published full primary fingerprint is `68B3537F39A313B3E574D06777193F152BDBE6A6`; the fetched key matches it. The ownership anchor is pinned upstream HTTPS key material plus the independently published official full fingerprint. GPG exit zero and the complete matching `VALIDSIG` record authenticate each payload; an imported UID or a SHA-256 alone does not establish ownership. [Official release signing](https://archlinuxarm.org/about/downloads), [official key fingerprint and signing model](https://archlinuxarm.org/about/package-signing).

`scripts/ci/inputs.lock.json` freezes the 165-package signed base inventory and a resolved 248-package upgrade/dependency transaction, including individual package and detached-signature SHA-256/size pins, exact versions/architectures, signed-metadata dependency/provide/conflict/replacement fields, license identifiers and source URLs. The dependency downloads total 702,096,424 bytes; signatures add a small amount. The expected resulting builder inventory is 341 packages. This includes base-devel, diffutils and all four original recipes' build/runtime dependencies; Hyprland is `0.56.2-4`. Generic kernel/firmware files remain inert within the builder only. This is not an Asahi platform transaction or installation image.

The transaction was resolved using installed native-host pacman in **print-only mode**, isolated temporary root/database/cache paths, the signed rootfs's local metadata and captured core/extra/alarm/aur databases:

```sh
pacman --root /tmp/cachy-asahi-native-arm-audit/resolver/root \
  --dbpath /tmp/cachy-asahi-native-arm-audit/resolver/db \
  --cachedir /tmp/cachy-asahi-native-arm-audit/resolver/cache \
  --config /tmp/cachy-asahi-native-arm-audit/resolver/pacman.conf \
  -Sup --noconfirm --print-format '%r %n %v %f %l' \
  base-devel diffutils fish zsh hyprland alacritty wofi swaylock \
  wireplumber brightnessctl lua python
```

No `-y`, installer or source/recipe execution occurred during resolution. The local host package database was untouched. `freeze.py` consumes this already captured transaction and databases as data; it neither resolves nor downloads anything. Database hashes and the exact transaction lines are retained in the lock. ALARM explicitly does **not** sign repository databases. Their hashes anchor the captured metadata; signatures on all selected package payloads authenticate their contents. One unselected `extra/findnewest-0.3-4` database entry contained zeroed description bytes; it is recorded in the lock and was not silently treated as a selected package. An official historical full dependency archive was not established. The captured transaction is a project candidate snapshot, not an upstream assertion of historical consistency.

The audit actually downloaded and authenticated the rootfs and all 248 package/signature pairs. It also matched package `.PKGINFO` fields to the frozen database and the signed rootfs inventory to the lock. It records package `.BUILDINFO` where supplied, all installed paths and all installation/ALPM hooks. The GPG receipts and output hashes are in `scripts/ci/source-audit.json`; full local audit output and original input bytes are in the private local locations it records. All native execution gates remain NOT RUN.

## Bootstrap and build contract

`native_arm.py build` requires independently reviewed full hashes for both input and four-recipe locks. Any recipe drift, missing package, unexpected installed package inventory, bad/expired/revoked signature, wrong signer, missing content, changed size/hash, insecure redirect or host/daemon architecture mismatch stops the job. Cache bytes are rechecked after copying into the Docker context. There is no fallback to latest, no recompression of signed packages, no QEMU/binfmt setup, and no implicit paid resource choice.

The proposed bootstrap is deliberately narrow: `FROM scratch`, extract the authenticated rootfs, copy the independently verified `.pkg.tar.xz` inputs and pinned keyring, initialize trust and install the complete offline transaction inside the disposable native image with `--network=none`. All package scriptlets are disabled with pacman's documented `--noscriptlet`; all rootfs/transaction ALPM hook names are masked by `/dev/null` overrides in a higher-priority `/builder-disabled-hooks` directory. Explicit `ldconfig` runs inside the image. Service activation, binfmt registration, sysctl, module-loading, tmpfiles/sysusers generation, boot image updates and target installation are not exercised. The existing signed rootfs `alarm` account is assigned the invoking runner UID/GID for non-root builds. These changes are confined to the builder; no host signing identity is created or imported. Pacman generates only a disposable internal trust key. [Scriptlet option](https://man.archlinux.org/man/pacman.8.en), [documented hook masking](https://man.archlinux.org/man/alpm-hooks.5.en), [HookDir priority](https://man.archlinux.org/man/pacman.conf.5.en).

The shared `scripts/build/provision.py` now accepts original signed `.pkg.tar.zst`/`.pkg.tar.xz`/`.pkg.tar.gz` archives following the build owner's narrow interface fix. It still requires a preexisting registry digest; this signed dated-rootfs route has no preexisting OCI image. **No packages are renamed or signatures bypassed.** This worker supplies the above reviewed scratch bootstrap as an explicit rootfs alternative, then consumes the existing immutable-image build/compare contracts. Coordinator/build owner may later consolidate scratch-rootfs provisioning into the shared tool; no shared provisioner code was changed by this worker.

After bootstrap, the script records the actual immutable Docker image ID and exact `pacman -Q` lock, checks the expected 341-package inventory, then uses the existing `scripts/build/build.py --mode native` contract for each recipe in two fresh read-only, non-root, network-disabled containers. `compare.py --require-bytes` must pass for every recipe. No package is skipped; failures remain failures. Recipe/artifact metadata binding and source checksum verification stay enabled. The daemon must use the default local UNIX socket; remote contexts are rejected.

The probe captures Linux kernel/CPU, host and Docker architecture, page size, UID/GID, Docker version/endpoint, runner image metadata, project commit/run ID and bootstrap script hash. The inner build runner records its own `uname` and page size. These are observed execution evidence backed by GitHub's documented ARM VM route, not independent hardware attestation. A usual 4K-page ARM runner does not establish M2/16K-page compatibility, platform performance or hardware behavior.

## Coordinator integration and dispatch

1. Review this trust/bootstrap candidate and the receipt/lock files. Retain `/tmp/cachy-asahi-native-arm-audit` and the receipt's full output directory in a durable **private** input store before the temporary cache is lost. The workflow does not provide durable input retention. Each source URL must continue to yield the exact pinned bytes; unavailable moving-repository filenames fail closed. Mirror/provider changes require a newly reviewed lock with unchanged content hashes. Do not publish rootfs/dependency binaries without satisfying their upstream source/license obligations.
2. Recheck the integrated shared build interfaces. The build owner has fixed original `.xz` support and the benign desktop `.SRCINFO` comment/exact-diff incompatibility: only blank/full-comment lines are normalized, while field/value/order and effective metadata binding remain strict. This worker source-verified both fixes; no desktop validation is skipped. The setup package additionally requires its canonical/source/license sync checker before recipe freezing and dispatch.
3. Review all four recipes and freeze their final bytes **after** the setup owner's canonical fixes and refreshed packaged copy are complete. The corrected package-worker handoff is complete; `scripts/ci/recipes.lock.json` now freezes all four current recipes as a candidate for independent coordinator review. The pure read-only synchronization guard runs before freezing and building, binding canonical/package helper and both licenses to the packaged provenance. Any owner changes require regeneration and another review. Run appropriate existing shared-tool checks, plus `python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v`.
4. Integrate only the owned CI files, input/recipe locks and reports, commit/push through the coordinator, then dispatch the default probe first. Record the actual run URL/results. Dispatch audit or build with the reviewed hashes after the previous checks are settled.

Current input lock and remaining recipe freeze:

```text
inputs.lock.json   7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41
recipes.lock.json  8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0
```

Local audit and recipe-freeze commands:

```sh
python3 scripts/ci/native_arm.py audit \
  --inputs-sha256 7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41 \
  --cache /tmp/cachy-asahi-native-arm-audit --output /absolute/new-audit-output
python3 scripts/ci/native_arm.py freeze-recipes \
  --cache /tmp/cachy-asahi-native-arm-audit --output scripts/ci/recipes.lock.json
```

Only the coordinator runs these GitHub dispatch commands after integration:

```sh
gh workflow run native-arm-build.yml --ref main -f mode=probe
gh workflow run native-arm-build.yml --ref main -f mode=build \
  -f inputs_sha256=7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41 \
  -f recipes_sha256=8906c36f5cbcdb0e1e70798e6db23be1d30f45385d57af0094a1cd509c7a89d0
```

The recorded recipe digest is a candidate requiring coordinator review. Regenerate/review the lock if an owner changes any reviewed input. The workflow is manual only, serialized, bounded to 50 minutes, and exposes no production signing credentials or publication permissions. Probe success establishes runner availability/observations; source-audit success establishes authentication/metadata receipts; only actual complete build/comparison evidence can advance the native build gate. M1 and all release/hardware gates still require coordinator review and their additional evidence.

Evidence is framed by `CACHY_ASAHI_EVIDENCE_BEGIN <name> sha256=<digest> bytes=<size>` and the matching `...END` marker. Download logs with `gh run view <run-id> --log`, remove GitHub's log prefixes from lines between each marker, base64-decode into a `.tar.gz`, check the marker's SHA-256 before extracting, and inspect `runner.json`, `result.json`, bootstrap/build provenance and comparisons. Expanded bundles are capped at 16 MiB and compressed bundles at 8 MiB. Input caches, Docker contexts and GPG homes are excluded. Preserve receipts/input locks with the original private blobs; logs and input URLs alone are not a long-term retention guarantee.
