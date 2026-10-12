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

## Frozen development-only integration mode

The original four native build pairs passed in coordinator-reviewed run
`38189520114`, source commit `ebd5812640b0b69f5c09a47752b739e37e338754`.
The integration controller and adapters described here are implemented and locally
boundary-tested; actual native integration execution remains **NOT RUN**.
This section replaces the earlier proposed common entry/guard interface.

`native_arm.py integration` authenticates the unchanged signed ALARM inputs,
checks the reviewed original recipe lock and full integration source freeze, and
regenerates/hash-compares every fixture input before building. It requires the
accepted checkout to match `GITHUB_SHA`. It builds all four originals twice and
all four changed DEVELOPMENT fixtures twice, with strict archive-byte comparison.
No current-mirror fallback, host package installation, production signing key,
paid runner, cache or artifact service is added.

Freeze the final sources and generated fixture bytes before committing/dispatching:

```sh
python3 -B scripts/ci/integration.py --freeze \
  --recipes-sha256 20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63 \
  --recipe-source-commit ebd5812640b0b69f5c09a47752b739e37e338754 \
  --source-date-epoch 1791748800 \
  --output scripts/ci/integration.lock.json
```

The output must be new. The coordinator reviews the resulting SHA-256 and alone
commits, pushes and dispatches `mode=integration`, supplying `inputs_sha256`,
`recipes_sha256` and `integration_sha256`. CI source freeze includes every regular
file under scripts/tests/packages/examples, plus LICENSE/AGENTS/README and this
workflow; it excludes bytecode, its own lock, and independently developing
`scripts/virtual`, `scripts/client`, `scripts/experiments`, `scripts/port` and
`packages/tools` follow-up batches. Neither excluded batch
is invoked or claimed tested by this integration mode. Source modes and hashes,
fixture modes/hashes, original recipe commit and deterministic build epoch are
bound; changes require a fresh review/freeze.

Each stage has its owner's existing interface and guard:

| Stage | Container/input boundary | Evidence scope |
| --- | --- | --- |
| TEST signer | Fresh non-root ARM, read-only root, cap0/NNP/no network; expiring TEST private key only in tmpfs | Verified public fingerprint, certificate/signature hashes and exact eight archive bindings |
| Lifecycle/handoff | Fresh writable root, six explicit file/account/child-cleanup capabilities (including KILL); read-only `/inputs` and `/runner`, actual writable overlay `/tmp` | Real install/changed upgrade/remove/recovery; independent complete original payload/inventory check and visible-filesystem cleanup before exact stopped-container commit |
| Repository | Fresh read-only root; pacman target copied to 6GiB `/scratch` tmpfs, bounded TEST key tmpfs | Signed/revoked/rotated/tampered generic repository transactions; actual copied-root bytes/capacity measured before copy |
| Onboarding | Fresh non-root read-only derived installed image; complete package lock plus original baseline archive/payload manifest | Installed CLI, editor/PTY/C/shell journey and complete helper/release test counts |
| Desktop | Separate non-root read-only derived image; original desktop archive and unchanged base lock | Installed payload plus pinned parser/subset checks; compositor remains BLOCKED without DRM |
| Source suites | Fresh non-root read-only base image; full reviewed `/source` mount, private owned tmpfs HOME | Every requested source suite/package synchronization check; zero discoveries or skips cannot PASS |

Containers run serially with unique names and bounded resources. Only the exact
lifecycle container can be committed, after exit zero plus a fully bound READY
receipt, original baseline hashes/ownership, exact base-plus-four inventory and
all cleanup checks. That image stays local to the ephemeral runner: Docker commit
retains parent layers, so deleting a bootstrap-generated private keyring from the
visible filesystem does **not** erase lower-layer bytes or create a distributable
secret-free image. No image is pushed/exported. Flattened release images require
a separate audited process.

Outputs stay separate from original native-build evidence. The controller selects
public JSON/log/txt receipts, prunes sensitive state before reading/hashing it,
and applies `integration_export.py`; oversize, symlink, credential/private-key
content or sensitive paths reject export with public diagnostics. Repository
TEST-key command argv are represented by identity hashes/status rather than raw
keygen options. Nontext repository test materials are explicitly listed as
excluded without reading/hashing their content. The only binary package export
is an explicit rehashed set of the four reviewed MIT config-only fixture archives.
Successful TEST signer and repository artifacts also use separate explicit
receipt-bound public exporters: public certificates, detached signatures, approved
repository databases/packages and regular alias mappings. The signer exports exactly
one verified public certificate plus eight signatures; repository negative cases
retain their intentionally bad/revoked material for offline review. No GPG homes
or standalone sensitive revocation files enter these exports. Each binary bundle
has a 12MiB payload bound and all bytes are rehashed before/after copying.
Final controller summaries also pass the text exporter; failed stage/export
statuses are recorded separately from component statuses. Workflow publication
continues through all stage bundles even if one bundle fails. Private key homes,
source rootfs/dependencies, copied pacman roots and user homes never enter public
integration bundles.

Generic native ARM/4K software checks cannot satisfy physical M2, Asahi boot,
16K-page, accelerated graphics/audio, suspend/power, GUI usability, stable trust,
production publication or performance gates. All remain independently unrun.


### Corrective source review and freeze status

Independent review reproduced deterministic child identity-forwarding and public
repository log-naming failures, plus runtime-mount, cleanup, cancellation,
underlying-tmp, fixture-diagnostic and committed-image configuration gaps. These
have source fixes and focused mocked regressions. Handoff now runs without a
`/tmp` mount, cleans the actual writable image view, and requires
`image-tmp-view-empty` before READY. A fresh read-only container independently
checks the committed image's inventory, complete original payloads/ownership,
empty underlying `/tmp` and absence of visible private state before onboarding.

Lifecycle alone receives CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID/KILL; repository
and derived read-side verification retain the five file/account capabilities.
All relevant capability sets and no-new-privileges are checked by stage guards.
The handoff's nonce/image are passed through `/usr/bin/env` process argv rather
than Docker Config.Env. Commit restores the accepted base USER/ENTRYPOINT/CMD/
WORKDIR and verifies normalized executable image configuration and exact Env;
test identity cannot persist in the installed image metadata.

Cleanup requires bounded named removal and daemon-confirmed absence. Cancellation
stops tracked process groups, removes owned containers and finalizes sanitized
failure records; cleanup failure cannot retain PASS. Original error category and
separate cleanup outcomes remain visible. Already-created fixture provenance,
validation and detailed build logs are retained after failure. Six known public
repository verification/revocation logs are projected only when their exact
producer receipt binds the filename, label and content hash; general GPG/private
path denial remains intact.

The earlier lock SHA `641be67646a40f396f6aaff7c24dcfa4af2c91d4734c99a30702df6e472d54c8`
is **invalidated**, following corrective sources and the updated complete-port
roadmap. It has not been overwritten or used for dispatch. The coordinator must
review and regenerate the final source/fixture lock after confirming source
stability. Actual native integration remains NOT RUN. This initial four-package
integration foundation does not satisfy R1–R5/M5–M9/A12–A15; broader maintained
package/tool/platform/installation and physical acceptance tracks remain required.
