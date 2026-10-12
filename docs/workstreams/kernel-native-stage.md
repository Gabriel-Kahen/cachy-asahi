# Separate native kernel trial

This stage is implemented for review; **native ARM kernel compilation, native
ARM fixture execution, kernel execution, installation, M2 validation and
performance measurements have not run**. Its dependency authentication and
source/application audits ran locally. It does not change the accepted platform
tuple, original builder snapshot, boot configuration or shared release manifests.
The coordinator owns Git integration, workflow integration and dispatch.

## Frozen inputs

[dependencies.json](../../scripts/port/kernel-native-stage/dependencies.json)
is a separate, authenticated extension of the original 341-package builder.
Its SHA256 is
`cf4d6eaa80ab15f1b1359d161b7b07e187f37df6071e5f628e235cb9689a93d6`.
The unchanged base inventory SHA256 is
`89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f`;
base inputs are
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
The exact 356-package extended inventory hashes to
`454cd8783a72751f5a069e9286fa11b79267cc2c1dd9c269693b6859aa234ddd`.
All 341 original name/version pairs must remain identical.

The fifteen additions are bc 1.08.2-1, clang/compiler-rt/lld/llvm 23.1.1-1,
dtc 1:1.8.1-1, libgit2 1:1.9.7-1, libxslt 1.1.45-2, libyaml 0.2.5-3,
llhttp 9.3.1-1, pahole 1:1.32-1, rust/rust-src 1:1.99.0-1,
rust-bindgen 0.73.2-1 and xmlto 0.0.29-1. The packet records every exact
archive/signature URL, hash, size, dependency, declared license and source URL.
Fifteen detached signatures authenticated the archives against primary signer
`68B3537F39A313B3E574D06777193F152BDBE6A6`. Static archive inspection found
186 ELF64 AArch64 headers, 17 license notice files and no hooks/scriptlets.
This establishes authenticated inputs and declarations, not complete
corresponding-source license closure or successful ARM execution.

The [held candidate](../../scripts/port/kernel-candidates/candidate.json) pins
Asahi revision `94fb23346d522edf53722357c426a3e58030beea`, source archive
`874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad`,
and the selected BIO allocation-cache fix, patch
`d6564155f9cb9cabc2c281b39c92c8231086a6fce855aa685c9f3709e1f04674`.
The candidate changes only `block/bio.c`. Source application remains governed
by the held harness, including exact before/after hashes and zero fuzz/offset.
The standalone [embedded-config.txt](../../scripts/port/kernel-native-stage/embedded-config.txt)
is an exact copy of the retained kernel's embedded configuration, 240,677 bytes,
SHA256 `ae1d4ce855bd435b62c8fb213cbcf2d4eefd47b62274792c4a6bf299848b3876`.
It preserves the Apple drivers, Rust, BTF and 16K page configuration.

GCC/binutils remain the accepted builder versions. Rust 1.99/LLVM 23 are newer
than the historical embedded Rust 1.93.1/LLVM 21. The stage therefore permits
only the explicitly listed compiler/version metadata changes and the exact
new `CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS=y` probe. The pinned
`init/Kconfig` enables that probe at Rust 1.98; its two generated-bindings
consumers permit a newer lint. It introduces no new Makefile compiler flag.
Any other configuration difference fails. Generated baseline and candidate
configurations must match byte for byte. No historical byte reproducibility
is claimed for this newer toolchain.

## Acquisition and native interface

[acquisition.py](../../scripts/port/kernel-native-stage/acquisition.py) writes
only a new canonical directory below ignored `artifacts/kernel-native-stage`.
It gathers 35 pinned inputs: fifteen archives, fifteen signatures, three public
keyring files, the Asahi archive and the patch. It copies the pinned embedded
config and materializes the two BIO source slices without compiling or
installing. Reuse requires the exact size/hash; all fifteen signature checks
repeat in a new public-only GPG home. URLs and redirects are restricted to
the pinned sources. The acquisition byte budget is 1,200 MiB and its aggregate
work deadline is 1,800 seconds. It prints seven input paths as JSON:
`archive`, `config`, `patch`, `bio_baseline`, `bio_candidate`, `package_cache`
and `key_dir`.

```sh
python3 -I -B scripts/port/kernel-native-stage/acquisition.py \
  --root /absolute/checkout \
  --output /absolute/checkout/artifacts/kernel-native-stage/acquire-new
```

Optional repeated `--reuse-cache /absolute/existing/cache` arguments save
downloads but do not relax pins. A fresh-network hosted acquisition has not
run; the actual local acquisition reused all 35 hash-matching inputs,
reverified signatures and inspected all 100,117 archive members.

[stage.py](../../scripts/port/kernel-native-stage/stage.py) exposes `freeze`
and `run`. Freeze writes a new development source hash/mode map to the owned
`stage.lock.json`, or to a new ignored artifact path. It is not a signed release
or a native result. Run requires all of these explicit arguments:

| Argument | Required binding |
| --- | --- |
| `--root`, `--source-commit` | Canonical checkout, exact 40-character committed source/GITHUB_SHA |
| `--output` | New ignored directory below that checkout's kernel-native-stage artifacts |
| `--lock`, `--lock-sha256` | Independently reviewed source closure and external pin |
| `--docker`, `--docker-sha256`, `--endpoint` | Canonical hashed CLI and root-owned local `/run/docker.sock` |
| `--image` | Exact accepted base image ID, `sha256:…` |
| `--bootstrap`, `--bootstrap-sha256` | Same-job original image-provisioned receipt |
| `--accepted-result`, `--accepted-result-sha256` | Original native build PASS receipt with unchanged input/recipe pins |
| `--base-packages`, `--inputs` | Exact original 341-package inventory and inputs |
| `--archive`, `--config`, `--patch`, `--bio-baseline`, `--bio-candidate`, `--package-cache`, `--key-dir` | Acquisition's seven pinned paths |

Run checks every source byte and mode against both the lock and the exact Git
commit before copying its private code snapshot. It uses the existing FDK
accepted-base validator without modifying it. Original lifecycle acceptance
is not inferred from that helper's original-build PASS. The original ARM-C01
run 38218102399 remains overall FAIL; the strict-inflate source correction is
separate, with lock integration and a corrected native run owned by the coordinator.

## Container sequence and removal

An ordinary native ARM Linux host with zero effective/permitted capabilities
and at least 8 GiB host storage headroom is required. The local daemon must be
native ARM, rootful and use host UID mapping. Rootless/user-namespace remapping
is refused because the private output binds require the caller's actual UID.
Private empty Docker configuration/home directories avoid inherited contexts.

The provisioner runs as container root, network off, no-new-privileges, with
only CHOWN/DAC_OVERRIDE/FOWNER. It rechecks each signature, masks base pacman
hooks and installs exactly the fifteen archives with `--noscriptlet` and a
private configuration without repositories. It compares full inventories
before/after and runs the database dependency check. Host packages are untouched.
Public-only key/trust state, download cache and build scratch stay on tmpfs.

The controller commits one nonce-owned private image and restores the accepted
base's twelve effective Docker configuration fields. Added root environment
variables/labels are deliberately absent: Docker merges those fields at commit.
Commit and tag inspection requests use fixed Docker API 1.48. The hosted job
requires the actual daemon minimum/maximum range to include that version;
requests do not negotiate another version. The accepted helper's twelve-field
projection and empty-entrypoint sentinel are unchanged.
Provisioning identity is bound in the exact command. The derived image must
have the base RootFS layer prefix plus one layer, ARM64/Linux identity and a
bounded size increase. Before POST, the helper captures all current immutable
image IDs twice and requires equal canonical sets around the nonce-tag absence
check. Each query has a 30-second timeout within the existing stage deadline,
a 128-KiB output limit and at most 256 raw rows. Multiple tags can repeat an ID;
the saved `protected_image_ids` array is sorted and unique. It includes the
accepted base, preloaded images and existing intermediates. Missing base,
inventory churn, malformed rows or exhausted bounds refuse POST.

The file and parent directory of the ownership journal are fsynced before POST.
Cleanup requires its closed schema, private owner/mode, single-link regular
file, bounded captured bytes and complete protected-ID array. Older journals
without that array cannot authorize removal. A returned or recovered ID already
in the protected set causes FAIL before any tag or ID deletion. The POST may
already have attached the private tag to that existing ID; the helper retains
FAIL and does not attempt a speculative rollback. This is a cooperative
observed-preservation boundary, not prevention of concurrent daemon mutations.
The standalone stage CLI is unchanged; the protected set is captured locally.

Owned containers start with `docker start --attach <exact-ID>`. Docker start
does not support `--sig-proxy`; the copied flag has been removed. Audited Docker
CLI sources forward signals for non-TTY attachment, so cancellation may also
signal the exact owned container. The supervisor still kills/reaps its owned
CLI process group and the broker verifies/removes its journaled containers.
Source audit, parser checks and local process fixtures do not establish actual
daemon behavior. See [the compatibility record](kernel-docker-compatibility.md).

Three fresh nonroot containers run the source-derived C logic probe, full
baseline kernel build and full patched candidate kernel build. Each has a
read-only root, no network, dropped capabilities, no-new-privileges, private
namespaces, 14 GiB memory without swap, two CPUs, 512 PIDs and a 12 GiB `/tmp`
tmpfs. The worker measures the actual cgroup v2 and tmpfs values before work;
Docker command flags alone do not count as enforcement. Each full build uses
`make -j2 ARCH=arm64 LOCALVERSION=-cachy-asahi-kernel-c01 Image modules dtbs`,
the exact embedded config and explicit captured compiler tools. Configuration
generation has a 300-second timeout; each compilation has a 7,200-second
timeout; overall stage work is bounded to five hours. Runtime children have
bounded output, address space, file size, descriptors and CPU time.

The [strong output verifier](../../scripts/port/kernel-candidates/verify_build.py)
checks complete FDT structure and model/compatible identity for J413/J415,
ARM64 Image/EFI structure and 16K flags, embedded config in Image and vmlinux,
and full Image/vmlinux byte agreement under the pinned objcopy rule. It maps
each retained file-backed allocated ELF section through its load address,
compares every copied byte, requires zero-filled gaps and exact final length,
and excludes the exact removed note/comment sections and NOBITS/debug data.
Ambiguous or unsupported mappings fail. This establishes agreement between
the two retained outputs, not execution or compiler attestation. It also checks
valid vmlinux ELF/load segments, required audio modules, complete module
inventory/vermagic/exports and nonescaping resolvable source symlinks. Tools
and generated configs must be identical across the pair and probe. The older
held `native-build.sh` lacks the new required source argument and fails closed;
this controller provides the updated path.

Cleanup verifies nonce, daemon, command, mounts, image and container IDs before
deletion. Container and derived-image journals precede uncertain mutations.
An attempted image commit without a known immutable ID remains uncertain FAIL
when the nonce tag is absent: the daemon may complete the POST later. If that
tag appears, cleanup verifies and journals the recovered ID before removal and
requires absence of both the private tag and immutable ID. Every image removal
uses `--no-prune` without force, protecting untagged ancestors as well as explicit
protected-ID targets. The accepted base is not a removal target. Another tag
that prevents ID removal keeps cleanup at FAIL. Full legacy build-cache/layer
absence remains NOT ESTABLISHED; scoped removal does not establish an empty
daemon. Original producer uncertainty remains a separate hosted-job failure.
Normal cancellation defers signals during bounded cleanup, and cleanup failure
forces final FAIL. An initial FAIL receipt prevents an abandoned/hard-killed
stage from leaving an earlier PASS authoritative. Hard kill or host loss can
prevent cleanup and publication; journals retain ownership evidence, but this
stage has no standalone recovery command. A same-job disposable runner must
therefore remain the execution environment until recovery is separately wired.

Only a fixed status projection enters `public/status.json`. Private receipts,
bounded logs and the fixture's finite text allowlist remain in owned ignored
storage. Kernel/fixture executables are not publicly exported. No package,
repository, installation, boot or benchmark acceptance is inferred from PASS.

## Actual evidence and limits

- Fifteen archive signatures and the exact dependency closure were audited;
  authentication receipt SHA256 is
  `9d4a94cd6af1649e3d4ee48ff4c19d302222b339be236ffc94364a7bb150120d`.
- Local acquisition receipt is
  `artifacts/kernel-native-stage/acquisition-local-20261012/acquisition.json`,
  SHA256 `d15f437107ec49bfced448e8b67f44f2f099591f1e72312ae2258328067d0f48`.
- The extracted-C allocator fixture compiled and passed 13 cases per variant
  using host x86 GCC 16.2.1. It reproduces the baseline empty-cache/nonreclaim
  failure and candidate slab fallback, with cache-hit/failure/reclaim and
  cleanup checks. This is userspace logic evidence; it does not exercise the
  kernel allocator, concurrency, native ARM or M2 hardware.
- Unit and negative fixtures exercise signatures, input pins, configuration
  deltas, container policy, API framing/deadlines, ownership and failure
  publication. Their results and exact reviewed source closure are retained
  under `artifacts/kernel-native-stage/independent-review/`.
- Actual Docker provisioning/commit/removal, native tool availability and both
  full compilations are pending. A compiler failure remains a visible FAIL;
  there is no skipped variant or partial-pair PASS. Generic ARM compilation
  would still leave kernel execution, exact M2 Air hardware checks and
  performance measurements pending.

The API/start and protected-image corrections leave the previous 24-file source
lock held. The coordinator must rebind that lock and the dependent job packet, then prove the
committed source bytes/modes before dispatch. A previous lock or source review
does not authenticate these changed files.

The controller is MIT-licensed; the broker and runtime retain attribution to
the reviewed FDK implementation. The source-derived extracted-C fixture is
GPL-2.0-only. Kernel source,
BIO patch and config remain associated with the pinned kernel's retained
GPL-2.0 licensing and notices. Package notices and license declarations are
recorded in the dependency packet; distribution/license acceptance is pending.
