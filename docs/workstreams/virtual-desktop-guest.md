# Generic ARM software guest proof handoff

Source implemented and reviewed October 11, 2026. **Native fixture-image
construction, guest disk preparation, guest boot, software compositor execution,
frame capture and frame review: NOT RUN.** Portable guard/limits/data tests pass;
the GBM probe compiled/linked against existing x86 host headers without execution.
This is intermediate R1/R4 software integration infrastructure. The complete
port requirements R1–R5/M5–M9 and both M2 Air acceptance records remain required.

The [source feasibility audit](../research/virtual-desktop-feasibility.md) explains
why a guest kernel can supply virtual DRM without host devices. The executable
slice is confined to `scripts/virtual/`; no shared CI, dependency manifest,
original package, platform stack, host mount/module or host package was changed.

## Authenticated tooling extension

`tooling.lock.json` adds exactly 19 original ALARM packages to the existing
341-package builder inventory: **360 upstream packages**, plus the **four
original overlay packages** for the proof image. The refreshed native input lock is
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`
with Perl `5.42.3-1`. An actual isolated pacman
print-only solve against reconstructed frozen installed metadata returned zero
and those exact 19 additions. No base package replacement/update or dependency
trimming is allowed by the runtime checks. The revised solve compared all 341
installed versions with this lock and replaced only Perl local version/dependency/
provide metadata in the isolated resolver. The selected 19 archives are unchanged.
The previous tooling lock/audit were bound to the superseded native snapshot and
are not accepted as evidence for this baseline. `resolver.baseline_refresh`
records both snapshot hashes and captured repository database hashes.

Local read-only `audit_tooling.py` downloaded 13,662,132 package bytes, verified
all detached signatures with the pinned official primary signer, compared every
signed `.PKGINFO` to the frozen dependency/version/license metadata, and retained
`.BUILDINFO`, paths and GPG status in public `tooling-audit.json`. **All 19 passed;
none has `.INSTALL` or an installed libalpm hook.** Architecture declarations
and signature verification are data evidence; native QEMU execution has not run.
All 19 detached signatures and signed metadata were rechecked against the fresh
lock using the original private cache. Public-key-only auditing uses
`gpg --no-autostart` with a fresh temporary key directory; it needs no agent,
private key or host trust state.

Tooling lock SHA-256:
`7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25`.
Private original blobs and signatures are presently under
`/tmp/cachy-virtual-tooling-cache`; retain them in the coordinator's private input
store. Do not publish the cache or guest disk through public evidence exporters.
The lock contains exact HTTPS URLs, archive/signature hashes/sizes, licenses,
source URLs and captured database/base-lock bindings. QEMU's source pin is
`4fc49f46dc95d4a27de2509e7fceb2931e91faeb` (11.1.2). Dependency recipe/source
revision mapping and source distribution obligations still need review if these
upstream binaries are redistributed; the audit is not publication clearance.

Reproduce the data-only audit without a network inside the child container:

```sh
python /runner/virtual/audit_tooling.py \
  --lock /inputs/tooling.lock.json \
  --lock-sha256 7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25 \
  --cache /inputs/tooling-cache --output /out/tooling-audit.json
```

The controller owns constructing a **separate immutable fixture image**, derived
from the successful original installed-image handoff, with only this offline
19-package tooling transaction. Authenticate originals before installation;
install them only inside the disposable image build, using the existing ALARM
trust configuration and exact original filenames/signatures. Freeze its actual
Docker image ID, image construction receipt and 360+4 inventory. No moving apt,
network-enabled child, host installation or OCI architecture-only provenance is
an alternative. The original builder lock and first V01–V09 CI batch are untouched.

## Fixed input and controller contract

Mount one disposable input directory at read-only `/inputs`, this repository's
`scripts` directory at read-only `/runner`, a fresh private output directory at
`/out`, and a writable `/tmp` tmpfs. The scripts require actual aarch64 Docker,
loopback-only network, an immutable installed-image ID and explicit nonce.
They reject host display/audio/user sockets, Docker sockets, DRM/input/audio,
KVM/FUSE/memory or block devices, system-path mounts and nested input/work mounts.

`/inputs/virtual-contract.json` is coordinator-generated and SHA-256 pinned on
both invocations. Its schema is:

```json
{
  "schema_version": 1,
  "execution": "qemu-tcg-generic-aarch64",
  "nonce": "32 lowercase hex characters",
  "image_id": "sha256:actual immutable tooling installed-image ID",
  "source_commit": "40 lowercase hex source commit after coordinator freeze",
  "output_uid": 1001,
  "output_gid": 1001,
  "baseline_handoff": "lifecycle.json",
  "baseline_handoff_sha256": "actual handoff receipt hash",
  "base_runtime_lock": "expected-packages.lock",
  "base_runtime_lock_sha256": "actual original 341-package lock hash",
  "tooling_lock": "tooling.lock.json",
  "tooling_lock_sha256": "7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25",
  "tooling_audit": "tooling-audit.json",
  "tooling_audit_sha256": "actual public tooling audit receipt hash",
  "baseline": [
    {"name": "each of the four original package names",
     "version": "actual original version", "archive": "baseline/original.pkg.tar.xz",
     "sha256": "actual original archive hash",
     "payload_sha256": {"usr/path": "actual complete installed-file hash"}}
  ],
  "runner_sha256": {
    "common.py": "actual source hash", "guest.py": "actual source hash",
    "prepare.py": "actual source hash", "run.py": "actual source hash",
    "gbm_probe.c": "actual source hash"
  }
}
```

The displayed values are placeholders, not an executable candidate contract.
Use all four baseline rows from the completed lifecycle original handoff;
`baseline_handoff_ready` must be true, status PASS, version/payload maps identical.
The scripts also compare every original archive member, installed hash and
pacman file owner; a partial payload map or fixture upgrade cannot substitute.
The controller binds the derivative image to that handoff through its Docker
construction receipt and actual native daemon/image inspection. Environment
variables alone do not attest provenance. No private signing key is an input.

## Two guarded entrypoints

Preparation runs as container root with **only CHOWN, DAC_OVERRIDE, FOWNER and
FSETID**. FSETID preserves reviewed upstream setgid modes such as `wall`/`write`;
source/staged special-mode ownership and modes are checked. Running the VM is
non-root with **all capabilities dropped**, no-new-privileges and a read-only
root. Both use `--network none`, 4-CPU/6-GiB limits, a bounded PID count, and no
host device or socket passthrough. Controller UID/GID in the contract must match
the VM runner UID; preparation transfers its private outputs to that owner.

Inside the contracted preparation container:

```sh
python /runner/virtual/prepare.py \
  --contract /inputs/virtual-contract.json --contract-sha256 ACTUAL_CONTRACT_HASH
```

It copies immutable `/usr`, `/etc`, `/var` and `/boot` plus root library/bin
symlinks into a fresh private staging tree. It retains the complete 360+4 package
inventory and original package payloads. **Extended attributes/file capabilities
are deliberately not copied**; this generic software fixture does not certify
all base security metadata or target-image fidelity. Fresh home/runtime/device
mount directories replace container-specific state. Every guest-only
passwd/group/shadow/fstab/hostname/machine-id/systemd/probe/config change is
recorded. `depmod -b` applies only to that guest tree. The exact signed generic
`Image` is copied and checked; no bootloader/custom kernel is built.

`mkfs.ext4 -d` populates an 8-GiB sparse raw disk without a loop device or mount.
Before copying, actual `du` allocated sizes and `statvfs` free bytes must allow
**twice the source footprint plus 1 GiB**; before population, actual remaining
space must cover the staged footprint plus 1 GiB. The full base is not silently
trimmed. Successful cleanup and output ownership precede an accepted PREPARED
receipt. Root tree, raw disk and logs remain private; staging is deleted only
when preparation succeeds.

Preparation outputs `/out/prepared/{guest.raw,Image,prepare.json}` and capped
command logs. Move/link the whole prepared directory into the next read-only
input directory as `/inputs/prepared` without hardlinking individual input
files (the input guard requires link count one). The VM process uses QEMU's
private snapshot overlay, so the accepted disk remains immutable. Retain failed
preparation diagnostics; do not proceed when the receipt is FAILED.

Inside the contracted non-root VM container:

```sh
python /runner/virtual/run.py \
  --contract /inputs/virtual-contract.json --contract-sha256 ACTUAL_CONTRACT_HASH \
  --prepare-receipt prepared/prepare.json \
  --prepare-receipt-sha256 ACTUAL_PREPARE_RECEIPT_HASH
```

Use the same frozen image/source/nonce contract. The run rechecks original
archives/payloads, 360+4 inventory, tooling audit, sources, prepared disk and
signed kernel before starting QEMU. It requires cgroup memory.max <=6 GiB and
CPU quota <=4. One hard 20-minute trial deadline includes input checks; guest
boot has a 10-minute deadline. Cleanup kills the process group and retains
FAILED diagnostics. Preparation independently has a hard 20-minute limit.

The fixed QEMU invocation uses `virt-11.1`, TCG, 2 vCPUs/4 GiB guest RAM, direct
`Image` boot of `/dev/vda`, 2D `virtio-gpu-pci` at 1024x768, no NIC, no host
display/audio, private Unix UART/QMP sockets and a guest proof target. UART
waits for the controller before boot, then output is stream-capped at 64 MiB;
QEMU/session/command logs have tighter caps. QMP requests have absolute
10-second deadlines. No TCP listener is created.

The guest kernel auto-mounts devtmpfs (`CONFIG_DEVTMPFS_MOUNT=y`); guest-only
`virtio_gpu` loading/udev settlement supplies the DRM card. A root guest service
starts pinned seatd with `SEATD_VTBOUND=0`, a fixture-owned socket and ordinary
UID 23001. The software test runs through `runuser`/`dbus-run-session`, with a
fresh home/runtime/config/cache, two llvmpipe threads and no optional autostart.

The C probe refuses before DRM access unless aarch64, guest declaration and
exact guest cmdline token match. It verifies virtio_gpu, PRIME, software renderer,
required EGL/GL extensions, linear GBM buffer export/import, framebuffer
completeness and all 4096 magenta pixels. It does not certify scanout. Only after
that succeeds does the guest launch minimal then actual installed overlay Lua
config, verify IPC/configerrors/output, and map **Wofi --normal-window** (default
layer-shell is outside `hyprctl clients`). Each phase offers a finite capture
window and requests a clean compositor exit.

## Evidence and review point

`/out/proof` retains `result.json`, capped `serial.log`/`qemu.log`, and
`minimal.ppm`/`overlay.ppm` when capture succeeds. JSON binds contract/image/
prepared-disk/log/frame hashes, guest events, mapped-client IPC and decoded
session logs. Binary frames need a separately reviewed bounded retention path;
current text-only integration export must not silently omit them. A small
compressed/base64 frame transport could be integrated by the controller later;
no exporter/workflow was changed here.

A successful automated run stops at **CAPTURED_REQUIRES_VISUAL_REVIEW**. It can
report GBM pixels and session IPC PASS, while compositor/frame acceptance remains
**REVIEW REQUIRED** and visual review **NOT RUN**. Eight colors merely reject
blank frames; colorful/stale console output cannot pass visual acceptance. The
coordinator must inspect both matching hashed frames for the intended Wofi
window and record a separate reviewed result bound to the captured logs.
Hardware, acceleration, 16K pages and performance remain NOT RUN regardless.

Finite stop: one frozen tooling/fixture build and one <=20-minute VM trial.
Retain the exact first error. Resource, kernel boot, DRM/GBM, seat, compositor or
capture failure is a concrete corrective task for these inputs; do not spawn an
Apple emulator, custom-kernel project or indefinite matrix from this proof.
M2 platform/16K/accelerated desktop/audio/power/installation acceptance remains
separate, and this software facility does not complete the broader port.

## Local validation

`python -m unittest discover -s scripts/virtual -p 'test_*.py' -v`: **31 PASS** (14 core and 17 controller checks).
Checks cover host/device/cap/network/mount refusal, duplicate/nonfinite JSON and
input pin/symlink rejection, exact 19-package signature/receipt binding, active
stream caps, process-group timeout cleanup, immediate short-log durability,
absolute dribbling-QMP deadlines and no heuristic frame-review PASS. Real child
regressions inject TERM/INT/ALRM after `Popen` creates a sleeper and before it
returns: both process wrappers register then reap the child, close streams, and
restore handlers. Spawning defers Python cancellation without blocking signals,
so the child retains normal SIGTERM behavior. A default terminating disposition
is converted to an interruption exception during registration so cleanup runs.
Controller regressions cover cancellation during projection, workspace cleanup
and final receipt writes, including the actual mocked `main()` path; receipt and
return both remain failure after late cancellation.
Strict C syntax and x86 compile/link passed with already installed headers;
the probe binary was never run. Independent readonly review found/fixed output,
deadline, Wofi layer-shell readiness, prepared-receipt cleanup and special-mode
fidelity issues. Native ARM fixture preparation/runtime remain NOT RUN.

## Native controller added after the first integration freeze

`controller.py` now prepares the separate tooling image and invokes the frozen
five-file proof. **Controller Docker execution and every native/guest phase
remain NOT RUN.** Its 17 controller tests and 14 core tests pass.
Nothing invokes Docker on an x86 host: the native/non-root Linux check precedes
the first Docker CLI call. The reviewed cancellation correction changes `common.py`; its new hash is explicitly bound in the controller. The other four core source hashes remain unchanged.
The controller is excluded from the initial V01–V09 integration freeze and needs
a separate coordinator-reviewed workflow call.

Host invocation, on the native ARM runner only:

```sh
python -B scripts/virtual/controller.py \
  --contract /absolute/private-inputs/controller-inputs.json \
  --contract-sha256 ACTUAL_CONTROLLER_INPUTS_HASH \
  --output /absolute/fresh/virtual-public
```

The new **host** contract is distinct from the earlier generated child proof
contract. Generate it only after accepting the installed baseline handoff:

```json
{
  "schema_version": 1,
  "execution": "native-aarch64-controller-qemu-tcg-guest",
  "source_commit": "new 40-hex controller/proof source freeze",
  "baseline_source_commit": "40-hex source from accepted installed baseline receipts",
  "installed_image_id": "sha256:actual accepted private 345-package image",
  "controller_sha256": "actual controller.py source hash",
  "audit_tooling_sha256": "189af6c1ac05eecf1ba3cc9628760dc636ff45fc9ceab4e957d7a5eb3877d6d9",
  "core_sha256": {"common.py": "accepted hash", "guest.py": "accepted hash",
    "prepare.py": "accepted hash", "run.py": "accepted hash", "gbm_probe.c": "accepted hash"},
  "cache_dir": "tooling-cache",
  "baseline": ["all four original baseline rows, as in the accepted handoff"],
  "files": {
    "base_inputs_lock": {"path": "native-inputs.lock.json", "sha256": "actual hash"},
    "base_lock": {"path": "base-packages.lock", "sha256": "actual hash"},
    "installed_lock": {"path": "installed-packages.lock", "sha256": "actual hash"},
    "lifecycle_receipt": {"path": "lifecycle.json", "sha256": "actual hash"},
    "installed_image_receipt": {"path": "installed-image.json", "sha256": "actual hash"},
    "committed_config": {"path": "committed-config.json", "sha256": "actual hash"},
    "committed_verification": {"path": "committed-image/result.json", "sha256": "actual hash"},
    "commit_receipt": {"path": "commit-receipt.json", "sha256": "actual hash"},
    "tooling_lock": {"path": "tooling.lock.json", "sha256": "7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25"},
    "tooling_audit": {"path": "tooling-audit.json", "sha256": "3a7c30ba244a874625da994f896ae080a2b60f092b04f5f2d6caa70239e4f41d"}
  }
}
```

These are placeholders. `baseline` must contain actual object rows, not the
illustrative string. Copy original archives below `baseline/` at their accepted
relative paths. All metadata/archive/cache files must be regular, singly linked,
non-symlink files. `tooling-cache/` contains exactly the lock-selected original
packages, signatures and three official public keyring files. The controller
checks their hashes/sizes before and after snapshotting them into its private
workspace. It also checks the original 341 package versions against the exact
native input snapshot hash already bound in `tooling.lock.json`; package counts
alone cannot substitute for the full dependency set.

`source_commit` identifies the new execution source; `baseline_source_commit`
identifies the earlier accepted image/READY/lifecycle/fresh-verification records.
They may differ. Original payload/version/archive rows must remain identical
across both records. The actual Docker image architecture, ID and normalized
Config must match the accepted committed-config receipt. The controller rejects
remote endpoints, host root, x86, image volumes/healthchecks, inherited test or
connection environment, extra capabilities/devices, unbounded resource settings,
wrong read-only binds, and preexisting container names.

The verified baseline intentionally removed `/etc/pacman.d/gnupg`. The tooling
child therefore creates a **TEST local pacman master only inside the disposable
image's temporary directory**, imports only the exact pinned official public
ALARM keyring, locally trusts the known official primary fingerprint and
re-verifies all 19 archive signatures and signed metadata. Strict
`SigLevel = Required`/`LocalFileSigLevel = Required` govern its offline explicit
`pacman -U --noscriptlet` transaction. Every existing global hook name is masked
with a `/dev/null` override; the 19 authenticated packages themselves have no
scriptlets/hooks. `ldconfig` is an explicit in-image operation. No host keyring,
production signing credential or unsigned-package fallback exists.

The child verifies exact 360+4 inventory and unchanged original payloads, kills
its temporary GPG agents, removes the TEST trust directory, and checks that
image `/tmp`, `/root`, package cache and the sole alarm home are empty and system
GPG/pacman-log state remains absent. Only an exit-zero READY receipt allows a
private local image commit. Its actual immutable ID and restored Config are
checked, followed by an independent read-only verification container that uses
only DAC_OVERRIDE to read the sanitized image's 0700 home. Neither child mounts
host system/user/device paths. Temporary process identity is passed through
`/usr/bin/env`, so it is absent from committed image Config.Env.

A random owned private tag makes the local commit recoverable for cleanup; no
push or publication occurs. The controller then runs the unchanged preparation
and TCG phases with the earlier exact limits. It records actual free space,
cache allocation, baseline image size and preparation `du`/free-space results.
It never trims the 341-package base or substitutes a declaration of architecture
for native host/daemon or actual execution evidence. The controller has a fixed
55-minute overall budget; the QEMU trial remains at most 20 minutes and can end
earlier if the overall budget is exhausted.

All newly created containers are removed and daemon absence is checked. The
owned private tag/new image is removed and checked; uncertain commit outcomes
or unverified cleanup fail the stage. Existing baseline images or colliding
container/image names are preserved. The private workspace, raw disk, copied
package/key inputs and raw tooling key-init logs are deleted after the explicit
public projection; their cleanup is recorded. Parent image layer erasure is
**NOT CLAIMED**. No Docker prune command or unrelated object removal exists.

Public output is an explicit projection: `result.json`, guest event diagnostics,
bounded controller/QEMU phase diagnostics and matching hashed
`minimal.ppm`/`overlay.ppm` frames when present. No generic directory export,
image layers, keyring, rootfs or raw disk is copied into it. It still stops at
**CAPTURED_REQUIRES_VISUAL_REVIEW**, with frame/compositor acceptance pending an
actual inspection. A nonzero phase preserves its first bounded diagnostic and
cleanup status. The coordinator owns workflow wiring, dispatch and visual
review; no hardware or full-port acceptance changes here.

The 17 controller tests use temporary metadata and mocked cache/daemon replies,
cover native-before-Docker refusal, local daemon checks, exact handoff/source
bindings, original tamper, distinct capabilities, actual Config/resource checks,
owned cleanup/collision/cancellation, uncertain commits and receipt-bound public
frames. They require neither Docker nor the private package cache. Run together:

```sh
python -m unittest discover -s scripts/virtual -p 'test_*.py' -v
```

## Accepted empty-entrypoint metadata correction

The virtual controller compares Docker's exact `Entrypoint: [""]` reset sentinel
as an empty entrypoint and null Labels as an empty map, matching the accepted
initial handoff's semantics. It retains exact Env order/content, nonempty
commands/entrypoints and nonempty labels; `['', '/bin/sh']` is not an empty
entrypoint. The baseline must still satisfy the complete accepted 345-package
lifecycle/READY/immutable/fresh-verification contract before any tooling install.

The tooling image's existing CLI commit previously emitted `ENTRYPOINT []` for
an empty base entrypoint. The [pinned Moby 28.0.4 merge branch](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
can then inherit the tooling container's runtime command. The commit now emits
`ENTRYPOINT [""]` for `None`, `[]` or the exact sentinel, retaining the accepted
base command. [Moby container creation](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go)
resets that sentinel; each virtual child additionally chooses `/usr/bin/env`
and its explicit executable. No runtime identity is passed using Docker Env.

The private recovery tag is still prechecked and registered before commit;
unknown commit results remain FAIL, owned tag/image absence is independently
checked, and the accepted baseline is preserved. Full derived Config comparison
and fresh read-only 364-package/original-payload/private-state verification
remain mandatory. The correction adds no dependency on the independently edited
CI commit module. The read-only CI reference informed the sentinel semantics;
its in-flight API/ownership code was not copied or imported.

Meaningful local tests exercise all empty/nonempty command combinations using
the actual generated CLI changes and the pinned Moby command-merge branch,
exact sentinel/null-label equality, changed Env/order/labels/commands, and the
actual mocked controller path with a sentinel-bearing baseline and derivative.
The full 31-test virtual suite, Python compilation and whitespace checks pass.
No Docker, tooling-image build, native guest or frame execution ran on this host.

October 12 source handoff hashes (the five-file core mapping in `controller.py`
remains unchanged; the host contract must use the new controller hash):

| Source/input | SHA-256 |
| --- | --- |
| `common.py` | `6479ee7245be45617deb58dfe5c4e2ca8aa13493a500c6a61feb69008942c381` |
| `guest.py` | `8a31f3d251e6e60db7c0c33bfebb8d9e37fea7924a72fdce493a9388ccde143f` |
| `prepare.py` | `22d9f926ef8b3965052585e9bb401502c9c53cccbd031f807db6ef85e7d1c4ff` |
| `run.py` | `87992add6ffd1fb8f9effd900e5a1bf8c119c393613c24f3eaf3f687280eaf8a` |
| `gbm_probe.c` | `fe0bb7b15df0bc93c4b5115543619e182ba3dac2ed22d0d8b1ab541d77a72efd` |
| `controller.py` | `63a5dd2185bd263bb8b7699bf7ac3bec1c5746329259c386dc9d93090e73dd64` |
| `audit_tooling.py` | `f2005ea8366f64cd81aa7fb7dbae9e60c835da77164adba4d8e434af262fda13` |
| `test_controller.py` | `d77091fd5cf6200a7ee5f79d6b09f3a66afe183effe5113cc0abfdecc38c8f43` |
| `test_virtual.py` | `d4f778326d1f02fef576b74a9ca6a712061f60bf58901cc6af638f9cb4f8286a` |
| `tooling.lock.json` | `7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25` |
| `tooling-audit.json` | `3a7c30ba244a874625da994f896ae080a2b60f092b04f5f2d6caa70239e4f41d` |
