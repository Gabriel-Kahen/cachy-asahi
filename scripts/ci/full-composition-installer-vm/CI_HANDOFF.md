# Source-only native CI handoff

Adopt this candidate at **`scripts/ci/full-composition-installer-vm/`** using
`integration.patch` and `adoption-map.json`. **No existing-core source delta is
required.** Root owns adoption, source/workflow pinning, publication and dispatch.
The implementation has not run Docker, GPG, package builds, mkfs, QEMU, namespaces,
mounts, ALPM or services. Prior tiny17 VM results and native-container P0 failure
remain separate and unchanged. No production Asahi defaults are changed.

Root's complete manual workflow is
`.github/workflows/native-arm-full-composition-installer-vm.yml`. It preserves
the existing native/FDK bootstrap and fixed preparation checkouts, supplies the
exact `source` input to this caller, and selects a350-minute job with a270-minute
caller step. Its final step retains only nine named bounded reports/logs; private
tooling caches and producer work directories are never uploaded.

## One concrete caller

`ci.py` performs the held composition preparation, authenticates/exports all587
signed input archives, obtains the held21 tooling inputs, builds a separate
574-plus-tooling generic disk, boots it and launches the installer, then retires
VM resources before producer resources. It returns nonzero unless transaction,
preservation, natural QEMU exit and every required cleanup succeed. It retains
bounded JSON receipts under the supplied output path. Cleanup uncertainty retains
the producer's private inputs rather than removing live actors' backing data.

Use the existing full-root composition job's exact input bindings. The producer
checks these original source revisions and native/FDK/setup4 pair provenance;
it neither fabricates artifacts nor starts the full-root upgrade actor. `code`
is the adopted candidate checkout at the dispatched full SHA.

```yaml
- name: Full composition installer in owned generic ARM VM
  timeout-minutes: 270
  shell: bash
  run: |
    set -euo pipefail
    test "$RUNNER_ARCH" = ARM64
    test "$(uname -m)" = aarch64
    test "$(id -u)" != 0
    test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
    timeout --signal=TERM --kill-after=60s 15600s python3 -B \
      scripts/ci/full-composition-installer-vm/ci.py \
      --code "$GITHUB_WORKSPACE" --code-revision "$GITHUB_SHA" \
      --preparation-source "${PREPARATION_CHECKOUT:?}" \
      --product "${PRODUCT_CHECKOUT:?}" --updater "${UPDATER_CHECKOUT:?}" \
      --desktop "${DESKTOP_CHECKOUT:?}" --updater-v2-source "${UPDATER_V2_CHECKOUT:?}" \
      --native "${CORE341_PAIR:?}" --fdk "${FDK_PAIR:?}" \
      --cache "${COMPOSITION_CACHE:?}" --setup4-pair "${SETUP4_PAIR:?}" \
      --output "/tmp/full-installer-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
```

Declare job timeout **290 minutes** or longer so the caller's ordered cleanup
can finish after the step's finite termination window. Bind those variables to
the same already authenticated checkout/artifact directories as the existing
composition job. The preparation checkout is exactly
`93bc9bfac7343ee3b443ae3332c0942ed1ba5b55`; updater v2 is exactly
`480053c0866a922138d85af2b9880fb0e10d7b2c`. Product/updater/desktop revisions
remain the held caller's `SOURCES` map. No new package or binary artifact pin is
needed. Keep the original core341 image/pairs and shared composition cache alive.
No host SYS_ADMIN, unconfined seccomp, unmasked proc, host device or KVM is needed.

The native runner needs its existing Docker daemon, Git and Python; its generic
ARM guest's package tooling comes from the exact source-held lock. Runner host
system packages are not installed by this candidate. The actual full574 builder
image supplies the pinned generic4K kernel and original platform payload. The
union refuses a tooling package that would replace an existing different version.
Image preparation uses metadata capabilities only and `mkfs.ext4 -d`, without
host mounts. Runtime is UID23001/cap0/NNP, offline, TCG,4GiB guest RAM/2CPUs,
snapshot20GiB disk. Provision sufficient disposable runner disk space: measured
source/stage/image capacity guards and a12GiB runtime snapshot reserve may refuse
small runners; they never trim the587 composition. VM budget5400s, installer
engine4500s, preparation children1800s each, VM-owner actor window9600s.

Before dispatch, Root should freeze the adopted source and workflow normally;
`candidate-freeze.json` records the candidate hashes and existing dependency
hashes. For inert verification after adoption:

```sh
python3 -B -m unittest discover -s scripts/ci/full-composition-installer-vm -p 'test_*.py'
```

Retain the outer `result.json`, producer/cleanup JSON, VM-owner JSON and
preparation/VM JSON. Only upload these bounded explicit files, not private
producer signing state, package caches or entire work directories. A timed-out
CI step may leave cleanup UNKNOWN; report it plainly and preserve the recorded
owned image tag/paths for a scoped follow-up. Do not label such a run PASS.

## Exact acceptance and remaining limits

The new target is a fresh disk-backed directory inside the generic VM, with two
declared user/configuration preservation files. Empty local DB -> exactly the
initial587 composition (updater4.4.2-2/setup0.1.0-3), with unchanged ALPM
NOHOOKS|NOSCRIPTLET and dependency/conflict checks. Actual package archives,
signatures, both public signer roles, prepare map, reopened inventory, real
ALPM ownership/database, file hashes/modes/literal symlinks/closed hardlinks,
private trust, preservation fixtures and parent guest inventory/source/cache
are checked. The child reuses the **unchanged** installer `isolate` proc/mount,
minimal device, recursive read-only and seccomp barrier, then reduces caps.
The full target uses its disk-backed evidence bind;384MiB metadata tmpfs limits
and old tiny fixture limits remain unchanged.

The distinct full profile streams bounded signed tar data. Absolute literal
symlinks and closed regular-file hardlinks are admitted; archive special nodes,
nonroot ownership, parent symlink aliases, overlapping nondirectory payloads,
conflicting shared-directory metadata, unsupported compression/decoder limits
and undeclared outputs fail closed. The first actual producer/profile/VM run
may expose such a shape, tooling collision, insufficient capacity or a proc
restriction; none has been silently bypassed. Every package must remain present.

ALPM may invoke the exact pinned static target ldconfig even with hooks and
scriptlets disabled. Its internal helper exit status is **NOT OBSERVED**.
The candidate checks signed payload identity, the held helper/config/scan closure,
generated cache shape and live auxiliary keys after the transaction; it does not
claim suppressed auxiliary execution or a separately observed helper exit.
The parent independently observes the installed payload after namespace exit.

This route gives no target boot/session, macOS partition/boot integration,
interrupted installation/recovery, independent user journey, production key
custody, M2 hardware,16KiB compatibility or measured performance credit. It does
not complete M8's hardware journey. Native producer, full guest transaction and
resource retirement remain **NOT RUN** until Root dispatches and checks actual
receipts. Existing tiny17 and native-container P0 records retain their original
meaning.
