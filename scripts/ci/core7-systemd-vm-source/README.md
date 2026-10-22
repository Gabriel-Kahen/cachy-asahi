# Core7 real-systemd two-boot source factory

This dedicated source-only factory reproduces the complete published 34-file
source `a74c54093bf8d09883e32b0d64b77f46223920e1`
(`codex/core7-host-qemu-v1`). It does not change the existing GNU/Core
factories, their defaults, manifests or any accepted result.

```
python3 -I -B scripts/ci/core7-systemd-vm-source/prepare.py --source-only
python3 -I -B scripts/ci/core7-systemd-vm-source/prepare.py --output /fresh/ordinary/output
```

Thirty-one readable files under templates/ are byte-held. The factory derives only
the source manifest and two identical registered workflows. Its pinned profile
closes all 34 final files; all template bytes and final bytes are checked before
creating the output and checked again afterward. Missing/extra files, empty
foreign directories, drift, symlink/hardlink inputs and existing/aliased/nested
outputs refuse. Filesystem reads compare stable identity while excluding atime.
No development artifact path is imported by the factory or emitted runtime.

The emitted workflow uses the original authenticated Core800 owner, fresh574
producer, full current64 verification and original TEST signer/assembly bodies,
then a separately bounded owned generic16K VM case. First boot starts original
systemd and performs ordinary signed original/candidate transactions with real
ALPM hooks; its original .INSTALL must re-exec the candidate as actual PID1.
Second boot requires that same candidate, same root, a distinct boot ID and the
complete persistent graph/capability map. Natural worker/probe retirement,
actual final manager running, exact account/cache/config effects and ordered
media/producer cleanup remain mandatory. Owner14400/media1900/boot3600/shared7200
are explicit new-case budgets; original producer2300/assembly1070/transaction90/
cleanup60 remain held. Existing Core800 NoHooks and Python-PID1 cases are intact.

The read-only path-scoped CI uses Python3.12/3.14 and immutable fixtures for the
whole expected34, Core800, KSM637, accepted Core7 carrier26, kernel carrier28 and
current64 carrier134. It hashes all fixture members and runs three factory
controls plus the original 24 plus three host prerequisite emitted source/adapter/emission controls. Those
controls include the full original owner through inert actor boundaries, staged
source registries, complete original media/kernel mechanisms, generated shell,
isolated CLI paths and source drift refusals. Original complete574 source pins
remain bound through the whole Core800 profile; CI does not copy/re-authenticate
its 1GiB package cache. The native workflow retains its separate whole-source
Git proof and all original signature/GPG requirements before actors.

These are source controls, not native package installation, boot qualification,
Asahi/M2 hardware validation, automatic rollback or performance results. This
factory runs no Docker/QEMU/GPG/pacman/systemctl actors and does not replay old
native positives. Raw packages, kernels and root filesystems are not vendored.
All actual selectors remain NULL in source-only outputs until genuine runtime
workflow binding; new acceptance requires the separate strict native reader and
Root decision.

The current workflow installs and verifies host `qemu-system-arm` before building
the producer. Update and install each have a 120-second cap with retries disabled.
Four initial checkouts have unique names. This corrects the authenticated prior
run39736610069 failure: QEMU was absent before either VM boot. The original
33-file trial remains recorded in Git; its failed run is not VM acceptance.
