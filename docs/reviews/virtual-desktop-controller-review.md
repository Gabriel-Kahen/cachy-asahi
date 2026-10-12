# Virtual desktop controller independent review

October 11, 2026 local project date. Source/portable-fixture checkpoint before
the next native phase. The reviewer owns this document only. Read the updated
roadmap and inventory first; complete R1–R5, both exact M2 Air sizes and their
physical/release/maintenance requirements remain mandatory.

No Docker operation, package/image/rootfs download, package/account/keyring
mutation, actual ARM program, compositor, GPU device, workflow or Git action was
performed. Portable tests used temporary files, mocks and bounded isolated
Python children. One such child intentionally survived the faulty cancellation
boundary; the reviewer then killed its group, reaped it and closed its pipes.
The C probe was compiled temporarily on x86 and exercised only its refusal gate.

**Final checkpoint: VD1/VD2 are independently resolved and the corrected source
is ready for controlled native execution.** The actual accepted installed
baseline remains a prerequisite; no guest/frame/visual/M2 acceptance is inferred.

## Reproduced findings

### VD1 — Cancellation can leave a newly spawned process untracked

`common.py::bounded()` and `LoggedProcess.__init__()` invoke Popen without
deferring cancellation through child-handle registration. A TERM/INT/ALRM handler
can raise after Popen creates its child but before the caller assigns the return
value. `bounded()` then reaches its finally with `process is None`, so it never
kills/reaps that child. The constructor has a corresponding unregistered-child
window.

Exact bounded reproduction wrapped the actual Popen of a harmless isolated
Python sleeper and raised local SIGTERM after construction, before returning
the handle. The actual shared runner produced:

```text
bounded interrupted: synthetic review interruption
child still alive after bounded finally: True
review child removed: True
```

The host controller uses this shared runner for Docker create/start/commit and
cleanup commands. An untracked host CLI may continue after the controller's
owned-object cleanup/query, so a bounded command timeout/group-cleanup assertion
is insufficient at this boundary. This reproduces an isolated child leak, not
an actual late Docker allocation or private-key leak.

Reported immediately. Defer cancellation through spawn/handle registration,
replay it only after the handle is available to cleanup, preserve normal child
signal delivery, and clean registered constructor children/pipes/logs on
BaseException. Add exact after-Popen/before-return regressions. Owner correction
and independent rerun are pending.

### VD2 — Late finalization cancellation is forgotten by status and return

The controller checks CANCELLED near the beginning of its protected finally,
then projects guest evidence, copies diagnostics, deletes the workspace and
saves its result. `cleanup_signals()` remembers later TERM/INT by setting the
global flag, but no later status/return check uses that updated flag.

Independently exercised the actual `controller.main()` with temporary input and
receipt fixtures, mocking all native/Docker/stage operations to isolate this
control boundary. The projection callback invoked the installed TERM handler
inside cleanup_signals after the early check:

```text
late projection cancellation remembered globally: True
actual main returns success: True
retained status: CAPTURED_REQUIRES_VISUAL_REVIEW
```

Reported immediately. Recheck pending/global cancellation through final
projection/workspace/result finalization and fail both the retained controller
status and return when cancellation occurred. This does not create a visual or
M2 PASS—the existing visual gate stays pending—but it loses the controller's
cancelled failure state. Owner correction and independent rerun are pending.

## Reviewed contracts and boundaries

- The outer controller rejects x86/root before its first Docker command and
  requires a local native ARM daemon. It binds the accepted installed image by
  immutable ID, Linux/ARM architecture, actual normalized Config and pinned
  baseline/lifecycle/READY/committed-image receipts. It preserves the original
  341 base versions plus all four original packages and their complete payload
  maps; the new execution commit may differ from the accepted baseline commit.
- The separate tooling lock binds 19 additional authenticated packages, official
  public keyring inputs and audit/source hashes. Counts distinguish 360 generic
  base-plus-tool packages from the complete **364** package image including the
  four originals. No dependency trimming or replacement of existing packages
  is accepted. Cache/archive/signature sizes and hashes are checked before and
  after copying; source pins are rechecked.
- Tool installation occurs only in a private writable container. The temporary
  TEST local pacman master imports the pinned official public keyring, trusts
  the explicit official primary, re-verifies all archive signatures/metadata,
  requires package/database signatures, disables scriptlets, masks global hooks
  and rejects package hooks. Existing original files and inventory are checked
  again. Temporary trust state is removed before a private local commit; parent
  layer erasure is explicitly not claimed.
- Process-only identity uses `/usr/bin/env`, preserving image Config.Env.
  Commit restores the accepted USER/WORKDIR/ENTRYPOINT/CMD, checks full normalized
  Config equality and is followed by a separate read-only installed-state/private
  view verifier. Existing images/container names are preserved; owned private
  names are removed and daemon absence is checked. Unknown commit outcomes or
  unverified cleanup fail the stage. No push/prune operation exists.
- Created specs are checked for immutable image, no network, restricted UID,
  cap-drop plus stage-specific metadata capabilities, no hardware devices,
  read-only binds, bounded tmpfs, 4 CPUs, 6 GiB memory/swap and 256 PIDs. Guest
  preparation and VM runtime are separate stages; the VM process is nonroot.
- Preparation copies the full private software tree into a bounded raw ext4
  fixture, preserves selected ownership/special modes, records guest changes
  and original payload hashes, and explicitly excludes extended-attribute/file
  capability fidelity. The signed generic kernel/direct-boot configuration is
  a separately source-audited input. No Asahi boot or macOS partitioning claim
  follows from this fixture.
- The fixed guest uses TCG, a generic ARM virt machine and virtio GPU, with no
  KVM/NIC/host display/audio/device passthrough. Boot, GBM, original payloads,
  compositor IPC/configuration, mapped client and phase/capture events are
  required; QMP and log/disk/time bounds are explicit. Actual execution remains
  unestablished by source inspection.
- Public output is a deliberate receipt-bound projection of guest events,
  selected bounded diagnostics and hashed minimal/overlay PPM frames. Raw disks,
  copied roots, private cache/key-init logs and image layers are excluded.
  Color count rejects blank frames but does not certify a desktop: status remains
  **CAPTURED_REQUIRES_VISUAL_REVIEW**, with visual/compositor/frame acceptance
  pending independent inspection. Hardware, acceleration, M2 16K and performance
  fields remain NOT RUN.

## Actual checks and readiness limits

Independently ran all **25 current portable tests: passed without skips**.
They cover contracts, cache/archive/source drift, ownership of disposable names,
resource/capability/connection refusals, bounded process groups/logs/QMP deadlines,
signature identity/revocation and hash-bound frame projection. They did not cover
the VD1/VD2 cancellation boundaries reproduced above.

Compiled `gbm_probe.c` temporarily with the source's C11/O2/Wall/Wextra/Werror
flags and installed x86 development headers/libraries: compilation passed.
With a spoofed guest declaration it exited 1 at `guest_guard`, before DRM,
reporting zero verified pixels and NOT RUN scanout/M2/performance. This is a
portable compilation/refusal check, not a native ARM or software-rendering result.

Snapshot hashes:

| Source/input | SHA-256 |
| --- | --- |
| Controller | `0e6e9e99d0b92615198bb42e41447c6a1d6c37e5d1294e0fe478b57c51c4f563` |
| Common runtime | `c5b5b0b62aa41c44ee1cb0778b31e559ba4a2d673a3be0590a36e4e4ee39c836` |
| Preparation | `22d9f926ef8b3965052585e9bb401502c9c53cccbd031f807db6ef85e7d1c4ff` |
| VM runner | `87992add6ffd1fb8f9effd900e5a1bf8c119c393613c24f3eaf3f687280eaf8a` |
| Guest | `8a31f3d251e6e60db7c0c33bfebb8d9e37fea7924a72fdce493a9388ccde143f` |
| Tooling auditor | `189af6c1ac05eecf1ba3cc9628760dc636ff45fc9ceab4e957d7a5eb3877d6d9` |
| Tooling lock | `a434c965eb05ed5b1d8487a597e84b4a0dd5480e69044d999d74a93546c9433b` |
| Tooling audit | `4878430402a9139541950c4d626c4a709b6ff606e2d09238e2228bc878675e00` |
| C probe | `fe0bb7b15df0bc93c4b5115543619e182ba3dac2ed22d0d8b1ab541d77a72efd` |

**Initial checkpoint was not source-ready for the next native phase:** validate VD1
and VD2 corrections, refresh changed common/controller source pins and freeze
the final controller contract. The actual accepted installed 345-package image
and completed original lifecycle/commit receipts are prerequisites; the failed
initial integration runs supply no replacement runtime proof. Afterwards review
the real 364-package tooling transaction/cleanup, prepared kernel/disk, TCG
guest/capture records and images independently. This generic virtual proof
cannot pass exact M2 platform, 16K, physical usability, stable release or full
R1–R5 acceptance.

## Final correction, input and resolver verification

October 12, 2026 local project date.

Independently reran the exact VD1 interruption window for both bounded and
LoggedProcess with real isolated children and TERM, INT and ALRM. All **six**
cases now reaped the child and restored the original handler. The corrected
spawning context defers Python handlers through handle registration and replays
cancellation into cleanup without blocking child signals. Constructor failure
cleans its registered group, pipes and log before rethrowing.

Reran the exact temporary/mocked native-controller VD2 main reproducer. A TERM
callback during late projection now produces CANCELLED true, retained **FAIL**,
and **False** return. Final-report checks also cover save/workspace finalization.
All **29 revised portable tests passed without skips**, including real bounded
child-registration regressions and the actual mocked-main late-projection case.
**VD1 and VD2 are resolved for the reproduced cases.**

The tooling closure is re-resolved against native input lock SHA-256
`3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650`.
Independently inspected the retained reconstructed local metadata for all **341**
packages against that exact input set and canonical inventory hash. Perl is
`5.42.3-1`; its dependencies/provides match the new pinned metadata. All other
**340** versions match the earlier accepted input set. All four captured sync
database hashes match the refreshed tooling lock.

Copied those databases/configuration into a separate temporary root/db/cache and
reran the same **pacman PRINT-ONLY** query. It exited zero and reproduced the
exact ordered **19-package** transaction, including versions/filenames/URLs.
The temporary root/cache remained empty. This is offline metadata resolution,
not a host/native installation; original resolver files and host configuration,
database, trust and package state were not mutated.

Independently checked the existing tooling cache, with no download. All three
official public keyring input hashes/sizes matched. The official certificate is
armored, so it was dearmored only into a new temporary public file and supplied
explicitly to GPGV. Reverified **all 19 actual archive signatures** with the full
expected primary identity, all archive/signature sizes/hashes, exact declared
metadata/relations and absence of hooks/scriptlets. All passed. No public-key
import, host/default-keyring change, private key, package extraction/install,
Docker or ARM program execution occurred in this verification.

Final source/input pins, independently compared with actual bytes and controller
constants:

| Changed source/input | SHA-256 |
| --- | --- |
| Common runtime | `6479ee7245be45617deb58dfe5c4e2ca8aa13493a500c6a61feb69008942c381` |
| Controller | `a249133480b5d00a1bd701380bfe5d480b1d768b0c3947278abae16b8ee86618` |
| Tooling auditor | `f2005ea8366f64cd81aa7fb7dbae9e60c835da77164adba4d8e434af262fda13` |
| Tooling lock | `7d7df36348ab70fded74fbcb6803e8a16bfece1fc29d439ca8ed1805a867bd25` |
| Tooling audit | `3a7c30ba244a874625da994f896ae080a2b60f092b04f5f2d6caa70239e4f41d` |

Preparation/VM/guest/C-probe pins retain the earlier values. Every controller
CORE/auditor/lock/audit pin matches; the audit contains every selected package
and binds the refreshed lock. The 360 generic plus four original package model
remains explicit and source readiness does not substitute for its actual
transaction, private image verification, disk preparation, TCG execution or
visual review.

**No remaining reproduced material blocker was found in this bounded final
source/input review.** Proceed with the controlled native phase only using the
actual accepted 345-package installed image and its complete prerequisite
receipts. The original eight native build results remain distinct from failed
fixture/audit/Hyprland integration stages and supply no lifecycle or guest GUI
PASS. Exact-model Apple/16K/hardware/performance/full R1–R5 requirements remain
unaccepted by this generic proof.
