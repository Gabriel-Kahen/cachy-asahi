# ARM16K Rust stage0 VM adapter

Status: **source preparation only; no Source construction, archive extraction,
preparation, VM boot, Rust/Cargo invocation or runtime qualification performed**.
The implementation is isolated in
[`scripts/integration/arm16k_rust_stage0_vm`](../../scripts/integration/arm16k_rust_stage0_vm/README.md).
It changes no package inventory, Asahi platform component or existing adapter.
Root retains publication, authority, execution and admission responsibility.

## Evidence and scope

The retained official aarch64 GNU stage0 inputs are Rust **1.98.0**, although the
owning source-reference package concerns the later Rust 1.99 source. The three
archives total **108,298,076 bytes**. Their complete member inventories,
individual hashes, ELF geometry reports, component model and twelve notices
are copied as pinned DATA with origin paths recorded in `origin.json`.
`data/retained-acquisition.json` records the earlier verified-TLS acquisition
from `https://static.rust-lang.org/dist/2026-08-20/` with these exact filenames.
This worker did not repeat acquisition or authenticate a release signature.
Rust/Cargo carry MIT/Apache-2.0 terms plus the retained COPYRIGHT and Cargo
third-party notices; no broader source/license or distribution admission is
claimed by copying those notices. New adapter code uses MIT terms.

| Archive | Compressed bytes | SHA-256 |
| --- | ---: | --- |
| cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 11,116,188 | `5784379d73ac881d15a9e67eed2882cd58c747c276221c23cdf9aff37e015ff6` |
| rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 30,768,752 | `a36f7ac98af20ef0ba6368aace0345efabbebaef7962eba99f47190fd256162d` |
| rustc-1.98.0-aarch64-unknown-linux-gnu.tar.xz | 66,413,136 | `00590657f2356d7163ca5ef295283523974c340fa21bb94b420ce794f29b358c` |

The modeled component tree has 166 nodes, including 145 regular files totaling
511,504,024 bytes, before added fixture and notice files. Fourteen top-level
AArch64 ELF objects passed the retained static 16K load-segment geometry check.
That is **not a runtime result**; 33 nested archive/rlib objects were not parsed.
`rust-objcopy` has a different library-search qualification concern from
`rustc`; this fixture does not qualify every supplied executable. The Cargo
archive's `0.99.0` crate metadata is not an observed Cargo CLI version.

The baseline is the unchanged original111 prepared ARM16K reference at
`/tmp/cachy-asahi-arm16k-preparation-20261114-r5/assembly`. Its separate historical
first-boot report at `/tmp/cachy-asahi-arm16k-first-boot-root-20261114/report.json`
records an emulated aarch64/16K systemd, serial PAM builder session and normal
logout followed by natural QMP quit/reap. This adapter does not inherit a Rust
runtime result from that prerequisite.

The selected RTC/UI-seat kernel is the built-only bundle under
`artifacts/development/orchestrator-resume-20261114/Root-UI-seat-kernel-compile-r1/actor-output/stage/bundle`:
release `7.1.13-generic16k-managed-gui-rtc-uiseat1`, Image SHA-256
`36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494`.
The qualified owner image is
`sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a`.
Its retained device-help result establishes the selected QEMU/block declaration;
it does not establish the new guest's behavior. Full metadata pins are in
`data/base.json`, `data/kernel.json`, and `data/qemu-metadata.json`.

## Reviewable preparation and removal

Preparation is a separate explicit entry point. It requires an external,
digest-selected Root authority and an exact public Source readback receipt,
original baseline/report/consumed-marker pins, all three actual archive pins,
exact kernel/tool inputs, a fresh Root readonly guest-input certificate,
private original credentials, a reviewed local rootless daemon endpoint and
available resource reserves. Templates leave actual selectors NULL and both
allow flags false. Missing qualification refuses before output creation,
daemon use, cloning or actor submission.

The baseline has GNU binutils and glibc, but no GCC. Root must independently
inspect and certify the existing loader, GNU ld, CRT objects, runtime libraries,
link-time library selections and fixture tools, with actual hashes, resolved
paths and ALPM ownership/version, before preparation. The offline actor repeats
that check against a bounded readonly streaming inventory of the original image **before
cloning it**.
It must not install dependencies to make this pass.

The archive assembler prehashes all three compressed inputs before creating its
destination. It streams and verifies every reviewed member, including skipped
installer content, rejects unexpected members, links, sparse entries, bad
modes, duplicate/escaping paths and truncated or concatenated compressed data.
It strips only the reviewed root/component names and omits `manifest.in` from
the component tree. No `install.sh` runs. The twelve exact retained notices are
added under the private prefix, with their full license/third-party text.

The only root-filesystem additions are `/opt/cachy-asahi` when absent and
`/opt/cachy-asahi/rust-stage0` with its modeled tools, libraries, fixture and
notices. A complete readonly readback must prove all original namespace nodes
and all111 package-owned content, type and mode unchanged. There are no ALPM
transactions, hooks, services, shell-profile edits, replacements of global
tools, guest password changes or new boot/PAM settings. Installation/removal is
disposable fixture assembly/removal: discard only the newly owned output clone
and its attempt output after evidence retention. No host/target installer or
removal command is supplied.

## Finite guest protocol

Root boots only a new selected clone, with a separate Rust nonce and exclusive
attempt marker. The original PAM nonce and consumed first-boot marker remain
unchanged. The guest is software-emulated TCG with two CPUs, 2 GiB RAM, no NIC,
no KVM or other host device, and the exact 16K/RTC kernel. The owner container
has two CPUs, 3 GiB memory for preparation and **4 GiB for boot**, with no
additional swap, 256 PIDs, no capabilities,
no-new-privileges, a readonly root and no network. No GUI/performance result is
claimed.

The controller uses the retained ordinary PAM login path for builder UID/GID
1000, confirms systemd/logind/DBus and actual aarch64/16384 page size, then runs
the fixture with a cleared environment. All compiler outputs and Cargo state
live in a fresh mode-700 directory under `/home/builder/.cache`. Cargo is
`--offline --frozen`, has no dependencies, uses an empty Cargo home/target and
refuses ancestor Cargo configuration. The exact private `rustc` and `cargo`
versions must be 1.98.0; rustc's host and sysroot must match the selected target
and private prefix.

Both direct rustc and Cargo build/run the same small std fixture. It starts
four threads, checks the exact arithmetic sum 500050000, writes/syncs/reads and
removes a private file, and emits exact expected stdout. Linkage uses the
Root-certified native GNU ld, explicit existing CRT/loader/library inputs and
16K max-page-size flags. This has not been compiled or linked by the worker.
Compilation failure is a reported runtime qualification failure, not grounds
for silently adding GCC or relaxing the fixture.

The guest checks exact111 package names/versions and the conservatively
user-readable owned-file/link subset before and after the fixture. It cannot
read root-private owned files. A bounded guest `sync` is required. Normal PAM
logout precedes QMP quit. After signal-free natural QEMU exit, final reap and
empty process group, the same owner converts only the disposable overlay to
private verification scratch. Because QMP quit is not a shutdown, it replays
only committed ext4 journal records on that new verification copy and requires
a separate readonly filesystem check before streaming its inventory. It never replays or
repairs the selected base or the disposable boot overlay. An offline complete
all111 ownership comparison,
protected original PAM/boot/profile/nonce comparison and exact private-prefix
comparison must all pass before the host can report success. A changed owned
runtime file also causes HOLD; no exclusions are silently added.

Each preparation and boot operation has a total 600-second ceiling: 555 seconds
of work, then at most 45 seconds for cleanup/reporting. Guest compiler commands
have individual limits and a 360-second combined compiler budget. Remaining
host deadlines can refuse later phases. Raw logical size is at most 3 GiB
(the original geometry is retained), overlay file size at most **1 GiB**,
preparation allocated output at most **2 GiB**, boot allocated output at most
**2.5 GiB**, with at least 2 GiB free disk and 2 GiB host memory reserve beyond the
phase owner requirement (5 GiB minimum host MemAvailable for preparation,
6 GiB for boot). Watched subprocesses stop on output/allocation/reserve
violations. Cleanup Docker calls stop by second597, reserving the final three
seconds for reporting and retirement. If a child is still held after its local
budget expires, exactly one bounded 0.5-second emergency handoff retains
custody; its overrun flags force HOLD even if it exits zero. This never renews
passing work. These limits are proposed
and source-checked, not demonstrated runtime capacity.

The earlier 3 GiB boot owner allowed only 1 GiB beyond the 2 GiB guest for
QEMU, the actor and charged file cache. The new 4 GiB proposal adds 1 GiB of
headroom; its adequacy remains unmeasured. Root reported a different UI283 VM
exited -9 under a 3 GiB owner without memory.events evidence. That cause is
**UNKNOWN**; this source change neither diagnoses OOM nor proves a fix.

`memory.py` reads only fixed cgroup-v2 numeric files: memory.events, peak,
current, max, swap.current and swap.max. It creates exclusive mode600 receipts
before the VM, after QEMU retirement and finally after verification, flushing
each file and its parent directory. Each read is at most 4096 bytes and each
receipt at most 16384 bytes. It requires actual 4 GiB/no-swap cgroup limits before
launch; missing/unbounded/invalid data records REFUSED and blocks success.
The host retains available receipts on failure and requires all three observed
stages for PASS. Events are observations, not an automatic cause classifier.
A killed actor can leave exit/final receipts missing; absence is not OOM proof.
Only the small numeric-reader pattern was implemented here; no desktop adapter
or executable Root wrapper is copied or imported.

Filesystem free space is not the host UID's quota headroom. Root reported a
12.5 GiB own-UID shared-memory quota; the worker did not query it or change it.
Preparation reserves **2 GiB allocated plus 2 GiB reserve = 4 GiB initial
headroom**; boot reserves **2.5 GiB plus 2 GiB = 4.5 GiB**. These are additional free
headroom requirements at phase admission, after retained inputs/other outputs
have already consumed their charges. UI wrapper thresholds of 1500/1152 MiB
cannot be reused. Measure boot headroom afresh **after retaining preparation outputs**; these
are separate phase thresholds. Reserving both worst cases simultaneously would
need 6.5 GiB headroom. The earlier budgets are retained in
`data/budget-history-d8c10ee2.json`; its 6 GiB preparation allowance was an
allocated-byte cap, while the logical raw cap was 3 GiB.

Root authority now requires `resource_review.quota_guard` matching
`quota-guard.TEMPLATE.json`: actual host UID, output parent/device, phase,
operation, current Source-lock pin, initial headroom threshold and live 2 GiB
reserve, with status `ROOT_REVIEWED_OWN_UID_QUOTA_GUARD_FOR_ENTIRE_ACTOR`, method
`READ_ONLY_Q_GETQUOTA`, and unknown/exhausted handling `HOLD_AND_OWNED_CLEANUP`.
Root must supply the actual outer host guard, covering Python assembly and
all actor work, including intervals outside command watchers. The guard must
account for applicable soft/hard/grace and inode constraints, and stop safely
when required quota evidence becomes unavailable. The adapter deliberately
performs no quota syscall and does not duplicate a host-ABI-specific wrapper.
Its certificate gate is an explicit Root review boundary, **not proof that an
external monitor is running or a reservation of quota**. Root must implement
and review that outer monitor before issuing the certificate or launching;
a startup-only quota check does not satisfy this contract. Per-tree allocated
bytes and `df` checks remain independent supplementary checks. Disk-backed
scratch avoids treating shared-memory files as cost-free host RAM; Root must
account for the actual output filesystem in its memory review.

## Physical-budget successor

`data/allocated-budget-v2.json` records the facts, component caps and peak
model. The original prepared descriptor records 603,406,725 regular bytes and
31,097 nodes. Its sparse raw is 1,610,612,736 logical bytes and 617,082,880
allocated bytes. The worker also read only the fixed 1024-byte superblock and
file stat as passive DATA: 4096-byte ext4 blocks, incompat 0x22c2, rocompat 0x46b,
inode size 256. No complete baseline scan, export, tool or actor ran.

The previous preparation retained a baseline dump, raw clone, staged prefix
and complete readback dump together. Even deleting the first dump leaves a
complete prepared export of about 1.115 GB beside about 1.14 GB of allocated raw;
that already exceeds 2 GiB before other files. The successor exports no baseline
or readback bodies. It copies the existing independent ext4 reader unchanged,
with a thin deadline/identity/profile wrapper that hashes file bodies in place
and captures only bounded ALPM text (4 MiB per record,16 MiB total). It permits
256 MiB leaves for the 160,121,840-byte LLVM file, 150k nodes and2 GiB of total reader
I/O. Unsupported profiles, missing entries, changed hashes, incomplete111 joins
and unknown ownership still refuse. Readonly e2fsck remains required; the raw
parser does not establish filesystem checksum/allocation integrity itself.

| Concurrent physical component | Preparation | Boot verification |
| --- | ---: | ---: |
| Extended or verification raw, allocated blocks | 1280 MiB | 1280 MiB |
| Private staged prefix | 512 MiB | 0 |
| QCOW2 overlay | 0 | 1024 MiB |
| Output manifests, kernel copies, logs and directory overhead | 128 MiB | 128 MiB |
| Modeled peak envelope | **1920 MiB** | **2432 MiB** |
| Enforced total cap | **2048 MiB** | **2560 MiB** |

The input base must fit 640 MiB allocated. Stage0 has 511,504,024 regular bytes
plus 185,350 notice bytes; the 512 MiB prefix cap also covers fixture files,
ownership manifests and block/directory rounding. No compressed archives are
copied: all 108,298,076 input bytes are read from the readonly material mount.
Only one private prefix is assembled, then deleted after insertion before final
readback. Node/hash maps live in bounded RAM rather than exported trees.
The2 GiB envelope covers even the raw+prefix overlap during debugfs insertion.
Raw logical geometry stays the original 1.5 GiB, below the 3 GiB logical cap;
logical file length is never charged as physical allocation in this model.

Every component allowance is an **admission/refusal cap, not a measured peak**.
Preparation checks actual st_blocks for raw, prefix and metadata; streaming
assembly and inventory loops call periodic finite guards. Command watchers
retain allocated-total and live-disk-reserve checks. Boot conversion additionally
watches verification.raw allocated blocks during the child lifetime. Sparse
conversion can preserve nonzero deleted blocks or journal contents, so live
payload sums do not prove it will fit 1280 MiB; an excess refuses. Python inventory
checks retain the same guard/deadline, and all111/PAM/prefix comparisons remain
complete. This change removes material duplication; it does not relax package,
Source, natural-retirement, quota-monitor or hardware acceptance requirements.
Root must record actual peaks when running this new revision.

Frozen baseline process/ownership/RTC helpers remain byte-identical. Thin
adapters retain child custody across launch/cancellation, defer cancellation
only during owned cleanup, and route every owned Docker CLI through the frozen
final signal/reap supervisor. PASS requires natural signal-free QEMU completion
and verified owner-container absence; forced cleanup may dispose owned state
but cannot manufacture a passing result. QMP quit after logout is not a guest
shutdown qualification.

## Validation and remaining work

See `validation.json` for the exact fenced control results. Tests use tiny
synthetic archives, temporary DATA trees, parser inputs and mocked process
objects. They do not run retained payloads, compiler/linker, actual Source
construction, Root authority, preparation, Docker or QEMU. Bash syntax is checked.

Root must publish/read back the final Source, issue genuine phase-specific
inputs and authority, construct Source if desired, inspect the baseline guest
inputs, review resources, execute preparation and then a separate single boot,
and review all reports before admitting any emulated Rust compatibility claim.
All new actual Source/ref/authority/prepared/attempt/boot selectors remain NULL.
Native16K, M2, full Rust bootstrap, all14-tool coverage, performance and release
acceptance remain **UNQUALIFIED**.
