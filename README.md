# Rust stage0 on the original111 ARM16K reference

**SOURCE ONLY.** No archive extraction, Source construction, preparation, daemon,
VM, Rust/Cargo invocation or new runtime qualification has run. Root owns the
operational steps. See [the port note](../../../docs/port/arm16k-rust-stage0-vm.md)
for inputs, preserved platform boundary, protocol, resources and limitations.

This adapter is independent of the existing ARM TCG, RTC and lifecycle helpers.
`origin.json` pins exact retained DATA and unchanged frozen helper copies.
`source.lock.json` closes this directory's complete file/byte/mode membership;
actual Source/ref/authority/prepared/attempt/VM selectors are NULL.
`validation.json` records only fenced controls.

## Entry points

- `construct.py`: explicit isolated code/DATA Source constructor, no archive/raw
  payloads or operational calls. Its prospective tree is the standalone copied
  subtree, not the repository's public Git tree.
- `prepare.py`: separately authorized Root offline preparation. Its actor
  `prepare_image.py` checks the original image before cloning and writes only
  `/opt/cachy-asahi/rust-stage0`, with complete readonly readback.
- `boot.py`: separately authorized, exclusive fresh attempt, ordinary builder
  PAM login, actual rustc/Cargo fixture, logout, natural QMP quit and complete
  offline ownership/PAM/prefix comparison before PASS.
- `stage0.py`: exact finite streaming member verifier/assembler. Installer
  scripts are hashed as DATA and never executed.
- `contracts.py`: all Root/source/material/kernel/tool/guest-input/resource
  gates; missing qualification refuses before clone/actor/daemon use.
- `runtime.py`: fixed local-rootless transport and supervised child custody.
- `memory.py`: durable bounded cgroup-v2 numeric receipts; no cause inference.
- `image.py`: streaming raw ext4 hashes and bounded ALPM records; no full exports.
- `data/allocated-budget-v2.json`: modeled2 GiB preparation/2.5 GiB boot limits,
  1 GiB overlay and retained prior budget; actual peaks remain unmeasured.
- `ownership.py`, `protocol.py`: pure bounded ownership/serial checks.

The executable entry points require ordinary host user, Python `-I -B`, explicit
allow flags, fresh disjoint private outputs and digest-selected Root inputs.
Imports do not launch operations. No public source or authority is fabricated
by the worker. These are future Root command shapes, **not executed commands**:

```text
python3 -I -B /ABS/construct.py --allow-source-construction \
  --source-lock-sha256 ROOT_REVIEWED_LOCK_SHA256 --output /PRIVATE/FRESH/source

python3 -I -B /ABS/prepare.py --allow-prepare \
  --base /EXACT/original111/assembly --base-first-boot-report /EXACT/report.json \
  --materials /EXACT/official-stage0-archives --kernel-bundle /EXACT/rtc-bundle \
  --qemu-metadata /EXACT/Root-device-help-r2.json \
  --guest-inputs /PRIVATE/Root-guest-inputs.json --publication /PRIVATE/Root-publication.json \
  --authority /PRIVATE/Root-prepare-authority.json --authority-sha256 ROOT_DIGEST \
  --output /PRIVATE/FRESH/prepare

python3 -I -B /ABS/boot.py --allow-boot \
  --base /EXACT/original111/assembly --base-first-boot-report /EXACT/report.json \
  --materials /EXACT/official-stage0-archives --kernel-bundle /EXACT/rtc-bundle \
  --qemu-metadata /EXACT/Root-device-help-r2.json \
  --guest-inputs /PRIVATE/Root-guest-inputs.json --publication /PRIVATE/Root-publication.json \
  --authority /PRIVATE/Root-boot-authority.json --authority-sha256 ROOT_DIGEST \
  --prepared /PRIVATE/prepare/actor-work/assembly --prepared-sha256 ROOT_DIGEST \
  --output /PRIVATE/FRESH/boot
```

Root must replace templates with real evidence. The guest-input template cannot
be filled from architecture declarations or the worker's static review: it
requires actual readonly baseline file/CRT/ld/loader/library inspection. Private
credentials remain outside Source, mode600, and are never printed. Boot now
requires a 4 GiB no-swap owner plus 2 GiB host reserve (6 GiB MemAvailable); preparation
remains 3 GiB plus 2 GiB. Root must implement/review a readonly outer own-UID quota
guard across the whole actor and embed the completed quota-guard template in
`resource_review.quota_guard`: initial headroom 4 GiB prepare / 4.5 GiB boot, live 2 GiB
reserve. Check boot quota headroom afresh after retained preparation outputs
are charged. The adapter makes no quota syscall; `df` or a startup snapshot alone
is insufficient. Preserve
attempt/report/log evidence; removal concerns only the newly owned clone/output.

## Fenced checks

From this directory, with no operational selectors:

```sh
ulimit -v 131072
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -v
bash -n guest/check.sh
```

These controls never invoke Root operational entry points or actual compiler,
linker, archive payloads, container daemon, VM or network. No build/boot claim
follows from their passing.

## Proposed direct dynamic libgcc selection successor

This unbuilt successor requires a new Root certificate kind
ARM16K_RUST_STAGE0_BASE111_DYNAMIC_GCC_INPUTS_V2. Its gcc_s input is exactly
/usr/lib/libgcc_s.so.1, already among the fixed required runtime paths. The
other six direct-ld library searches and their independent closure checks remain
required. The resulting path union has39 rows (33 fixed plus6 distinct selected
paths), rather than Source65's40. Source65 and its failed r6 evidence are retained.

The r6 retained 132-byte libgcc_s.so script contains
GROUP ( libgcc_s.so.1 -lgcc ). The retained .so.1 is a133352-byte AArch64 ELF,
SHA256 ac598673a4bf67c0295b6609e46b1fafd0d4adf3f80a513d61ac49ecff772e48,
owned by libgcc16.1.1+r12+g301eb08fa2c5-1. These are expected future input pins,
not a Root-issued certificate or completed guest/closure qualification.

Both rustc and Cargo select fixture/link-stage0.sh with unchanged ld flavor.
This fixed Bash adapter replaces exactly one dynamic -lgcc_s token with the
absolute ELF path before one exec of /usr/bin/ld. It preserves other argument
bytes/order, refuses a missing/duplicate selection, static gcc operands, static
gcc_s context and response files, and limits argv to512 entries/131072 bytes.
Appending .so.1 alone would leave the original script selection possible.

This deliberately bypasses the script's static libgcc contribution. If the
fixture needs symbols unavailable from .so.1/Rust's existing compiler builtins,
the future link must fail and remain HOLD; no library, dependency or compiler
is installed and no failed symbol is silently ignored. The command/data tests
do not establish that the real Rust fixture will link or run.

Official stage0 archives are reused by path and pin without copying payloads.
PAM login, builder identity, original nonce/marker, ordinary-user direct and
offline Cargo thread/arithmetic/file probes,16K checks, full111 preservation,
clock protocol, all resource budgets and frozen helpers are unchanged. Root
must independently review/publish this Source, obtain a fresh complete39-row
certificate plus ELF/remaining-script/archive closure, then authorize any run.
All future actual Root publication/certificate/authority/VM fields remainNULL.

Each real linker invocation must create a fresh private direct-ld.receipt or
cargo-ld.receipt (mode0600, no overwrite). It records original/replaced argv
with Bash %q quoting, counts and fixed /usr/bin/ld operand before exec. Bounded
refused vectors also get a REFUSED_BEFORE_EXEC receipt with original argv and
zero executed/replacement arguments, so unexpected static defaults stay visible. Receipt
size is capped at65536 bytes each. finish emits both nonce/phase-delimited
receipts outside the unchanged Rust result frame into the retained serial log,
including any available receipt on failure. Missing receipts forceFAIL. Their
pre-exec status never asserts a successful link. Root must treat quoted argv
as DATA, never eval it. No frozen serial/parser limit is increased. The wrapper
uses the existing certificate-required /usr/bin/bash, not guest Python.

## HOME/Btrfs capacity-guard successor

This Source-only contract extension retains the strict READ_ONLY_Q_GETQUOTA
branch and adds only an explicit Root-reviewed HOME/Btrfs guard declaration.
The new mode requires /home/gabe, UID1000, device54, Btrfs /@home/subvolid257,
repeated ENOSYS38 ownUID quota observations, live fstatvfs and the same finite
output/reserve/phase limits. Zero inode counters mean NOT_REPORTED; the bounded
15000-node output census still applies. No positive quota/inode capacity is
invented, other quota/qgroup constraints remain UNCLAIMED, and capacity is not
reserved. EPERM/EINVAL/other errors, unknown filesystem identity, allocation/
inode/ENOSPC failures or monitor loss HOLD with the existing cleanup policy.

The new quota-guard-home-btrfs template is wholly unissued. Root must separately
review the profile and monitor, publish/read back this new Source, and supply
its genuine authority. Source68, all frozen helpers, guest linker/probes, PAM,
39-row V2 certificate kind/consumer and baseline111 checks remain unchanged.
The genuine39-row Root certificate produced from Source68 observations remains
baseline evidence with that original provenance; this filesystem-only Source
delta does not require new debugfs extraction or relabel that producer.

No actual ownUID quota/Btrfs query, actor, VM, linker, compiler, lease, network
or publication is performed by the worker. Future public Source/grants/runtime
selectors remainNULL.
