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
`resource_review.quota_guard`: initial headroom 8 GiB prepare / 6 GiB boot, live 2 GiB
reserve. The adapter makes no quota syscall; `df` or a startup snapshot alone
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
