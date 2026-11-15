# Fixed Perl 5.42.3-1.3 host pair

Status: **actual sequential x86_64 host pair passed with byte-identical archives**.
Driver commit `ba220c029a799f3fd311860ad59429951eed4643` built the exact 1.3
candidate at `c8e9baea97f83f652763e701143d6dec5b679f31`. Both ordinary clean
builds and full upstream harnesses passed; the untouched compressed archives and
all 3,262 decoded entries match. See `RESULTS.md` and `validation.json`.
This qualifies this host pair only; installed/native/target/release gates remain
open. Earlier capacity refusals are retained in Git and private evidence.

This successor owns only this directory and fresh private output/resources.
It imports authenticated helpers from `../perl5423-host-build/`, the finite FDK
runtime and the existing capacity/decoded-archive helpers read-only. The original
1.2 builder, both candidates and previous evidence remain unchanged.

## Fixed execution contract

Run from the repository with host Python 3.14 (`compression.zstd` is required):

```sh
python3.14 -I -B scripts/port/perl5423-repro-host-build/run.py \
  --source /absolute/path/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz \
  --output /tmp/perl-repro-host-pair-fresh
```

The output parent must exist. `--capacity-only` performs the authenticated input
and local Docker capacity checks without making build resources; its successful
exit is explicitly different from successful builds. No capacity bypass or
one-build option exists. The daemon must use a local Unix socket; a remote
Docker context is refused before local filesystem accounting.

- Exact cached official amd64 base and frozen 2026/11/09 signed dependency
  provisioning are inherited without changes. Only the disposable provision
  container uses the network. No host package manager runs.
- Each actor has 2 CPUs, 4 GiB memory, zero swap and 256 PIDs; UID/GID 1000,
  read-only root, dropped capabilities, NNP, offline network, immutable input
  snapshot and one private named work volume. Actual inspect/cgroup evidence is
  required. The upstream default full harness and ordinary dependency-checked
  `makepkg --cleanbuild --nosign --noconfirm --log` remain intact.
- The first exported archive and all retained export identities are checked and
  recorded before its actor, initializer and work volume are removed. Name
  inventories must prove retirement before the second volume is allocated.
- The staged interpreter must report the canonical source-epoch `cf_time`
  `Sun Aug  2 00:00:00 UTC 2026`; the generated `config.over`, source configuration,
  actual C extension smoke, source/build maps and package metadata are retained.
- Both full compressed archive identities (bytes and SHA-256) and every decoded
  entry's metadata/content/link identities must match to return
  `PASS_HOST_PAIR_BYTE_IDENTICAL`. A successful harness alone cannot return it.
  No clock shim or source/archive normalization runs.
- The existing finite runner supplies the 4800-second operation deadline,
  900-second provisioning and 1500-second per-build limits. Cancellation/failure
  uses a separate 60-second harvest and 180-second cleanup budget. A stopped
  owned actor's makepkg log may be preserved as at most 8 MiB of DATA tar,
  requiring 32 MiB capacity plus the 1 GiB reserve; truncation/failure is labeled.
  Cleanup attempts every registered resource and requires final absence checks.

## Capacity contract

Capacity is checked before input snapshot allocation, provisioning, image commit,
each volume/build actor and each export. Requirements on the same device are
added, with one 1 GiB reserve per filesystem. At initial admission:

| Allocation | Budget |
| --- | ---: |
| Provision/commit image growth | 2048 MiB |
| One complete work volume | 2048 MiB |
| Two exports including decoded inspection scratch | 512 MiB |
| Immutable input snapshot | 64 MiB |
| Shared filesystem reserve | 1024 MiB |
| **Peak on one filesystem** | **5696 MiB (5,972,688,896 bytes)** |

The provisioning allowance exceeds twice the previous 573 MiB installed plus
130 MiB downloaded dependencies and leaves room for image copy-up/commit. The
work allowance covers a complete source/build/stage tree; the inherited
provenance collector itself refuses source maps beyond 1 GiB. These are
conservative admission estimates, not measured maxima for 1.3 or atomic
reservations against other applications. Unrelated disk use can change capacity.
Decoded inspection scratch is placed in the private output directory so its
filesystem is covered by the export allowance. Before commit, only the remaining
1024 MiB image allowance is requested because the provision layer already exists.
No alternative tmpfs work-volume profile is silently selected.

With the explicitly supported output under `/tmp`, Docker/home requires the
unchanged **5120 MiB (5 GiB)** image/work/reserve budget. The separate tmpfs
requires **1600 MiB** for source snapshot, both exports/scratch and its own 1 GiB
reserve. These amounts are added when paths share a device. No allowance is
removed by choosing a different output filesystem.

The filesystem-specific model in `capacity_profile.py` authenticates the exact
path and mount before and after each measurement. It joins GNU stat filesystem
type/magic/ID, actual path and mount-target `st_dev`, statvfs ID, findmnt's
UUID/source and the exact kernel mountinfo device/target/source/type entry.
Btrfs mount device numbers and subvolume `st_dev` are recorded separately.
Shared Btrfs UUID/statfs identities across distinct device groups are refused;
the shared capacity helper cannot safely aggregate that layout.

[Btrfs creates inodes dynamically](https://btrfs.readthedocs.io/en/latest/Administration.html#filesystem-limits).
For authenticated Btrfs only, actual `f_files=f_favail=0` is recorded as
`UNREPORTED_DYNAMIC`. No positive free-inode count is invented. One raw
`Metadata,DUP` and global-reserve record must be parsed from a successful
read-only `btrfs filesystem usage -b EXACT_PATH` query. The model subtracts the
entire global reserve from allocated-but-unused metadata, requires its used
count to be zero, then requires **512 MiB workload headroom plus 512 MiB retained
metadata reserve** for at most **102,000 nodes per device**. These are explicit
bounded engineering budgets, not a universal bytes-per-inode guarantee. The
[global reserve belongs to metadata](https://btrfs.readthedocs.io/en/latest/btrfs-filesystem.html#subcommand).
Failed/malformed queries, mixed/unsupported profiles, low headroom, inconsistent
counters and mismatched/changing filesystem identities refuse admission.

Ext2/3/4, XFS and tmpfs retain the exact reported free-inode checks, including
refusal of a real zero pool. Unknown filesystems refuse admission. Original
inode demand is 80,000 for Docker work, 12,000 for exports and 10,000 reserve per
device. Only the proven Btrfs dynamic case uses a zero **inode demand** in the
shared helper, with the metadata check replacing that inapplicable fixed-pool
check; original counters/demand remain in the receipt. Byte checks always use
real statvfs availability and unchanged budgets. The memory check still requires
8 GiB MemAvailable: the 4 GiB actor plus 4 GiB reserve.

## Verification limits

`python -I -B -Werror::ResourceWarning test_driver.py` and
`test_capacity_profile.py` exercise twenty-one controls,
including capacity/remote-daemon refusal, final input rechecks, export identity
and timestamp refusal, complete comparison, sequential retirement and
cancellation cleanup. Docker success/cancellation in those tests is simulated
and cannot qualify a build. After Root reclaimed owner-confirmed obsolete
resources, the actual pair
passed all nine fresh byte/metadata/RAM gates and completed both builds. Five
owned containers, two work volumes and the derived image were removed and
absence verified. Raw exports and receipts were retained with matching file
identities. No prior archives were reused.

Native ARM, 16K, M2 (both Air sizes), installed lifecycle/ABI, external XS,
performance, legal-policy, production trust and release acceptance remain open.
