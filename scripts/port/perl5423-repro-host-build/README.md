# Fixed Perl 5.42.3-1.3 host pair

Status: **concrete driver; actual pair blocked by capacity**. The source candidate
at `c8e9baea97f83f652763e701143d6dec5b679f31` is pinned in `inputs.json`.
No 1.3 compilation, upstream harness, package archive or byte reproducibility
result exists from this driver. See `validation.json` for the actual refusal.

This successor owns only this directory and fresh private output/resources.
It imports authenticated helpers from `../perl5423-host-build/`, the finite FDK
runtime and the existing capacity/decoded-archive helpers read-only. The original
1.2 builder, both candidates and previous evidence remain unchanged.

## Fixed execution contract

Run from the repository with host Python 3.14 (`compression.zstd` is required):

```sh
python3.14 -I -B scripts/port/perl5423-repro-host-build/run.py \
  --source /absolute/path/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603.tar.gz \
  --output /absolute/path/to/fresh-private-output
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

Initial inode demand is 80,000 for Docker work, 12,000 for exports and 10,000
reserve per device. The existing capacity helper refuses unknown/free inode
counts of zero. Btrfs on this host reports zero total/free inodes; that means this
contract cannot prove inode capacity, **not that Btrfs has exhausted its inodes**.
Freeing bytes alone therefore does not satisfy the current strict guard.
The memory check requires 8 GiB MemAvailable: the 4 GiB actor plus 4 GiB reserve.

## Verification limits

`python -I -B -Werror::ResourceWarning test_driver.py` exercises nine controls,
including capacity/remote-daemon refusal, final input rechecks, export identity
and timestamp refusal, complete comparison, sequential retirement and
cancellation cleanup. Docker success/cancellation in those tests is simulated
and cannot qualify a build. The actual local run stopped before allocating an
input snapshot or any Docker build resources. No prior archives are reused.

Native ARM, 16K, M2 (both Air sizes), installed lifecycle/ABI, external XS,
performance, legal-policy, production trust and release acceptance remain open.
