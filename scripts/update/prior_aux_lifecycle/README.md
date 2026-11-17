# Genuine prior-aux host TEST lifecycle

`test_prior_aux_lifecycle.py` is a standalone opt-in actor fixture. Importing it
does not run transactions; ordinary unittest discovery does not execute it.
It exercises the unchanged `prior_aux_runtime.apply` through real release
snapshot authentication, policy/configuration/capacity checks and libalpm
prepare/commit/checkpoint. No host package installation, dependency acquisition,
production trust or live session is involved.

The three distinct cases use fresh copied roots and fresh apply workers:

1. A signed synthetic587 baseline upgrades `selected`1-1→2-1, updates one data
   leaf, adds one and removes an obsolete leaf; the checkpoint advances.
2. A deliberate prior-archive edit at entry to the real precommit callback
   refuses before commit. The inherited engine still calls this phase `prepare`;
   `fault.json` independently records callback entry. The complete root map stays
   equal and the helper is not invoked by ALPM.
3. A real successful package commit is followed by a deliberately edited
   unrelated user file. Observe-after refuses with committed packages and an
   unchanged checkpoint; no rollback is claimed or performed.

## Explicit host fixture profile

This is a **TEST binding/closure override**, not unchanged production ARM
helper/comparator coverage. The frozen CachyOS x86_64 libalpm16.0.1 pin remains
`da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888`.
Neither its guard nor its transaction/signature flags are changed.

The only accepted helper/library inputs are the installed CachyOS
glibc2.44+r24+g16be1518495f-1 files, joined independently to its installed mtree:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `/usr/bin/ldconfig` | 1321200 | `8b5b2cb6ded837a2c645459d658afdfd8dd4cc4599edb981f7a018ac9dc4b829` |
| `/usr/lib/libc.so.6` | 2444640 | `848dae1dfcff0fc864292b28b2d426b0093425002a856a55c3a2b8ed31e2ea40` |

The helper is an x86_64 static PIE with no interpreter or NEEDED libraries.
These literal pins are checked before copying/execution. It runs chrooted only
inside the fresh fixture and initializes actual caches for source and copied
library inodes. At least one genuine native-library auxiliary key is required.

The original comparator source and its original ARM binding are validated by a
pristine loader instance. The test context selects the separate host helper and
scan closure and restores all fixture globals afterward. **Comparator-to-running
host-helper source correspondence is NOT VERIFIED; ARM explicit TARGETS are NOT
EXERCISED.** Both cache files must independently remain RAW_EQUAL. No ARM-tail
padding or cache-reorder exception can satisfy the host fixture.

ALPM ignores its built-in helper return, so ALPM success is insufficient.
[GDB fork tracking](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Forks.html)
and [exit events](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Events-In-Python.html)
observe the real helper `/proc/PID/exe` hash and its normal exit0. Both real
commit cases require this independent proof. All crypto, ALPM, capacity and
authorization methods remain real. Only the named fault-case filesystem edits
and the explicit host fixture profile are injected.

## Bounds, execution and evidence

Requires existing Python3.14, GPG/GPGCONF, GDB with Python, mount/umount, unshare
and the exact installed profile above. No tool is installed or fetched. The
runner refuses without an inherited cgroup enforcing memory≤512MiB, swap0,
one CPU and≤64 PIDs. Run it through a new user-owned transient scope with a
180-second runtime/10-second stop limit, `unshare -Urnm`, clean PATH/environment,
and explicit `--sandbox`/`--evidence` directories beneath a fresh private owned
scratch directory. The sandbox must be empty. `--worker` is internal only.

It mounts a64MiB/20000-inode nodev/nosuid tmpfs only in that private mount
namespace. Actual source/copy limits are16MiB/4000 nodes; the existing copier's
reserve and real filesystem capacity checks remain unchanged. Each debugger
worker is bounded to45 seconds and1MiB output. No canonical project lease,
container, hardware actor or workflow dispatch is used.

Per-case evidence retains signed public inputs and whole pins, complete source/
before/after node maps, actual inventory, transaction result, raw cache bytes,
helper exec/exit events, initialization and worker logs, capacities and copied
workspace retirement. TEST secret keys stay only in private tmpfs. GPGCONF exit,
owned-agent absence, private unmount, resource peaks and outer scope absence are
checked separately. Initial failed development logs remain separate from the
accepted final run.

This establishes a finite **host TEST component**. It does not qualify production
ARM closure/source correspondence, full587 Asahi composition, native ARM, either
M2 model, true-root installation, automatic recovery, performance or release.
