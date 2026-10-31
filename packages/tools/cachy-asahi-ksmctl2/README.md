# cachy-asahi-ksmctl 0.1.0-2

This alternative recipe keeps the original read-only `cachy-asahi-ksmctl`
status/report command byte-identical and adds `cachy-asahi-ksm-experiment` for
explicit named **global scanning-control** experiments. It can write only
`/sys/kernel/mm/ksm/run`:0 pauses scanning;1 resumes scanning of memory already
eligible for KSM. It never writes2, requests unmerge, registers eligible memory,
changes tuning knobs, installs a service/drop-in, or enables an automatic policy.
Pausing does not unmerge pages. Restoring a scalar does not restore previous
memory contents or sharing. No improvement, safe workload policy, Apple kernel
qualification, native build or M2 result is implied by these software controls.

## Preview, explicitly apply, inspect, undo

Run all experiment steps as the same root identity. The program never invokes
sudo, polkit, a daemon or another command. The root requirement covers the live
interface and its saved state; it is not hardware authorization or a recommended
default. These commands deliberately change global scanning only when apply or
undo is explicitly requested:

```sh
sudo cachy-asahi-ksm-experiment preview pause-study --pause
# Read baseline/desired and copy the exact plan_sha256 from the JSON output.
sudo cachy-asahi-ksm-experiment apply pause-study --plan-sha256 EXACT_SHA256 \
  --confirm CHANGE_GLOBAL_KSM_SCANNING
sudo cachy-asahi-ksm-experiment inspect pause-study
sudo cachy-asahi-ksm-experiment undo pause-study --plan-sha256 EXACT_SHA256 \
  --confirm RESTORE_KSM_SCANNING_BASELINE
```

`preview NAME --resume-scanning` explicitly selects1 instead of0. A preview
captures the current value and boot generation, writes a new immutable baseline
plan and private journal, and does not write the KSM control. No argument chooses
a default experiment. Names are1..48 lowercase ASCII letters/digits/hyphens,
starting with a letter. Existing names cannot be reused. `--help`/`--version`
read no kernel/state interface. Unsupported actions, malformed state, missing
KSM or a current unmerge2 baseline refuse. Exit0 is a completed requested
software operation/observation; exit1 is refusal or uncertain operation, exit2
is invalid CLI syntax.

State lives only in `/var/lib/cachy-asahi-ksm-experiments`, created0700 on the
first preview. Plans/journals and the advisory lock are0600, owned by root.
There is no state/root/boot-path CLI option, environment override, restore-from-
arbitrary-file command or installed test mode. The live KSM and boot inputs must
be real sysfs/procfs respectively. The mutation command uses `/usr/bin/python3 -I`
to exclude user Python paths and environment configuration. Every path ancestor is opened without following
symlinks and rechecked; exposed control, boot, state-file and lock aliases or
identity/ownership/permission changes refuse. Plans bind the boot hash and
control/store identities; reboot makes an old plan unusable. SHA256 identifies
the reviewed local plan, not a signed remote authority or hostile-root defense.

The single store lock serializes cooperating helper operations across all names.
Another active/uncertain experiment blocks new preview/apply until inspected and
undone. Kernel values and file identities are checked again before writes and
readback. This is **not** external-writer compare-and-swap: an uncooperative
writer can change sysfs between check and write, and an ABA change cannot be
detected. Stop other KSM managers/editors during an experiment. Same-root hostile
writers are outside the protection boundary.

## Interrupted or failed operations

Before a kernel write the helper atomically publishes and fsyncs a journal
`APPLY_INTENT` or `UNDO_INTENT`, including its immutable plan hash, and syncs the
state directory. It sends one complete decimal line in one sysfs write, checks
the returned length and reads back the scalar. It never truncates/fsyncs the
sysfs attribute, trusts its advertised size as the read length, retries a failed
write or silently performs guessed rollback. Completion is published only after
successful readback. Failed readback, a short write, process death or failed
completion journal leaves the prior intent/uncertain state available.
A filesystem error after a journal rename can instead leave the new phase
visible with durability unknown; the command still refuses. Inspect the current
scalar and retained records before recovery. A returned error is never proof
that no kernel write occurred.

Inspect reports the saved phase and a separately sampled current value; a saved
phase alone is never current-kernel proof. After an intent, explicit undo permits
only the saved baseline or experiment scalar and restores the baseline if needed.
After a completed apply, a different current scalar refuses rather than restoring
over it. Observed run2 always refuses mutation. Successful undo and apply are
repeatable without another kernel write when the expected scalar still matches;
an undone plan cannot be applied again. No tool can detect an external writer
that returns the same value. Incomplete/corrupt/aliased journal records refuse;
do not erase an uncertain baseline merely to make a new experiment pass.

At most64 named records,16KiB per JSON,65 bytes per scalar read and38 bytes per
boot read are allowed. Each apply/undo has a5-second deadline checked between
operations; individual filesystem/kernel/fsync calls can outlast it. This is not
a hard real-time guarantee. Durable syscall ordering and abrupt-process recovery
are tested on local private files, not physical power-loss recovery.

## Packaging, source and validation

`packages/tools/cachy-asahi-ksmctl2` is an upgrade alternative producing the same
package name as v1, version0.1.0-2. It is not a second coinstallable package.
The frozen v1 recipe/source/accepted results and its original provenance remain
unchanged. The original command retains its original read-only behavior and
version0.1.0 output. Both installed commands, documentation, notices and complete
source provenance are under `/usr`; there are no package hooks. Removing the
package removes those files, leaves saved root state and current kernel scalar
untouched, and never automatically restores an experiment. Undo before removal
when restoration is wanted.

The original diagnostic is GPL-2.0-or-later, adapted from the exact retained
CachyOS source/commit in `NOTICE` and `source-provenance.json`; its source,
adaptation and GPL text are unchanged. The new helper/tests are original2026
project code under GPL-2.0-or-later. `experiment-provenance.json` records local
source hashes with no invented Git revision. Python3.11+ and Linux sysfs/procfs
are required. No upstream management implementation or optional policy validator
is executed or shipped as a management authority.

`check()` parses/verifies source, runs the held read-only regressions and new
private sysfs-like fixtures, and checks help. Research/build/check code never
writes real `/sys`, installs packages, changes a host DB or starts a privileged
actor. Private Python fixture injection rejects `/sys` and `/proc` and is absent
from the production CLI. Controls cover apparent sysfs size4096 with actual
two-byte EOF, single-store semantics, SIGKILL after a private write, journal/
readback/short-write failures, stale boot, external edits, malformed state and
symlink/hardlink/ancestor swaps. Local software evidence remains separate from
native ARM builds/installed lifecycle, real KSM/eligibility/workload security,
energy/OOM experiments, both physical M2 Air sizes and release admission.
