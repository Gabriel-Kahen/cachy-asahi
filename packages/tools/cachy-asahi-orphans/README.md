# cachy-asahi-orphans 0.2.0-1 successor proposal

This opt-in successor retains `assess`, `plan` and `verify` with their original
read-only meanings and adds explicit finite `remove` for private offline roots.
Root `/` is refused. It is not a selected release or general live-system cleaner.
The inherited contract is in READONLY.md; its historical no-removal statements
apply to the separate read-only component. Native removal remains NOT RUN.

## Invocation and identity

Assess an explicit conventional offline target, create a plan with exact repeated
`--select NAME`, and review its complete dependency/protection facts. Then invoke:

```sh
cachy-asahi-orphans remove /absolute/private/plan.json \
  --plan-sha256 REVIEWED_SHA256 --select exact-leaf-name \
  --result /absolute/private/new-result.json --timeout-seconds 60
```

The named command, reviewed hash and repeated exact selection are the invocation.
No extra confirmation flag is needed. There is no default selection, wildcard,
recursive removal, dependency expansion, force, arbitrary command or pacman-argument
forwarding. Empty plans stay valid read-only plans but cannot invoke removal.
Old assessment/plan JSON still reports `NOT_APPLIED`, `apply_supported:false`.

The SHA256, exact names/versions and original assessment inode/hash are checked
before opening a transaction and again before commit. The adapter acquires ALPM's
ordinary lock with exactly `NOHOOKS|NOSCRIPTLET`, retaining dependency, conflict
and version checks. Under that lock it recomputes the full installed snapshot,
reasons, reverse dependencies, hard/optional satisfiers, pinned floor and caller
protection. Its transaction cache must agree. ALPM prepare must return no additions
and exactly the reviewed removals. No cascade/recurse/nodeps/nolock flags exist.

The inherited component adds only an internal optional owned-lock checker and
snapshot entry for that checked lock. All public read-only defaults still refuse
every lock. ALPM creates mode000 locks: removal binds the regular single-link inode,
owner, mode, size and timestamps immediately after successful initialization; it
never reads/chmods the lock. Every later check and release requires that identity.
Only lock-induced DB-root size/times may differ before commit. After commit, only
selected local records and corresponding parent-directory size/times/link-count
changes may differ. Other records and opaque sync data must be identical.

## Supported subset

The existing offline root must be caller-owned and not group/world writable;
its DB must be ROOT/var/lib/pacman. Selected packages must be dependency-installed
leaves, with no install scriptlet or backup metadata. Selected files must be
regular, single-link, non-setid, exclusively owned by the selection, and have no
symlink ancestors. Only ordinary usr/bin and usr/share payloads and their parent
directories are supported. ALPM hooks, systemd, D-Bus, polkit, ALSA, PipeWire,
WirePlumber and existing Asahi audio/speaker-protection paths are refused.
The complete original base/platform floor and caller protection cannot be weakened.
No boot/kernel/firmware/graphics/audio/platform operation is added.

Target ldconfig executables or aliases at usr/bin/ldconfig, usr/sbin/ldconfig or
sbin/ldconfig refuse: ALPM flags alone do not suppress that helper. A full copied
base can correctly refuse. Do not remove platform files to bypass refusal.
General installed-system cleaning remains separate unfinished work. Root has a
minimal disposable native trial recipe, outside this package proposal.

All unselected ownership is checked against selected files. Selected identities
are rechecked after prepare; after commit the selected files must be absent and
the remaining installed map must match exactly. No backup/pacsave, script migration,
network, hook or scriptlet execution is supported. ALPM locking excludes cooperating
package-manager transactions, not hostile same-UID/privileged payload writers.

## Results and interruption

The result must name a NEW mode0600 file in an existing private caller-owned parent
outside the target. Existing files, unsafe parents, symlinks and replacements
refuse. The parent holds the descriptor and checks file/parent inode identities.
Phases are fsynced before entering commit and after its return. The final JSON also
goes to stdout. Precommit output failure prevents commit; postcommit output failure
reports failed/unknown or observed committed state, never false non-commit.

Results contain selected/prepared identities, before/after inventory SHA256/count,
plan/assessment identities, phase, commit-started/committed state, transaction/handle
release, lock state, errors and worker exit/reaping. The full before inventory
remains in the assessment. `APPLIED`/exit0 requires exact postchecks and cleanup.
Refusal/failure exits1; syntax exits2. An interrupted/failed commit keeps
`packages_committed:"UNKNOWN"`; a returned commit can instead be True with failed
postchecks or cleanup. There is no automatic retry, unlock or rollback.

The fixed fork worker has Linux parent-death SIGKILL protection. Work is bounded
at 1–120 seconds, followed by TERM, two seconds' grace and KILL/reap. Parent-side
errors also attempt bounded kill/reap. Signals are blocked during transaction
initialization until lock identity is captured. Uninterruptible kernel/filesystem
operations can exceed user-space bounds; unestablished reaping is reported.
A killed worker's remaining lock stays uncertain and is never removed. Replaced
locks prevent both transaction release and alpm_release, since either could unlink
a foreign lock. The process abandons the handle; exit reclaims its memory.
Parent SIGKILL can leave only the last durable phase. Inspect that receipt and the
target/lock before any further operation. No power-loss or boot-recovery claim follows.

Original limits remain:2048 packages,32MiB input,30s checked snapshot/query budgets.
Removal adds32768 ownership entries,4096 selected entries and64KiB result. Oversize
exact selections refuse before acquiring a transaction. ALPM error-detail memory
is reclaimed at finite worker exit, without unsafe errno-dependent union decoding.

## Provenance and checks

MIT source; all local recipe inputs are SHA256 pinned. Dependencies are Python3.11+
and pacman's trusted root-owned libalpm16 on Linux. No service, polkit permission,
automatic hook, Git checkout or repository-runtime dependency is introduced.
Repository-runtime supplies authentication helpers, not a transaction engine.
The adapter follows local_transaction/Apps fixed flags, exact prepare-set checks
and checked release patterns, without importing their fixture namespace machinery
or bypassing independent signed-release gates.

Run `python3 -B test_orphans.py`, `python3 -B test_remove.py` and
`python3 -I -B check_source.py`. The removal suite uses real read-only metadata and
empty lock holders, plus model fixture edits and recording ABI doubles. It NEVER
calls real ALPM remove/commit on this host. Host controls, native ARM packaging,
real disposable removal and physical M2 are separate evidence; the latter remain
NOT RUN until Root executes and retains the actual trial.

Shared selected/unselected directories require an existing unselected child outside
the selection, and their inode/owner/mode must survive. Potential removal of an
unselected-owned empty directory refuses before commit.


## Owned-child retirement correction

The supervisor now requires one main-thread owner, default SIGCHLD and a successful
default reset before fork. It observes with WNOWAIT without reaping until the last
possible signal, then uses direct waitpid. ECHILD or a failed ownership observation
permanently disables numeric signaling and reports unknown commit/exit/retirement,
with the last durable commit facts retained separately. No Popen status fallback
is involved. Independent/native reapers and hostile privileged interference are
outside this single-owner CLI contract. Eight real inert-child controls exercise
this boundary without ALPM operations; source/native/hardware evidence remain distinct.
The candidate version remains0.2.0-1 because the blocked source-only predecessor
was never dispatched or admitted as an archive; all new source identities are pinned.
