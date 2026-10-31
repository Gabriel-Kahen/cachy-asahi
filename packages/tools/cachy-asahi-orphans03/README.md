# 0.3.0-2 causal guard-order successor

Explicit `/` removal now refuses a nonroot operator before reading any plan,
policy or target database. Strict owner, mode, single-link, exact-plan, solver and
protected-state guards are retained. The privilege fixture uses pre-input
sentinels and UID1000/1001/65534 subtests rather than spoofing a real plan owner.
This successor has pure causal controls only; full recipe/native/ALPM validation
is for Root's next trial. Historical0.3.0-1 development evidence below is not
transferred as a passing build or lifecycle for0.3.0-2.

# Explicit live backend development candidate 0.3.0

The new `live` subcommand implements explicit-target orphan preview, exact reviewed
planning, and a real ALPM removal backend. Every operation requires
`--target-root`, `--target-dbpath`, `--policy`, and `--policy-sha256`. No mutation
target is discovered or defaulted to `/`. Existing read-only and finite offline
commands retain their separate contracts, documented below.

Actual ALPM16 reason, dependency, optional dependency and versioned-provider state
is inspected. Protection includes the pinned base/platform floor, the exact
operator-declared supported base/platform versions, Asahi/kernel/firmware/graphics
namespaces, and their actual installed provider closure. Preview eligibility also
checks payload ownership, selected scriptlets/backups/configuration, matching
removal hooks, frontend package-preservation policy, and helper effects. Plans
bind these facts and selected payload bytes/inodes. Simultaneous selection must
preserve hard and currently satisfied optional relationships.

## Explicit policy and CLI

The operator supplies a new mode0600 JSON policy with these exact fields:

```json
{"schema_version":1,"profile":"private-fixture","root":"/absolute/private/root","dbpath":"/absolute/private/root/var/lib/pacman","supported_base":{"test-base":"1-1"},"platform":{},"transaction_flags":1152,"hooks":"refuse-matching","scriptlets":"refuse","configuration":"refuse-selected","ldconfig":{"mode":"forbid"}}
```

That example is for an existing private fixture only. The `private-fixture` profile
requires a caller-owned0700 root and cannot authorize `/`. Production profile
`asahi-alarm-m2` requires the seven core and eight platform names in live_policy.py
with their exact installed versions, plus the explicitly supported base map. This
profile names an intended contract; it is not physical-M2 acceptance. No installed
inventory is automatically promoted into a policy or accepted supported base.

In an already authorized operator context, substitute explicit absolute paths:

```sh
cachy-asahi-orphans live assess --target-root ROOT --target-dbpath DB --policy POLICY --policy-sha256 POLICY_SHA --output NEW_ASSESSMENT
cachy-asahi-orphans live plan ASSESSMENT --target-root ROOT --target-dbpath DB --policy POLICY --policy-sha256 POLICY_SHA --select EXACT_NAME --output NEW_PLAN
cachy-asahi-orphans live remove PLAN --target-root ROOT --target-dbpath DB --policy POLICY --policy-sha256 POLICY_SHA --plan-sha256 REVIEWED_PLAN_SHA --select EXACT_NAME --authorize-live-removal --result NEW_PRIVATE_RECEIPT
```

Repeat `--select` for the exact reviewed set. Review target identities, versions,
protected/provider state, payload hashes, policy and effects before supplying the
plan SHA. All artifacts must remain private and owned by the same operator context.
Actual `/` apply additionally requires effective UID0. The CLI never invokes sudo
or acquires privileges. There is no cascade, recursion, force, nodeps, auto-retry
or auto-unlock mode. Source preparation does not authorize a host removal.

The worker locks ALPM, revalidates the complete installed/protected/selected state,
prepares the real transaction, requires no additions and exactly the reviewed
removals, then reopens all input, policy, DB, payload, hook/helper/configuration
facts immediately before commit. Postcommit checks require the exact remaining
inventory, unchanged unselected metadata and preserved shared owned directories.
Selected `/etc`, home, library/platform integration, backups, scriptlets, aliases
and unowned/shared file overlaps refuse. No user configuration is adopted or
migrated. Direct ALPM does not parse pacman.conf; the backend independently
preserves HoldPkg/IgnorePkg and refuses unsupported group/custom/indirect policy.
The fresh handle must have no configured logfile/syslog; durable private receipts
record this workflow without silently selecting a system log.

## Hooks, helper effects and interruption

NOHOOKS|NOSCRIPTLET (1152) remain mandatory. Matching removal hooks and unsupported
hook semantics refuse eligibility. There is no hook-enabled policy or apply mode.
No repository is registered or fetched; supported mirror includes are inert,
bounded configuration inputs. Unknown indirect frontend options refuse.

ALPM can invoke ldconfig despite NOHOOKS. The default policy refuses its presence.
A separately reviewed `ldconfig` policy may use exactly `mode: reviewed`,
`executable_sha256`, `config_sha256`, and `libalpm_sha256`. It binds the reviewed
runtime's fixed `/usr/bin/ldconfig`, main and included configuration. Its declared
effects include cache regeneration and possible SONAME symlink changes. The exact
libalpm build semantics must be reviewed; arbitrary ABI16 builds are not asserted
equivalent merely because hashes can be supplied. Helpers were not executed in
these controls. A target requiring unimplemented hook/helper/configuration
semantics remains refused.

The live supervisor creates a new worker session using a two-way ready/grant
barrier: no work starts until its parent verifies and registers that session while
retaining WNOWAIT ownership. Timeout/cancellation and the final group SIGKILL occur
before direct leader waitpid, including after natural worker exit. This covers
reviewed helpers that remain in the worker session. It does not prove descendant
exit, contain detaching helpers, or guarantee cleanup after abrupt parent SIGKILL.
Receipt fields distinguish leader reaping and session registration accordingly.
The original helper-free supervisor stays unchanged.

Ownership/status loss records UNKNOWN/null exit evidence and preserves last
durable commit facts. Interrupted/failed commit does not imply rollback and never
retries or clears uncertain locks. Resolve the outcome from the receipt, target
inventory and actual lock owner before generating a new plan. The ALPM lock
serializes cooperating package managers, not all payload/configuration writers;
stop external writers during apply. Boundary rechecks are not atomic against
hostile concurrent filesystem changes.

## Evidence and packaging

The25 integration controls use real ALPM queries, remove registration, prepare and
release, with commit simulated by temporary fixture-file edits. A separate bounded
component also passed a real ALPM commit removing exactly one inert leaf from a
script-created two-package private root, through the live session supervisor;
unselected configuration and the protected base remained unchanged, and the owned
lock/handle/leader were released/reaped. That is x86 private-fixture evidence,
not a host/live-target removal. No helper ran. Separate inert session controls
cover worker/descendant signaling. Native55 evidence stays separate. No ARM, M2,
release, performance or maintained-live acceptance follows.

The proposed package owns only its executable/private runtime, documentation and
license files; it adds no hook, service or automatic activation/configuration.
Original package lifecycle and native checks remain required before integration.

---

The retained documentation below describes the original finite offline backend.

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
