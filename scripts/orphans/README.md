# Disposable Orphans removal adapter

This development script composes the existing read-only Orphans planner with the
existing signed Apps transaction backend. It can remove only a nonempty exact
caller selection that both planners independently allow in an explicitly owned,
offline disposable copied root. The installed Orphans package and Welcome remain
read-only; no package or desktop integration is part of this proposal.

Use Apps' existing `prepare-copy` operation to create the copy and obtain its
ownership hash and four complete before pins. Generate an Orphans assessment and
explicit removal plan against that exact `WORKSPACE/root` and conventional
`WORKSPACE/root/var/lib/pacman` database. Separately generate the unchanged Apps
signed `plan remove APP...` against a complete collected inventory of the same
copy. Orphan names are package names; Apps application IDs are separate operands.
The signed Apps plan must remove exactly the selected names/versions and contain
no additions, upgrades, dependency expansion or conflicts. Being an orphan does
not authorize removal or synthesize a signed catalog entry.

Invoke `transaction.py apply` with all of these explicit operands:

- Existing Apps inputs: `--workspace`, `--ownership-sha256`, `--apps-source`,
  `--apps-provenance-sha256`, `--repository-source`, `--release`,
  `--release-sha256`, `--catalog`, `--catalog-sha256`, `--catalog-signature`,
  `--keyring`, `--signer`, `--plan`, `--plan-sha256`, `--applications APP...`, and
  `--before-{tree,database,packages,inventory}-sha256`.
- Adapter inputs: `--apps-backend-sha256` pins canonical
  `scripts/apps/transaction.py`; `--orphans-source DIR` and
  `--orphans-source-sha256` pin the unchanged `cachy-asahi-orphans` script;
  `--orphan-plan` and `--orphan-plan-sha256` pin its saved mode0600 plan;
  `--selected-names PACKAGE...` names the exact nonempty removal set.
- Both `--confirm-orphan-removal` and `--confirm-disposable-transaction`.
- For a full574-owned copy, forward all four original operands unchanged:
  `--full574-policy`, `--full574-policy-sha256`, `--full574-lease`,
  `--full574-lease-sha256`. Partial or missing authority is refused by Apps.

The adapter has no install operation, autoremove, implicit selection, force,
no-dependencies, privilege escalation, network or lock-deletion path. Existing
Apps mapped-root/offline/environment/copy-ownership/provenance/authentication and
payload guards remain active. An ordinary host invocation refuses before opening
an ALPM transaction. The fixed backend is compiled from the exact checked source
bytes, rather than rereading an unpinned file at import. Orphans retains its own
pinned protection-floor and root-owned fixed-system-libALPM checks.

Preflight holds the existing Apps workspace lock and requires the caller's four
pins to match an actual complete copied-root observation. It authenticates a
private snapshot of the independent Apps release/catalog/plan using Apps' public
APIs. It scopes the saved Orphans assessment to the guarded copied root, then
calls the unchanged Orphans `plan()` verifier against current ALPM metadata:
reason, reverse dependencies, protected packages, saved database identity,
simultaneous hard dependencies and currently satisfied optional dependencies all
remain checked. A second complete Apps observation must equal the caller pins
and the first observation. The original Orphans plan must remain unchanged.

After releasing the workspace lock, the adapter calls Apps' public `apply()`
exactly once in its supervised worker. Apps reacquires its workspace lock,
reauthenticates and regenerates the signed plan, compares all four before pins,
acquires the ordinary ALPM transaction lock and rechecks the entire root except
its own zero-byte lock before commit. Thus Orphans' conclusions are bound to the
same metadata contents that Apps authorizes and commits against; intervening
content/mode/owner drift refuses. The owner must exclude other actors from this
workspace, as required by Apps.

There is no new locked callback and no monkeypatching of the transaction engine.
Orphans deliberately refuses an existing ALPM lock. The composition does not
assert that Orphans runs under that lock or that Apps' content hashes preserve
Orphans' inode/ctime identity fields through execution. A stronger requirement
for fresh orphan computation on the already-locked ALPM handle would need an
explicit Apps precommit-validator API and an Orphans API that consumes that
handle. Neither bypass is implemented here.

Full574 policy is unchanged: all original574 packages remain immutable; only its
four exact current candidate packages can be selected. The adapter cannot remove
arbitrary baseline orphans, widen the catalog, alter a protection floor or waive
policy/lease checks. It can succeed only for the intersection of current Orphans
and signed Apps authorization.

The default CLI uses the existing Apps supervisor:300 seconds,1MiB combined
output, process-group retirement and direct-child reaping. Python `apply(args)`
is only for an already supervised owner. Pre-delegation failures report no
commit. The backend's actual success/failure/commit/cleanup fields are preserved;
adapter or worker uncertainty reports UNKNOWN and requires disposal. There is
no retry or rollback. Existing Apps pending-marker, ALPM locking and cleanup
behavior is reused. Never delete a lock or reuse an uncertain copy: retire all
actors and discard the disposable outer container when cleanup cannot be proved.
Use Apps' normal explicit `dispose-copy` only after a known completed attempt
with no active ALPM lock.

Run focused local controls with `python -B test_transaction.py`. The separately
labelled `handoff/test_actual_synthetic.py` creates temporary signed any-package
fixtures and a new mapped user/mount/network namespace. Its private read-only
bind of a byte-identical caller-owned libalpm at the existing fixed system path
satisfies the unchanged root-ownership check inside that mapping; host library
bytes/mounts are unchanged. This is namespace fixture plumbing, not a production
library override. Signing authority remains outside transaction workers.

The handoff records actual test results and exact source/evidence pins. Synthetic
x86 success is not full574, native aarch64, installed-package, M2, safe host
removal, release freshness or stable-admission evidence. Root owns adoption,
source freezes, future actual-owner bindings, packaging and admission.
