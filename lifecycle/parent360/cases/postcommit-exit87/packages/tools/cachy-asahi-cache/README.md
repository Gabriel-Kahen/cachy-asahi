# cachy-asahi-cache 0.2.0

Inspect package-cache archives, protect explicit local objects, and apply a
reviewed selection under a **real libalpm transaction lock**. Default `list`,
`plan` and `verify` commands are read-only for the cache and ALPM. Only explicitly
confirmed `apply` moves and deletes selected archives/signatures. It never
installs, uninstalls, upgrades or removes orphan packages, changes package records,
updates databases, clears a preexisting lock or changes host configuration.

This is an unselected source candidate. Host tests use temporary roots/databases
and real libalpm16. Native ARM packaging, installed lifecycle, Asahi/M2 operation,
storage power loss and maintained release admission are untested.

## Inspect and declare local protection

```sh
cachy-asahi-cache list --cache /var/cache/pacman/pkg --dbpath /var/lib/pacman
```

JSON lists ordinary archives/signatures with byte count, SHA256, mode, uid/gid,
device/inode, link count and modification/change times. Unrecognized names,
including partial downloads, are ignored and retained. Names are not evidence of
package validity or obsolete versions; nothing is selected automatically.
Archives are never extracted or executed, and signatures are not authenticated.

Create a caller-owned mode0600 protection JSON outside the cache/database. Choose
the archives yourself and supply exact bytes/hash from your local records:

```json
{
  "schema_version": 1,
  "cache": "/var/cache/pacman/pkg",
  "protected": {
    "example-1-1-aarch64.pkg.tar.zst": {
      "bytes": 123,
      "sha256": "<exact 64 lowercase hexadecimal characters>",
      "signature": {"bytes": 456, "sha256": "<exact signature hash>"}
    }
  }
}
```

This explanatory example needs real values. Use `"signature": null` only if the
associated `.sig` is absent. Existing signatures cannot be omitted; every
protected object must match. An empty `protected` map explicitly declares no
protected archives. This policy establishes **no signed-release, supported-system,
known-good rollback or boot-recovery authority**. Deciding what to preserve and
whether recovery is possible remains the operator's responsibility.

## Prepare a fresh version2 plan

```sh
cachy-asahi-cache plan --root / \
  --cache /var/cache/pacman/pkg --dbpath /var/lib/pacman \
  --protect /root/private/cache-protection.json \
  --select example-old-1-1-aarch64.pkg.tar.zst \
  --output /root/private/cache-plan.json
cachy-asahi-cache verify /root/private/cache-plan.json
```

Use paths owned/readable by the account running the operation. The tool performs
no privilege escalation. System cleanup normally requires the administrator to
prepare/review a mode0600 plan and policy owned by that same account. Repeat
`--select` for exact basenames; globs, paths, partial downloads and standalone
signatures are refused. Associated signatures are included automatically. No
selection produces a no-op plan. `planned_bytes` is a preview, not reclaimed space.

Plans remain `NOT_APPLIED`. They bind the target root, cache/database directories,
all inspected cache objects and ignored names, protection file and exact selected
objects. Verification rehashes the inventory and policy and checks all recorded
metadata/inodes. Drift makes a plan stale. A present `db.lck`, even an unsafe node,
blocks planning/verification. Absence is only an observation; exclusion is obtained
later through the real API. Regenerate old version1 plans; they cannot be applied.

Output must be fresh mode0600 in a caller-owned parent without group/world write
permission, outside cache/database. Existing output is never replaced. Relevant
symlinks, hardlinks, special files and symlink path components are refused. Read
access follows normal filesystem atime behavior; recorded content/mode/ownership
fields are never changed by inspection. A plan does not lock out later writers.

## Explicit apply

```sh
cachy-asahi-cache apply /root/private/cache-plan.json \
  --plan-sha256 '<exact plan_sha256 returned by plan>' \
  --quarantine /var/cache/pacman/cache-cleanup-unique \
  --confirm REMOVE_SELECTED_CACHE_ARCHIVES
```

Apply currently supports conventional paths under one explicit target root:
`ROOT/var/lib/pacman` and `ROOT/var/cache/pacman/pkg`. Custom/shared cache layouts
are not admitted as equivalent transaction coordination. Quarantine must be
fresh, outside cache/database/inputs, in a caller-owned parent with no group/world
write permission, and on the cache's filesystem. No copying fallback is used.
Existing quarantine directories are never reused or swept.

The existing system libalpm.so.16 must be root-owned and not group/world writable;
the existing target local database must have version9. The CLI calls only
initialization, an empty transaction with flags0, ownership/error accessors and
release. It never calls package addition/removal, transaction prepare/commit or
database-update APIs. Another real ALPM holder refuses this operation. Unknown
or stale locks are refused without clearing them. No advisory flock is credited
as package-transaction exclusion. pyalpm is unnecessary.

Under that real lock, every plan, policy and cache input is revalidated. A fresh
0700 quarantine and durable0600 journal record intent **before** each atomic
same-filesystem `renameat2(RENAME_NOREPLACE)`. Archives and signatures move as
separate recorded objects. Every moved inode/hash/mode/owner/group/link count and
mtime must match; rename's ctime change is recorded. If a live-cache name is
replaced during the move, the replacement is quarantined, detected and retained;
it is never deleted from the live cache through a stat-then-unlink operation.

No purge begins until all required moves, protected/unselected objects, policy,
plan, lock and quarantine contents pass rechecks. Each quarantined object is
checked again before it is unlinked inside the private directory. The journal
records purge intent before unlink, then records completion after fsync. The
cache directory itself is never the target of unlink. Protected and unselected
cache files must remain unchanged. After final checks the original transaction
API releases its own unchanged lock. Journal remains for review.

`APPLIED`/exit0 means the complete selected operation and owned lock release
passed. It reports `removed_logical_bytes`; physical disk space is **not measured**
and `reclaimed_bytes` remains null. If another transaction starts after our
successful release, its distinct lock is reported and never touched.

## Refusal, interruption and recovery limits

Failure/interrupt returns a refusal or leaves an in-progress journal. Quarantine
and journal are retained. Some files may already have moved, or may already have
been purged. Neither rollback nor an untouched cache is implied. An outstanding
`MOVE` or `PURGE` intent means the exact completion boundary may be uncertain.
No removed-byte or reclaimed-space success is reported after uncertainty.

Observed foreign/drifting lock identity is never API-released or raw-unlinked.
SIGKILL/SIGTERM can leave the original real lock; SIGINT also retains lock
uncertainty. Later apply attempts refuse it. **No automatic stale unlock, restore
or resume is implemented.** Use a separately authorized package-manager recovery
procedure and inspect the recorded objects; this tool supplies no boot/recovery
attestation or raw lock-removal command. Do not reuse the quarantine path.

Journal replacement is guarded by the last recorded inode/hash; unknown journal,
quarantine or file changes refuse further purge. Fresh0700 quarantine isolates
ordinary cache writers. Processes with the same account's authority or root can
still tamper with its namespace; permissions cannot defend against an actively
privileged adversary. Detected interference is refused, never treated as success.
No physical-storage power-loss recovery or transaction across multiple databases
is claimed.

Read-only plan publication uses private temporaries, fsync and atomic no-replace
linking. A hard interruption can leave an output temporary or a two-link plan;
verification refuses unsafe plans and no automatic temporary sweep occurs.

Bounds:10000 cache entries,16GiB per archive/signature,64GiB per inventory and
30s checked between reads;16MiB JSON/journal; fewer than10000 selected objects so
quarantine has room for its journal;120s checked between apply operations. A
blocking filesystem call can outlast a checked budget. Recognition covers
`.pkg.tar`, `.pkg.tar.xz`, `.zst`, `.gz`, `.bz2` and `.lz4` ordinary basenames.

## Tests and packaging

`python -B test_cache.py` runs real CLI/tempfile controls and real libalpm holders
against isolated conventional target roots. It covers selective success/no-op,
protected/signature/database preservation, concurrent refusal, live-cache
replacement, no-replace collision, policy/payload/journal/lock drift, injected
release failure and actual SIGKILL during move and purge. Durable intent and
retained uncertain locks are asserted. Test teardown removes whole disposable
fixtures after assertions; it is not a product stale-lock recovery procedure.
Fault checkpoints exist only as Python test callbacks, not runtime switches.

The local MIT recipe installs only CLI, README, NOTICE and LICENSE, and depends
on Python and the existing pacman/libalpm system package. It bundles no libalpm
bytes. `arch=any` describes text payload, not native ARM or M2 test evidence.
Package removal/orphan management and full R4/maintained-release acceptance remain
open. The candidate is never selected for development or release automatically.
