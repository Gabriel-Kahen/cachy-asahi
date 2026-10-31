# cachy-asahi-orphans 0.1.0

Read installed package metadata through the existing trusted libalpm16 public
API. Report install reason, real required-by and optional-required-by lists,
dependencies, optional dependencies, provisions and current satisfiers. Prepare
an explicitly selected **read-only removal plan**; never remove packages or
change installation reasons, databases, locks, cache or configuration.

No transaction, prepare, commit, package-add/remove, repository-update or
package-manager subprocess API is exposed. No network is used. Existing `db.lck`
means active **or uncertain**: refuse, never clear it. The tool neither acquires
a lock nor claims transaction exclusion. Later authenticated updater integration
must acquire the correct exclusion and revalidate/re-authorize any real operation.

## Assess a conventional target

```sh
cachy-asahi-orphans assess --root / --dbpath /var/lib/pacman \
  --protect my-important-dependency \
  --output /home/operator/private/orphan-assessment.json
```

Root/database paths must be explicit ordinary absolute paths and the database
must be `ROOT/var/lib/pacman`, with an existing local ALPM version9. The CLI does
not elevate privileges. Read permission suffices. A true host view of a trusted
root-owned, non-group/world-writable `/usr/lib/libalpm.so.16` is required; a
UID-remapping sandbox can correctly refuse it. Do not weaken that check.

Output is optional for inspection; without it the full JSON report goes to
stdout. An output parent must already exist, belong to the caller and not be
group/world writable. Files are newly published mode0600 outside the database,
with fsync and atomic no-replace linking. Existing outputs are never overwritten.
Relevant symlinks/hardlinks/special nodes and symlink path components are refused.
No archive or installed executable is loaded or run.

The full database tree, including opaque sync files, is snapshotted by relative
path, type, bytes/SHA256, mode/uid/gid, device/inode, link count and mtime/ctime.
Desc records are checked for unique complete identities/reasons and compared with
libalpm's actual loaded local cache. Database snapshots before/after queries and
lock checks must agree. Ordinary read atime follows filesystem policy and is not
a preservation claim. No package payload/hash/native/architecture/hardware proof
is inferred from these records; temporary metadata fixtures are not installations.

## Conservative finite candidate semantics

A candidate must meet **all** conditions:

- Its actual ALPM install reason is dependency, rather than explicit/unknown.
- Its actual required-by list is empty.
- Its actual optional-required-by list is empty.
- Its name is outside the protected floor and caller additions.

This is a dependency-installed **leaf** assessment, not recursive garbage
collection. Cycles remain needed and are never implicitly collected. Explicit
packages are never candidates even when no other package needs them. A package
satisfying a versioned virtual provision is needed when libalpm says so. Redundant
providers are treated conservatively when required-by names a consumer. No age,
package-size or filename heuristic chooses removals. Listing candidates performs
no selection and makes no recommendation that they are safe or useful to remove.

`protection-floor.json` carries names from the existing exact574 development base
plus the existing protected Asahi/platform set. Those names cannot be weakened
through CLI input. `--protect NAME` adds installed names; duplicates/unknown names
refuse to avoid silent typos. All protection is included in the assessment binding.
The floor is deliberately conservative: packages in that base stay protected even
if they could otherwise be a metadata leaf. Missing floor names are not fabricated
as installed packages.

This floor is a source-pinned reference, **not an accepted target/release/platform
policy**. No accepted target Apple update policy is shipped by this tool. Supply
any additional target-specific names explicitly and have the authenticated updater
validate its real base/platform policy before later mutation. Local names and raw
metadata never establish supported-system, known-good rollback, signed-release
or boot-recovery authority.

## Explicit selected removal plan

```sh
cachy-asahi-orphans plan /home/operator/private/orphan-assessment.json \
  --select example-unused-dependency \
  --output /home/operator/private/orphan-plan.json
cachy-asahi-orphans verify /home/operator/private/orphan-plan.json
```

Repeat `--select` for exact package names. No default/all selection, glob, path,
recursive removal or dependency installation is performed. Omit all selections
for a no-op plan. Assessment/plan inputs must be caller-owned ordinary single-link
mode0600 JSON. Changed package/version/reason/dependency/protection facts or any
full database-snapshot change make the assessment stale. Editing a report to
remove required-by/protection facts cannot authorize a plan: actual libalpm facts
are recomputed before planning and again during verification.

Plans refuse explicit, protected, needed, optional-needed, unknown or duplicate
selections and inconsistent installed metadata with unsatisfied hard dependencies.
Libalpm also evaluates the **whole remaining package set** after simultaneous
selection. Every remaining hard dependency must have a satisfier; every previously
satisfied optional dependency must retain one. Version constraints and versioned
provisions are handled by `alpm_find_satisfier`, never a handwritten version
comparison. Optional descriptions are retained in reports; the relation without
its `: description` is passed for resolution. A report's satisfier is one match
chosen by libalpm, not a claim that there is exactly one provider.

Plans bind the original assessment inode/hash, full DB snapshot hash and actual
complete dependency/protection facts. Successful planning and verification exit0
and still say `NOT_APPLIED`, `apply_supported:false`. Refusal exits1; syntax errors
exit2. There is **no apply/removal command**. No selected plan is removal authority.

Readonly snapshots cannot prevent a transaction beginning after the final check;
a saved plan can become stale immediately. Existing/concurrent observed locks,
changed directory/file identities, malformed/incomplete local records and unsafe
outputs refuse. No automatic stale-lock recovery, restore or sweep is provided.
Interrupted publication can leave a private temporary or a two-link output;
verification refuses unsafe inputs, and operator review/fresh output is required.

## Bounds, source and validation

Bounds:2048 packages,20000 DB nodes,32768 relation items,64KiB per desc,128MiB per
other DB file,512MiB read total per snapshot and32MiB JSON. Snapshot/read and
metadata-query budgets are30s checked between operations; an individual blocking
filesystem/native-library call can outlast a checked budget. No physical-storage
power-loss or hostile privileged/same-UID writer defense is claimed.

Project source is MIT, with local no-follow snapshot/publication patterns from
the existing MIT cache/mirror tools. `protection-floor.json` records exact source
hashes for its existing base inventory/platform-name provenance. Existing system
libalpm is a separate dependency and is not bundled. The recipe pins every local
input and checks this test suite; it installs CLI, README, floor, NOTICE, LICENSE.

`python -B test_orphans.py` exercises real libalpm on temporary hand-authored ALPM
metadata, plus real temporary CLI commands and a genuine counterpart transaction
holder. The product never exposes transaction APIs; test-only holders establish
concurrent refusal and prove readonly handle release does not clear another
handle's lock. Tests cover reasons, versioned/provided/optional dependencies,
cycles, simultaneous losses, protection, stale/tampered facts, malformed/unsafe
metadata, limits and exact non-lock DB preservation.

Host source/tempfile/staging results are separate from native ARM package builds,
installed lifecycle, authenticated updater integration, actual orphan removal,
M2 hardware and maintained release acceptance. `arch=any` is a text-package
statement. This candidate is never selected for development or release itself.

Dependency satisfier results are memoized only within a single read-only
assessment, separately for its immutable full and remaining ALPM lists. The
cache holds package names or absence, never handles or cross-assessment facts.
Cache saturation falls back to the original ALPM query without dropping facts.
Optional descriptions share only the identical normalized ALPM query.
Every assessment still checks the complete before/after DB snapshot, locks,
protection floor, reverse dependencies, relations and original deadlines.
