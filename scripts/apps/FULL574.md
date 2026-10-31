# Explicit Apps original574 data closure

`transaction.py` has an optional, dedicated `full574_closure.py` adapter. Its
scope is the measured original574 source and these exact current candidates:
Apps 0.1.0-5, repository-runtime 0.1.0-1, Cache 0.2.0-1, Orphans 0.1.0-1.
The default backend and all shared Setup3→4/full-root grants remain unchanged.
Native original574 transaction execution is pending a dedicated lane; temporary
data controls are not native acceptance, installation or hardware evidence.

The native owner must supply a never-started, measured source snapshot mounted
read-only (checked with `fstatvfs(ST_RDONLY)`), an extraction receipt, actual
ALPM9 inventory, and explicitly hash-bound policy and producer lease. These are
development authority supplied by Root, not admission receipts generated here.
The source's sorted `name version\n` lock must be the original574 SHA256
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
The four candidates must initially be absent. Source and copy must be disjoint;
the backend's existing offline mapped/container, private workspace, ownership,
confirmation, signed release/catalog/keyring and exact replan gates still apply.

Add all four options to `prepare-copy`, `inspect` and `apply` (the worker receives
the same argv). An owned full574 marker refuses inspection/application without
its original policy/lease hashes. Existing explicit owner disposal remains
available even when policy validation fails.

```text
--full574-policy /inputs/policy.json --full574-policy-sha256 SHA256
--full574-lease /inputs/lease.json --full574-lease-sha256 SHA256
```

Both JSON documents have exact field sets. Common fields are `schema_version`
(integer 1), `purpose` (`APPS_ORIGINAL574_READONLY_CLOSURE`), and six hashes:
`snapshot_sha256`, `extraction_receipt_sha256`, `source_tree_sha256`,
`source_packages_sha256`, `source_closure_sha256`, `source_capabilities_sha256`. All must be lowercase SHA256
and equal between policy and lease.
The policy additionally has `baseline_lock_sha256` (the fixed hash above) and
`candidates` and `source_capabilities` (the complete canonical path→raw-hex map). Its
`C.digest(source_capabilities)` must equal the shared capability hash. The lease additionally has `token` (the existing 32-hex
`CACHY_ASAHI_APPS_TRANSACTION` token), `source` (canonical consumer path, e.g.
`/seed`), and `source_identity` (`[st_dev, st_ino]` at that path).

`candidates` contains exactly the four package names from `C.VERSIONS`. Each row
has exactly `version`, `archive_sha256` (actual accepted input archive bytes),
and `payload_sha256` (`C.digest(C.current_payloads()[name])`). The adapter builds
the payload node maps independently from the current recipe's bounded, regular,
non-ELF source/data files. Only those exact nodes, ordinary modes and directories
are allowed; no symlinks, scriptlets, backup state or hooks are introduced.

For source assembly, import the adapter as `C` and backend as `T` without calling
their CLI entry points. `C.measure(source, T.limits())` returns the complete raw
observation with original ineligible diagnostic flags retained. Bind:

```python
source_tree_sha256 = C.digest(observation['nodes'])
source_packages_sha256 = C.digest(inventory['packages'])
state = C.aux.checkpoint(source, observation, budget)
source_closure_sha256 = C.digest(C.canonical_state(state))
source_capabilities = C.capability_map(source, observation, budget)
source_capabilities_sha256 = C.digest(source_capabilities)
```

`canonical_state` removes only inode identities for cross-copy content joining;
actual before/after closure comparisons retain the inode/metadata records.
The source root inode, read-only mount, full tree, hardlink annotations, package
lock and closure are independently rechecked. Snapshot and extraction receipt
hashes are Root-bound provenance operands; the adapter does not claim to replay
the producer or inspect Docker/image history.

Copying uses the existing hash-pinned isolated `aux_copy` data copier. Every
original node, including boot/platform/trust, original574 DB entries and user
state, must match the source on every observation. Additional nodes are limited
to exact candidate payloads and current-version local ALPM `desc/files/mtree`
records. The transient ALPM lock is checked separately by the original backend;
no stale lock deletion or lock bypass is added. Existing finite bounds remain
587 packages, 500000 nodes and 8 GiB. The dedicated full574 worker has600
seconds with a610-second caller; the generic/small executor remains300 seconds.
Both hash-pinned policy and native lease must carry exactly
`execution_budget={"backend_seconds":600,"caller_seconds":610}`. Missing, legacy
or mixed budgets refuse before source traversal; the copy marker binds the
policy/lease and exact budget. The interrupted full574 worker uses600 seconds
and its original5-second reap bound. Whole lifecycle3000-second and interruption
actor900-second caps remain finite and unchanged.

Absolute links must pass the unchanged finite measured87 literal/endpoint policy;
unknown paths and endpoint shapes refuse. The existing held helper, configs,
SONAME/DSO scan and main/auxiliary cache closure are captured without executing
`ldconfig`. Main and auxiliary cache bytes must remain **RAW_EQUAL**, even after
commit. No load/save-order transition waiver is used. The only scan projection
is the exact `usr/lib/cachy-asahi-apps` ordinary directory, whose independently
pinned script/data contents glibc's nonrecursive scan ignores. Other new scan
entries refuse.

The original cache may refer to producer inode keys after extraction/copy. Its
bounded aux format is parsed, original bytes are joined to the immutable source,
and both caches are held unchanged. Copied aux inode liveness is explicitly
`NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS`; no refreshed-cache or helper-exit claim
is made. These four transactions cannot alter any selected ELF, SONAME,
configuration, provider, library path or cache, and cannot consume this helper.

Failures keep the backend's existing commit uncertainty/pending marker and
owned-copy disposal recovery. No interrupted commit is described as rollback.

Only the Apps-specific `export_extract.py` derivative accepts
`SCHILY.xattr.security.capability`, with exact Linux revision2/3 value validation.
It compiles the exact shared extractor SHA
`9738acb125ce6d468d5359ecfbd5540454826567fd4ac4481576ec31da37190c`
in an isolated namespace, replacing one hash-bound metadata predicate. Every
other metadata/path/content/hash bound remains; all other unknown PAX/xattrs and
nonregular capability carriers refuse. Original and adapted source hashes are
retained. The ordinary extractor initially produces data without xattrs; it may
not report success until the complete header map, including hardlink aliases,
has been restored and independently observed over every extracted node.

`file_capabilities.py` checks every supplied node, including directories,
symlinks and candidate additions, for unknown attributes and exact capability
bytes with nofollow descriptors, mount/identity/drift/hardlink checks and the
existing deadline. It never executes a capability-bearing file. Every source,
copy and before/after transaction map must exactly equal the leased source map;
current candidate archives are separately checked for absent xattrs before actors
and before installation. The unchanged `aux_copy` omits xattrs, so the dedicated
adapter restores and verifies them before returning a copy ownership receipt.
Unknown or conflicting existing values refuse; no deletion/overwrite/rollback
path is added. Restore failure leaves an unaccepted owned copy for disposal.

Only extract/lifecycle/interruption actors receive SETFCAP; other grants, NNP,
network isolation, resource limits and output limits remain unchanged.
Only the dedicated full574 deadline described above differs.
The failed interrupted copy is inspected after its worker group is gone, while
commit outcome remains UNKNOWN; teardown still requires outer consumer absence.
The original64KiB policy/lease limit is unchanged. Namespace-visible capability
bytes must compare exactly; rev2/rev3 translations are never normalized to pass.
This is a preserving source proposal following actual diagnostic38975802137;
native extraction/transactions with these new grants and hardware remain NOT_RUN.

The Apps-only `full574_copy.py` binding handles the native owner’s same-device
readonly `/seed` and writable `/work` bind mounts. It changes only the exact
hash-pinned copier’s ambiguous-bind predicate, in a private module, into a
bounded proof from the current mount namespace. Only `/work/main/root` and
`/work/interrupted/root` are supported. Source/work mount IDs must remain
distinct; their device and filesystem must match, and their canonical backing
roots must be strictly disjoint. Missing, escaped, nested, shadowed, overlapping
or changed mounts refuse. Source/parent/work named and held descriptors, mount
flags and backing rows are rechecked at all five original root checkpoints and
after copying. All original per-node mount/identity/hash/hardlink checks remain.
The generic copier’s same-device guard remains unchanged.

The original and derived copier hashes, actual mount-root proof and seven
checkpoints are kept in the copied ownership marker. The native lifecycle
retains that exact hash-bound marker as `main-copy.json`/`interrupted-copy.json`
before proceeding. Capability restoration and complete-map verification still
finish before the marker exists. Actual38977834026 remains FAIL before commit;
its successful capability-preserving snapshot alone is not a transaction pass.
This correction has only source and temporary-data evidence pending a new run.

The Apps-only `full574_statx.py` binding pins/reuses the exact2784B
`expanded600-installer-vm/observer600.py` descriptor query. The original full-root
observer runs in its proven private namespace; private capability scan/observe/
restore function dictionaries and copier facades select the same fresh statx
query. Every descriptor is queried anew, the first result is cross-checked with
original fdinfo, and unsupported ABI/symbol/syscall/mask follows original fdinfo.
Disagreement, zero IDs and other errors still refuse. No mount IDs are cached or
equated. Generic modules, the bind-scope proof helper and capability source files
are untouched; all node/hash/attribute/identity/alias checks and limits remain.
Auxiliary closure policy and raw-cache comparisons remain unchanged.

An ownership marker records exact binding source pins and scope. Stderr carries
bounded monotonic BEGIN/END/FAIL phase observations (at most96 records,512B each);
stdout JSON and the original combined output cap remain unchanged. Reaching the
logging cap omits further diagnostics, never functional work. These observations
may locate a subsequent timeout but do not prove the stage of an earlier one.
Actual38979455129 timed out at its original310-second caller limit with no phase
output; it remains FAIL with no completed-copy/commit/source-after claim.
Temporary-data controls establish behavior and scoped query mechanics only.
Native performance, successful copying and transactions need a new actual run.

Actual38981475599 remains FAIL: complete copy-data and postcopy observation
finished, then final source capability scanning reached the300-second backend
deadline; caller terminated at310.031862 seconds before an ownership marker or
commit. This finite capacity correction skips no independent observation, hash,
node, identity, xattr, trust or cleanup check. Success/performance remains native
pending; no duplicate check was removed.

## Explicit signed same-version repair

The current source adapter identifies Apps0.1.0-6, Orphans0.1.0-2, Runtime0.1.0-1 and Cache0.2.0-1. Historical held5/1 sources and archive-derived facades retain their own identities. A new full574 policy must bind actual matching current archives and payload hashes; old package metadata does not transfer.

Only explicit reinstall enters repair observation, inside the existing authenticated and byte-identical replan context. Selection must match installed/signed version and metadata, exact policy archive hashes and explicit requested packages, without additions, removals, upgrades or dependency expansion. Default source/prepare/inspect/install/remove observations remain strict. The caller must provide the complete actual before-map pins through existing transaction arguments; generic inspect continues to reject damaged payloads.

Selected ordinary file byte damage or missing regular leaves may be repaired only with exact ownership/mode and existing exact ordinary parents. Unselected/base/source/DB/user/trust/capability state remains exact. Aliases, hardlinks, special nodes, metadata/xattr changes, new paths and missing directories refuse. The complete damaged map is returned and pinned, rechecked before commit, and the exact signed selected payload must be restored afterward. Source/lease/authentication/lock/ALPM/copy/preservation and600/610 bounds remain.

Twenty-nine closure and fifteen transaction controls pass, including real temporary filesystem cases and modeled authenticated-context guards. These do not attest new signature verification, ALPM repair or native execution. A genuine native full574 repair fixture remains required.
