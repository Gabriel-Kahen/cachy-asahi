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
(integer 1), `purpose` (`APPS_ORIGINAL574_READONLY_CLOSURE`), and five hashes:
`snapshot_sha256`, `extraction_receipt_sha256`, `source_tree_sha256`,
`source_packages_sha256`, `source_closure_sha256`. All must be lowercase SHA256
and equal between policy and lease.
The policy additionally has `baseline_lock_sha256` (the fixed hash above) and
`candidates`. The lease additionally has `token` (the existing 32-hex
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
587 packages, 500000 nodes, 8 GiB and a 300-second worker.

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
