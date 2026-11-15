# Exact LLVM v2 hosted-alias correction

This is a new, unissued Source constructor. Its operational outer operation,
job and artifact names remain v2; the frozen inner actor contract remains v1.
`successor_v3` identifies this correction lineage, not a newly qualified job.
Root alone constructs, publishes a fresh Source/ref and issues any once-only
admission. The failed Source 6d attempt must not be replayed.

Run 43720263251/job 132830512686 failed in `entry.base_binding()` before secrets,
artifact creation, bootstrap or native work. The retained Original job log is
33,286 bytes, SHA256
`9a6c98cdf8e1118b63e94416b9d3e0ee6d7002a51223d25c8717b7cfce3a2680`.
The actual failing read is `hosted/common.py`'s `ALIASES`: it names the absent
v1 workflow while the 251-file Source contains only the generic/v2 aliases.
The same tuple also governs named-workflow context and repeated bootstrap
Source validation.

Only three existing operational leaves change:

- `hosted/common.py`: exactly one v1 workflow alias becomes its real v2 alias.
- Both identical workflow aliases: exactly one common-file SHA guard changes.

`hosted/entry.py`, the entire actor subtree (all four Python files, shell and
derivation JSON), producer/Reader/volume, policy/resources, Root template,
candidate, original200 and existing v2 inverse remain byte/mode identical.
The inspected outer v2 and deliberate inner v1 bindings otherwise agree.

The 253-file prospective packet adds `previous-v2/source-map.json` and
`successor-v3.json`, and regenerates its closed map. Its inverse uses only
retained DATA to reverse the three counted literals and restore every byte,
mode and member of the exact 251-file parent. The existing v2 inverse can then
restore the exact 248-file ancestor. All prospective actual Source/ref/run/job,
Reader/authority/approval/artifact/image fields remain null. No acceptance,
current trust, performance, native, M2 or release claim follows from DATA tests.

Required parent: published Source `6d0243dc8f5cf4ee5b9316b8c804f14a3236ecb0`,
tree `87f5aa3537474c2dd33a02c50e869ea5fb25e7b4`, 251 files/40,807,998 bytes,
map SHA256 `809f57839dfd574b7abf0c65535321aeac08c58608d4f9597f936a7af78fb3a2`.
Ancestor for the inverse control: Source `4ceaa1c6958349451197b19acdb084a2a5be216b`,
tree `b6d4f3bcbfb7454b1760c3ff9f9910d734d8bece`, 248 files/40,788,233 bytes.
Both operands must be closed ordinary Source exports. No payload is imported
or executed by the constructor.

The constructor requires the independently supplied whole
`constructor-profile.json` SHA and verifies count, bytes, map and Git tree
before atomic publication to a fresh disjoint directory. Its limits are
320 files, 96MiB aggregate Source DATA and 512MiB address space. Publication of
Git Source, Root approval, GET, lease, actor and native operations are absent.

Controls, each in its own isolated Python process:

```sh
python3 -I -B -Werror::ResourceWarning test_constructor.py --parent-source "$PARENT_6D_EXPORT" --ancestor-source "$ANCESTOR_4CEA_EXPORT"
python3 -I -B -Werror::ResourceWarning test_hosted_guard.py --parent-source "$PARENT_6D_EXPORT"
```

The guard controls compile only the actual named common guard and entry
`base_binding`/`proof` definitions. They execute those bodies against a sealed
temporary DATA fixture and explicitly modeled future admission text. Credentials
and storage are modeled; the only command callback returns modeled Git DATA.
A process/socket/ctypes fence forbids actual operations. The stale alias is
reproduced before any callback; the corrected path and hash/mode/map/ref/operation/
approval/HEAD/membership/blob negatives exercise the actual guard chain.
These are guard regressions, not an actual hosted proof or Root admission.

The existing independent v2 Reader still selects the old 6d/251-file packet.
It does not automatically admit this correction; a separately reviewed new
Source binding and 253→251 inverse projection are required for future Original
validation. No Reader pin or historical output is changed here.
