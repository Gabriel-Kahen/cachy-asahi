# Bounded root observation

`scripts/update/full_root.py` measures an explicitly supplied root without following
filesystem symlinks. It is development infrastructure, not authorization to update
a running system. `Limits` supplies one absolute deadline and finite package,
node, byte, depth and diagnostic bounds. Unsupported or incomplete observations
are ineligible.

Default `observe(root, limits=limits)` still refuses multiply linked regular files,
absolute or escaping links, special nodes and unaudited ldconfig paths. Default
`projected_paths` rejects maps containing internal-hardlink group tags. The updater
Runtime and current scoped-copy caller do not opt into hardlink support.

## Internal regular hardlinks

The explicit development-only call is:

```python
observation = observe(root, limits=limits,
                      hardlinks='generic-development-internal')
```

Only complete internal groups are supported. The distinct observed aliases must
equal the stable inode link count. Every opened directory/file must have the root
mount identity, including same-device bind mounts. The observer hashes each inode
once, holds its descriptor, and reopens every alias through checked parent
descriptors. It verifies content/metadata identities through final validation.
Bounds are at most 4,096 groups, 16,384 aliases and 4,096 members per group; FD exhaustion
refuses without changing process limits. Cleanup attempts every held close once;
a close failure makes the observation incomplete.

`projected_internal_hardlinks` accepts explicit selected old paths, removals,
added nodes and protected paths. It preserves every existing group and ancestor,
including aliases outside the selected package. Selected writes to any member
are refused even when replacement bytes match. Removal accounting, raw/resolved
aliases, ancestor changes and forged incoming group tags are checked.
`check_hardlink_preservation` compares complete before/after group content,
topology, mode and ownership. It does not establish inode continuity between
separate observations or provide rollback.

These are checked intervals under caller-owned quiescence, not atomic snapshots.
The caller must exclude source/destination writers and mount changes throughout
observation and any subsequent operation. Matching package inventories, hashes or
one read-only view do not establish that exclusion. No caller currently uses these
helpers to authorize ALPM transactions.

The implementation has 25 focused local filesystem/data checks and a bounded
independent review, including EMFILE plus close-fault cleanup. The existing 12
root checks remain applicable. Static CI runs both files. Actual bind mounts,
full 587-package activation, ALPM transactions through this opt-in, physical 16 KiB/M2 and
performance are untested. The measured full root remains ineligible; absolute
links, specials, auxiliary execution and copy integration remain open.
