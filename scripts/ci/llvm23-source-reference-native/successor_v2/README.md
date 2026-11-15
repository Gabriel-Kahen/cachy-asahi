# LLVM native owned-work-volume successor v2

This pure constructor consumes the complete published 248-file v1 Source and emits a separately reviewable v2 Source. It does not initialize a volume or run Docker, a compiler, a namespace probe, a Reader or a native job. The original failed Source and all its operational roles remain unchanged.

The actual v1 observation is `PermissionError` creating `/work/home`. A prior Root0 CHOWN-only initializer had already returned zero. No work-volume stat was retained at builder entry, so root ownership or Docker copy-up is a hypothesis, not a measured cause. `observed-failure.json` pins the selected retained ordinary DATA operands.

The successor creates both exact source/token-labeled containers before starting the final initializer. Both work mounts specify `volume-nocopy`. The initializer is Root0, read-only root, network none, one owned work-volume mount, one CPU, 512 MiB memory with no additional swap, 64 tasks and 120 seconds; its only added capability is CHOWN. It opens the empty root-owned directory, records stat, chmods 0700 while still owner, then chowns 1001:1001 and records the same device/inode. It never recursively changes ownership. Ordinary command supervision and natural exit remain required.

The derived entry shell first performs a read-only check as uid/gid 1001: exact admission digest, actual stat matching the initializer receipt, empty ordinary work root and effective write/search access. It creates no marker before the frozen actor's empty-root check. The four Python actor/runtime inputs and the entire LLVM candidate stay byte-identical. The inner actor contract remains explicitly v1; only the outer operation/job/workflow aliases are v2. Existing actor caps, PATH, mounts, compilation user and runtime predicates remain intact.

The producer cleans only exact image/source/token/role-owned containers and the exact labeled local volume, including initialization failures. Forced retirement remains a failure. It retains the first actor failure independently of any export refusal. The matching Reader rejoins owner, admission, actual stat, initializer domain/exit and nocopy builder inspection before retaining all original package/runtime checks.

The additional initializer budget is explicit: native envelope 19,920 seconds, enclosing active timeout 19,620 seconds and native step 332 minutes. Job timeout remains 360 minutes; compiler actor remains two CPU / 8 GiB / 512 tasks / 14,400 seconds. Existing disk, inode, memory reserve and signed bootstrap gates remain unchanged. This is a proposed resource profile requiring fresh Root approval.

Run DATA controls with an explicit independently authenticated parent export:

```sh
python3 -I -B -Werror::ResourceWarning scripts/ci/llvm23-source-reference-native/successor_v2/test_controls.py --parent-source "$PARENT_SOURCE"
```

Root-only DATA construction, after checking the independently retained profile SHA:

```sh
python3 -I -B scripts/ci/llvm23-source-reference-native/successor_v2/prepare.py --parent-source "$PARENT_SOURCE" --profile-sha256 "$REVIEWED_PROFILE_SHA256" --output "$FRESH_SOURCE_OUTPUT"
```

The profile binds every constructor input plus expected complete map/tree. The constructor verifies all parent bytes/modes/map/tree, a complete inverse, frozen actor/candidate bytes and fresh disjoint output. Output publication, a new full Git readback, v2-aware once selectors, fresh resource/source approval, live gates and a new Root attempt are still required. All successor Source/ref/run/job/authority/approval/artifact/Reader/image fields are NULL; no previous attempt can supply them.
