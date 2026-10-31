Proposed maintained retained build inputs

This is one consolidated, source-tested proposal. The coordinator owns integration; no canonical file, manifest or frozen trial is edited here. Package payloads stay in two external immutable carriers:

- ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad: complete original574 archives/signatures,1154 source leaves, native248 subset496 or desktop574 set1148.
- 8ee14069b7a74455a7bea1171ba319932c9df304: exact original updater compiler6 archives/signatures,11 source leaves.

carrier-profile.json and compiler6-profile.json contain the complete fixed source maps. genuine-publications.json joins both profiles to genuine Root publication, full Git-source authorization and remote proofs, plus the original compiler lock/policy/index. The unchanged seed.py reference and original lock/index files document the existing-cache contract; prepare.py executes the immediately re-pinned helper from the proved external carrier.

prepare.py is a bounded CLI with three modes. native248 and desktop574 require an existing caller-owned0700 cache. Both validate every previous entry against the exact original574 union:1148 package/signature files, two rootfs files and three keyring files. They add only the selected package bytes, never replace an existing entry, and require all previous inode/owner/mode/link/size/mtime/ctime/hash maps unchanged; reads may advance atime. Compiler6 creates a fresh original policy cache without an index. Full filesystem, immutable commit/tree and every Git blob join precede copying; Git HEAD and inherited environment values are not authority.

The existing source-owned caller supplies its original absolute monotonic deadline, explicit carrier/Git paths and unchanged lock. These are commands for a new disposable CI source revision, not commands executed by this proposal:

```bash
python -B scripts/ci/retained-build-inputs/prepare.py \
  --carrier "$RETAINED574" --git-dir "$RETAINED574_GIT" \
  --cache "$RUNNER_TEMP/alarm-cache" --mode native248 \
  --lock scripts/ci/inputs.lock.json --deadline "$PREFETCH_DEADLINE"
python -B scripts/ci/native_arm.py audit \
  --inputs-sha256 "$INPUTS_SHA256" \
  --cache "$RUNNER_TEMP/alarm-cache" --output "$RUNNER_TEMP/native-audit"
python -B scripts/ci/native_arm.py build \
  --inputs-sha256 "$INPUTS_SHA256" --recipes-sha256 "$RECIPES_SHA256" \
  --cache "$RUNNER_TEMP/alarm-cache" --output "$RUNNER_TEMP/native-evidence"
```

For the original574 caller use mode desktop574, its unchanged original574 lock and existing deps cache, then its unchanged acquisition/build command. Keep native rootfs/keyrings and earlier desktop extras in that same cache. The separate compiler preparation precedes its unchanged original CLI and later seed:

```bash
python -B scripts/ci/retained-build-inputs/prepare.py \
  --carrier "$RETAINED_COMPILER6" --git-dir "$RETAINED_COMPILER6_GIT" \
  --cache "$RUNNER_TEMP/frozen-updater-archive6" --mode compiler6 \
  --lock "$archive6_inputs" --deadline "$PREFETCH_DEADLINE"
python3 -I -B "$archive6_helper" --policy "$archive6_policy" \
  --inputs "$archive6_inputs" --cache "$RUNNER_TEMP/frozen-updater-archive6"
```

legacy_prefill.prefill(carrier, fresh_cache, unchanged_policy_result, original_deadline, git_dir=...) is the corresponding exact32/20/8/6 API. It writes no index. Every original policy, CLI, timer, index, seed, current GPG, metadata, acquisition and native/runtime gate remains mandatory; original CLIs must report requests0/reusedall. The cache receipt is DATA and grants no acceptance. No system installation is added.

Ready callers are the unchanged native_arm audit/build input acquisition; Core/Boot/current607/Updater/GNU/repair original574 caches and archive32/20/8 transports; and Boot/current607/Updater compiler6 transports. Ready means the input contracts and integration seams are demonstrated, not that frozen sources can change in place or that native packages/hardware pass. caller-adoption.json lists their scopes. Preserve preparation order, environment wipe, budgets and positive reader predicates in each new source/reader revision. Derive fixed workspace paths from a validated source root before or after the wipe; a late helper must not depend on GITHUB_WORKSPACE surviving.

Controls are reused in control-evidence.json: full original574 current signatures/metadata; real496→1148 preserving rootfs/keyrings/desktop extras; real80→1148; real relatime/link/hash/deadline refusals; full1154/11 Git joins followed by actual unchanged32/20/8/6 CLI entrypoints/timers/indexes with network denied and every input reused. The new CLI adds three routing/refusal controls; its positive routing control mocks proof/copy calls explicitly. No package-copy control was rerun for this consolidation. Native/hardware/release acceptance remains separate.

Shipped focused tests are test_seed.py (four small metadata/cache/identity controls) and test_cli.py (three portable routing/refusal controls). Run them with `python -B scripts/ci/retained-build-inputs/test_seed.py` and `python -B scripts/ci/retained-build-inputs/test_cli.py`. The CLI test builds its temporary carrier from the shipped lock/policy metadata only; it mocks source proof and copying explicitly, while exercising real shipped native lock validation and real CLI refusal entrypoints. Compiler metadata and its policy parser are also explicit routing stubs because their original bytes live in the external carrier; the actual compiler integration control remains separate. It needs no development artifact, external package payload, Git object database or network.

The full signature/metadata, large-cache, complete Git/blob and zero-request original archive CLI controls described above are retained development evidence indexed by control-evidence.json; they are not rerun or claimed by these shipped focused tests. The reference paths remain audit references, not runtime dependencies.
