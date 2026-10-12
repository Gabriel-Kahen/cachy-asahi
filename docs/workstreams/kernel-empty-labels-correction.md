# Kernel empty-label compatibility correction

This four-file source candidate is held for independent review and coordinator
binding. Corrected native execution is NOT RUN. Actual kernel4 trial 38288838400
remains FAIL; its precise failed ownership conjunct is UNKNOWN. It observed
provision ownership refusal after returned create CID and before attached start,
with independently failed cleanup and UNVERIFIED preservation/owned absence.
Neither compilation nor a successful worker is inferred from create/inspect.
The sealed actual-run review and its receipts remain unchanged.

## Source behavior and narrow correction

Provisioning deliberately adds no container labels. The old inspector required
raw inherited-label equality, so image Labels null versus container Labels `{}`
failed despite representing the same empty label set. The derived-image config
comparison had the same distinction. Both defects were reproduced with all other
ownership/config/resource/mount/command/layer/size predicates valid. Actual raw
image/container inspect records were not exported, so these are source-causal
counterexamples rather than proof of the actual kernel4 conjunct.

`broker.labels(value)` accepts only null or an exact dictionary whose keys and
values are exact strings. It returns an empty map for null and copies a valid
map. Provision equality compares these semantic maps. Build-role nonce equality
remains required; malformed label maps are refused there too. Existing fixed
`docker-container-ownership` diagnostics remain the refusal boundary.

`image.effective(config)` applies the same strict Labels normalization to its
existing twelve-field semantic footprint. Its previous Entrypoint/Cmd
normalization is unchanged. New journal `accepted_config` therefore uses `{}`
for an absent/null Labels field. The actual accepted image config and base image,
launch arguments/environment, API request bytes and `commit_config` payload are
not changed. Historical private journals are not rewritten or granted cleanup
authority across source versions.

Every nonempty label entry stays exact: removal, addition or value change is
refused for provision/derived equivalence. Malformed booleans, lists, scalars,
nonstring values or nonstring captured-map keys cannot masquerade as empty labels.
All other ownership, protected-image, profile/resource, mounts, command, cleanup,
cancellation and timeout gates remain. No new daemon query, timer change,
pruning, catch-and-continue path, schema key or diagnostic whitelist is added.

## Pinned primary reference

Docker CLI `v28.0.4` resolves to commit
`b8034c0ed70494a90c133461d145cd072d920d7c` (annotated tag object
`f1dd3499480213671632801f5f9ba05dac5385e2`). Its
[container options](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/cli/command/container/opts.go)
set Labels using
[ConvertKVStringsToMap](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/opts/parse.go),
which allocates an empty map when no labels are supplied.

Moby `v28.0.4` resolves to commit
`6430e49a55babd9b8f4d08e70ecb2b68900770fe`. Its
[create path](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/create.go)
merges image config; the
[merge and commit path](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/commit.go)
initializes nil Labels, inherits image entries and also merges committed config.
The [Config type](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/api/types/container/config.go)
uses a string map. Both projects carry Apache-2.0 licenses, verified in their
pinned LICENSE files. Exact seven file lengths/hashes/URLs and the retained
reference bytes are in
`artifacts/reviews/kernel-empty-labels-correction-20261012/primary-source-pins.json`.
This is a primary-source compatibility reference, not a public observation of
the actual native daemon's raw configuration. No upstream code was executed.

## Validation and handoff

Working source passed 85 owned-stage tests. A separate captured copy passed 85
owned-stage tests and 205 job tests, zero failures/errors/skips, with
ResourceWarnings treated as errors. Seven added tests cover null/absent/empty
provision inspect, preserved raw base config, strict maps and nonempty drift,
all five other ownership conjuncts, build nonce equality, derived-image journal
verification/cleanup, refused cleanup for nonempty drift, and unchanged other
metadata. Original real fake-CLI signal/timeout and private Unix HTTP fixture
tests also run; no Docker, GPG, compiler, network or system actor runs in tests.

Two causal regressions fail against the exact old committed 2e0 production files
and pass with the held correction. Those red runs occurred after the complete
copied green suites; restored held bytes match every capture row. Static checks
retain the exact eight broker/nine image actor call expressions in source order
and seven broker/three image clock/Runner call expressions. The four-file diff
passes whitespace checks. A copied projection/journal is evidence about source
behavior, not actual native cleanup or build acceptance.

Only `broker.py`, `test_broker.py`, `image.py`, `test_image.py` and this guide are
owned here. Source paths/counts stay stage 26/job 117. The coordinator must refresh
four stage rows, the stage lock, `packet.py`'s stage-pin literal and its packet
rows before committed proof. The owned capture prospectively binds stage SHA
`0ef3ad174f0bdc1cd9b1a3c4874775dc2c486f3fc08429c6d2751715ccce2290`
and packet SHA
`647d4dd0101b2188d348adc87089fc5804e288872ff5fc9352d76861a512f342`,
117 rows/2,021,846 selected bytes. Primary locks, packet constants, workflow,
Git and native dispatch remain coordinator-owned and unchanged by this author.
Exact source hashes, copied bindings, tests, red controls and reference pins are
retained under the correction artifact directory. Independent source review and
committed bootstrap proof precede another native trial.
