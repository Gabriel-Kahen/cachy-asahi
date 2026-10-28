# Actual kernel trial 38288838400

The actual trial remains **FAIL**. Diagnostic2 narrows the first child error to
provision ownership inspection after a returned create CID and before attached
start. It does not identify which ownership conjunct failed. Cleanup fails the
same ownership predicate; preservation and owned absence remain UNVERIFIED.
No probe, baseline/candidate kernel compilation or compiler invocation is proved.

## Authenticated run evidence

The peer independently captured all 117 committed packet source blobs, lengths
and Git modes at `2e0dc0dab2c8a10db162fb99bb6da994805cd720`. The nested 26 stage
rows match stage SHA `387e72fc836103b9654e65ee9e186369ebe34e240f9603f8b9779f6f317e2b63`
and packet SHA `9ca9414c8461d2a134d68390381755811b0d61aa9097ef23b747ef91f138dbf0`.
Workflow SHA is unchanged
`1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4`.

The retained 55,316-byte workflow log matches
`cb0b275beee1168a13f593bfbf78ee628ad9b1d0f1bccd5e1a8d36df876f6589`.
All nine decoded log files match the retained ZIP index's sizes and hashes.
The peer did not receive the original ZIP for a second archive-byte hash; its
recorded archive SHA is root-retained evidence, distinguished from the decoded
member checks. One terminal status occurs in the log. The exact committed
projector accepts it and reproduces its compact canonical bytes, SHA
`2684d5fb9f39713a88a85020100be6b6546f2e4f20230538d40879f7240587a0`.
This also agrees with root's separate public verification record.

| Retained observation | Actual value |
| --- | --- |
| Outer producer/acquisition returns | EXIT_ZERO /0 each |
| Producer/mutation | PASS /COMPLETE_ACCEPTED |
| First outer failure | kernel /KERNEL_EXIT |
| Bound child receipt/actual child return | VERIFIED /EXIT_NONZERO /1 |
| First child predicate | PROVISION_COMMAND /INVALID_DATA |
| First operation | provision /INSPECT_OWNERSHIP /docker-container-ownership |
| Primary query return | CONTAINER_INSPECT /EXIT_ZERO /0 |
| Separate daemon response | HTTP_STATUS /200 |
| Create/start observation | CID_OBSERVED /NOT_ATTEMPTED |
| Provision command accepted by stage | UNOBSERVED /null |
| Child cleanup | FAIL /ABSENCE_UNVERIFIED |
| First cleanup operation | cleanup /INSPECT_OWNERSHIP /docker-container-ownership |
| Final owned absence/preservation | UNVERIFIED /UNVERIFIED |

The public binding digest records trusted job capture; private nonce/config,
raw inspect response, container/image IDs and raw child receipts were not exported.
The peer cannot recompute the private binding or infer which conjunct failed.
CLI zero and HTTP 200 do not establish container ownership, successful worker
execution, compiler invocation or safe removal. The previous kernel3 trial
remains its original FAIL.

## Concrete source diagnosis and bounded proposal

The ownership guard combines six predicates: full inspected ID syntax, expected
name, equality to an already recorded CID, immutable image ID, requested user,
and provision inherited-label equality (build containers instead require the
nonce label). Six isolated committed-source fixtures each violate one conjunct;
all yield the same generic ownership predicate. Thus the actual diagnostic
cannot distinguish a label mismatch from the other five failures.

A separate causal fixture keeps all other ownership/resource/mount/command
checks valid. Image Labels `null` and container Labels `{}` are rejected;
empty/empty, null/null and matching nonempty label maps pass. Added nonempty
labels are rejected. This is a source-evidenced representation incompatibility:
the pinned [Docker CLI 28.0.4 opts.go](https://github.com/docker/cli/blob/v28.0.4/cli/command/container/opts.go)
uses `ConvertKVStringsToMap`, whose [implementation](https://github.com/docker/cli/blob/v28.0.4/opts/parse.go)
allocates an empty map even without labels. Moby's
[create path](https://github.com/moby/moby/blob/v28.0.4/daemon/create.go)
merges the image config; its
[merge function](https://github.com/moby/moby/blob/v28.0.4/daemon/commit.go)
initializes nil user labels and inherits all image entries. The API's
[Config type](https://github.com/moby/moby/blob/v28.0.4/api/types/container/config.go)
keeps a string map label field. These facts prove expected source behavior,
not the unexported actual image/container label values.

The same issue exists downstream: a synthetic derived image with only Labels
changed from base null to empty map fails `image.verify`, while all other config,
identity, layer and size checks pass. Moby's commit path also invokes the same
merge. Actual kernel4 never reached derive; this is a separate source-causal
counterexample, not another observed native failure.

The smallest correction is strict null-or-string-map validation, canonicalizing
only absent/null versus empty labels in provision equality and the existing
semantic image-config comparison. Preserve raw accepted image config and commit
payload, every nonempty label entry, build nonce checks and all other ownership,
resource, command, cleanup and protected-image requirements. A closed six-way
subpredicate observation would further identify any remaining native mismatch;
it must publish fixed labels only, with no values, paths, IDs or raw errors.
The coordinator selected the normalization correction separately after this
review; no implementation, shared binding, Git or native actor changed here.

Exact source capture, terminal bytes, root proof hash and causal fixtures are
retained in `artifacts/reviews/native-kernel-38288838400-root-peer/`.
Controlled fixtures and primary-source interpretation are not native Docker or
hardware acceptance. Kernel runtime, M2/16K, installation and performance remain
NOT RUN/NOT MEASURED.
