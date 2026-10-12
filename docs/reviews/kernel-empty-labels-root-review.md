# Kernel empty-label correction — independent source review

Disposition: **PASS for the exact held source candidate; no confirmed source blocker.** Corrected native execution is NOT RUN. Actual kernel4 `38288838400`, commit `2e0dc0dab2c8a10db162fb99bb6da994805cd720`, remains FAIL at the generic provision ownership predicate, with cleanup FAIL and owned absence/preservation UNVERIFIED. The failing native ownership conjunct remains UNKNOWN. Source-causal label failures do not identify that actual conjunct or establish compilation/worker/hardware success.

## Held authority

Author receipt `artifacts/reviews/kernel-empty-labels-correction-20261012/held-receipt.json` is 3,541 bytes, SHA `d044a48462077ff3fb8d3d1d48bc644b4565778310db86baf9ef6bcf83067082`. This review independently rehashed all receipt-indexed evidence, the four primary held source/test files, the guide, all 117 rows in the author capture and all seven retained upstream reference files. A separate owned source copy contains the exact captured bytes/modes, prospective maps and guide, with no PYC. The 117 selected source rows total 2,021,846 bytes; capture, tests and independent controls reside under `artifacts/reviews/kernel-empty-labels-root-peer-20261012/`.

| Held path under scripts/port/kernel-native-stage | Bytes | SHA256 |
|---|---:|---|
| broker.py | 30,976 | `d4b0a0aec14491e2990833172543004d961bb287094182e4d962653d72282bf7` |
| image.py | 15,700 | `3bfd0c1b78d28a4575f9e38c3d6a326da9cc4dae4952cf8f6db21843c6304730` |
| test_broker.py | 29,167 | `2c8d0019a7ce6fa03da2d58f3bbf14817328bc435ad0fbb4b96a6715e31c8075` |
| test_image.py | 31,199 | `57a3bdf419dbc9b473f9909d48c2efaaeafd9b151090a82d14f14eeb6ab9378f` |

All four modes are 0644. Guide `docs/workstreams/kernel-empty-labels-correction.md` is 6,020 bytes, SHA `0d15ca7270319e41e3adaeb9689b576e476931d952196bcf76e7b27af19f94be`.

Exact old production broker/image bytes were independently captured with read-only `git show` at the actual commit, without using current checkout authority. Old broker SHA is `88633689f8b07fe837b5fba8cac7dd8e3ab332d2d574fc0a915f79b430e1dac4`; old image SHA is `90f17fd16d9bb19848fbef89bc4204c88da0411c32dbe08abf72ec2557393e34`. Across the 117 proposal rows, exactly six differ from that commit: four held files, the copied stage lock, and copied packet.py's stage-pin literal. The other 111 rows match old committed bytes; no original producer, recipe, package evidence or workflow change is introduced here.

## Narrow semantic effect

`broker.labels` admits only None or an exact dictionary with exact string keys and values. None becomes a fresh empty dictionary; a valid map is copied. Provision ownership compares these maps rather than raw None/{} representation. Missing Labels is treated through the existing `.get` as None. Every nonempty entry remains exact, including empty string entries; additions, removals and value drift still refuse provision equality. Dictionary/string subclasses and malformed scalars, booleans, arrays or nonstring entries refuse. Build role retains its original required nonce equality and also rejects malformed extra label values; it does not acquire provision-style full-map equality or relax the nonce.

`image.effective` applies the same strict Labels rule to the existing twelve-field footprint. Its pre-existing Cmd/Entrypoint sentinel handling remains unchanged. Accepted semantic journal Config therefore represents an empty label set as `{}`. Raw base image Config, commit_config input, API request construction/body, labels sent to actors, Env/nonempty commands and launch environment are unchanged. Old private journals are neither rewritten nor granted cross-version cleanup authority.

Only the old Broker._inspect body and image.effective body differ as existing function definitions; all other existing definitions compare identically as AST. Independently source-ordered inventories preserve eight broker actor call expressions and thirteen image expressions under this review's broader selector (including wire/request calls), and eight broker/three image clock/Runner expressions. These selectors are broader than the author's reported eight/nine actor and seven/three clock inventories; all selected expressions and ordering match before/after. In particular, commit, verification, cleanup selection, API 1.48, raw request bodies, deadline calculations, cancellation, resource/mount/command profiles and baseline/protected-image operations remain unchanged. No query, timeout, retry, pruning or catch-and-continue path is added.

The combined ownership guard retains inspected CID syntax, expected name, expected CID equality when bound, exact image, exact user and role-specific labels. Independent full-inspector controls with None/{} labels still refuse privileged HostConfig, writable-mount drift, environment drift and changed commands. Fixture actual Config lists were independently copied to match real decoded inspection semantics; mutating a shared synthetic Env list would mutate both expectation and observation and is not a source defect.

## Primary-source reference and its bounds

Seven captured files and both Apache-2.0 LICENSE texts match `primary-source-pins.json`. The fixed Docker CLI reference is `b8034c0ed70494a90c133461d145cd072d920d7c`; the fixed Moby reference is `6430e49a55babd9b8f4d08e70ecb2b68900770fe`. Retained [CLI container options](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/cli/command/container/opts.go) invoke [ConvertKVStringsToMap](https://github.com/docker/cli/blob/b8034c0ed70494a90c133461d145cd072d920d7c/opts/parse.go), which allocates an empty map without labels. Retained [Moby create](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/create.go) enters config merging; [merge/commit](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/daemon/commit.go) initializes nil Labels and inherits image entries. The [Config type](https://github.com/moby/moby/blob/6430e49a55babd9b8f4d08e70ecb2b68900770fe/api/types/container/config.go) is a string map.

This is pinned primary source supporting the compatibility route. Its retained lengths/hashes were independently checked; remote tag resolution/downloads were not repeated. No upstream program or actual Docker daemon was executed. Actual kernel4 raw base/container inspection bytes were not exported, so even source-backed null/empty behavior remains a possible source cause rather than the observed native cause.

## Independent replay and boundaries

Fresh-copy tests, with ResourceWarnings treated as errors, PASS:

- 54 broker/image tests, 14.830 seconds.
- 31 stage/evidence integration tests, 0.388 seconds; together the exact authored 85-test stage roster.
- 205 separate job tests, 4.375 seconds.
- 48 independent controls for exact types/copying, nonempty maps, preserved inspector profiles and all other effective Config fields, plus two old-red/held-green causal pairs.

There are zero test failures/errors/skips. Local fixtures use fake inspect/API/CLI responses, private temporary files, tiny owned Python processes/signals and temporary Unix sockets. Default sandbox does not permit socket binding; the authorized owned-socket fixture runs used the needed local permission. There was no Docker, package execution, GPG, compiler/native kernel, upstream code, installation or host configuration action. The old-red cases execute exact old Python broker/image code with identical producer-shaped synthetic fixtures: provision image Labels None versus container `{}` refuses; null base versus empty derived Config refuses downstream verification. Both cases pass on the held source with other predicates unchanged. They are not a native replay.

Every held primary and copied row is rehashed after testing; no PYC or foreign source was added. The captured pure packet.preview reproduces the proposed 117-row map byte-for-byte, while all 26 stage rows are independently checked. Proposed stage SHA is `0ef3ad174f0bdc1cd9b1a3c4874775dc2c486f3fc08429c6d2751715ccce2290`; proposed packet SHA is `647d4dd0101b2188d348adc87089fc5804e288872ff5fc9352d76861a512f342`, with copied packet.py SHA `4baf72a76b1bc38e857e03dd4aa59c79e8b99b9442304fea64ebfa1d09d28288`.

Primary coordinator inputs remain untouched: stage lock `387e72fc836103b9654e65ee9e186369ebe34e240f9603f8b9779f6f317e2b63`, packet `9ca9414c8461d2a134d68390381755811b0d61aa9097ef23b747ef91f138dbf0`, packet.py `ed9de6b4c899e124bf0a438c26b18e6acfb1b5ee70b9fade833f757cee2d1cdc`, and workflow `1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4`. Root must rebind stage rows/lock and packet.py/packet, verify actual committed blobs/modes and bootstrap, and decide native dispatch separately. This review changes no source or map and does not waive the generic ownership failure or cleanup gate.
