# Kernel provision capability equivalence

The coordinator selected the finite proposal from the sealed [kernel6 actual review](../reviews/native-kernel-execution-38301759759.md), receipt SHA256 `164df38634672bad9bdd293141beec076818a0b1bfcb306b89bd0ea3293d4523`. This change implements only the selected source correction. Actual run38301759759 remains **FAIL**, native compilation **NOT RUN**, cleanup **FAIL**, owned absence **UNVERIFIED**. The actual private CapAdd array was not exported, so no actual spelling, ordering or capability membership is inferred.

## Exact selected behavior

Provision inspection accepts an exact built-in list of exactly three exact built-in strings when removing at most one literal uppercase `CAP_` prefix gives exactly one each of `CHOWN`, `DAC_OVERRIDE` and `FOWNER`. The six permitted strings yield48 representations: six order permutations times eight prefix combinations. The length and normalized-set requirements reject missing or extra entries and duplicates, including bare/prefixed aliases of the same capability. Unknown names, ALL/CAP_ALL, lowercase, whitespace, repeated prefixes, other value types and string/list subclasses do not pass the pure helper.

The existing provision options continue to request exactly `--cap-add=CHOWN`, `--cap-add=DAC_OVERRIDE`, `--cap-add=FOWNER`, alongside `--cap-drop=ALL`. Build-role nonempty CapAdd remains forbidden. Provision cleanup uses the provision broker's same role-bound inspection; this does not authorize extra capabilities or change removal conditions.

`provision_capabilities` is a pure predicate. Only after it succeeds for the provision role, `_inspect` creates a shallow local check view whose CapAdd equals the original canonical expected list. The decoded private host is not mutated. The original resource conjunction, forbidden-field checks and their order remain in place. `Trace.resources_refused` receives that same check view if the resource gate fails. Therefore a valid alias cannot become a false CapAdd label when an independent field, such as Devices, caused refusal. Invalid CapAdd remains untouched for the original MISSING/TYPE/VALUE classification.

Ownership, image/user/role binding, mounts, commands, environment, CapDropALL, resource bounds, networknone, private IPC/cgroup namespace, security options, start sequencing, query count, deadlines, journal, cleanup and PASS gates are unchanged. There are no new operational calls or public raw-value fields. The schema3 finite field/kind ABI is unchanged.

## Why equivalence is supported

The [sealed primary-source trace and deterministic model](../../artifacts/reviews/native-kernel-38301759759-root-peer/semantics/proposal.md) authenticates pinned Docker CLI/Moby references and separately pins OCI specification v1.2.1. Moby capability normalization recognizes bare and CAP_ spellings; dropALL selects only the requested added capabilities. OCI capability arrays describe sets. The retained storage/inspect path does not establish a rewrite. The original broker model accepted only one of48 equivalent representations and rejected47 as CapAdd/VALUE. That proves the comparison limitation without claiming the actual array had an equivalent representation.

## Hold, tests and admission boundary

Owned production files are only `scripts/port/kernel-native-stage/broker.py` and `test_broker.py`. This guide and the new artifact namespace [`artifacts/reviews/kernel-capability-equivalence-20261012/`](../../artifacts/reviews/kernel-capability-equivalence-20261012/) contain the selected source hold, causal tests and receipts. Independent review is assigned by the coordinator after this hold.

Tests exercise actual `_inspect` through modeled bounded decoded results, including all48 equivalent provision arrays and the same48 during cleanup, malformed and capability-expanding values, build-role refusal, unchanged resource guards, correct diagnostic attribution and sticky first failure. The same final added tests are run against the original broker for RED and the candidate for GREEN. The fresh complete117-source baseline capture substitutes only the two granted candidate files; stage/job suites run in separate isolated Python processes with real short owned TMPDIRs for harmless host fixtures. Results and any harness failures are retained in the artifact namespace. These tests do not run a production daemon, native compiler, installation or GPG actor.

Source audit caught that placing the added lookup before the resource scope would change the reported gate for malformed HostConfig. The final lookup is inside `INSPECT_RESOURCES`, preserving the original exception boundary. A regression control covers malformed HostConfig in provision and cleanup; it also passes against the original broker. Earlier source/results are retained separately. The stage discovery includes eight original real-C controls skipped because private pinned Asahi source copies are absent; compiler actors are outside this grant, so those controls remain **NOT RUN**. Broker and job controls have no skips.

Final captured results:

| Check | Actual result |
| --- | --- |
| Nine focused added broker methods, candidate | PASS, zero failures/errors/skips |
| Identical final nine methods, original broker | Expected RED:16 failures/95 subcase errors; malformed-HostConfig compatibility control still PASS |
| Full broker suite, candidate | 36 PASS, zero skips |
| Fresh117-source captured stage suite | 150 executed controls PASS;8 real-C fixture controls NOT RUN (158 discovered) |
| Fresh117-source captured job suite | 209 PASS, zero skips |
| Original stage-lock admission of candidate | REFUSED `code snapshot differs: scripts/port/kernel-native-stage/broker.py` |
| Operational AST audit | Exact original AST after removing the pure helper/check view and reversing its local variable alias |
| Fixture cleanup | All short owned TMPDIRs empty; no PYC |

The final two-source hold is broker SHA256 `370a6036d7c268267c31fa40dd08b159b70dba6e7ccd693b46b92df512725fe7` and test SHA256 `a82e38e0362793962e9a9a73613dd2028545e05d07e21ba8fb1113e224c16248`, both mode0644. The tests receipt is `cd66a7b3752b856bbd7fcacf58b3ab67ada4bdb940fb4f5b1eb6aebf701f11da`. The first test runner had a quoting SyntaxError before any actors; the corrected runner and original failure are retained. Independent review remains pending coordinator assignment.

The shared26/117 maps, packet pin, workflow and Git are not edited by this worker. The captured original stage lock and packet intentionally remain unchanged. Their source-authentication gates must refuse the candidate's changed bytes. Root must separately update the stage map, receiver stage pin and aggregate packet/workflow registration and obtain the required review before a selected native run. Passing modeled tests is not acceptance of the candidate under the old committed packet.

The actual kernel6 review, KSM observation hold and guest4 actual review/loader diagnosis are re-read unchanged. This source correction does not convert any actual native failure to PASS or establish a compiler, kernel execution, M2, 16K or performance result.
