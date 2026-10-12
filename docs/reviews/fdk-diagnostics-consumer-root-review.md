# Independent FDK diagnostics consumer review

**The source consumer logic passes; admission is held for two policy/documentation
corrections.** No captured-import, schema, vector, acceptance, downgrade or
cancellation defect was identified. Fresh reviewer controls passed 29 tests,
zero failures, errors or skips. This is a source/interface result, not native
build acceptance or committed Git proof.

## Exact combined hold

Author receipt
`artifacts/reviews/fdk-diagnostics-consumer-20261012/held-receipt.json` is SHA256
`1987f1b7170eb7f7c01e20a4ef2a59edaf2cf8d38e5dfe68a73bbe7cda3a2aee`.
The four owned references match the primary source and the fresh reviewer capture:

| File | SHA256 |
| --- | --- |
| `scripts/port/fdk-native-job/job.py` | `39fba50688727b75f11492bf1fbb55a89f782f99a6d30d4f6f6307838dcae67d` |
| `scripts/port/fdk-native-job/test_job.py` | `44a335d488adaf767b00392718f17c2542c401b5cf546ffbbf6dd65e3e4b162b` |
| `.github/workflows/native-arm-fdk.yml` | `fa1af3aad80ffd488fef5ddd875583c3251c49e6a0efcac58f14c6d5429d38f6` |
| `docs/workstreams/fdk-diagnostics-consumer.md` | `20ba30245137447410acb7ba8691721fdd74b901465106d0af6279187452f00f` |

All seven stage source hashes and the stage guide still match the
[sealed stage review](fdk-build-worker-diagnostics-root-review.md). Its receipt
`34e7ab164f95fa61dccc43b8940499245df1e32f9f920d45ee201bde62b7477a`
remains unchanged. The coordinator's primary stage40 lock is
`4db538d6292c6580c1eb1cc0d330fc84b9c27ae7b570dbfea5a0cdda6f403e3c`;
packet.py is `09bde8c730cbd1b596b2cdc23fd8e2c6d75ded82a6355c3b4fac4ebda058aec0`;
packet129 is `b91331eb4799718bf0700d8b9a81bbf39c99d5dad4a4f06f777e54d08392ac9d`.
All 129 rows match the author's prospective copy exactly in bytes, lengths and
modes; their selected source size is 2,141,231 bytes. The primary packet itself
also matches the prospective bytes. This verifies source rebinding, not a commit.

## Consumer and workflow checks

The job captures the stage lock and both dependency sources, verifies their
packet hashes/modes/lengths/identity and separately pinned nested stage rows,
then compiles those bytes. Its private modules intercept the mutual `evidence`
and `worker_evidence` imports through explicit private builtins. They neither
replace the outer producer's unrelated module named `evidence` nor write those
names into `sys.modules`. Both ambient module names were independently poisoned;
the authenticated pair still validated a complete vector and the poisoned
globals stayed untouched. Source/PYC import machinery is not used for the pair.
Standard-library imports retain the ordinary trusted interpreter boundary.

Stage public receipt capture is bounded, owned and attempted once. Validation
and publication reuse its snapshot. Missing or invalid first capture remains
refused even if a later file appears; a later replacement cannot rewrite a valid
captured result. Public schema 2 has exactly 13 keys. PASS requires the three
distinct VERIFIED actual-zero COMPLETE diagnostic roles, an exact integer zero
stage subprocess return, original producer acceptance, uncancelled completion
and actual positive scoped cleanup. Boolean zero is refused. Missing, malformed,
private-field or contradictory vectors cannot pass, and schema 1 has no current
fallback. Validators check claims; the stage's captured execution and original
artifact checks supply their execution basis.

Outer failure downgrades FDK acceptance while retaining a valid inner vector
and its original first-failure fields. It does not manufacture an inner failure
when outer cleanup or publication failed. Fallback diagnostics are finite FAIL:
NOT_RUN before an attempt, UNAVAILABLE/UNOBSERVED after an attempted stage without
a verified receipt. Cancellation, bounded final rewrites and failed rewrite
removal retain failure across job, producer and FDK public outputs. These
controls use mocked native calls and owned files, not actual Docker cleanup.

The first workflow Python guard requires exactly 129 packet rows and checks
source hashes, lengths, modes and committed bytes before native launch. The
always-step independently authenticates packet, loader, pin literal, stage lock
and dependency bytes against dispatched pin and committed source/modes/workflow
identity. It extracts only the exact undecorated captured pure loader function,
binds both dependencies against the nested stage lock and rejects a coherently
rehashed but unbound helper before execution. Its public guard requires current
schema 2 and the same strict vector gate, plus existing native outcome, source,
producer, allowlist, cancellation and owned-absence conditions. Encoding uses
the validated bytes copied into a private snapshot. Run-attempt forwarding is
present alongside the existing run ID.

## Required corrections

1. **[P2] Preserve inherited HOME in the owned workflow environments.** Workflow
   lines 74 and 634 assign HOME to RUNNER_TEMP; job line 277 assigns it to the
   private job directory. This is inherited behavior, not a newly detected
   runtime regression, but the current session rule says never to repurpose
   HOME. Preserve its original value/absence or omit it as appropriate, while
   retaining explicit private Git/Docker/temp configuration. The unchanged
   stage remains outside this four-file edit scope. Rebind any changed executed
   source after the correction and perform the focused consumer checks.

2. **[P2] Make the guide's commit statement prospective.** The guide says the
   workflow “is separately reviewed and committed,” while this hold and its
   adoption record explicitly leave fresh committed proof pending. State that
   the workflow must be separately reviewed and committed before dispatch.
   The source and fixture results do not establish that commit.

These findings do not contradict the passing consumer controls. They prevent a
blanket admission PASS for the current four-file hold. No source repair or
policy exception was made by this reviewer.

## Verification and remaining native gate

The fresh copied suite selected 14 loader/bootstrap/public controls, 12 job
source/exit/acceptance/cleanup/cancellation controls and three independent
import/vector/downgrade controls. All **29 tests passed, zero skips**, using
isolated Python, no bytecode, and ResourceWarning as an error. Relevant imported
job/test/runtime/packet/evidence/broker modules resolve to the captured tree;
captured hashes stayed unchanged and zero PYC files existed before and after.
Git replies and all native/tool/source-stage calls were mocked. Real TERM tests
exercise the controller's own signal handling in controlled host fixtures.

Both workflow Python bodies parse and are exercised through their extracted
functions. The author's 174-test and YAML-structure logs were hash-verified,
not relabeled as reviewer executions of those full checks. The retained eight
historical public files and historical workflow were independently hash-bound
as separate test inputs. Their exact schema-1 FAIL replays through the retained
historical guard; the current guard rejects that receipt.

Actual run **38277573107 remains FAIL**, phase build-1, native build NOT ACCEPTED;
its FDK receipt remains
`df953517781c0811b604946099d9c57a4ad0af4366f34c14f7d37452e7e02404`.
Compiler invocation is not established. No new native Docker/compiler/GPG,
installation, hardware, release or performance result was produced. Coordinator
correction/rebinding and fresh committed Git/copy proof remain before dispatch.

Evidence is held in
`artifacts/reviews/fdk-diagnostics-consumer-root-peer-20261012/`: the fresh source
tree, capture receipt, focused log/results, reviewer scripts and review receipt.
The sealed stage and installer follow-up reviews remain unchanged.
