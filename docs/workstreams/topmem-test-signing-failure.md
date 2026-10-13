# Topmem TEST signing failure: bounded diagnostic successor

Hosted ARM run38450105697 ended FAIL at Source `bf5ea66bb12ba99c1f5684746630b9c7564da254`. Its immutable retention completion is `799cf4b790baee4b1f4d50b4386a3b6818af8d20c1ec482a3959f4df95d87376`. The retained baseline passed8 builds,4 comparisons and249 signature observations, receipt `fb3bd22d1f92d22c79aaf60ef740b3fc62ae4774da13cdb86f5a3a3b10974494`; addon counts stayed0, cancellation was false, and owned-image absence was true. The precise inner signing predicate and signer recovery outcome remain UNKNOWN because the selected retention phase did not export them.

This is a source-only proposal under `artifacts/reviews/topmem-test-signing-failure-proposal-20261013`. It does not establish a successful addon build, installed package, real signer recovery, M2 hardware behavior, performance or R1–R5/M5–M9 completion. No selected source, shared manifest, workflow, Git state or existing seal was edited. No GPG, agent, library, Docker, network, package or native actor was launched. Root owns independent review, source registration, integration and any later execution.

## Proven failure boundary

Pinned original caller `bf795d8849e85e9549f0cfbd45451d1f4d336ac76d8e3e90400152b20655f0a6`/51,562B assigns parent phase `signing` at372 and changes it to `addon` at376. Between those assignments it runs `signing.start`, saves `addon-config.json`, and hashes that saved configuration. Therefore the retained `signing-failed` narrows the failure to that start/handoff branch; it does not identify a particular signing guard or command. A later child `signing.prepare` failure produces child `signing-failed`, but the existing parent only imports child cancellation and records parent `addon-failed`.

Pinned signer `a0d0db64e1f62a160ac9ad9efeca9e34deb22f082e882dc4d0cca6b78f2260e1`/42,378B has separate attempt, policy/tool/source, fresh-directory, socket-length, launch/identity, handoff, command, fingerprint and certificate guards. `start` can fail before its owner journal exists; journal availability cannot prove success or absence. `prepare` checks policy and custody before its command block; journal phase alone cannot identify its last refusal. No retained evidence proves a signing-algorithm correction, tool-policy relaxation or alternative actor is warranted.

## Minimal successor behavior

The six common bodies remain identical across Topmem and Fish. Only `caller.py` changes. `signing.py`, the inherited launcher, producer, repository adapter and addon recovery remain byte-identical. The candidate caller is `16a84d23e88b2dcc69282ca1ea4c40045a3f1db64d9fd2e362371f82ad15dcb8`/60,169B. The candidate manifests are:

| Profile | Manifest SHA256 | Bytes |
| --- | --- | --- |
| topmem-v1 | `6ca00cefac43850ce56a793a3962bb51caad284182a752aa0ed0dd151fbc425b` |1680 |
| fish-history-v1 | `003e6e2b8da6f5f6f91ec64c2c09b95f100e355a29ac6d399d2e90388d7af9b8` |1686 |

Closed public metadata advances explicitly to schema2. It adds two fields:

- `signing_diagnostic`: stage `not-attempted`, `start`, `handoff-save`, `handoff-pin`, `prepare` or `prepared`; code is null, one of67 literal `signer-*` codes captured from the pinned signer, or the closed classifications `cancelled`, `io-failed`, `unclassified`. Only an exact `ValueError` with one allowlisted string argument exports its literal code. No error stringification occurs. A bound child diagnostic is copied without changing the existing first-cause behavior.
- `signer_retention`: validated owner-journal projections before/after recovery, plus a closed signer-recovery projection. A journal projection contains only status, phase, launch-attempted, agent-bound and sticky-uncertain. Recovery contains only status, agent-absent, keyhome-absent, cancelled and a closed reason. Missing or invalid evidence is `UNAVAILABLE` with null values, never a passing absence claim. Journal cancellation makes caller cancellation sticky while the remaining cleanup still runs.

The source journal verifier still checks custody and job/source/nonce/policy binding. Raw journals, private keys, owner references, certificate material, PIDs, socket identities, paths, argv, stdout, stderr and arbitrary exception text are not exported. The optional snapshots use the existing bounded journal read and the same recovery deadline, then all signer/addon/baseline recoveries retain their original order. No new clock, retry, key generation or recovery authority is introduced. Retained PASS additionally requires `prepared` with null error code and signer-recovery PASS; all original package counts, binding, cancellation, image-absence and acceptance guards remain.

The closed export distinguishes a refusal predicate from a unique instruction: repeated codes such as `signer-tool-pin` or `signer-command-failed` still require their safe boundary and journal state for interpretation. It deliberately does not export raw tool errors or identify a particular GPG invocation beyond the `prepare` boundary.

## Finite inert verification

`controls.py` extracts the exact original/candidate caller functions and injects synthetic tool, runner, child, graph, journal and recovery doubles.30 cases cover both profiles and both caller versions: start refusal, child prepare refusal, handoff save/pin failure, failed recovery, unavailable journal and synthetic success, plus candidate journal cancellation. They prove the old boundary propagation, proposed safe classification, unchanged baseline counts, zero addon admission on failure and all three recovery calls. Closed-field/type/schema/PASS mutations and arbitrary error-content controls are refused. Synthetic success is a control result, not native acceptance.

`signing-controls.py` extracts the exact unchanged signer start/prepare functions.16 cases across both profiles exercise attempt/policy/entry/socket-length and handoff guards before any actor boundary. Socket creation, subprocess launch and tool execution are replaced with forbidden doubles. These cases show that several distinct refusals are possible; they do not identify the actual ARM failure. Unsealed harness setup failures and their inert scratch directories are retained in `attempts.json`; the corrected final controls pass.

## Registration and next actual check

`source-pins.json` authenticates both original manifests and all six common bodies. `source-registration-plan.json` gives exact candidate paths, bytes, modes, SHA values and the explicit pin cascade. Root should independently rederive and review this proposal, then register the common caller body and the separate manifests in both canonical profile trees. Recompute both full source closures: Topmem123/Fish129 source rows, source+policy proof124/130, and workflow-inclusive125/131. Preserve the baseline/addon/producer and actual ARM20-row policy bytes. Update each workflow's exact caller and caller-manifest pins without changing its clock, profile, trigger/ref or output ownership. Bind each actual successor commit to its external source variable; no future commit SHA is fabricated here.

A later reviewed native attempt must retain schema2 caller metadata on success and failure. On failure, require the safe stage/code, both journal projections and signer recovery result; preserve UNKNOWN where evidence is absent. On success, Root still requires overall hosted success, exact Source/policy/clock/proof bindings, natural completion, fresh baseline8/4/249, addon4/2/6/1 and2 internal database productions, complete non-null observations, both signing/command journals, exactly14 expected passed signing entries with6 verifications, all recovery and image-absence evidence. This diagnostic successor does not lower those requirements or provide actual execution authority.

Freeze the proposal after its receipt. Any correction requires a separately retained successor. Preserve the failed ARM run and every earlier sealed proposal/review.
