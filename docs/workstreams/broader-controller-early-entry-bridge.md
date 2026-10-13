# Private controller early-entry bridge

This is a source-only candidate for the reviewed precheckout launcher. It does not register a workflow, issue a real clock/grant, start Git or native actors, execute P0, or establish runnable-workflow acceptance. Primary sources, source maps, workflows, the frozen controller baseline and Git are unchanged.

The candidate is `artifacts/reviews/broader-controller-early-entry-bridge-20261013/source/scripts/ci/development/controller.py`, SHA-256 `2bba69dd425cb9a8dd0f246e293c3091487f1367504860f7cad8a345e5d0cd61` (86068 bytes). Its test is `source/scripts/ci/development/test_controller.py` under that artifact directory, SHA-256 `28a9f098694c92a6c168530db07b6fd738485368fb272dcc4c21832c01ae65bf` (89604 bytes).

The parent independent controller receipt `59cb98463ba87920534c6f6705a6fe6afc857b9f807e8b8817107e9f77c83dfa` was authenticated across all 282 indexed rows. The retained baseline is controller `9d0108ec0f5eaaff0a37692924b7ad5c9b48aa32884d1c1beb56319152bc693b` and test `704e3728f5d2e6594d9bd7dc5145559a82d808d4c3308593c34ed785d7bbd342`, matching primary bytes at capture. The reviewed launcher proposal receipt `d491f816f16374e412f51f58a123d177572eef067ecef5cb9c663b5e052c572a` was authenticated across its 94 artifact rows; launcher `5f4d1fe40f84c515f4a8e959eb09d19cbc43ff0dafadadcdd015b7df4db508b8` remains unchanged.

## Boundary and retained time

The only changed controller definitions are `workflow_clock`, `composed_main`, and `main`. All other definitions, top-level constants, imports and classes are AST-identical to the reviewed baseline.

`main` still records its actual monotonic entry before constructing the parser or reading sources. The optional CLI flag `--controller-entry-monotonic` parses a float. After the same captured twelve-field clock passes issuer, job/workflow, exact clock-domain and timestamp authentication, the controller requires an exact built-in finite float satisfying:

```
clock.issued_monotonic <= supplied_entry <= actual_child_main_entry
stage_J = min(clock.deadline_monotonic - 120, supplied_entry + 10080)
```

This can only shorten the local-entry cutoff. The controller immediately checks that J has not elapsed. Invalid supplied values and elapsed J refuse after only the private clock capture, before packet/source, execution-grant or runtime capture, handler installation and actor construction. Foreign float subclasses fail the type check without comparison/conversion hooks.

With the flag absent, J retains the inherited local-entry calculation. An explicit flag with no composition refuses before legacy packet preflight. Dropping the flag consequently selects the documented local-entry behavior; this candidate does not treat an ambient value or the flag alone as authority. The existing authenticated launcher must supply its retained post-issuance/pre-Git entry explicitly.

Every inherited stage/source/grant/runtime/SDK/native cutoff and snapshot receives the single retained stage J through the unchanged consumers. Publication retains its separate inherited reserved tail, `min(workflow_end, publication_start + 120)`, and is not newly clipped to stage J. The original clock12/grant17/runtime3 contracts, nonce32, profiles, original159/view160/generated125 and stage4/client71 contracts are unchanged.

## Fresh evidence and proposed packet delta

A fresh raw-source controller run passes **93 tests: the original 81 test-method ASTs unchanged plus 12 new synthetic entry/domain/CLI/delivery models**, zero failures, errors or skips. These controls cover issuer/domain precedence, future/preissuance/nonfinite/bool/int/subclass entries, elapsed cutoff equality before sources, actual main-entry-before-parser ordering, exact float forwarding in both composed modes, legacy flag refusal, absent-flag compatibility, unchanged J across later validation, exact J/nonce/runtime delivery and the inherited publication tail. The new controls use fixed synthetic monotonic values and a plain synthetic domain. Existing source-constructor and codec fixtures retain their established source-model scope; their positive results are not fresh authority for native frames.

The initial 93-test attempt had one error in the new parser-order model: replacing `argparse.ArgumentParser` globally disrupted argparse's superclass lookup. The model now replaces only the controller's argparse reference. `controller93-initial.json/.log` retain that failure; the corrected complete run is `controller93.json/.log`. No production correction arose from that harness error.

Ten causal observations compare exact frozen baseline code with the candidate under a synthetic clock/domain and a source tripwire. The baseline ignores supplied future/nonfinite/bool/preissuance/elapsed-early entries and reaches that tripwire; the candidate refuses before it with the expected stable error. Both preserve valid/absent dispatch and domain mismatch refusal. Exact positive cutoffs are baseline `110080.0`, candidate `109900.0`, same workflow end `110600.0`. Reaching a tripwire is not source authentication, grant acceptance, frame acceptance or P0 execution.

Both proposed composed packets were freshly derived by unchanged captured `packet.freeze_composed`, without Git:

| Composition | Source rows | Pins | Proposed packet SHA-256 |
| --- | ---: | ---: | --- |
| repository-svg | 258 | 12 | `c74c957bdb7ab592919bcffe986d67310e9f50b2d1ad865d645a1f56b9af80b8` |
| installer-preflight | 265 | 12 | `97e6cd9f79348a09ab9c229899390c8ad5d1714a785bf36d235118f02fadfd8a` |

Only the controller and test source rows change against the reviewed `6dad0b7e…`/`b7cecd7e…` parent packets. All twelve metadata pins, original159 and generated125 rows are exact. The seven-row installer extension is preserved. All 265 captured source files were checked after tests/derivation, with zero PYC and no forbidden actor attempts. Temporary fixtures live only under this artifact directory's private `tmp`; audit hooks refuse subprocess/spawn/exec/system/socket actors.

## Finite remaining handoff

Root must independently review this exact source2 and proposed packets, adopt the two source files, rebind the authenticated code selection and controller packet pins, and then derive the final immutable workflow/code/data selection. The existing launcher selection must forward its exact early float and six clock/grant/runtime path/hash bindings. Workflow/source-map/body registration and bootstrap/code/selection/data publication remain Root-owned and pending this candidate's independent review. Any newly adopted workflow/body bytes require dependent packet rebinding; these proposed packets still contain the preserved reviewed workflow bytes.

The launcher's retained 75 bootstrap/launcher models and 13 peer controls were authenticated as history; they were not freshly executed here and are not added to the 93 count. Actual Root clock/grant issuance, real launcher child launch, Git checkout, native owner frames, tools, image/GPG actors, Docker, native P0, ABI, release, hardware and performance acceptance are **NOT RUN**. This closes a source-level CLI handoff gap only.
