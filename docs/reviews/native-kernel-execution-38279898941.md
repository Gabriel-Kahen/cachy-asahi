# Actual kernel trial38279898941: provisioning-boundary diagnosis

The actual run remains **FAIL**. Its new child diagnostic successfully narrows the first retained failure to **PROVISION_COMMAND / INVALID_DATA**, with provision result **UNOBSERVED**, but does not identify the first internal predicate. No kernel compilation, probe or paired baseline/candidate acceptance is established. Cleanup and final preservation/owned absence remain independently failed/unverified.

## Actual retained evidence

Source commit: `bae171ea0dd6c4c5c492403dc112b2dcbdb79953`. The independent read-only capture verifies all117 committed packet rows by Git bytes, lengths and modes, and all26 stage-lock hashes/modes. Packet `4d392a614ce63509133c9595a8e62299c8bccefc050f0640dd6b0afbf3f7279d`, workflow `1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4` and actual public status `db71b7b81fb32f3fcd44e16242e467d3c4f4b6d70faa228b16602d7938eb6ed2` match. The9-member log ZIP and every decoded file match retained sizes/hashes. Full workflow log:54,431 bytes/SHA-256 `65f0a7a745c5e6db33f94570102c309a35982099b2deb03532996165ae1580a9`.

The actual committed projector accepts the retained failure, returns the identical dictionary, and serializes to identical canonical public bytes. The workflow contains one matching status and reports actual execution exit1. The root verification record and exact projector/stage source hashes are bound in the peer receipt below. No moving working-tree source is used as run authority.

| Observed field | Actual retained value |
| --- | --- |
| Producer/acquisition actual exits | EXIT_ZERO /0 each |
| Producer status/mutation | PASS /COMPLETE_ACCEPTED |
| Initial daemon baseline | 6 image IDs,0 containers |
| Initial identity digest | `124fd070b1b7bc795026a7b7ed4773c03383c492587efeeaffc5faf65f7cb869` |
| First outer failure | kernel /KERNEL_EXIT |
| Kernel child capture/exit | VERIFIED /EXIT_NONZERO /1 |
| First child boundary | PROVISION_COMMAND /INVALID_DATA |
| Provision result | UNOBSERVED /null |
| Probe/baseline/candidate | NOT_RUN /null |
| Child cleanup | FAIL /ABSENCE_UNVERIFIED |
| Final baseline preservation/owned absence | UNVERIFIED /UNVERIFIED |

Child binding digest is `25ee9c99c7bb5f5155b015660b0d04de852011b1a2a64277c6742f31c67fa2ff`. Its private source/run/nonce/input/output binding, raw child receipt and logs were not exported. The root can independently check public schema and the committed capture/verification code, but **cannot recompute that private binding digest** from this projection. VERIFIED records the trusted job's capture/binding observation; it does not supply the missing raw private witness.

## Exact source boundary and uncertainty

The stage first accepted its base and dependency packet and initialized the provision broker, then entered its provision command boundary. It sets the command result UNOBSERVED, writes the PROVISION_COMMAND checkpoint and calls `Broker.launch`; result classification follows the return. Thus the retained first boundary includes checkpoint persistence, launch validation, broker operations and returned-result classification. It is not proof that an error originated inside the Docker worker.

Broker launch validates action/persist/role, timeout, mount paths and the fixed environment, then loads/reserves a durable nonce-bound journal. It checks existing-name absence, records create commitment, invokes create, validates the returned full CID, inspects ownership/resources/mounts/command, and invokes attached start. Each CLI operation checks captured local CLI/socket and daemon identity before and after the query. The supervisor also has finite argument/output/deadline checks. Any of these internal checks can refuse before a result reaches the stage; a post-query identity refusal can occur after actual create/start activity.

Consequently UNOBSERVED means **no command result was accepted by the stage**, not no launch or no mutation. A normally returned worker/create nonzero would instead receive a typed EXIT_NONZERO and COMMAND_NONZERO category. The observed category groups ValueError,KeyError andTypeError. Without raw private evidence or a finer first-gate record, no particular resource/config/identity/query/worker cause is justified.

The provision worker uses only its recorded signed extension, disposable root container, network-none, fixed capabilities and immutable code/input mounts. Worker profile, signature/import/install or inventory errors remain potential inner events only if the worker actually ran. No actual worker failure label or profile value is supplied here. Source order does not reach derived-image commit or kernel build/probe after an unreturned provision command. Cleanup remains a separate gate; it cannot erase the first failure or establish B preservation/absence from VM completion.

## Independent bounded controls and next correction

Four source/mock tests pass with zero failures/errors/skips and ResourceWarning treated as error. They cover precompile checkpoint separation, returned nonzero versus unobserved launch, provision command identity/capability construction and strict inspected container profiles. Six modeled static private ValueError labels independently collapse to the same current INVALID_DATA category while cleanup retains the sticky first PROVISION_COMMAND. These are classification controls, not witnesses to the actual inner cause. No Docker, socket connection, GPG, network, compiler, upstream kernel execution or system mutation was performed by this peer.

Before an identical native retry, instrument a closed immutable first checkpoint/broker gate, current fixed action and query kind, and actual typed query return **before** post-query checks. Distinguish CHECKPOINT_WRITE, launch validation, name/journal/create, inspect ownership/resources/mounts/command, attached start and pre/post identity checks. Unknown messages must remain UNKNOWN; public output must exclude raw errors, paths, IDs, argv and logs. Keep an independent sticky cleanup failure and unknown create/start commitment. Extend the existing bound child/receiver schemas together with focused fake-backend causal schedules, without adding daemon queries, changing timers, weakening ownership/removal, pruning, capabilities, B preservation or PASS gates. Root selected a separate bounded source correction after this read-only hold; this diagnosis makes no implementation change.

Historical schema4/diagnostic1 evidence and this actual FAIL remain unchanged. M2/16K runtime, installation and performance remain unrun claims.

Peer evidence: `artifacts/reviews/kernel-third-provision-diagnosis-20261012/final-review-receipt.json`, exact committed source capture, actual public-status copy, canonical projector/log/source proof, classification controls and focused-test log. The review records the root verification record's actual hash rather than treating it as new private native evidence.
