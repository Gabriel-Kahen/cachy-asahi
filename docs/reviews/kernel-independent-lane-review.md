# Independent native kernel lane review

October 12, 2026. **PASS, scheduling-source review only.** No remaining material
finding in the reviewed two-line change. The reviewer changed no workflow,
source, pin, Git state or dispatch; only this review and reviewer-owned ignored
artifacts were written. Root owns subsequent commit, committed-source/bootstrap
proof and any actual launch. This review supplies no account capacity, runner
availability, execution or kernel acceptance claim.

## Exact reviewed proposal

| Identity | SHA256 |
| --- | --- |
| Kernel workflow | `1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4` |
| Matching existing test_public fixture | `7cdf4eac53c5fdc2b3f0d09185a0214477f0da98401c9198a46f6dde8f57276e` |
| New canonical 115-file packet | `b2e3858426b1eb675dd1df57e788233f72034f48de2dde6b00eb45cdc7f300b3` |
| Previous adopted 115-file packet | `41f41b5f5cbb13e1dd01e52f60e59390ebe7c7e6105367955840ec633a5fcdcd` |
| Unchanged 24-file stage lock | `825abddbe38ff9f8a78c340a56e7e51e2b38449661b22b7d2e755b65230c7ed1` |

Independently compared the retained historical workflow/test bytes with the
actual candidates. The workflow differs only at line 12:
`group: native-arm-build` becomes `group: native-arm-kernel`. The existing
workflow-shape test differs only in its corresponding string literal. There
are no added tests, changed assertions/logic or other byte differences in either
file. Historical workflow-only proposal evidence remains separate; it does not
authenticate the final two-row packet.

Independently regenerated `packet.preview` using the current held helper,
compared its complete map and exact sorted/indented JSON/newline bytes with the
new packet, and rehashed every source row/mode. Result: **115 files,
1,905,898 bytes; exactly two changed rows and 113 unchanged rows**. The stage
lock hash and all 24 locked source bytes/modes match. The current packet includes
both the changed workflow and matching test row. Existing job/public runtime,
source authentication, inline bootstrap, original producer and every other test
byte remain unchanged relative to the prior packet.

Manual-only dispatch, public-repository gate, `ubuntu-24.04-arm`, read-only
contents permission, pinned checkout, disabled persisted credentials,
`cancel-in-progress: false`, source authentication, resource/deadline checks,
scoped cleanup and actual native outcome revocation are unchanged. Root reported
all 70 affected public tests passing from its fresh 115-file copied source; the
independent reviewer did not repeat that already-passing suite. The review's
canonical source proof is not a committed Git/blob/mode or fresh-bootstrap proof.

## Scheduling rationale and remaining boundary

The reviewed [scheduling policy](../native-builder-scheduling.md) reserves the
new `native-arm-kernel` lane for a bounded kernel trial and leaves the other
native workflows in `native-arm-build`. All inspected native workflows use
these two groups and hosted ARM runners. GitHub documents fresh runner image
instances per hosted job and a new VM for this standard public ARM label;
there is no shared self-hosted Docker daemon introduced by changing a
concurrency group. Separate job VMs justify independent daemon namespaces, as
an inference from the hosting contract, while per-VM checks remain mandatory.
[GitHub runner documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).

Default concurrency permits one running and one pending workflow in a group;
a new pending submission replaces the earlier pending run. Keeping
`cancel-in-progress: false` preserves an active run but does not preserve a
prior pending reservation. The coordinator's stated policy—one active and one
pending maximum in each lane, no submission over an existing pending
reservation—is therefore necessary. It is a dispatch policy, not enforcement
against another actor manually submitting runs. Group membership limits these
native lanes to two concurrently executing jobs; account queues and host
availability may still delay either. No additional runner quota or compute
capacity was checked or inferred.
[GitHub concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

Physical Mac mutations/measurements remain serialized per actual machine.
Changing scheduling does not relax package, platform, source, cleanup,
installation, hardware or performance acceptance. Root must commit both
source-line changes and the exact new packet, then repeat actual committed
source/mode/inline-bootstrap/fresh-snapshot proof before dispatch. Actual
execution and available capacity remain NOT ESTABLISHED here.

[Independent machine-readable review](../../artifacts/reviews/kernel-independent-lane-peer-20261012/review.json),
SHA256 `fb6ce61affe556613c2d186a4300e310227ec18ea7ebd01640da3a995be7ca48`,
retains the proposal hash, canonical packet proof and both exact diffs. No
historical source or run receipt was rewritten.
