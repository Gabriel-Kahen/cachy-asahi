# Native builder scheduling

The coordinator classifies each exact source and operation before dispatch. Two
heavy hosted lanes remain reserved:

| Lane | Group | Limit |
| --- | --- | --- |
| Full-system/package transactions and virtual-guest trials, including Core, GNU and full-system ALPM | `native-arm-build` | One active and one pending reservation |
| Kernel builds | `native-arm-kernel` | One active and one pending reservation |

Trials keep their existing source-pinned workflow groups. A distinct historical
group name does not create another heavy lane. The coordinator enforces these
two reservations across such groups, never submits over an existing pending
reservation, and never cancels or replaces a prior trial. Two heavy Core/GNU/ALPM
trials must not overlap. At most one non-kernel heavy trial and one kernel trial
may execute together.

The finite lightweight component lane set is:

| Closed component operation | Fixed group | Status |
| --- | --- | --- |
| Source tools | `native-arm-source-tools` | Maintained factory on main |
| Platform tools | `native-arm-platform-tools` | Maintained factory on main |
| Image tools | `native-arm-image-tools` | Maintained factory on main |
| Desktop tools | `native-arm-desktop-tools` | Maintained factory on main |
| Security maintenance | `native-arm-security-maintenance` | Proposed factory in PR314; trial gates remain |
| Release tools | `native-arm-release-tools` | Reserved proposed Source201; not yet published or admitted |
| Measurement tools (`measurement-tools-alpm-v1`) | `native-arm-measurement-tools` | Reserved proposed finite component; Root trial gates remain |

Each component must use its exact qualified closed Source, operation and fixed
workflow group, with `cancel-in-progress: false` and `queue: max`. The group
serializes that component's jobs; the coordinator checks actual active/pending
ownership before dispatch and preserves every earlier reservation. This list
does not classify arbitrary jobs by a similar name. New groups, changed operations
or expanded source scope require explicit coordinator classification before
dispatch. Source publication and applicable CI gates still precede each trial.

The Release reservation covers only the finite package-component journey, never
a full-system VM or installer. Root must qualify its complete new Source201,
exact component operation, actual resource isolation and matching strict reader
before using it. No Source SHA is assigned by this policy, no frozen Source is
changed, and the reservation grants no automatic trial admission.

The Measurement reservation covers only `measurement-tools-alpm-v1`, with one
active and one pending reservation for its finite Docker image-build and
unprivileged-container component. Retain the consumer's 2 CPUs, 4 GiB memory,
256 PIDs, 2 GiB `/tmp`, read-only root, no network, dropped capabilities and
no-new-privileges, and the inherited probes' 1 CPU, 128 MiB and 32 PIDs. Image
builds retain inherited daemon-default resource limits; consumer/probe limits do
not bound daemon builds. The tools image-build 840-second cap, 135-minute job
and all other existing caps remain held. Root alone classifies, adopts, publishes
and dispatches the exact Source. This reservation is not trial admission. Actual
native namespace support stays UNKNOWN until the first observational trial; a
prior namespace PASS is not required for that trial. Namespace failure remains
retained failure under the unchanged guard, without fallback. Existing Source
publication/readback, applicable CI, signing, custody and matching-reader gates
remain unchanged.

These seven components may overlap one another and the two heavy lanes only on
separate fresh GitHub-hosted jobs with independent Docker/image namespaces and
run-scoped evidence. All lanes retain `ubuntu-24.04-arm`; no self-hosted runner
or shared Docker daemon is introduced. [GitHub documents that hosted runners
use new virtual machines except for single-CPU runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners).
The overlap permission requires fresh VM isolation and each job's actual host
and resource checks; it does not extend to a shared VM or shared resources.
Runner availability and actual overlap are observed, not promised.

Every job retains its existing CPU, memory, storage, output and finite deadline
caps. Source/public-evidence, package, signing, custody, cleanup and hardware
acceptance gates remain unchanged. Shared Root signer resources stay serialized,
as do physical Mac mutations and measurements per actual machine. Scheduling
permission is not native, installed, hardware, performance or release acceptance.
