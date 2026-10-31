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

These six components may overlap one another and the two heavy lanes only on
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
