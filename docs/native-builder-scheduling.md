# Native builder scheduling

The coordinator reserves two independent hosted lanes: `native-arm-kernel` for
one bounded kernel job and `native-arm-build` for one other native development
job. Each remains manual, source-pinned and non-cancelling. All jobs still use
`ubuntu-24.04-arm`; no self-hosted machine or shared Docker daemon is introduced.
[GitHub documents](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job)
that these hosted jobs receive separate fresh virtual machines. This supports
independent Docker/image namespaces; actual host and resource checks remain
mandatory on each VM. Availability is observed from actual dispatch, not promised.

The coordinator permits at most one active and one pending dispatch in each
lane, and never submits a new pending run over an existing pending reservation.
This prevents GitHub's concurrency queue from replacing a prior pending trial.
There are at most two native jobs executing concurrently. Each job retains its
existing CPU, memory, storage and finite deadline limits. No package, source,
public-evidence, cleanup or hardware acceptance gate changes with scheduling.

The long kernel trial can now proceed while shorter package and virtual guest
fixes receive their own native rechecks. Physical Mac mutations and measurements
remain serialized per actual machine. The kernel workflow changes only its
group string, with its115-source packet rebound to that exact workflow byte
change and matching existing workflow-shape test literal; the24-source kernel
stage and113 other packet rows are unchanged.
