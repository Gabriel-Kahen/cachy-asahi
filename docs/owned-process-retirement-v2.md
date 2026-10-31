# Reserved retirement profile v2

Use `developer_workflow_retirement_v2.RetirementCommands` to select the versioned,
strictly pinned core. The public `supervise()` signature, existing deadlines,
output limits, group bounds and RSS sampling contract stay unchanged. The shared
`developer_workflow.py` remains byte-exact at SHA256
`531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba`;
its legacy core and caller pin are not migrated.

Grouped runs keep the exact terminal leader reserved with `WNOWAIT`. A complete
bounded census must end with only that reserved terminal leader before its raw
wait is consumed. Remaining, live, foreign or incompletely observed members do
not qualify. Expected nonzero command exits still require complete ownership,
output and timing proof.

The opt-in core can retire exactly one additional zombie observed in the same
original group and session when its recorded PPID equals the supervisor PID.
That numeric equality is only a candidate selector. Before consuming the child,
the core must acquire its exact kernel `WNOWAIT` terminal status, recheck its
PID/start time/group/session/PPID identity, and confirm that the original leader
is still reserved. Its raw wait must consume that exact child with the matching
zero exit status. A fresh complete census must then establish the unchanged
`RESERVED_LEADER_ONLY` condition. Two additional children are outside this path.
No broad child wait, global reaper or subreaper setting is installed.

`group_retirement` is bounded pre-reap DATA. It records the wait-owner PID,
member PPIDs and numeric parent relationships; subreaper state remains
`NOT_OBSERVED`. When the adopted-child path is considered, its finite
`adopted_child` receipt records the candidate, kernel status, identity check,
raw wait and final census. Refused or incomplete receipts confer no positive
qualification. A PID receives no further numeric query after its wait custody
is lost or its raw status is consumed. If the consumed extra PID appears during
the final enumeration, the scan refuses before reading it. Consuming or losing
the reserved leader closes all further numeric group operations.

The new controls use fresh isolated host Python children and an owned temporary
subreaper fixture. Competing-reaper, identity, foreign-parent, live-member and
PID-reappearance cases are labelled fault injections. Audit hooks are inactive
at import/discovery and apply only inside owned fixture contexts; fixture
cleanup uses an exact known-child ledger and kernel reservation before each
consuming wait. These controls do not establish native ARM, 16K, M2, package,
release, escaped-child or global daemon absence. Native qualification of the
new proposal remains separate.
