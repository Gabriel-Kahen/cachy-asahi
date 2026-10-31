# Reserved retirement profile v2

`owned_process_retirement_v2.py` retains the public supervisor API and all clocks.
Grouped runs reserve the exact terminal leader with WNOWAIT, complete a bounded
original-group census while that leader is unreaped, then consume the raw wait.
Only `RESERVED_LEADER_ONLY` qualifies. Remaining or incomplete membership fails.
No numeric process/proc operation follows raw consumption or ECHILD. This does
not establish global daemon absence, escaped-child absence or native acceptance.

Use `developer_workflow_retirement_v2.RetirementCommands` for the explicit byte-pinned profile.
The shared `developer_workflow.py` remains byte-exact at SHA256
`531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba`.
Its legacy `Commands` body, core file and pin remain unchanged for legacy callers; they retain their older census contract and are not migrated by
this additive patch. The native release successor selects v2 for its business
and cleanup commands. Expected nonzero exits still require complete custody,
output and timing proof; exit zero alone never qualifies.

Tests use modeled counterfactuals and bounded fresh host Python children. The
late-reuse model reproduces a possible old classification, not the actual native
descendant/reuse cause. Native/M2/16K and release qualification remain separate.

The versioned caller has one fixed v2 profile and its own strict core pin. Its
fixture audit hooks are inactive at import/discovery and scoped to each owned
fixture context; unrelated subprocesses and neighboring test threads are not
subject to those local fixture restrictions.
