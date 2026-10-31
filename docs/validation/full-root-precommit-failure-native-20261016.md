# Full587 precommit interruption and disposal

[Actual38885492612](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38885492612)
passes the controlled `precommit-exit86` negative case. Source/workflow is
`001f0484ab8b599ddc03a84e62fd81af315a2a03`; configuration SHA256 is
`43e1e3de12317b0c357678854679cd80a6f57e211d2413fce738b0d7b3c55e6e`.
This is interruption/disposal acceptance for that exact source, not a successful
upgrade, hardware recovery or acceptance transferred to a later source revision.

The actual signed setup0.1.0-3→0.1.0-4 transaction prepares against the complete
copied587 root. All original precommit checks return before the child writes its
bound witness and exits86. The worker is reaped and its group retired. Exactly
one failure case and zero committed transactions are reported. Commit_started,
packages_committed and checkpoint_changed are all false.

The parent checks the initialized complete copy against its pre-child baseline:
payload/database, modes, ownership, literal links, closed hardlinks and checkpoint
are unchanged, with only the declared empty mode0000 root-owned ALPM lock retained.
It never removes that lock or reopens/retries the copy. The complete workspace is
then disposed; the original persistent source manifest is unchanged. Outer
container/image cleanup passes with an empty failure list and independent owned
volume absence. The nested normal driver and controlled child remain FAIL;
the separate verified negative-case result is PASS.

Root independently joins all53 frozen source pins, the selected configuration,
worker return/retirement, prepared addition/no removals, case count, all literal
commit/checkpoint flags, preservation/disposal assertions, persistent-source
manifest equality and outer cleanup/volume receipts. Raw full node maps and the
private witness are not exported, so their detailed comparisons remain enforced
by the selected source rather than separately recomputed from public bytes.

Earlier failures remain recorded:38877815636 and38880150909 stop child observation
under the old128-FD ceiling;38884478088 passes that observation with8192 then
refuses the old8MiB XZ budget during prepare. Local real1048-hardlink observation
and exact setup4 archive decoding identify those prerequisites. This passing
actual selects the fixed8192-descriptor/16MiB decoder budgets.

Logs:3435601 bytes,
`a70f44a96693cdd0acdbb095e7f70cf1bcddcf91eb6b3c355ca44d63152d51ea`.
Only the dedicated public frame is decoded:177822 compressed bytes,
`b187d523f4026405aa4a6d98762f2095469d70b1f65b996d8f5c784ed6af0021`.
Root reads only result/coordinator/transaction records from its closed bundle.
Local evidence is `artifacts/development/full-root-failure-run38885492612/`.
Postcommit interruption, normal checkpointed upgrade, boot restoration, physical
M2/16KiB, production trust and complete M3/M8 acceptance remain separate gates.
