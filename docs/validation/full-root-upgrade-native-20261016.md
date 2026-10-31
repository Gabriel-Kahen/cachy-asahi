# Signed upgrade of the copied full587 persistent root

[Actual38885490672](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/38885490672)
passes one signed setup0.1.0-3→0.1.0-4 upgrade in a disposable copy of the
complete587 persistent composition. Source/workflow is
`de04c6b102890218da4f0b77e938315d601e824f`; configuration SHA256 is
`b78c34f92cec146af49eb632bdb1955e3c87823bf12e6da056bffa44c2eefa0c`.
Acceptance belongs to this exact source; later source revisions are separate.

The persistent materialization has124745 nodes and113759 package-owned
nondirectory paths. Runtime contents and declared build infrastructure are
excluded during that materialization; its resulting complete tree is copied
without exclusions. The initial copy is byte-identical. The held one-shot cache
initialization occurs only in the copy before its baseline; repository
construction then preserves that baseline.

The real update prepares only cachy-asahi-setup0.1.0-4 with no removals, commits,
verifies the after state, writes its checkpoint and syncs the checkpoint directory.
Both inventories contain587 packages. Before lock is
`2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7`;
after lock is
`dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac`.
The setup4 archive is
`c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a`.
Exactly one committed transaction is reported. Nonselected database records,
113755 protected payload nodes and seven user fixture nodes are preserved.

Main cache bytes remain equal;995 auxiliary records retain their actual live
keys and permitted pinned-source load/save ordering and tail-padding treatment.
Auxiliary exit status remains NOT OBSERVED; hooks/scriptlets are NOT RUN. These
limits are retained. The copy and checkpoint workspace are then disposed.
The original persistent-source manifest and original587 inventory remain
unchanged. Outer container/image cleanup has no failures and the owned volume's
absence is verified. Disposal is not a downgrade or live boot restoration.

Root joins all47 frozen source pins and the selected configuration/archive,
independently computes both inventory hashes, and checks literal commit/checkpoint
flags, checkpoint sync, baseline/preservation/source equality and inner/outer
cleanup receipts. Raw full node maps, signature operations and checkpoint bytes
remain Source-enforced rather than separately re-exported/recomputed. The reused
low-level runtime retains its conservative full587/Apple acceptance disclaimers;
the enclosing driver establishes this specific copied-root operation, not full
port, platform, service, production trust or hardware acceptance.

Logs:3491808 bytes,
`7da11bcfd3f66570bbfec5768e9e9075535ce17c625503ee74855d49341c446e`.
Only the dedicated public frame is decoded:199069 compressed bytes,
`0a2b53c8a7e7cdc2a74fe177f05e08fef62e1e40d5e5d325b565360d29510bf1`.
Root reads result/coordinator/transaction records from its closed bundle.
Evidence is under `artifacts/development/full-root-upgrade-run38885490672/`.
Physical M2/16KiB, target Asahi stack updates/boot recovery and complete M3/M8
acceptance remain open. Earlier path/XZ refusals remain recorded separately.
