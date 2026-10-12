# Installer correction follow-up review

**Source admission remains on hold for two custody gaps.** The held
correction addresses captured child execution, directory replacement, atomic
publication failure and HOME preservation in the checked source/model controls.
It does not yet revoke promoted authority when CLI printing raises
`KeyboardInterrupt`, or preserve a foreign destination inserted during staging.
No new namespace or package transaction was performed.

The [previous review](local-install-transaction-root-review.md) and its blocked
findings/evidence remain unchanged. This follow-up applies only to the following
mode-0644 hold:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `scripts/install/local_transaction.py` | 63,921 | `c3175e48de81942520d5a4ac63113fb5674c6232c8b78ffb4d3221b561aac1ca` |
| `scripts/install/test_local_transaction.py` | 58,554 | `74ef9e28e5cc8f86308f200934f207abe4d0fc36d15d5ba52352a287ccd948b8` |
| `docs/workstreams/local-install-transaction.md` | 14,227 | `59cc3ea1cce0b734dea6ec93880c7ab9e03bde54c75465df7f28262b5d2d8784` |

The supplied checkpoint hash
`bc0af5408c081506257345c0afa408ad81834dd57458d7b092469286bdbc7d25`
belongs to `artifacts/install-local-transaction-correction-20261012/checkpoint.json`.
The older `artifacts/install-local-transaction-20261012/checkpoint.json` remains
the historical `438442cf…` receipt. Both are preserved. The runtime remains
`8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`.

## Corrections verified

`execute(..., worker_source_sha256=...)` requires an independently supplied
source pin before child launch. It captures expected bounded worker bytes,
captures the pinned runtime, and seals both memory descriptors against write,
growth and shrinkage. The outer loader reopens those exact retained parent
descriptors with device/inode/seal checks. The child checks sealed buffer hashes,
references, engine-spec bytes and initial evidence identities before compiling
and executing the captured buffer. The engine requires those captured globals;
an ordinary pathname launch cannot supply them. Runtime loading uses the captured
bytes, without a child source or bytecode fallback. Harmless marker controls
exercise the child loader, including changed/unsealed buffers, wrong pins and
references, and adjacent poisoned source/PYC refusal. The outer namespace chain
was inspected statically, not executed in this follow-up.

Evidence retains the original directory and authoritative node descriptors.
Checked promotion requires original directory/node identity, ownership, mode,
type and link predicates. Pending new inodes are registered before atomic
replacement; retired original nodes remain held. Failure revokes original,
pending and retired receipt/lock authority through descriptors, even after
directory or node replacement, and preserves foreign replacements in the tested
post-publication failure paths. This closes
the prior directory-replacement reproducer in the tested ordinary-exception
paths. A separate control verifies the case where atomic replacement takes
effect and then raises before the tracked node table is updated. Retained
hardlink aliases cannot keep PASS or a valid installed lock after revocation.

Both supervisor and GnuPG environments inherit HOME's exact value or absence.
Private GNUPGHOME/homedir/TMPDIR and `--no-options` remain explicit. Positive and
absent-HOME harmless loader controls and custom-value parent-environment controls
passed. No host environment or trust store was changed.

## Remaining findings

**[P1] Keep CLI cancellation inside the revocable custody scope.**
At `local_transaction.py:975–980`, `main()` checks promoted authority, prints the
result, and checks again. Its exception handler at line 981 catches only
`Exception`; `KeyboardInterrupt` bypasses it. The finally block at line 995 then
closes the retained evidence descriptors without revoking the promoted nodes.
The prior `execute()` cancellation handlers have already finished at this point.

An independent fresh-source model made mocked `execute()` publish an owned PASS
receipt and installed lock, then injected `KeyboardInterrupt` at the final
terminal print. `main()` raised that interruption, closed custody, and left the
original PASS and lock intact. This reproducer performs no package operation;
its receipt explicitly records `commit_started=false` and `committed=false`.
It establishes a CLI revocation defect, not an actual commit or accepted failed
CLI. The consumer's required zero CLI exit still rejects the interrupted attempt.

The correction should catch cancellation while original descriptors remain
usable and revoke through those descriptors before closing them. Custody
disposal must also tolerate interruption without losing the descriptors needed
for revocation. Add focused interruption controls at printing and final custody
disposal alongside the existing ordinary-exception fallback. No source repair
was made by this reviewer.

**[P1] Refuse a replaced destination before promoting the staged receipt.**
`Evidence.write()` checks its tracked destination at line 253, stages and
fsyncs bytes at line 263, then replaces the destination at line 264 without
checking it again. A foreign node appearing during staging is overwritten.
The post-write check validates the newly installed own node, so it misses the
foreign overwrite. The absent-result branch in `revoke()` also calls a
nonexclusive write after checking absence and has a related replacement window.

An independent model replaced the original result name with owned foreign bytes
at the staged regular file's fsync, before `os.replace`. The save returned
normally, the final node check passed, and the foreign bytes were lost. No
package operation occurred; the model's own receipt nodes were revoked after
recording the finding. Recheck the destination after staging and refuse a
changed node; absent-name creation should be exclusive. A pathname recheck has
a residual POSIX check-to-rename race, so document or strengthen the actual
custody boundary rather than claiming atomic foreign-node preservation. The
deterministic staging replacement control must refuse and preserve foreign bytes.

## Focused evidence and limits

A fresh copied worker/test/runtime/guide/checkpoint tree was hash-checked before
and after execution. **24 tests passed, zero failures, errors or skips** with
isolated Python, bytecode disabled and ResourceWarning treated as an error:
13 selected author parent models, seven harmless child-loader fixture tests,
and four additional reviewer custody/environment controls. The captured tree
had zero PYC files before and after. Temporary poisoned bytecode in the explicit
loader refusal fixture was removed with its fixture directory.

Model setup substituted inert certificate/signature bytes and structural
archives. It did not invoke GPG or authenticate those bytes; mocked child
completion provides no package execution evidence. Two additional models
separately confirmed the remaining findings. The CLI model retains its modeled
receipt/lock; the pre-rename model retains its result and revoked own nodes.

Two bounded static peers independently checked source/HOME and receipt custody.
The source/HOME peer found no actionable issue; the custody peer identified the
same CLI cancellation and pre-rename replacement gaps. Current source, prior review/history and the sealed
FDK review were preserved. No shared maps, source pins, workflows or Git were
edited. No new namespace, supervisor trial, libalpm transaction, installation,
ARM/M2 hardware, production signing or release acceptance was run or established.

Evidence is retained under
`artifacts/reviews/local-install-transaction-correction-root-peer-20261012/`:
`focused-tests.log`, `focused-results.json`, `cli-interruption-results.json`, `pre-replace-results.json`,
the modeled authority nodes, captured sources, reviewer scripts and
`review-receipt.json`. The correction is ready for bounded custody repairs and
a peer recheck before any new tiny actual transaction.
