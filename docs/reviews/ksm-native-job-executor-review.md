# Independent concrete KSM job executor review

Reviewed 2026-10-12. Historical checkpoints `f4cf…` and `1f71…` were **BLOCKED by KSM-J1**. The final exact `e547…` hold below closes J1/J2 and the J3 deletion boundary and is **accepted within this bounded source-review scope**. This is a source and controlled-fixture review; coordinator production-packet/Git/dispatch acceptance and the concrete hosted executor, signing, installation/removal, artifact upload and M2/16K hardware execution remain **NOT RUN**.

## Captured source and actual checks

Checkpoint `scripts/port/ksm-native-job/source-checkpoint.json` SHA256 `f4cf0d9ef3f102aff10c4879fe8eab27695ad5a0f741e54b70953904d3b50919` binds 41 owned files including itself and a finite 152-path capture set. I verified all 40 declared owned rows plus 16 held dependency rows against their actual hashes, sizes and modes, with no mismatches, then copied all 152 paths into the reviewer-owned artifact directory. This verifies the declared checkpoint and captured copy; the coordinator's future externally pinned production packet and committed Git closure remain separate acceptance steps.

Principal captured hashes:

| Source | SHA256 |
| --- | --- |
| runtime.py | `5baefe9f70567c19eeb38c6ab27c4d260b8fc157782dadea97caebb942f942d1` |
| executor.py | `d6ebfde1eda7db2163c147cc8b60087e225e90d16e199bed56c469e08842ccd6` |
| broker.py | `ea2e766f2144e66124dab40271129cdc3d79c7d31f024273b26d0cf6e7ab3737` |
| acceptance.py | `7beb64c2927c0b919d8b431cbad8623b9030d3786bb1118660c77d1f838d04d4` |
| public.py | `1d9ecb0b710daa3ce65f915e937fd51d0c935712f9600e8b5942e0a30a55f244` |
| native-arm-ksm.yml | `ae2dc0adace61812c4fcf6396dfec2a219dbef66813a00c28852ca6d156f34ae` |

I ran `python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/port/ksm-native-job -p 'test_*.py' -v` in that fresh copy. The restricted initial run completed 195 tests with 184 passes, 11 temporary Unix-socket bind `EPERM` errors, no assertion failures and no skips. The authorized bounded rerun outside that socket restriction passed **195 tests, zero skips, 5.655 seconds**. These fixtures use synthetic Git repositories, fake Docker observations, small isolated real processes and explicitly simulated disk capacity; they establish no native execution or hosted capacity result. An independent C++ yaml-cpp parse and fixed structural assertions also passed for the captured workflow: sole manual packet input, read authority, sole ARM job, 150-minute bound, three steps, pinned credential-free checkout, executor shell, actual-step-success upload gate and publication settings. Embedded workflow Python compilation passed in the suite. Actionlint and executable GitHub workflow validation/dispatch were not performed.

Evidence is under `artifacts/ksm-native-job/root-peer-review-20261012/`: `copy-receipt.json`, `source-copy/`, `tests.log`, `tests-unsandboxed-fixtures.log`, `yaml-check.cpp`/`yaml-check.log`, and the independent probes below. No implementation, Git, shared lock, host Docker, network acquisition or system mutation was performed by this reviewer.

## KSM-J1 — healthy producer atomic rename aborts periodic resource observation

At captured `runtime.py:368`, an enumerated descendant must still exist when the descriptor-relative `stat` runs; the corresponding `open` at line 378 has the same issue. `FileNotFoundError` becomes `ResourceFailure` with `resource-observation-unavailable` at lines 398–401. The unchanged pinned producer actually writes temporary download files and performs `partial.rename(target)` at `scripts/ci/native_arm.py:98`; its acquisition receipt also uses atomic replacement. The supervisor scans this concurrently mutating tree every 0.25 seconds. A healthy rename between enumeration and lookup can therefore cancel acquisition and prevent all later native phases.

`rename-probe.py` schedules a **real same-directory atomic rename** immediately after the stale enumerated name is selected and before its original descriptor-relative `stat`. The final archive remains present with the unchanged synthetic payload; the `.partial` name is absent. Nevertheless, captured runtime rejects it with `ResourceFailure`, caused by `FileNotFoundError`; the receipt is `rename-probe.json`. This is a controlled filesystem interleaving, not an observed hosted failure and not an actual download.

A correction must reconcile genuinely vanished descendants within bounded enumeration without accepting a missing/replaced private root or log directory, ignoring fresh unsafe nodes, losing member/byte budgets, weakening nofollow identity checks, or swallowing permission/security/other I/O errors. The coordinator was notified immediately; no reviewer source changes were made.

## Cancellation, authority and ownership checks

Independent `terminal-probe.py` exercises two real isolated signal schedules around a synthetic completed pipeline. TERM during the flushed terminal PASS print, followed by three repeated TERM events during failure durability operations, returned actual exit **1**, preserved the open invalidation descriptors, and rewrote both private result and public evidence to FAIL. TERM queued precisely at the final restoration/unmask of the default handler terminated the isolated CLI with **SIGTERM / exit -15**. Synthetic PASS bytes remain in that latter post-cutoff case, as the workstream explicitly documents; the workflow only uploads on actual native-step success, so those bytes do not become accepted uploaded evidence. `terminal-probe.json` records both schedules. No native producer or Docker was substituted into a native acceptance claim.

The captured implementation invokes the unchanged producer/build/compare and held lifecycle CLIs as supervised subprocesses. The producer and build routes use the finite private RPC grammar; mutation reservations precede backend operations, observed zero exits and immutable IDs bind completed work, and daemon/ELF/socket identity is checked around operations. Unknown commitment or post-operation identity loss stays sticky FAIL. Cleanup selects owned immutable IDs and checks image ID, nonce labels, reserved tag and individual container name/ID absence. The fresh copied suite covers lost create responses, post-commit drift, pending operations, local and aggregate deadline exhaustion, failed/cancelled lifecycle authority, scoped process reaping and replacement refusal. No additional reproduced defect was found in those reviewed boundaries.

Public export captures and validates finite inputs before creating output: two exact KSM package archives and constructed evidence JSON. The comparator's actual exit and full equality record, two observed native builds, completed held lifecycle and cleanup acceptance are required before PASS. Raw logs, private signing material and arbitrary paths have no publication passthrough. This does not establish legacy Docker intermediate/cache absence: the workstream correctly retains **NOT ESTABLISHED** and refuses a global prune claim. Interrupted held lifecycle cleanup also remains uncertain FAIL rather than a VM-destruction absence claim.

## Snapshot limit

During review, the owner began changing worktree `runtime.py` to `f6cfd2f63a592cdca8446979dc80a20480a84ac55509204549de79b6699c494f`; checkpoint `f4cf…` still described the captured historical `5bae…` bytes. The tests and findings above apply only to the immutable reviewer copy. Corrected source closure requires a new held checkpoint, independent regression replay and coordinator-owned committed packet proof. The package inventory still selects KSM only for development, with installation/hardware unfinished; local source checks cannot promote it to release or hardware acceptance.

### Moving correction compatibility finding

An additional controlled probe captured draft runtime SHA256 `e42a96c4b57ae4745adb57f2498633e2466c201c4c12cc6d6d3bd3afa8776e1e`. Its new unconditional descendant `st_uid == coordinator` requirement rejects a legitimate held lifecycle root-owned output. The unchanged stage creates its private tree using `TemporaryDirectory(prefix='ksm-private-stage-')` at line 444, which follows inherited `TMPDIR=private/tmp`; its lifecycle container runs `0:0` at lines 213–219 and bind-writes `/out/worker-receipt.json`. The unchanged worker persists that receipt as UID0, mode0644, without changing ownership. Consequently the surrounding periodic scan can observe it before the stage removes its private tree and fail.

`root-output-probe.py` applies the expected UID0 metadata to a real bounded mode0644 receipt in that path shape and reproduces `private-foreign-owner`; `root-output-probe.json` records the captured hash and distinguishes simulated ownership from actual root/Docker execution. The owner and coordinator were notified immediately. This is a regression in moving correction bytes, not a second finding against historical `f4cf…`, and it needs closure before a corrected candidate can be accepted.

## Corrected 216-test hold: J2 closed, J1 still reproducible after open

The second exact held checkpoint is SHA256 **`1f71d1ee22fe36e72fb0f64113ba67c9474462e2f655c5985abd7550eeb8bdfc`**, again 41 owned files and 152 capture paths. Before copying, I independently verified all 40 owned rows plus 16 held dependencies against actual bytes, sizes and modes. The unchanged original build/compare/producer and held lifecycle/BASE/GUARD bindings remain exact. Relevant changed source hashes are runtime `f4b758436391f2c78df79483264704f1922593b21bd51bb54807cafdb69496c6`, executor `ca0699e8ed6df798627dc64f746a7558d9a056c55cb06a2e4f45e782cac94b2f`, runtime test `ef68923f6a72240dee57a9b473ccfb5df28deaf2373472525e6559f7bdc34e35`, executor test `caf99a638f6f0bb4beef78edb797368053e6ce4bcca34f7b5708c5a98dac862c`, and workstream `fb4a63b13e4ef7f5bfee3cb749e99e1c3f1e0f9f53cea18e7d8436e0f63a4f0a` (all mode0644).

A fresh independent 152-file copy ran the full suite with `-B -Werror::ResourceWarning`: **216 PASS, zero skips, 5.882 seconds**. Temporary Unix-socket/process fixtures used the authorized bounded sandbox exception. An earlier shell invocation selected a log path outside the owned workspace and failed at redirection before tests ran; it was corrected to the owned copied tree without altering source or tests. Post-probe rehash verifies no copied byte/size/mode drift.

The original J1 before-first-stat reproducer now passes with one complete 37-byte archive charged. Seven independent malicious retry schedules still refuse: fresh symlink, FIFO, foreign-owner metadata, oversized file, member-cap exhaustion, replaced root and missing root. These are actual bounded filesystem node/rename schedules, with foreign UID metadata simulated.

**J2 is closed at this held source boundary.** The new grant exists only around the held lifecycle subprocess and binds the exact fresh `private/tmp/ksm-private-stage-<eight-character suffix>/installed/worker-receipt.json`, original source/input hashes, contract phase/purpose/job/image/package/nonce/signing shape, retained stage/source/installed directory identities and receipt inode. UID0/GID0 single-link regular mode0600/0644 metadata is observed via `O_PATH`, so an incomplete root-owned write need not be readable or parsed by the coordinator. Root output remains charged to member/byte/deadline limits. The final held lifecycle receiver still supplies content and actual-exit authority; accepting partial metadata cannot establish native PASS.

An independent **19-case matrix** accepts bounded partial/growing JSON metadata in modes0600 and0644 and refuses no active scope, completed scope, wrong UID/GID, unknown/root-extra path, FIFO, symlink, hardlink, excessive size, mode0666, wrong phase, source/inventory poison, changed contract nonce, replaced stage and replaced receipt inode. No actual UID0 file creation, Docker or native stage was used: filesystem operations are real and root UID/GID observations are explicit fixture metadata.

**Remaining J1 blocker:** the correction introduces a final ordinary-leaf `named = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)` after descriptor opening and `fstat`. A healthy producer `.partial`→archive rename at this point still raises `FileNotFoundError` and becomes `ResourceFailure(resource-observation-unavailable)`. The retained descriptor and destination archive contain the unchanged 37-byte payload, already charged to the observation. `rename-after-open-probe.py` changes only the injection point of the historical real atomic-rename reproducer to this second named stat; it reproduces FAIL on exact held runtime `f4b758…`. The owner's `test_opened_regular_move_is_not_treated_as_unobserved_disappearance` intentionally expects this refusal, but the unchanged real producer can perform its ordinary rename at that same interleaving. Therefore the previous failure window is reduced, not eliminated.

The ordinary-file observation should reconcile a genuinely vanished basename and charge retained/newly enumerated metadata within the same bounded retry rules, while keeping the special granted root-receipt inode, named directories, reappearing entries, quotas and all other I/O/type/security failures strict. This residual was reported immediately; no source correction was made by the reviewer. The source disposition at **`1f71…` remains BLOCKED**, while J2 and the initial J1 scheduling point are independently resolved.

Evidence: `artifacts/ksm-native-job/root-peer-review216-20261012/{copy-receipt.json,source-copy/,tests.log,rename-probe.py,rename-probe.json,rename-after-open-probe.py,rename-after-open-probe.json,rename-negative-probes.py,rename-negative-probes.json,grant-probes.py,grant-probes.json,review-receipt.json}`. Historical 195-test sources, counterexamples and receipts above remain unchanged. Native/signing/install/removal/hardware execution and coordinator-owned production packet/Git/dispatch acceptance remain **NOT RUN**.

## Final 229-test held source: independent closure

Final checkpoint SHA256 **`e54715b27d8ff753be0e4a07b3301485f80f3cd1e619205a641732d80b39d099`** again binds **41 owned files and 152 capture paths**. Before copying, I verified all 40 declared owned rows and 16 held dependency rows against actual hashes, sizes and modes. The original producer/build/compare, old147 lifecycle and held BASE/GUARD are unchanged. A fresh independent 152-file copy ran the complete suite under `-B -Werror::ResourceWarning`: **229 PASS, zero failures/errors/skips, 6.062 seconds**. The bounded temporary Unix-socket/process fixture exception was authorized; no Docker, native stage, signing or system operation was run. Post-probe byte/size/mode rehash finds no copied drift; the worktree checkpoint still matches this exact hold.

| Final source (0644) | SHA256 |
| --- | --- |
| runtime.py | `1d695acda2a7161510a161034278999cc05063526c0ba33c99e27580321e6354` |
| executor.py | `ca0699e8ed6df798627dc64f746a7558d9a056c55cb06a2e4f45e782cac94b2f` |
| broker.py | `40611863b0d020df0e039e4bf7cddad448e1fb1be04a57b4168ad5665a0da45e` |
| executor_contract.py | `a13b471b08edcb5b529b930daf8611a6fb102424ef9b14b49ea49978e88a19df` |
| test_runtime.py | `2826ec4727677b34f8822a20e42b433587d9b3adcf71e3a6505ba674a31d9d18` |
| test_broker.py | `33d2dd3d542e18dc54af2b1056e67a466f668cc4c2e97e643e5d623fb08c43ea` |
| test_executor_contract.py | `ecae675e20affc4d80a835d8215ee9bfeeeaf3b195b2256476d7a98c61953a33` |

### J1: all three normal atomic-rename schedules resolved

Replayed the unchanged historical real-filesystem before-stat and after-FD-open/final-named-stat probes, plus the corresponding before-open schedule, against captured final runtime. **All three PASS** with the exact unchanged **37-byte** destination payload, one charged file and three charged names. Post-open recovery observes two bounded rebinding entries. Previously failing `rename-after-open-probe.py` is therefore independently closed.

Recovery is confined to an ordinary coordinator-owned, single-link regular inode proven beneath the same retained parent. It checks old-name absence, exactly one matching candidate, retained/candidate descriptors, final named inode/owner/mode/size/mtime and root/log/parent identities. Fresh directory descriptions avoid sharing the outer enumeration offset. Every observed inode retains its maximum charged size; novel names and auxiliary search entries have bounded accounting. Immutable lifecycle input capture and the special root receipt do not take this exception.

Eleven independent actual post-open transitions refuse: moved outside the parent, lost file, substituted inode, foreign-owner metadata, hardlink, reappearing old-name symlink/FIFO, fresh unsafe FIFO, replaced root, excessive bytes and member exhaustion. Retained bytes remain charged on loss; replacement charges both observed inodes; a 50-byte candidate fails the 20-byte cap; novel-name exhaustion fails at entry3. The prior seven unsafe pre-open/root-loss/type/owner/quota schedules also remain refused. The full copied suite additionally checks previously walked directory replacement with a hidden unsafe child, bounded search/churn, actual subprocess resource ticks and immutable input/root-receipt strictness.

### J2: accepted exact root receipt lease preserved

Independent AST comparison confirms `_LifecycleOutputs` is unchanged from the accepted216 correction. The same19-case independent grant matrix passes again: partial/growing UID0/GID0 mode0600/0644 metadata is accepted only under the authenticated active lifecycle scope and remains charged; wrong roles, owners, paths, node types, links, modes, sizes, copied source/input hashes, contract and directory/receipt replacements refuse. The metadata grant does not parse an incomplete root write or establish final native PASS; old147 final-content/controller-exit authority is unchanged.

### J3: no pruning or force on the new executor's image deletion

Source audit finds one new-job image mutation for disposal: **`image rm --no-prune <owned immutable ID>`**, after ownership checks/reservation. The sealed cleanup grammar and journal require this exact form and reject force, aliases, foreign image IDs and hidden prior operations. The held lifecycle is not edited by this correction.

The independently checked pinned [Docker CLI v28.0.4 implementation](https://github.com/docker/cli/blob/v28.0.4/cli/command/image/remove.go) maps `no-prune` to a false ancestor-pruning option and leaves force false; the [Moby v28.0.4 implementation](https://github.com/moby/moby/blob/v28.0.4/daemon/images/image_delete.go) recursively attempts ancestor deletion only when pruning is enabled. This is primary-source semantics, not an actual daemon trial.

An independent causal fake backend demonstrates that the historical immutable-ID removal model loses a pre-existing untagged ancestor, while the actual final broker command preserves it and removes only its bound image. Thirteen injected extra journal operations are refused even when followed by a valid removal: old deletion, forced deletion, aliases, leading/global/image-group options, system/builder/buildx/image prune, foreign image deletion and duplicate otherwise-valid deletion. Eight corresponding unsafe sealed cleanup command shapes refuse; the exact nonpruning form passes. These are modeled Docker effects and actual pure-validator executions; no real ancestor-preservation result is claimed.

### Disposition and practical execution limits

**J1 CLOSED, J2 CLOSED/preserved, J3 source boundary verified. No residual material source defect was reproduced within this review's scope. The exact `e547…` checkpoint is ready for coordinator-owned production packet/Git registration and a bounded native trial.** Historical195/216 sources, findings and receipts remain retained.

This does not establish the future runner's actual clean daemon, capacity/tool availability, frozen HTTPS payload retrieval/signature verification, legacy-builder behavior, eight original builds, two KSM builds, comparison, old147 signing/install/removal or independent cleanup. Each still requires actual same-job evidence and a successful process/workflow exit before curated upload. **Legacy intermediate/cache absence remains NOT ESTABLISHED**; no global prune or foreign-ancestor ownership is inferred. Abruptly interrupted old147 lifecycle still lacks a durable caller-owned nonce/ID recovery interface and remains uncertain FAIL; VM destruction is not scoped cleanup proof. Actual corrected hosted execution, production trust/promotion, safe target KSM management, M2/16K hardware and measured performance remain **NOT RUN**.

Final evidence is under `artifacts/ksm-native-job/root-peer-review229-20261012/`: `copy-receipt.json`, `source-copy/`, `tests.log`, the three `rename-*-probe`/initial `rename-probe` scripts and receipts, `rename-negative-probes`, `post-open-negative-probes`, `grant-probes`, `image-delete-probes`, and `review-receipt.json`. Fixtures use actual bounded temporary nodes/renames/signals and synthetic UID0 metadata, Docker, package and native authorities, with no host/system mutation.
