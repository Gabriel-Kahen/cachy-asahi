# Private native updater stage: independent source review

2026-10-12. **Held-source review: correction required (UN1). Native execution NOT RUN.** Read the current roadmap, package inventory, `docs/workstreams/updater-native-stage.md`, and the five held implementation modules. Reviewer owns only this document; no implementation, package, lock, Git or workflow changes were made.

## Reviewed checkpoint and tests

All ten source/test files have mode `0644`. The five implementation SHA256 values exactly match the owner's held handoff:

| File | SHA256 |
| --- | --- |
| `stage.py` | `96ddf13af155a0a01c499a53d92e8e8b5a50e28173368bbfdb8df3b0965b309c` |
| `source.py` | `259b13b210123d90f824f21bf7662785d50c7586519a78451ab62e97ec577d5f` |
| `runtime.py` | `15d8d9433ecad359fe4a5b34b6a9a8d7791abaa00f94e253fc612de65e32debe` |
| `broker.py` | `709acce8e7cda08f6c641979080ce21842d666ee1485966f0a351ef23f669126` |
| `public_worker.py` | `73c8e85b229ea41e6ad48bd7feac2dfae36d433eeed2ff95f97b0433b2759278` |

Test SHA256 values, respectively: `test_stage.py` `1521213a12e5241535066b30d580e9fc9a4178a477c2d69ef4bc71d244abff17`; `test_source.py` `dd76bb2baaf5dd8d438b0568124144dd9add6af6a1573469c9dc1f273224826b`; `test_runtime.py` `c30f379f0677f0ad5559d4e2bf5631fbf78f2ad8facde8f15db51e16e2ba248b`; `test_broker.py` `d26ce10554b59185303fb3331b9cbe9f3717601dbbfc3b9bf75d014619df7c02`; `test_public_worker.py` `05daba8e9a7a5849b582811ef0744ab7863b22f593f5bf39774dd1cdf18d57de`.

Independently ran `python3 -B -Werror::ResourceWarning -m unittest discover -s scripts/port/updater-native-stage -p 'test_*.py' -q`: **133 PASS, zero skips**, 5.623 seconds. Independently rehashed the ready map `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2` and all **63 package / eight root pins: zero drift**. This establishes current byte agreement, not committed stage Git proof or actual native behavior.

## UN1: adopted broker clients are killed but not reaped

`runtime.run_process()` temporarily acts as a Linux child subreaper. A broker's separately registered client starts a new session, so it lies outside the direct native-helper process group. If that helper/broker exits or is cancelled while the client remains, the stage can adopt the client. `broker.terminate_client()` authenticates its PID/group/start-tick/UID identity and sends TERM/KILL, but never reaps an adopted child with a scoped `waitpid`. A terminated client therefore remains a zombie in this stage process; `killpg(group, 0)` continues to observe its group and the broker reports cleanup failure. Private raw removal is then refused despite successful client termination.

Reproduced with bounded real Python processes in an owned temporary directory, using the exact held runtime and broker functions, without Docker. The runtime's direct owned parent spawned a separate-session sleeping client with private/discarded stdio, recorded its PID, then exited. The direct group was absent and the runtime returned PASS. `broker.client_identity()` accepted the actual client. `terminate_client()` returned **False** after its bounded TERM/KILL attempts; `/proc/<pid>/stat` showed **Z**. The reviewer's subsequent `os.waitpid(pid, WNOHANG)` reaped that exact adopted child, immediately making `group_absent(pid)` true. All fixture children were reaped; no host application was signalled.

This is a cross-module interruption/recovery defect missing from the passing individual tests. Reported to the coordinator for owner correction: reap only authenticated owned/adopted client identities and test the real subreaper/session boundary. Do not introduce global wait/reap, broad process signalling, or weaker PID-generation checks. Existing behavior fails closed and retains private data; it does not falsely claim cleanup PASS, but it prevents successful bounded cleanup on this legitimate path.

## Other reviewed boundaries

- Bootstrap requires the externally checked stage hash and authenticates the source helper before executing its bytes. Source closure includes the fixed ready map, its exact package/root pins, the additional helper dependencies and the complete stage subtree. Bounded Git queries use a fixed executable, curated environment, no hooks/fsmonitor/replacements/lazy fetch, exact HEAD/blob/mode/worktree checks, and final rereads. The controller requires the resulting external hash before helper imports. Actual final committed-stage Git verification remains pending.
- Runtime imports and private snapshots are hash-bound; snapshots preserve modes and reject extra/missing/link entries. The host contract binds ordinary matching positive UID/GID, Linux ARM identity, boot/release, exact executable hashes and local socket inode/device. Tool, source and disk/socket observations are repeated during execution.
- The materializer invokes the pinned built-in `--child` directly in the owned runtime session, retaining its original resource limits. Native helper builds, broker clients, Docker containers/images and raw files have distinct ownership records. Durable direct launch INTENT precedes spawn; ambiguous registration prevents removal. Broker permits only the pinned helper command shapes, private mounts, explicit nonces/labels, local endpoint and owned identities. Missing final image identity or daemon observations fail closed; no prune or foreign-resource removal path was found.
- Private directories are registered by parent/child/marker inode and nonce. Cleanup rejects altered ownership, hardlinks, special files and nested mounts and uses descriptor-relative deletion. Recovery requires a pinned ownership receipt, the original stage's absence and exact retained identities. Completed removal permits an attested repeat no-op; unexplained missing raw data does not.
- Projection, credential guard and bundling run as three authenticated bounded public-worker subprocesses with fixed operation paths and exclusive outputs. Public helper trees and bundle sizes/count/depth are bounded. The worker suppresses helper diagnostics and emits fixed scalar status JSON. Public terminal summaries exclude raw paths, commands, keys, source and vendor/artwork data. Late cancellation supersedes PASS; failed canonical terminal replacement revokes prior public terminal evidence.

No additional concrete defect was reproduced in those reviewed boundaries. The independent workflow's planned ceiling and publication configuration are outside this held-stage signoff. Source budget accounting alone cannot prove hard retention under a stalled filesystem/host; the documented disposable VM/daemon disposal requirement remains necessary.

Final source readiness is withheld pending UN1 resolution and new held hashes. No actual Docker, network acquisition, Git mutation, compiler/Cargo/build script, installation, updater execution or host service change was performed. Private native compilation, licensing/publication acceptance, target installation/removal and both M2 Air hardware checks remain separate unfinished gates.

## Final held correction review: UN1 resolved

The final owner-held checkpoint changes only `broker.py` and `test_broker.py`:

| File | Corrected SHA256 |
| --- | --- |
| `broker.py` | `0291f10d605d50914f5551787839c823ace8fe96439f9940eb56a569fad6d98e` |
| `test_broker.py` | `28e044985027182ff4c0db4da145a5c657319538b9367a0a27dbe8b2e1b6eb91` |

All eight other stage source/test hashes above, including runtime, remain exact and unchanged; all ten modes remain `0644`. These hashes match the latest held workstream. Independently rehashed the unchanged ready map and its 63 package/eight root pins again: zero drift. The retained pre-fix broker `/tmp/cachy-broker-un1-prefixed-wia8t5hv/broker.py` matches the original `709acce8…` hash; its retained typed regression receipt records one expected failure, zero errors and cleaned fixture children.

The fix adds bounded `waitpid(recorded_positive_pid, WNOHANG)` calls after repeatedly validating the exact UID, session/group and start-tick generation. The kernel's child relationship enforces this caller's authority to reap: ECHILD returns NOT_CHILD and never redirects to another PID. Reaping remains reached through the controller/nonce/socket-bound client ledger during actual cleanup. No global wait or global signal was added; the unchanged runtime's negative wait is separately scoped to its owned process group.

**Independently reran the original actual UN1 fixture against the held new broker: resolved.** The unchanged runtime adopted the separate-session Python client after its direct parent exited. Broker cleanup returned true, the recorded client PID and group were absent, and a subsequent reviewer `waitpid` received ECHILD because the broker had already reaped that exact child. An independently launched unrelated child remained alive throughout, then was explicitly cleaned by its fixture owner. No Docker operation was involved.

Independently ran the complete prescribed suite once against this checkpoint: **136 tests PASS, zero skips**, 6.194 seconds, with ResourceWarning treated as error. This includes both owner's real cross-module fixtures (normal parent exit and real cancellation), survival of the unrelated child, restored signal/subreaper state, and the scoped ECHILD/generation-drift regression. Log retained at `/tmp/cachy-updater-stage-un1-independent-tests.log`.

**Final disposition: PASS for bounded held-source readiness; no remaining material defect reproduced.** The coordinator can proceed to commit the ten files and perform the actual committed-source freeze/Git check. This review does not attest that pending committed closure or a hosted/native run. Existing private/publication restrictions, unresolved licensing records, target transaction/install/removal and both exact M2 hardware gates remain open. The separate ARM-C01 export correction remains under its own interim review and is not accepted by this updater signoff.
