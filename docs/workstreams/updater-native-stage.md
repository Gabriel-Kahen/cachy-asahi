# Finite private native updater stage

Status: **SOURCE-IMPLEMENTED; MOCKED/PRIVATE FIXTURES PASS. Committed source freeze, hosted execution, native compilation, installation, and M2 testing NOT RUN.** This stage is separate from the stable package checkpoint. It creates no workflow, dispatch, Git commit, repository upload, installation, updater execution, or service changes.

Read the [package workstream](cachy-update.md) for source, licensing, recipe, generator, dependency and materialization evidence. The full vendor archive and package remain **NOT ACCEPTED for publication**; four unresolved macOS notice records are still blockers. Private native compilation cannot resolve those terms or establish target/M2 compatibility.

## Stable package inputs

| Input | SHA256 |
| --- | --- |
| `packages/tools/cachy-asahi-update/runner-ready-pins.json` | `ff879da588419fc0f90ef6a27c8afc528c3f6a557ef2c060544d1b5e99ade4e2` |
| `materialize-inputs.py` | `4e8a6111a70bdb93d2a5e75aa786c96ce099a54d0fcd5e4bba38177da4c2e964` |
| `runner-inputs.lock.json` | `ba869e80d9fa2bdeb9c5bf504dc9cbddff1b164f6276d3ab75516fc5985fa0ac` |
| Reviewed root native helper | `a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898` |
| Base lock | `3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650` |
| Thirteen-package extension lock | `988a74e39f5d3b74cee18dcd53e78733c38872fe2143ccf4e2f4e95d5a5f8776` |
| Exact 354-package inventory | `d5e2b02a4af36b763c24c0eded8d4b7326874448996f94126fbfc3f787946271` |

The stage imports no package source in its bootstrap. It requires the ready-map digest above, every one of its 63 package-file pins and eight root-file pins, the ready map itself, the three additional comparator/container-entry/log-bundle dependencies, and every new stage source/test file. No fallback to an older native helper is allowed. The unchanged helper still owns acquisition, image/bootstrap inventory checks, metadata/build policy, and two clean native builds.

Source checkpoint, 2026-10-12; these are implementation hashes, not an executed controller freeze:

| New stage source | SHA256 |
| --- | --- |
| `stage.py` (external bootstrap check) | `96ddf13af155a0a01c499a53d92e8e8b5a50e28173368bbfdb8df3b0965b309c` |
| `source.py` (first helper import) | `259b13b210123d90f824f21bf7662785d50c7586519a78451ab62e97ec577d5f` |
| `runtime.py` | `15d8d9433ecad359fe4a5b34b6a9a8d7791abaa00f94e253fc612de65e32debe` |
| `broker.py` | `0291f10d605d50914f5551787839c823ace8fe96439f9940eb56a569fad6d98e` |
| `public_worker.py` | `73c8e85b229ea41e6ad48bd7feac2dfae36d433eeed2ff95f97b0433b2759278` |

## Source binding and bootstrap

The workflow owner must commit the complete package and stage closure first. Freeze requires an externally supplied exact commit that equals HEAD, tracked blob identities, exact Git/file modes, worktree byte equality, and a closed package/stage file inventory. Missing, extra, untracked, modified, symlinked, hardlinked, special or oversized inputs refuse execution. Files are capped at 128 total and 32 MiB combined. Bytecode caches are excluded and never imported. These checks have not yet run against a committed final stage tree.

Before invoking Python on `stage.py`, the trusted workflow must independently check that file against its reviewed literal SHA256. Pass that same digest as `--bootstrap-stage-sha256`, and the reviewed `source.py` digest as `--bootstrap-source-sha256`, to `freeze`. The source helper is authenticated before its first compile/import. An in-process self-check cannot replace the initial external check.

`source.py` uses bounded owned Git subprocesses and a curated absolute Git executable, disables hooks/fsmonitor/user/system configuration and replacement objects, and sets `GIT_NO_LAZY_FETCH=1`. Git checks have a 60-second aggregate bound. Freeze writes an external `/tmp` controller; it does not write an in-tree lock or mutate the checkout.

Run authenticates the external controller SHA256 before importing source/runtime/broker/export helpers. The controller binds the reviewed source closure, budget, ordinary positive matching real/effective UID/GID, native Linux aarch64/arm64 host, boot identity, release, local Docker socket identity, and exact resolved Python/Docker/Git/GPG/GPGConf executable hashes. Source and executable drift refuse the run. The daemon must independently report ARM and the fixed local endpoint `unix:///run/docker.sock`.

The private snapshot preserves exact source bytes and modes. Original Git/source binding is checked again after the native pair; snapshot bytes/modes and tool/socket/disk limits are checked between and during phases. Verified Python modules are compiled directly from bytes, with bytecode writing disabled.

## Execution and limits

`stage.py run` creates a fresh canonical 0700 `/tmp` output and registers its private directory by parent/child/marker inode, UID and random nonce before adding raw inputs. It seeds the exact minimal materializer launch receipt and invokes the unchanged materializer's built-in **`--child`** entry point directly. That entry point applies the original 900-second alarm, 600-second CPU, 2 GiB address-space, 512 MiB file, 128-descriptor and no-core limits and performs the original pinned reconstruction. The writer stays in the stage-owned process group; the separate-session materializer supervisor is not invoked. Forced termination can leave a RUNNING materializer receipt; only the stage's process result is authoritative in that case.

The sequence is daemon/storage validation, private materialization, candidate freeze/rehash, and the unchanged native helper's private pair. Projection, credential export and log-bundle construction then run through authenticated `public_worker.py` subprocesses. These three operations use the actual pinned selector, unchanged exporter and unchanged bundler, fixed paths, exclusive fresh outputs, and 60-second process deadlines. The terminal exporter only handles the bounded scalar/hash lifecycle summary. Candidate/native success is required for a stage PASS; no stage PASS is based on a source audit or emulation.

| Bound | Value |
| --- | --- |
| Main process phase deadline | 6,900 seconds |
| Raw retention accounting bound | 7,100 seconds, below two hours |
| Materialize / freeze / native process limits | 910 / 120 / 5,400 seconds |
| Projection / guard / bundle | 60 seconds each |
| Cleanup | At most 180 seconds, capped by the raw-retention deadline |
| Private directory | 8 GiB and 200,000 entries |
| Each owned process stdout/stderr | 16 MiB each |
| Public helper tree / bundle | 2,048 entries, depth 32, 16 MiB input / 8 MiB compressed |
| Initial free space | 10 GiB output; 8 GiB Docker; 18 GiB when on one filesystem |

Filesystem/hash operations additionally have explicit input/count bounds; their syscall duration is not an independent wall-clock guarantee. Failed or cancelled process deadlines retain an independent 10-second TERM grace followed by at most three seconds of KILL/reap. The workflow must apply an outer job/VM lifetime below two hours, reserving time for checkout/bootstrap and cleanup. The source wrapper alone cannot guarantee a hard retention limit when the host or filesystem stops responding.

## Ownership and recovery

Every direct launch, including scoped GPG cleanup, writes a durable INTENT first. Its runtime callback records PID/group/start ticks while cancellation is masked and only after an owned handle exists. Child-specific completion is recorded from verified group absence. A hard kill between spawn and durable registration leaves an ambiguous INTENT: it grants no right to signal an unknown process or remove raw files.

The Docker broker forces the fixed local endpoint and a curated environment without user credentials/configuration. It permits only the unchanged helper's reviewed command shapes, scoped mounts and unique owned names; it labels every build/run with the stage nonce, including inventory containers. Its separate client ledger records intent and owned identity. Cleanup targets only authenticated owned clients, containers and image identities, proves absence, and never prunes the daemon, removes foreign resources, or treats a nonzero inspect as proof of absence. Missing image identity, failed ledger persistence, reused PIDs or ambiguous group leaders produce FAIL.

The runtime's subreaper can adopt a separate-session Docker client when its broker parent exits. That client remains a child after the runtime restores its subreaper setting. Broker cleanup therefore revalidates the exact recorded PID/group/start/UID generation and makes bounded positive-PID `waitpid(..., WNOHANG)` calls to reap an owned/adopted child after termination. `ECHILD` means the process is not this caller's child; it grants no right to reap any other PID. No global wait is used. Runtime parent-group absence alone cannot establish separate client cleanup: broker client/group absence is also required before raw deletion.

Normal cleanup verifies direct groups, broker resources and scoped GPG cleanup before removing the registered private directory. GPG cleanup accepts only the canonical owned 0700 `private/native/gpg` path with no symlink components. Raw deletion refuses foreign UID, hardlinks, special files, nested mounts and changed parent/child/marker identity. A cleanup failure retains raw data and reports FAIL; it does not claim deletion. TERM/INT and an active alarm are deferred during teardown. Late cancellation supersedes PASS in both private and canonical public terminal receipts. Failed terminal replacement revokes the previous canonical terminal receipt rather than leaving stale PASS evidence.

An external always-step calls `cleanup` with the original externally pinned controller and an externally pinned SHA256 of the current `ownership.json`. Recovery requires the original stage to be absent, the same host/boot/source/output identity, exact directory registration, and verified launch records before signalling or deletion. It refuses active/reused/ambiguous ownership. Successfully recovered deletion updates its durable ownership receipt; after obtaining the new receipt hash, repeated recovery is an attested no-op. An untrusted ownership file or a missing directory with no prior cleanup attestation refuses recovery.

No global process signalling, GPG kill, package mutation or Docker prune is allowed. Runtime subreaper changes affect only the current process and are restored. Separate broker clients are independently registered; the unchanged materializer writer uses the runtime's direct owned group.

Docker can retain unlabelled intermediate/cache layers. This wrapper proves absence only for registered filesystem/process/container/image resources; it does not claim forensic erasure of daemon caches. **Use a dedicated disposable ephemeral builder/daemon and ensure its disposal within the outer retention limit**, especially after an ambiguous failure. A persistent shared daemon is not a suitable runner for this private trial.

## Public handoff and actual validation

Publish only `guarded/*.json`, the canonical `terminal-public/*.json` (or `recovery-terminal-public/*.json`), and `public-evidence.tar.gz`. Consume them after the stage exits and check the terminal outcome plus export manifest. The bundle contains guarded projected evidence, not the final terminal summary; it may describe a successful compile even if later cleanup makes the final stage FAIL. Keep controller, ownership, projection inputs, noncanonical guard attempts, raw result/logs, source, original artwork, all vendor/cache/package/binary outputs and keys private. No workflow-wide directory/glob upload is acceptable.

Local verification uses finite private Python/shell processes and mocked host/Git/native/Docker operations. Runtime and broker tests exercise cancellation, registration failure and kill/reap without native builds. The stage tests exercise real private registration/removal, source snapshot bytes/modes, real schema projection/export/bundle functions, partial failures, late cancellation, ambiguous launch preservation, bootstrap refusal, scoped GPG paths and repeatable recovery. They provide implementation evidence only.

Actual result: **136 tests PASS** using `python -B -Werror::ResourceWarning -m unittest discover -s scripts/port/updater-native-stage -p 'test_*.py' -q`: source 23, runtime 33, broker 29, public worker 13 and stage 38. One stage fixture runs all three actual authenticated public-worker CLI operations through real bounded runtime processes; all native/daemon/materializer/host/Git trust steps remain mocked. Two broker fixtures use the unchanged real runtime to adopt a separate-session Python client after normal parent exit or real cancellation, then verify authenticated broker termination/reaping, PID/group absence, survival of an unrelated child, and restored signal/subreaper state. The normal-exit regression fails against the exact prior `709acce…` broker source, with all fixture children cleaned; its retained source and typed regression record are `/tmp/cachy-broker-un1-prefixed-wia8t5hv/broker.py` and `regression.json`. A third added fixture verifies ECHILD and generation-drift refusal. The four other wrapper sources, including runtime, remain unchanged. The materializer's existing 18 focused tests independently passed. Final rehash of all 63 package pins and eight root pins found **zero drift**; package ready map remains `ff879…`. No Cargo, compiler, build script, Docker daemon, installation, service or updater execution occurred in these checks.

Next owned handoff: commit/freeze the final closure, independently check bootstrap pins in the coordinator-owned workflow, select free public ephemeral native capacity, dispatch the finite private trial, inspect actual evidence and verified cleanup/disposal, and then reassess package/target acceptance. Hosted/native/install/M2 outcomes remain **NOT RUN** until their corresponding evidence exists. Licensing, target dependency transaction, updater installation/removal behavior and actual hardware tests remain separate open gates.
