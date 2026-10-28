# Independent KSM lifecycle correction review

Historical held137 review outcome: **source signoff blocked by verified-byte helper loading**. The three original schedules in [the historical review](ksm-lifecycle-review.md) failed safely, but that worker permitted different source or cached bytecode to execute after its source checksum succeeded. Its blocked disposition remains historical; the corrected held147 closure below supersedes source authority without rewriting this finding.

Read the current roadmap, development package inventory, [KSM workstream](../workstreams/ksm-lifecycle.md), historical review and `/tmp/ksm-independent-review.py`. Current held evidence supersedes the task's inherited127 description with **137 tests** and further signal-restoration fixes. Native lifecycle signing/install/remove/reinstall, Asahi/M2, 16K hardware, management activation, production publication and performance remain **NOT RUN**. The existing two native KSM archives are build evidence, not execution of this adapter.

## Held bytes and fixture execution

The reviewed137 source checkpoint SHA256 is `9341bd854d7ed6fba33d5cd62295812dcb24322dec7302aa998d3197a3c5ac89`; test receipt SHA256 is `b8efbb557dadc3e51a2e8a561d5e2553d55cf7d39cea1041f350ecc466bebb69`. The workstream document at this hold is `2fd1fda99adc412647bcbfcfb70694f5662342268bc41853fa4bd807062ae472`.

| Source under `scripts/port/ksm-lifecycle/` | SHA256 |
| --- | --- |
| `stage.py` | `be4a61ac4ed8efbf243e2be1a5211c4ad0553f7be13a26b64e3e655de73cbaee` |
| `worker.py` | `e879cb22be50da3a1e7c5e8f700349cb9ec8d4e57f32b2745397425d24d4d258` |
| `contract.py` | `bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b` |
| `test_stage.py` | `e34c99bb71f57748c5f171f08085ca4d0ab3846e26cbc48ca07e246730218332` |
| `test_worker.py` | `d8a2535f5e9355454e350c44f94a686dcf079b4e521e0ebf6f526e09ad5a0f08` |
| `test_contract.py` | `13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258` |

External pinned helpers are original client stage `dc0c75969ed79548c3eb0ab1692f57ebffe7464d9192e591cdcf61aeaeb77154` and source guard `4bfec1387f87768e5b37475d6172bde302ef52c01c68f81297435048be7f2100`. This reviewer edited neither helper nor implementation.

Independently ran the held fixture suite: **137 PASS, zero skips**, including four real isolated Ed25519/SHA256 TEST GPG cases. The restricted attempt first reported 21 errors from forbidden temporary Unix sockets/GPG-agent setup. An authorized rerun permitting those owned ephemeral sockets passed all tests. No Docker daemon, native package transaction, network request, default keyring/trust, host installation or service was used. The sealed executable fixture is a copy of `/usr/bin/true`, not Docker. Signing/GPG homes and keys are disposable TEST fixtures.

## Original three schedules closed

An independently adapted reproducer, `/tmp/ksm-correction-independent-review.py`, uses actual temporary files/socket descriptors and mocks only daemon/package actions and phase prerequisites.

- **Daemon A→B→A after the name query:** using the real checked `Docker` boundary, the name query changes its mocked server identity to B. The post-request identity query refuses the result before create/start; neither operation is reached and the phase is FAIL. The suite also exercises pre-start drift, drift between cleanup name/ID queries and transport failure. Each operation, including removal and both absence queries, crosses pre/post daemon identity checks; each CLI invocation also checks the original positive UID/GID pair, CLI bytes/inode/metadata and retained socket identity. These are the recorded observation boundaries, not an assertion that an adversarial server cannot change internally between observations.
- **Cancellation during the actual lifecycle receipt chmod:** the independent fixture performs the real chmod and remembers cancellation at that exact boundary. Permissions now precede authoritative bytes. It returns **1** and retains durable **FAIL/cancelled**, replacing the original zero/PASS result. Additional held tests deliver real SIGTERM/SIGINT during final handler restoration and after controller writer return; cancellation is reconciled after the final deferral. Caller-handler restoration is covered. Arbitrary termination after a caller's handler has been restored still requires checking process exit as well as the receipt, as the workstream explicitly states.
- **Real UID1000 with effective UID/GID0:** the independent controller call is refused at `matching-positive-coordinator-uid-gid-required` before Docker or caller-input access. Matching positive real/effective UID and GID are required, and the checked Docker boundary retains the original pair to reject later identity drift.

The controller captures the checked ELF into a sealed anonymous memfd, executes its retained `/proc/.../fd/...` descriptor with an explicit endpoint, and never uses PATH lookup for Docker. Source identity is checked again after operations, including exceptions. Constructor failures attempt descriptor disposal; disposal errors prevent acceptance. Private directory removal and descriptor closure precede authoritative controller publication. Ownership checks require the exact image/nonce/contract labels before removal; successful separate name/known-ID queries establish absence, and transport errors do not. The public directory retains only a curated receipt, with hashes/public signer identity and explicit cleanup/retention state; raw outputs, archives, certificates, detached signatures and secret key homes remain private and must be removed.

## KSM-LOAD-1: checked source is not the executed helper

The held worker's `load` function constructs a `SourceFileLoader` and calls `exec_module`, reopening the pathname and consulting its bytecode cache. Callers in entry/guard/bindings first call `checked` but discard those returned bytes. The loaded helpers include BASE, GUARD and CONTRACT; the installed nonroot fixture probe uses the same loader. The controller's `load_base` and `load_contract` already compile the captured checked bytes and do not have this defect.

Two independent harmless-marker fixtures demonstrate the worker defect with real loader execution:

1. A helper containing `marker="reviewed"` passes `checked(path, SHA256)`. Replacing the source before `load` causes `marker="unreviewed"` to execute.
2. The reviewed source stays byte-identical and its checksum still passes. A timestamp/size-valid `__pycache__` file contains different compiled marker code. `load` executes `marker="unreviewed cached code"` with `sys.dont_write_bytecode=True` and interpreter `-B`. Those settings suppress cache writes; they do not prevent this cache read.

These fixtures change only disposable `/tmp` data and execute only inert marker assignments. No project helper, native payload or system action is substituted. Read-only/private copied source reduces ordinary mutation exposure but does not make the loader's selected bytes equal the verified capture. An installed-image cache can also predate the installed probe. The workstream's claim that all checked helper bytes execute from captured snapshots therefore cannot apply to held137.

The signing path has an additional instance of the same mechanism: `guard_entry(sign)` calls frozen `BASE.worker_guard`, whose own source checks GUARD and then reopens it through `spec.loader.exec_module`. Fixing only the KSM worker's initial guard load would leave that signing reload. Keep the frozen shared helper unchanged unless the coordinator explicitly reconciles it; the owned KSM code can apply the already captured guard's environment/guard, required read-only-proc and exact UID/GID checks directly, preserving its full signing guard. The installed probe likewise needs to compile its actual checksum-verified payload capture. Cache reuse must not bypass byte/pin validation.

Required closure is a new held checkpoint that binds those changes and demonstrates replacement/cache refusal or execution of the original capture across BASE/GUARD/CONTRACT and the installed probe, including the signing guard delegation. Until that evidence is reviewed, held137 remains blocked. Its successful137 fixture tests do not establish verified-byte loading or native lifecycle acceptance.

## Corrected held147 closure

**PASS for the bounded corrected source/fixture scope.** Current `scripts/port/ksm-lifecycle/source-checkpoint.json` SHA256 is **`f3966ce9d97b6a3661a57474740052eaa837929c7b7553ac2d82702562f03fc8`**. Independently checked all six current source/test byte hashes, sizes and modes; document, test receipt, both historical137 receipts and both external helper references also match (twelve bound files). Only worker and its tests changed from held137. No implementation, shared helper, Git or source map was edited by this reviewer.

| Current source under `scripts/port/ksm-lifecycle/` | SHA256 |
| --- | --- |
| `stage.py` | `be4a61ac4ed8efbf243e2be1a5211c4ad0553f7be13a26b64e3e655de73cbaee` |
| `worker.py` | `76a3e94f317bea79d1e2444630d719b8acaed6c6cb6427c0bb19beedbc4d6b83` |
| `contract.py` | `bfce5d9a5e8a9626cdedb121f299dafd730b13e484d1c4be7ba917207e4d161b` |
| `test_stage.py` | `e34c99bb71f57748c5f171f08085ca4d0ab3846e26cbc48ca07e246730218332` |
| `test_worker.py` | `5e9bac1045407585f26c8819c9e4d283cae3044e1cefbebabc1f4c086e517aa8` |
| `test_contract.py` | `13c7273a83cf3b67330f76380c05c14aa8af6ff4d7173c43d607d5c8b25e4258` |

Current workstream SHA256 is `95bb3558086553e49f52344c924a0a757c77ed701c164a85c3f3b5eb1558ac56`; current test receipt is `c0d5255a81443a4af927fff30c6ca04326abbe753b48a0ea46a1153b295f33aa`. Historical137 checkpoint `9341bd…` and test receipt `b8efbb…` remain byte-identical under their explicit historical filenames. External BASE `dc0c7596…` and GUARD `4bfec138…` remain unchanged.

Independently reran the complete fixture suite with owned ephemeral socket access: **147 PASS, zero skips**, including the four real disposable TEST GPG cases and ten new capture-consumer regressions. This adds no Docker, native transaction, network, host package/service/default-keyring or hardware execution. The existing actual signal, real chmod/fsync and CLI/socket fixtures retain their previously documented scope.

Independent marker replay is `/tmp/ksm-captured-independent-review.py`. After a same-size source replacement, an explicitly supplied verified capture executes only its original marker; loading the changed pathname with the old pin fails before module-cache reuse. For a timestamp/size-valid foreign `.pyc`, a real legacy-loader control selects the foreign marker while the corrected loader selects the reviewed source marker. The corrected loader compiles captured bytes directly, keys its module cache by absolute path plus verified digest, and validates capture/pin before cache lookup. CONTRACT consumes the source-map capture. BASE aliases share the same cancellation state.

The independent signing replay loads actual pinned BASE and GUARD captures, mocks runtime/container observations, and installs an assertion tripwire on legacy `BASE.worker_guard`. Signing reaches the captured guard's environment/guard functions without that tripwire; removing a required protected-proc entry is still refused. Exact accepted UID/GID checks remain in the signing path. No guard-source or shared-helper change is required.

The installed probe replay uses a benign temporary Python marker program, not the native KSM package. For both post-capture replacement and a valid foreign `.pyc`, **all five actual isolated Python child probes and the in-process fixture module execute the reviewed capture**. Every child reads the same sealed inherited memfd; mutation of that descriptor is refused and the descriptor is closed before completion. Observed CLI `__file__`, `sys.argv[0]` and `__name__` retain the installed filename/main identity. Synthetic phase guard/bindings/package prerequisites are explicitly mocked. Same-open-descriptor mode/UID/GID/single-link/hash checks protect capture; the new suite also refuses a mode change before any probe runs.

Finally reran the independently adapted original schedules against held147: A→B→A never reaches create/start and remains FAIL; actual chmod-boundary cancellation gives exit1 and durable FAIL/cancelled; effective-root identity is refused before Docker/inputs. Controller and contract source were unchanged; the full suite continues to cover final handler restoration and late controller persistence.

**KSM-LOAD-1 is closed at this exact held checkpoint, with no remaining actionable finding in the requested source/fixture schedules.** Ready for coordinator integration and a separately authorized actual native lifecycle trial. Native KSM build-pair consumption, container signing/install/remove/reinstall, management activation, Asahi/M2/16K hardware and performance remain **NOT RUN**. Matching clean process exits, bound PASS receipts and verified owned cleanup are still required from that future execution; fixture success does not supply them.

## Coordinator source integration

The coordinator independently passes all 147 tests without skips against
this exact six-file source set. The source checkpoint
`f3966ce9d97b6a3661a57474740052eaa837929c7b7553ac2d82702562f03fc8`
and every referenced current/document/history/helper hash, size and mode
match. Earlier rejected checkpoints remain recorded. This source acceptance
precedes committed Git proof and actual native signing/install/remove
execution; both-size hardware, safe activation and performance remain NOT RUN.
