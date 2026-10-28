# KSM inventory deadline driver: independent root peer

October12,2026. **BLOCKED: one confirmed source/capture API code-custody finding.** Root accepted that finding for correction; no implementation changes occur in this review. The exact held checkpoint is `artifacts/reviews/ksm-inventory-deadline-driver-20261012/checkpoint.json`, SHA`f34c636d74c7ca1c7044f4a29542f475b5c34f2c2680a6871dbd841cb4c6026a`. Actual KSM5/38303811300 remains FAIL: inventory returned6674 bytes after67529ms, reply BrokenPipeError, precleanup owned-count1 and cleanupFAIL. Its raw parent exception and actual TimeoutExpired remain UNKNOWN/unexported; the marker proof is not an actual native cause or escape.

## Confirmed KSM-DRV-CODE1

`load_graph` authenticates disk bytes and stores `(native,guard,deadline,original_run)` at producer_driver.py:158–159. `wrap_run` at179–183 requires the same original function object, but never binds its authenticated code object or execution globals/closure. Python allows changing `original_run.__code__` without changing the function's identity. The file guard then still authenticates the unchanged source files.

The bounded reproducer loads the exact two-source authenticated graph, preserves the original native.run object, replaces only its code with an inert function returning `INERT_UNREVIEWED_CODE`, and invokes the exact selected inventory request. `_GRAPHS[id(native)][3] is native.run` remains true; wrap_run accepts; source guards before/after pass; the marker returns with the correctly clipped19.666222516-second timeout from a20-second caller cutoff. The original code is restored before context exit, and owned dummy image-id/output files are removed. No subprocess/backend/Docker/image-query/compiler/GPG/namespace/native actor is invoked. The first fixture incorrectly expected180 despite its20-second cutoff; that expectation error is retained and corrected, not attributed to the driver.

Evidence is `code-poison-repro.py` and `code-poison-repro.json` under the peer namespace. This proves the exported capture/wrapper API accepts unreviewed code despite its live graph/function-object guard. It does not show an independent mutation actor in production driver.main, a hostile-host escape, or a trust/native/hardware acceptance bypass. Root explicitly selected this source/API boundary as material.

The author should bind the exact authenticated executable code, globals and closure custody relevant to the captured native/package-check graph, rather than relying on a function object pointer and current file hashes alone. Check the binding before delegation and through restoration/exit, preserve the exact original command/log/timeouts/guards/phase budget and actor selection, and retain this marker as old-red/new-green coverage. Globals/closure regressions must distinguish deliberately authorized inert testing facades from actual production source authority. Root will select the bounded author correction; this review does not add a new generic framework or edit their sources.

## Exact source and preserved wiring

| Held file | Bytes/mode | SHA256 |
| --- | --- | --- |
| consumer.py |9154/0644|2c801ac981df837397f5384639455f45b938e64bac461d97616007fb00f77ee2 |
| executor.py |38133/0644|60714ead249a6d431b6b73186c75067c911c1f3de5988e0c7a70a54f5849fc60 |
| producer_driver.py |11277/0644|d826c1af9352c22d95915f5d7bfeba10a68a2dce33ddfaee80ace8d3e79670ee |
| test_producer_driver.py |20412/0644|9a403aaa4eca9edfa091aa4dca4156945a6387861f78b00887568f37bdaa0744 |

The guide is8048 bytes/SHA`fe2bf87029c932346be105a8df60aae9582e4086eec722b031825a7a13904397`. All399 indexed author artifacts were freshly authenticated for exact hash/length/mode, regular single-link type and bounded size, totaling5,848,219 bytes. Seven selected source roles were copied into a fresh no-PYC tree: the four held files, runtime.py, native_arm.py (a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898) and package_checks.py (e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8). The actual original159 and held7ede evidence are preserved by the authenticated author index; they are not newly executed or admitted.

Independent AST comparison confirms only consumer.producer_command and executor.pipeline differ from the baseline. Removing the new `producer_end=producer_end` keyword makes the entire executor AST equal to the original. The default consumer command remains exact; selected commands retain every original native argument before the single trailer delimiter. The6600 producer cap,1650 later reserve and8460 aggregate budget are unchanged.

The timer selector matches only an exact builtin list of11 original inventory argv entries, logNone, integer60 and the current immutable image ID from the private output file. Other argv/log/timeout values are forwarded unchanged. Its selected timer is min(180, existing absolute producer_end−monotonic), with no new phase clock/reserve; expired/late observations refuse. Private output/image source identity, ownership/mode and pre/post guard checks were inspected and modeled. The new finding concerns executable-object custody, not a demonstrated timer arithmetic or command-selection error.

## Fresh focused evidence and bounds

All31 driver test methods passed from the fresh tree, zero failures/errors/skips, in7.958 seconds. They cover exact/nonmatching commands, clipping/expired/late returns, source/output/image custody, forged/expired contexts, closed project imports, poisoned standard-library caches/finders/hooks/builtins, source-only loading without PYC, signal handler/mask preservation and real runtime deferral, CLI trailer wiring, and parse refusal before actors. Independent wiring controls additionally confirm original default/forwarded args, finite trailer values and entire executor AST preservation. The new same-object code marker is an additional failing guard control that the31 methods do not cover.

The `_signal` regression uses an actual harmless isolated Python child and local signal handlers/masks; its initialized builtin reference, caller cache restoration and subsequent runtime deferral pass. Other wrapper subprocess calls are redirected to harmless facades; module loading and tiny ordinary-file/symlink fixtures are actual local operations. Local replay runs with `-I -B`,30 CPU seconds,768MiB address space and60-second wall. Owned TMPDIR is empty afterward and no PYC was created. No Docker, native, namespace, GPG, package installation/compiler or actual image query ran.

The author's final323-suite/13 wiring and three1/20 scaled causal receipts were authenticated but not broadly rerun. The scaled outcomes remain models using a dummy6674-byte payload, not the actual inventory/hash or a recovered parent exception. Their historical initial322 failures and `_signal` correction are retained. The fixed180 request cap cannot guarantee all later producer/build/lifecycle/cleanup or native gates succeed.

Two new rows make154 prospective packet paths; root alone owns RequiredPaths/packet/helper/workflow/Git registration and actual dispatch. The live154 proposal is not native admission. Only this review and the owned peer evidence namespace were written. Until KSM-DRV-CODE1 is corrected and independently closed, this held driver is not source-ready. Actual cleanupFAIL, unknown cause, hardware/16K/performance and all other unresolved gates remain unchanged.
