# Coordinator independent kernel native job review

The held 93-test checkpoint passes its existing source fixtures but needs two bounded finalization/budget corrections before source closure. Both reproductions use the actual job controller with mocked external stages; neither executes Docker or a kernel. The workflow's native-outcome projection and six-hour hosted cap prevent these schedules from becoming an accepted hosted PASS. They nevertheless contradict the controller's stated terminal-rewrite and launch-reserve guarantees.

Read the current roadmap, `manifests/packages.toml`, [job guide](../workstreams/kernel-native-job.md), original producer source and frozen kernel controller. The author's supplemental review was read after the controller sources and does not substitute for these independent checks. Hosted execution, the original producer in this job, native ARM allocator probing, both full kernel compilations, installation and M2 runtime remain NOT RUN; performance is NOT MEASURED.

## Held inputs

Handoff `artifacts/kernel-native-job/handoff-20261012/checkpoint.json` SHA256 is `cbef2e5cd8d9fb843ea8068779cb953052816b538bfc831d8388c71a592befcb`. Independently checked all ten new path byte lengths, SHA256 and modes against that receipt:

| Path | SHA256 |
| --- | --- |
| `scripts/port/kernel-native-job/job.py` | `dac074c67d13e5299acc1d645961d4cd3d6e7bd176503da5ac1767c416957eeb` |
| `scripts/port/kernel-native-job/packet.py` | `cae94b953e7ff1fb07695519bea4c2629d57d9884131893b049081c3de7e2bae` |
| `scripts/port/kernel-native-job/public.py` | `d305fca9375ef9f9ee71b600a17111ae7d38d86c0073aabf07aad681c48356bf` |
| `scripts/port/kernel-native-job/runtime.py` | `5e01ff6c87ba8b0090b0fc7ef6fc60ec3c361f75eb8e6a89953412da9bb6df9c` |
| `scripts/port/kernel-native-job/test_job.py` | `8c19ad51b80ef0575eafb39ab33fdfa7213f0b35304732120ee59722040ca69a` |
| `scripts/port/kernel-native-job/test_packet.py` | `fa8b0584abf0fa7cb03337e7368fe67b5168a379a30f9b69e0e61c3cbb6f8c9c` |
| `scripts/port/kernel-native-job/test_public.py` | `6b0ade205fcd0a5135e394ea82bdb53d1b9e710cd93f09c39896429a86b7008e` |
| `scripts/port/kernel-native-job/test_runtime.py` | `5a9d9cb72d17379ddf5cba99f35e18013ba64c764f1343c1abc9381f93543fdf` |
| `.github/workflows/native-arm-kernel.yml` | `40a16f84d2a52f0574b71bb1baffdc6069429b2e27345870795f0351c34d0e4c` |
| `docs/workstreams/kernel-native-job.md` | `675efa48af6979c0b81e77ea4510bc1d2d67d6ba68ff22fcf3ffc45a0c65636f` |

`packet.preview` independently yields 115 files / 1,753,534 bytes; canonical indented/sorted JSON hashes to `68d244158fbc484100c2cdf9cabce31036d5fe52c4ec97cfb9a50fd36660bc57`. Read-only actual Git blob/mode comparison independently confirms all 105 existing frozen files match HEAD and their preview pins. This is a proposed closure: no new packet lock, Git registration or dispatch was performed here.

## KJOB-ROOT-1: cancellation at outer handler restoration

The actual `main` catches a cancellation raised while its outer `cancellation_handlers` context exits, but only prints `KERNEL_NATIVE_JOB_FAILED` and returns 1. It cannot rewrite or invalidate the terminal receipts already produced by `execute`. The runtime handler restoration loop can also be interrupted before restoring the remaining handler.

Independent `/tmp/kernel-job-root-independent-repro.py` uses actual `main`, `execute`, atomic `finish` and signal contexts, with the existing controller fixture mocking only source/native/Docker stages. After the final PASS write, a signal-wrapper schedules real SIGTERM when SIGINT's original handler has been restored but SIGTERM's cancellation handler remains active. Result: `main` returns 1; raw public/private terminal candidates remain PASS with `cancelled: false`; SIGTERM's original handler remains unrestored. The harness restores the test process's original handlers in its own finally block.

The actual publisher with `native-outcome: failure` correctly converts that stale receipt to FAIL, so this is not a workflow acceptance bypass. Required source closure is protected handler restoration plus a main-level terminal failure rewrite/invalidation path that retains bounded publication behavior. A meaningful regression must exercise the outer context-exit schedule, beyond injecting cancellation during the inner writer. Reproducer SHA256: `521e356a6bad37a100d22073c1a0a0838cc9a9061e405d0b4a208c3c204dec9f`.

## KJOB-ROOT-2: native-step startup omitted from launch reserve

`execute` takes its monotonic origin only after directory creation and its initial durable receipt publication. Time consumed by those operations belongs to the same 346-minute native step but is omitted from the controller's later remaining-time predicates. The workflow has no first-step shared clock; one is not required by this finding. Its individual 5+5+346+3-minute caps plus one-minute guard do fit the 360-minute hosted ceiling.

Independent `/tmp/kernel-job-budget-independent-repro.py` advances a mock clock, with no sleep or process workload: finite initial publication600 seconds; setup300; parallel producer/acquisition2050; kernel envelope18240; cleanup150. The held controller launches the full kernel stage and returns local PASS after simulated 21,340 seconds, exceeding that native step's 20,760-second cap. Its reserve checks see only 20,740 seconds since the late origin. On a real hosted run, the step timeout would abort the controller before complete acceptance/cleanup and publication would fail or downgrade; the documented disposable-VM residue boundary remains necessary.

Required source closure is to include initial output/receipt work in the job's existing monotonic budget, and exercise a finite startup-delay refusal before launching a full kernel budget. This preserves the held kernel's five-hour budget and does not invent a mandatory workflow clock. Reproducer SHA256: `f6815c429ec9b11ebfecf307b556d57bc962d301adfe1622d89ee834e7f8693b`.

## Other audited boundaries and actual checks

The original producer command is the direct pinned `native_arm.py build` CLI, with exact input/recipe hash arguments and no FDK override/integration mode. Its build-only imported/helper/recipe closure remains captured. Receipt acceptance correctly requires the original 248-package authentication counter; the separately verified rootfs is not included in that field. The accepted 341-package inventory and same-job image/bootstrap/result/runner bindings feed the unchanged kernel controller. Acquisition supplies seven fixed paths; stdout cannot redirect the controller.

Inline standard-library bootstrap authenticates packet/Git/file bytes and modes before copying only captured rows into a new source tree. Timestamp-valid checkout bytecode and unlisted extensions cannot execute through the fresh bootstrap; producer/acquisition/controller code runs from fresh private snapshots while the kernel controller independently checks the actual Git checkout. The public bootstrap compiles authenticated captured helper bytes directly. Exact closure, original input/recipe locks, kernel24 lock and fifteen-package extension pins remain unchanged.

Native prerequisites retain actual ARM/ordinary real/effective identity, zero capability, local canonical hashed CLI/socket, native rootful cgroup-v2 daemon/API1.49, empty initial daemon inventories, 15GiB physical/14GiB available memory and 30GiB initial/8GiB pre-kernel disk reserves. Missing prerequisites fail without installs or fallback. Process fixtures verify one parallel deadline, pending-spawn registration, restored child signal masks, peer stopping, output limits and kill/reap of stubborn owned descendants. These are local process checks, not actual native daemon/cgroup evidence.

Only an accepted completed producer's exact immutable image ID is journaled and removable without force, after bound identity inspection and with actual absence/no remaining containers checked. Interrupted original producer work remains uncertain FAIL even if the current scan is empty. Unknown asynchronous daemon work, interrupted controller commits/recovery and private build-cache/intermediate residue remain explicit disposable-VM limitations; no global prune or complete cache cleanup is claimed.

The public helper reads only one owned single-link regular status record, at most16KiB, with exact finite fields/values and commit/packet binding. It refuses private strings/extra fields and gates final acceptance against native-step outcome. A baseline completion may be retained under outer FAIL while aggregate compilation becomes NOT ACCEPTED; runtime/install/hardware/binary publication remain NOT RUN, performance NOT MEASURED, release selection false. These gates correctly mitigate both reported schedules but do not make their stale raw receipt or missing launch reserve guarantees true.

Independent full suite: **93 tests PASS, zero skips**, 3.694 seconds. Actual YAML/alias parsing and workflow contract passed through a local yaml-cpp checker; all four step caps sum to359 minutes under a360-minute job cap. Inline Python compilation, bootstrap/native shell `bash -n` and scoped whitespace checks passed. The checker compiled only a tiny local YAML-validation program against the already available library; no kernel/native system work occurred. Fixtures use synthetic source/receipt/Docker data, temporary Git trees and tiny local processes. No Docker, network acquisition, GPG authentication, package installation or kernel execution was run.

Source closure is held pending the two corrections and independent rerun against an exact updated checkpoint. Only this owned review document was edited in the project; root retains source/map/Git/workflow integration and dispatch.
