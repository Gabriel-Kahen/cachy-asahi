# Actual kernel5 trial 38292740905 — independent retained-evidence review

Disposition: **PASS for bounded archive/source/public-status verification; actual execution remains FAIL.** Kernel5 progresses through provision ownership inspection and then fails `INSPECT_RESOURCES /docker-container-resources`, before attached worker start. Cleanup fails the same resource predicate. The particular resource-field mismatch remains UNKNOWN; no raw private inspect response was exported. Kernel compilation, probe/baseline/candidate workers, owned absence, M2/16K execution, hardware and installation do not pass. Kernel3 and kernel4 retain their historical failures; this run does not retrospectively identify kernel4's failed ownership conjunct.

## Strict archive and committed authority

Root downloaded `artifacts/ci/38292740905-logs.zip`. This peer independently opens the exact regular non-symlink archive, verifies unchanged descriptor identity across bounded reading, and hashes all 29,514 bytes: SHA `368023f19b1fb934585fe38f9c5dde94fe86e190b94601142e818a3aefd3b2dc`. Nine regular UTF-8 log members decode to 111,504 bytes. Their lengths, CRCs and SHA256 values are indexed under `artifacts/reviews/native-kernel-38292740905-root-peer/zip-index.json` (3,189 bytes, SHA `d9cf812c96f9d03d2dfdb5656ce38ec65c98584927821c4445677173d55801ee`). The decoder refuses duplicate/traversing/noncanonical/control-containing names, unexpected namespaces, directories, encrypted/unsupported compression or flags, overlapping compressed ranges, and unsupported modes. Actual archive entries have DOS creator/zero Unix mode; that explicit ordinary-file metadata is accepted, while local retained logs are created 0600. CRC validation is provided by bounded full ZipFile reads.

Caps are 8 MiB archive, 4 MiB per decoded file, 32 MiB decoded aggregate, 64 entries and 60 seconds. No archive content is executed. This authenticates retained bytes/member consistency and supplied run attribution; the peer does not manufacture an independent remote-origin signature. The 55,317-byte combined log SHA is `04804636791b221330c31b14e7aa5b58aa0891e470845c4fa97e5bc5313470f5`.

All 117 packet rows were independently captured using exact Git blobs and tree modes at `215bd7b4f7e0ba3fa5d23e38d60a503b963c2ed0`; every row matches its declared length/SHA/mode. Packet SHA is `647d4dd0101b2188d348adc87089fc5804e288872ff5fc9352d76861a512f342`, with 2,021,846 selected source bytes. Including the packet itself, the immutable peer capture has 118 files/2,044,292 bytes. All nested 26 stage rows match stage SHA `0ef3ad174f0bdc1cd9b1a3c4874775dc2c486f3fc08429c6d2751715ccce2290`. Workflow SHA is unchanged `1ff6d9c5711b527992499405e23130f10924d524514322942de199b3deabfba4`. Source capture receipt SHA is `2c60ab4622610d0e456aebcaa7b42ceac1032e1ad43f09d5c29be33ba2fb56b5`.

The committed workflow's actual inline `source()` gate was reexecuted against the still-matching 215 Git HEAD, with only source/Git reads: all 117 captures, modes, committed blob checks and supplied packet pin agree with the separate immutable snapshot. The workflow main/native host prerequisites and actor were not invoked locally. The actual log records matching checkout/source refs and `KERNEL_PREFLIGHT_PASS` at 18:42:46.9582262Z. A later clone refresh cannot replace this captured authority. Final captured-byte/mode checks pass with no PYC.

## Exact actual status and first failure

One actual terminal status occurs, at **2026-10-12T18:47:06.8517048Z**. Raw compact status is 2,635 bytes, SHA `9363a4a311a892fc37138981674d5e5d458e7dab9cd986599b323172e000bd0a`. The captured committed `public.py` (SHA `5e6a335a0f88b73a074c83cfa5d1de113853d070a5f04d58737914033b1e6d7c`) accepts this actual dictionary under the failure outcome and reproduces its compact canonical raw bytes exactly. Wrong source/pin, hardware promotion and an unknown raw field each refuse in four causal projection controls. The native step independently records exit 1 at 18:47:06.3316812Z; the successful later public projection retains the execution failure and is not kernel acceptance.

| Recorded observation | Actual value |
|---|---|
| Outer producer/acquisition returns | EXIT_ZERO /0 each |
| Producer/mutation | PASS /COMPLETE_ACCEPTED |
| First outer failure | kernel /KERNEL_EXIT |
| Bound child availability/actual return | VERIFIED /EXIT_NONZERO /1 |
| First child predicate/category | PROVISION_COMMAND /INVALID_DATA |
| First operation | provision /INSPECT_RESOURCES /docker-container-resources |
| Query return/separate daemon status | CONTAINER_INSPECT /EXIT_ZERO /0; HTTP_STATUS /200 |
| Create/start observation | CID_OBSERVED /NOT_ATTEMPTED |
| Provision command accepted by stage | UNOBSERVED /null |
| Child cleanup | FAIL /ABSENCE_UNVERIFIED |
| First cleanup operation | cleanup /INSPECT_RESOURCES /docker-container-resources |
| Probe/baseline/candidate commands | NOT_RUN /null each |
| Final owned absence/preservation | UNVERIFIED /UNVERIFIED |

The current operation's later CHECKPOINT_WRITE/NONE label does not erase the sticky first or cleanup failure. The source orders ownership before resource inspection, so this run passes the former gate before failing the latter. That progression does not prove actual kernel4 failed only on the null/empty label issue, nor expose kernel5's actual label values.

Private child binding SHA is `b9704d16aced177902e47c5f26aceba9cc30d332c90ce72e3a13e8be6855f601`. It records the authenticated job's exact invocation/nonce/source/receipt binding projection. Private nonce, raw child receipt, accepted producer/build receipts, Config/HostConfig, query stdout, container/image IDs and operation journal were not exported, so those private bindings or original archive comparisons cannot be independently recomputed from this ZIP. Zero CLI/HTTP returns and a create CID do not establish an accepted profile, worker launch or safe deletion. Source control flow places the resource refusal before attached start; no provision worker execution is observed or accepted.

Producer PASS/zero and mutation COMPLETE_ACCEPTED are the bound coordinator's receipt acceptance, not this peer's independent rehash of original archives/signatures/private production outputs. Acquisition exit zero is likewise a recorded child return; private acquisition payloads were not delivered here. No new original package-byte comparison or native workload was repeated for this review.

## Baseline, resources and unfinished scope

The outer record declares initial daemon baseline six image IDs/zero containers, pre-identity SHA `124fd070b1b7bc795026a7b7ed4773c03383c492587efeeaffc5faf65f7cb869`. Post-identity is null; preservation and owned absence remain UNVERIFIED, legacy build cache NOT_ESTABLISHED. Cleanup FAIL blocks acceptance despite the earlier accepted original producer. Disposable-VM teardown or a returned create CID does not substitute for scoped absence.

Resource observations are mem_total 16,722,010,112 bytes, mem_available 15,509,360,640 bytes, initial free disk 115,210,526,720 bytes and pre-kernel free disk 105,558,429,696 bytes. These bounded values are not the missing HostConfig inspection fields and cannot identify the resource comparator failure. They are not performance measurements. Native compilation, kernel runtime, hardware, installation, binary publication and release selection remain NOT RUN/false; performance is NOT MEASURED. No physical M2 or 16K compatibility follows from the ARM host or declared source architecture.

## Source-causal limits and smallest next diagnosis

Twenty-three independent inert committed-source inspector controls are retained: one valid provision profile, fifteen individually varied required HostConfig fields and seven individually present forbidden fields. Every variant produces the same `docker-container-resources` predicate, with exactly one synthetic inspect and no daemon actor. The controls therefore establish diagnostic ambiguity, not the actual mismatched field or a new source bug. They preserve valid ownership, mounts and command facts while varying one profile condition; there is no policy relaxation.

The required profile includes AutoRemove/Privileged/ReadonlyRootfs, network/IPC/PID/cgroup modes, memory/swap/CPU/PID limits, capabilities/security options, tmpfs and provision CapAdd. Forbidden devices, device requests, binds, volumes-from, links, port bindings and group-add presence use the same predicate. A missing field, default/representation difference, capability or mount policy deviation could all reach this boundary; the public terminal cannot distinguish them. No particular raw value, Docker normalization or syscall cause is guessed.

The smallest next observation proposal is a finite closed resource-field/presence mismatch label, retained as the first failure and separate cleanup failure, bound through the existing immutable child capture and public receiver. Publish no raw values, paths, IDs or query contents, and keep the aggregate profile predicate, query ordering, resource limits and cleanup/PASS gates unchanged. Any later normalization/correction requires the relevant actual field observation and pinned source evidence first. This review implements neither diagnostics nor a resource-policy change and grants no native dispatch.

No source, map, workflow, Git, package, Docker or system mutation was performed. Retained evidence and final hashes are indexed by `artifacts/reviews/native-kernel-38292740905-root-peer/review.json`. Earlier kernel3/kernel4 evidence remains unchanged; the actual kernel5 result stays FAIL.
