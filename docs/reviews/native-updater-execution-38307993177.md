# Native updater7 execution review: run 38307993177

**Actual FAIL, with a deterministic source-pin blocker reproduced.** The authenticated recipe ships `worker-metadata.py` SHA256 `4acc1fa076884b28973cf13b966030081dc6e5b030072332365b7a4485231f48`; the gate and policy still require `f54226c068f3f8a51556ed9185168b89f793c1c8f2219c81557246f587e0edf2`. Exact captured gate entry refuses before importing the observer or reaching compilation. The actual private gate stderr is **NOT EXPORTED**. The reproduced refusal message is source-model evidence, not recovered actual child text.

## Selected source and custody

Actual run `38307993177` selected source commit `f7217a1336c3b993c3f0d0daf8cc1b52872223f3`. Independent Git bytes/modes and the pure committed source-closure function authenticate86 files totaling4,206,723 bytes. The selected source86 capture is under `artifacts/reviews/updater-tool-alias-root-registration-20261012/source86`. The sibling `historical-ready.json`, `historical-stage.py` and `historical-workflow.yml` are older historical inputs; they are not substituted for this selected Git closure.

| Actual selected identity | SHA256 |
| --- | --- |
| Ready | `a13b61ca4f3e529e0adb8e0f4d57dc52af6cb5abe56da58fb23644764b0612ab` |
| Stage | `96067bc2fc388bacfa4a303d782b6bee04583e72b0f80faee17eca2e6262d5dc` |
| Source helper | `4d3e3fd9848aaed94154f786b04a5ae07c7816dcef82857b671b51555895eacb` |
| Workflow | `d0d3d686fbc288fe469cadc849671f45475ab09b452e6a700a105ee09fcff1ad` |

The root archive is [`artifacts/ci/38307993177/logs.zip`](../../artifacts/ci/38307993177/logs.zip),121638 bytes, SHA256 `4d91c19f5a0ba6964683c73914abf9e63ddb51a6d9b61b3289c0c515d12ee9bf`. Ten unique regular members total266,603 decoded bytes. Independent checks cover CRC, local headers/descriptors, member paths/types, the root index and extracted bytes. Three selected timestamp/base64/SHA frames contain bounded regular tar bundles: guarded, terminal-public and recovery-terminal-public. All16 public files match the separately retained root decode/index.

The auth peer uses exact committed pure validators and AST-extracted pure workflow projection/terminal functions. Their public schema/export manifests, worker diagnostic, controller correspondence, terminal and recovery checks pass. Sixteen hostile public mutation controls refuse. These checks authenticate the finite exported content and its available bindings; they do not recover removed private files or make a syntactic digest into unexported content verification. The first parser assumption about a workflow-log BOM refused; the corrected timestamp decoding retains that harness failure and original script.

## Actual execution boundaries

The closed worker diagnostic says controller validatedtrue, then first failure at `compile-gate`, predicate `command-nonzero`, command launch attemptedtrue, return observedtrue, returncode1. Compilation acceptedfalse, compiler launch attemptedfalse, compiler return observedfalse, cancellationfalse and diagnostic-write-failedfalse are retained. A later operation `entry-log-copy` does not replace the sticky first failure. The command's stderr/stdout summaries are null; its private logs were not exported.

| Layer | Actual retained result |
| --- | --- |
| Worker metadata receipt | Host/target `aarch64-unknown-linux-gnu`; native compilation and build-script execution NOT RUN; closed input/metadata/cfg/version/tool hashes retained |
| Worker inspector status | FAIL attempt, worker run returncode1; bound diagnostic; container exited1, not running/paused/restarting/dead/OOM-killed, no state error |
| Worker scoped removal | Attempted/complete/removal succeeded/absence verifiedtrue |
| Native result | Native pair FAIL, failed stage worker-1, finalized, publication NOT ACCEPTED, hardware NOT RUN |
| Owner terminal | FAIL/native compilation NOT RUN, failure native-pair/process-failed, return1, cancellationfalse |
| Owner cleanup | Docker/GPG/process/private scoped cleanup PASS; private data removedtrue |
| Recovery terminal | PASS for scoped recovery; native compilation NOT ATTESTED BY RECOVERY |

The public worker-status field labels the build attempt's native compilation FAIL, whereas the metadata receipt and owner terminal retain NOT RUN and the diagnostic records no compiler launch. These are distinct layers; the coarse attempt failure does not establish a compiler invocation. Metadata/version/cfg queries and hashes are not build-unit or compiler-success evidence. The private Cargo metadata, cfg/version bytes, full observed facts, controller nonce and raw controller input are not reconstructed here.

The owner terminal reports231 elapsed seconds, shared storage peak growth12,788,637,696 bytes, limit17,179,869,184 bytes, storage latchfalse and reasonnone. This is the failed prefix's observed budget state, not proof the full compile pair fits the budget. Daemon disposal remains NOT ATTESTED; cleanup PASS is scoped to the selected ownership/records. No runtime, Apple updater lifecycle, M2/16K hardware, installation, package distribution or performance gate is promoted.

## Source-causal compile-gate obstruction

The actual `guarded/build-1-inputs.json` recipe ledger independently binds these exact captured source bytes:

| Input | SHA256 |
| --- | --- |
| Observer `worker-metadata.py` | `4acc1fa076884b28973cf13b966030081dc6e5b030072332365b7a4485231f48` |
| Compile worker `worker-build.py` | `29108f15b9c1d5f9917b6b363ffe1cc179c106e84c8d12309e95429b8a13f5d0` |
| Gate `build-gate.py` | `068493948809df43da5e3891cf3cefb7a7f899182ba3f0783b119a97e49174a7` |
| Policy `build-policy.json` | `a3e469a20603f4fb2d04ac47993731cc358fb6b344346c7c9e02620b2b0c4b5c` |
| Closure `linux-closure.py` | `a73d7ba17018d2fd359e630675b7ca207965b01eca358f7574a80f690124d2a2` |

Both the gate's `MODULE_PINS` and the policy's `module_sha256` still pin the observer's older f54226 digest. They agree with each other, so `policy_check` passes. `gate.main` next calls `module(policy,"worker-metadata.py")`; that function hashes the selected file and refuses before import. The other closure/evidence pins match. The fixed compile-worker command supplies the required gate arguments, and recipe preparation does not modify these gate/observer Python files.

This is an actionable selected-source blocker, not merely a plausible raw-error interpretation. The committed recipe cannot pass that module check. It is consistent with the actual compile-gate return1 and no compiler launch. The exact actual child leaf error text remains unobserved, and this review does not assert that every later identity, source/vendor, license, build-script, Linux graph, retention or compilation check would pass after the pin is refreshed.

The independent exact-main facade exercises9 models with zero failures/errors/skips. Stale pins reproduce exit1 and `compile refused: validator/observer module pin differs` with an empty import trace. Policy-only or constant-only refresh still refuses policy consistency. Updating both in memory reaches only explicitly inert observer/closure import facades and a sentinel stops before worker observation. Mutated observer and closure bytes still refuse. No production code or files are patched by those models. The parent independently reproduces the module refusal and reruns all9 controls; traces match the sealed peer.

## Minimal proposal before implementation

The saved [`proposal.json`](../../artifacts/reviews/native-updater-38307993177-root-peer/proposal.json) proposes only:

1. Refresh the observer entry in `build-gate.py:MODULE_PINS` and `build-policy.json:module_sha256` to the selected4acc1fa digest.
2. Add a `test-gate.py` regression that hashes the actual shipped modules and compares their bytes with both the checked policy and gate expectations. Retain a stale/mutated-module refusal-before-import control and an inert positive control stopped before actual observation.
3. Root separately regenerates current derived recipe checksums and ready/stage/source/workflow registration, obtains independent review and selects any later native trial.

Proposed implementation ownership is those three existing gate/policy/test paths, plus a separately selected new guide/artifact lane. No implementation occurs in this review. The selected observer itself, all policy/evidence/inventory/module/source/identity/isolation/resource/deadline/output/cleanup/compiler/PASS checks, command sequence and public diagnostic schema remain unchanged. No gate bypass, obsolete observer restore, new daemon query, raw private-error export, broad diagnostic framework or timeout/resource increase is required for this defect. Historical `validation.json` and `recipe-validation.json` records with old pins remain historical; they must not be silently rewritten as new validation.

## Verification and preservation

The independent auth receipt is SHA256 `73f80e76dbdd5b6b8d7051b281e324e9c809b0b7bd5e356327412e8ea082084b`; the exact gate/model receipt is `48c14317907a632eb822b3e31c5e31d590f15e8a014aea776ada8897c82a1909`. Both are under [`artifacts/reviews/native-updater-38307993177-root-peer/`](../../artifacts/reviews/native-updater-38307993177-root-peer/). The parent re-reads their captured files and available external bindings before sealing this review. Production source, shared manifests/maps/workflows, Git and actual actors are not mutated or executed by this worker.

The sealed SVG peer remains receipt `ef0c6aae5927f77537f136cb17aa781db24c34241e83278dc9717377a7a14dc4`; its source/model/host-fixture PASS does not admit a guest actor. Its historical shared-manifest drift is separately explained by root's selected Zsh adoption commit `c45a44f`, whose manifest digest is `a05337fd4241cabc318e5472df661049a81ece871409d9979299e2b61e923543` and adoption receipt is under `zsh-autosuggestions-root-adoption-20261012/adoption.json`. The historical SVG row/labels are preserved unchanged. The kernel capability two-source hold, actual kernel6 failure, KSM and guest4 artifacts/documents also re-read unchanged. No prior native FAIL or unknown cause is promoted.
