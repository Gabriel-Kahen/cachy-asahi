# Corrected Topmem caller: isolated push workflow successor

This source-only successor enables the reviewed Topmem workflow to run from the isolated execution branch without requiring a dispatch-only workflow to exist on default `main`. Root owns publication, repository variables, the exact execution-ref push and actual hosted run. No Git command, source proof, workflow registration, push, dispatch, network, GPG, native library, Docker or package operation ran here.

The authoritative roadmap and outline still require full R1–R5/M5–M9 acceptance. This trigger proposal does not complete native Topmem validation, signed lifecycle/recovery, either M2 Air size, performance or a supported release. Shared primary files and package inventory remain unchanged.

## Minimal source delta

The parent registration-bound workflow is SHA `98a81b53317f47924343a0ea28056ed3604202b2e715897fc84b9be874a77464`. It already binds Root's selected policy `1bca9ee9afe9eabc3f9639592b5368e990d634aa0130168811777b667bd86d74`/3,884B/mode0644, producer `8e27901c8bf395b0a9145fd5303bb8f35db2cd498ebc86b412a6916aa09fe5a7`/26,388B and the corrected common caller/Topmem manifest. Its original dispatch-only proposal seal `01231dadbca49c0619bb8ee8336d9eae23f5e6052eb314e7d03194a6bf4942ac`/170 files is preserved in the parent's `attempts/attempt-01`; the policy-binding amendment has separately sealed controls and peer evidence. The old root receipt no longer authenticates six amended top-level files (workflow, plan, generator, derivation, handoff and sealer). It remains untouched as failed historical current-membership evidence; its complete matching snapshot and original peer copies are preserved. This push proposal does not alter the selected policy or source contract.

The only workflow changes are:

- Replace `workflow_dispatch` with a `push` trigger whose branch list is exactly `codex/topmem-native-execution-v1`.
- Extend the job guard to require both repository `Gabriel-Kahen/cachy-asahi` and full ref `refs/heads/codex/topmem-native-execution-v1`.

No wildcard branch, tag, pull-request, schedule or manual-dispatch trigger is added. The trigger and guard jointly restrict execution to the isolated branch in the exact repository. All environment values, step names/order/conditions/timeouts, pinned checkout, inline Python bodies, shell commands, one inherited clock, profile, policy, actor ownership, concurrency and metadata retention remain byte-for-byte identical to the parent workflow. `prepare.py` performs only those two exact text replacements and captures the parent inputs for review.

The workflow destination remains `.github/workflows/topmem-corrected-caller.yml`, outside the proof union. Canonical source remains `scripts/ci/topmem-corrected-job/` with123 rows and the separate policy `scripts/ci/topmem-test-tool-policy.json` adds the124th committed proof row. No wrapper is added inside the closed baseline/addon/caller subdirectories.

## Root registration and execution order

Root's committed source/policy checkpoint is `70238b7d434330fb1ece91eb806a481c7c61d67c` on `codex/topmem-native-caller` in `/home/gabe/.codex/worktrees/topmem-tool-observation/cachy-asahi`. Local readback and the parent's registration review bind those source123+policy1 bytes/modes. That checkpoint precedes this workflow and is not the final execution SHA.

Root must first commit this reviewed push workflow with the unchanged canonical source and selected policy, verify the actual resulting commit and exact workflow bytes, and assign that final workflow-inclusive SHA to `TOPMEM_CORRECTED_SOURCE_COMMIT`. Only then should Root publish that exact commit to `refs/heads/codex/topmem-native-execution-v1`. The external variable avoids an embedded self-commit hash. Its value must match both `GITHUB_SHA` and `GITHUB_WORKFLOW_SHA` for the triggered job; a blank variable, checkpoint-only SHA or mismatched ref/commit fails the inherited proof gate.

The branch name is fixed, but no future commit SHA is fabricated here. Root must preserve the registration plan, variable assignment and exact remote-ref readback as distinct evidence. A reviewed local workflow or a branch push alone is not proof that the hosted job started or succeeded. Retain the actual run ID, complete logs and final job conclusion separately. This proposal does not push any branch or assign any variable.

## Inherited execution and acceptance

The execution body remains the reviewed first-clock → caller proof124 → official prefetch501 → corrected caller native → separate closed caller/prefetch metadata route. The caller performs the fresh baseline8/4/249, TEST agent/key/signing, Topmem4/2/6/1 and2 internal database productions against the same owned image, then signer/addon/baseline recovery and image absence. It never reuses a cleaned earlier image or calls standalone lane native before the addon.

The original absolute clock remains start+7200s, with guardJ−120, workguard−480 and cleanupguard−60; all three recoveries share min(cleanup cutoff, recovery entry+180s). Source/proof/prefetch/native/retention bodies and reserves are unchanged. Only closed bounded metadata is retained; no private tree, keyhome, public-key credential carrier, cache, package, raw actor logs or artifact glob is exported.

Root's acceptance still requires overall hosted job success, a matching closed caller PASS, natural process completion, the exact source/policy/proof/clock bindings, complete non-null baseline/addon-command/signature observations and both journals, all recovery and image-absence evidence. The expected signature route is exactly14 passed journal entries with6 verifications; the frozen caller's12–16-row bound alone does not enforce Root's stronger exact14 condition. No trigger change tightens that source predicate or supplies native/hardware evidence.

Delta controls verify exact branch/ref admission and identical inherited execution bodies, not a GitHub event delivery or actual dispatch. No prior native/observer suite is replayed. The parent source/control evidence remains historical and unchanged; this successor's receipt binds its own input captures, delta controls, review and guide.

The new `inputs/parent-drift-record.json` records all six expected/current byte, mode and SHA rows and the changed guide separately. Matching original files and current changed files are captured under distinct paths, together with the unchanged old receipt, selected policy/checkpoint and registration-amendment control/peer evidence. The definitive new root receipt must bind every final file and internal evidence copy. Root selects only this new successor after independent frozen authentication. No file is changed after its final seal; any later correction requires a separately retained successor.
