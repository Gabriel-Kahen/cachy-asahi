# Single native terminal workflow caller

Source-ready only. Root owns adoption, registration, final refs, dispatch, actual
ARM actors and frame review. No Git/CI/native actor or peer was used here. All
new files remain under this artifact directory; accepted lanes are unchanged.

## Exact adoption and run

Use ci/adoption.json: 16 exact new files with source→target paths and SHA256.
Eleven lane source/data/doc files go to scripts/ci/desktop-terminal-workflow/;
caller.py, test_caller.py, source-manifest.json and this handoff go to its ci/;
the manual workflow goes to
.github/workflows/native-arm-desktop-terminal-workflow.yml.
Do not copy the broad artifact tree or pre-generated runner. The private stage
proved all 43 source hashes and reproduced all 11 generated-runner hashes using
only the declared canonical layout. The 30 accepted shared prerequisites remain
unchanged and are not copy targets.

The workflow is complete, not a step fragment. Dispatch its final 40-character
source SHA as source_sha after adopting/registering it. It requires that input
to equal GITHUB_SHA and GITHUB_WORKFLOW_SHA. Caller and manifest hashes are
embedded. Source proof precedes secret exposure. It is manual-only, uses the
accepted pinned checkout/upload actions, contents:read and native-arm-build
serialization without cancel-in-progress. Job limit: 90 minutes. No ref placeholder
or new secret is required.

It preserves the accepted six-file secret seed and exact fourteen-file public
seed at 04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd, including seed/index hash checks.
Current maintained 574 build uses its existing --job-token API; all consumers run
before its final owned cleanup. Native build is bounded 2300s and the separate
terminal runner 2050s. The controller's existing 1750s alarm preserves cleanup
reserve. Failed/uncertain ownership or cleanup makes the job fail honestly.

The new workflow runs existing hosted/guest controls, the 20 new workflow controls,
11 caller controls and 13 inherited runtime controls. It generates the exact
runner with the pinned prepare.py and checks every derived hash. Host libalpm is
not a CI dependency. No new packages are installed on the host; the exact 574
base, 16 fixture tooling additions and project settings give 591 guest packages.

## Acceptance and public proof

The distinct runtime status is
PASS_TERMINAL_EDITOR_CLIPBOARD_GENERIC_ARM_SMOKE. Source/event gates require
both phases' PID-owned native visible Alacritty windows, matching PTY/worker
parent identity, exact synthetic source-before/source-after bytes, real Vim Ex
command success, native AArch64 ELF and exact 42 stdout, and a separate-process
Unicode wl-copy/wl-paste result. A transcript is printed in the terminal and
retained with the bounded command/file/result proofs. Worker and terminal must
exit 0 after the owned release marker; compositor exit 0 and configuration
preservation are required. Clipboard/readiness cleanup retains original errors.

Only the explicit 128MiB-capped public evidence directory is uploaded. It contains
source proof, bounded builder/runtime/configuration diagnostics, embedded worker
file/result/transcript events, and both byte-identical 1024x768 QMP PPMs. It excludes
input caches, context/, runtime home, fixture disk, compiled executable and
package archives. Caller checks frame length/hash joins, all 14 VM cleanup
records and final original-image/probe absence through the same token. The
intermediate runtime base_image_present true is allowed while the original
owner's tag remains; final builder cleanup must prove absence.

Metadata success is PASS_NATIVE_METADATA_PIXELS_PENDING_VISUAL_REVIEW. Root must
independently read the terminal title, source, native 42 output and clipboard
PASS/Unicode line in both images. Geometry/visibility/transcript metadata alone
is not visual acceptance, particularly given the separate unresolved bar/reload
capture/opacity issue. This lane does not apply reload assistance.

The edit uses the shipped Vim in scripted Ex mode, not an interactive editor UI.
SUPER+RETURN→Alacritty is pinned as source; physical key invocation is NOT_RUN.
Thunar GUI and managed user-session implementation are UNSELECTED_NOT_RUN;
Asahi boot/graphics/audio, M2/16K hardware, battery and performance are NOT_RUN.
The kernel/boot stack and all accepted 574/591 evidence remain unchanged.

## Actual local checks

20 new workflow controls pass, including guarded entry, exact edit/output/Unicode
mismatch refusals, wrong ELF refusal, PTY/parent joins, visible-window lifecycle,
release/clean exit, config preservation and primary timeout/error preservation.
11 caller controls and 13 inherited runtime controls pass. Private libalpm metadata
resolution gives 103 packages/334 edges, no additions/replacements or unsatisfied
relations/conflicts. Candidate Python and Bash syntax pass; nine workflow shell
blocks, proof-before-secrets/order/digest anchors and 43-source/11-derived staged
layout pass. Full YAML parser/actionlint remain NOT_RUN_UNAVAILABLE, as in the
previous caller preparation. No actual terminal/editor/compiler/clipboard/VM
execution or frame was produced here. See ../VALIDATION.json.
