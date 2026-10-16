# Single manual ARM CI caller

Source-ready proposal only. No Git, dispatch, build/VM/package/service actors or
additional peers were used. All new files are confined to this ci/ directory;
the completed slice and runner still match their original delivery manifest.

## Adoption

Use `adoption.json` for exact source→canonical-target paths, sizes and hashes.
Copy the eleven selected original lane files unchanged into
`scripts/ci/desktop-bar-notifications/`: the eight Python/data files listed in
the map, pinned Mako wayland.c required by the regression control, and two exact
package MIT notices. Copy caller.py, test_caller.py, source-manifest.json and this
handoff into that directory's ci/. Adopt the proposed workflow at
`.github/workflows/native-arm-desktop-bar-notifications.yml`.
Do not copy the broader artifact tree or pre-generated runner.

The source manifest pins 43 files: 27 accepted slice dependencies, three existing
builder/seed/test dependencies, eleven selected lane files and two caller files.
It separately pins all nine expected generated-runner files. Existing accepted
shared sources are prerequisites, not proposed modifications. The source and
manifest/caller hashes are already embedded in the workflow; there are no ref
placeholders. Root's final commit must contain the exact mapped bytes.

Dispatch just this manual workflow with source_sha set to its final 40-character
commit. It requires source_sha == GITHUB_SHA == GITHUB_WORKFLOW_SHA and a native
Linux ARM64 runner. Source proofs precede all secret exposure. The workflow has
no push trigger, contents:read permissions, pinned actions and the existing
native-arm-build concurrency group with cancellation disabled. Job limit: 90 minutes.
It does not couple the independent user-session work.

## Reused builder and input route

The accepted workflow is retained at the manifest's held_workflow path/hash;
Root's successful canonical actual 38856669542 used the same workflow and public
seed revision 04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd. This proposal preserves its
six-file existing-secret seed environment and fourteen-file public seed. It
adds exact seed.py/index.json hash checks. No new secrets or input source are
requested. Public seed bytes are never included in evidence upload.

The workflow runs current hosted controls, the 44 accepted guest controls,
18 slice controls and 10 caller controls; it generates the separate runner with
the unchanged prepare.py, proves all nine output hashes, then runs its 13 runtime
controls and Bash syntax check. Local sibling-import programs use python3 -B;
standalone CI/accepted-helper programs retain -I -B. No host libalpm check is
required; the runner checks its exact 262-package client closure against 574.

Native execution uses the accepted maintained 574 builder and its existing
--job-token ownership API. The token is derived from run/attempt/source identity.
The exact 574 installed lock and same-job image feed the new runner. Native
build timeout 2300 seconds; runtime 2050 seconds, both with bounded termination grace. Its
acceptance status remains PASS_BAR_NOTIFICATION_GENERIC_ARM_SMOKE.

The final always cleanup calls the unchanged builder cleanup API after every
consumer, then retention verifies original image/probe absence. If the build
state is partial or uncertain, cleanup refuses and the job fails honestly.
Unlike the earlier untagged trial, runtime's base_image_present may be true
while the original owner's tag remains; final builder cleanup must still prove
it absent. The caller gate checks that final result and all 14 runtime cleanup
records, guest-disk removal and owned alias retirement.

## Evidence

Only a fresh directory capped at 128 MiB public evidence directory is uploaded, always after
retention. Explicit files include source proof, bounded builder/runtime reports,
guest/event logs, selected ordinary build/config logs, configuration diagnostics,
and both byte-identical QMP PPMs. No context/, input cache, runtime home, fixture
tree, disk or package archive is copied. Each file has a cap and SHA256; both
PPMs require 1024x768 geometry, exact byte length and agreement with runtime.json.

Successful metadata is labeled
PASS_NATIVE_METADATA_PIXELS_PENDING_VISUAL_REVIEW. Root must inspect both actual
frames for the visible bar and expected notification. Missing frames, old 591
status, hash/identity mismatch or incomplete cleanup retains available bounded
diagnostics and exits unsuccessfully. Hardware, battery, audio and visual
acceptance remain NOT_RUN until appropriate independent evidence exists.

## Verification

10 inert caller controls pass (0.146s), including synthetic PPM byte retention,
partial failure retention, caps, source/workflow identity, source drift,
cleanup/absence gates and old-result refusal. An inert staged canonical layout
proved all 43 source files and reproduced all nine exact runner files. All nine
workflow run blocks pass bash -n; manual trigger, proof-before-secrets,
cleanup/retention ordering and embedded hashes were checked. Full YAML parser
and actionlint were unavailable locally; their checks are NOT_RUN. No actual CI
or ARM execution was performed. See checks.json.

The completed slice's 18 controls / 13 runtime controls and its prior metadata
validation are unchanged. These source checks do not expand accepted 574/591
runtime evidence into new Waybar/Mako execution or whole-session acceptance.
