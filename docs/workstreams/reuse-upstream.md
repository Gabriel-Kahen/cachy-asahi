# ARM reuse and upstream return workstream

October 11, 2026. Status: **source-audited documentation and independently reproduced x86 verifier evidence; external submission and real other-ARM execution NOT RUN**. A10 remains incomplete. Ownership is limited to `docs/upstream/`, `docs/arm-reuse.md`, and this report. No implementation, manifest, Git state or another worker's files were edited. No packages were installed, session launched, service/configuration changed, target contacted, or upstream message sent.

## Concrete results

- [Upstream report draft](../upstream/hyprland-config-draft.md): pinned current PKGBUILD, settings tag/commit/archive/checksums, matching four config-file hashes, exact Hyprland version/API reference, five-line reduction, expected/actual diagnostics, full-bundle import rewrite disclosure and bounded Lua correction.
- [Routing/history record](../upstream/history.md) and `history-observation.json`: read-only primary upstream issue/PR/release/tag research, complete scoped query observations and actual states. The settings repository is archived. **Open PKGBUILDS PR #1972 already removes the legacy settings recipe**, so no duplicate issue is recommended. Its head is `185c9cd1f6d50291f513312224b881a60ddf526b`; `merged_at` is null. Root should refresh its status/comments before deciding whether new supporting evidence is useful.
- [Existing-PR evidence draft](../upstream/pr-1972-evidence-draft.md): short original result summary for possible coordinator-reviewed submission. It is NOT POSTED. Discovering existing external work does not count as this project submitting a useful report.
- [Other-ARM procedure](../arm-reuse.md): meaningful execution of the existing read-only package inspector on another native ARM target, either an identified physical board or provider-identified native hosted ARM VM. Exact component/archive/license/assembly-record hashes, preinstalled prerequisites, transfer preparation, target commands, board/provider/job evidence, actual x86 reference result and review/repeat criteria are documented. No desktop installation or native build is required or implied by this bounded component demonstration.

## Actual evidence

Primary upstream recipe/assets were re-downloaded to memory/temporary storage and checked against the desktop audit. Recipe SHA-256: `efb477c4f2ba94d8681e9555ee0507ce2fe60e156ac85b437dcf90dfe3ab4bff`. Settings archive SHA-256: `6329177a462392ae018e81572359aaf4c530e4ff4136ef6f170ab33eb043893b`; SHA-512 matches the pinned recipe. Four raw commit-addressed config files match the archive/inventory hashes. Third-party asset copies were temporary and are not shipped in project packages; root MIT does not relicense upstream assets.

Host was x86_64, existing Hyprland v0.56.2 at clean commit `efb50993780079460b0cbed1363e2166a2de1d9f`. Actual read-only verifier commands:

| Input | Command | Result |
| --- | --- | --- |
| Full pinned Hyprland subtree, only active import paths rewritten | `Hyprland --verify-config --config TEMP_REPRO/hypr/hyprland.conf` | Exit 1, including keybinds:17, variables:63 and windowrules:8 |
| Five-line no-import legacy reduction | `Hyprland --verify-config --config TEMP_REPRO/minimal.conf` | Exit 1, removed pseudotile/unknown dispatcher/invalid float field |
| Bounded three-line Lua correction using actual global `hl` API | `Hyprland --verify-config --config TEMP_REPRO/bounded-correction.lua` | Exit 0, `config ok` |

Sanitized logs and input/output hashes are under `docs/upstream/`; `reproduction-observation.json` includes host/library versions, commands, original/rewrite hashes and source-path changes. This task also retains two rejected draft API attempts transparently: importing `hyprland` as a Lua module failed; treating `hl.dsp.layout` as a table failed. The accepted illustration uses the pinned example's function form and is not a complete migrated profile or runtime-tested patch.

The reuse documentation subagent inspected the frozen original Fish configuration archive on the existing **x86** host: static inspector exit 0, 12 members, no errors/ELF. That reference helps compare a future target result; it is not actual ARM reuse. No implementation tests were needed for these documentation-only changes. Embedded command syntax, local links, JSON and recorded hash consistency were checked. An independent read-only peer review confirmed live PR routing/status, all retained log hashes, frozen inspector/archive inputs and independently fetched recipe/archive/API/config-file hashes; no concrete defect remained. That reviewer did not rerun Hyprland or execute on ARM. No submission command was run.

## Remaining gates and coordinator actions

| Required outcome | Actual status | Next action |
| --- | --- | --- |
| Useful upstream report/fix actually returned | NOT SUBMITTED | Review drafts and existing #1972 status/comments; determine useful nonduplicate return and obtain submission authorization, then record exact submitted URL/result |
| Maintainer acceptance/merge | EXTERNAL / NOT CLAIMED | Track actual response separately; open removal PR is not a merged fix |
| Other-native-ARM access and prerequisites | NOT RUN | Pi SSH inventory timed out; restore board access or review the CI worker's hosted ARM VM route and inventory its actual job/prerequisites |
| Component execution/review on other native ARM | NOT RUN | Fish archive retained under `artifacts/reuse/`; freeze source/job inputs, execute on identified board or native ARM VM and collect/review actual evidence |
| Full A10 signoff | INCOMPLETE | Coordinator links actual reuse and upstream-return evidence; drafts/x86/emulation do not replace either requirement |

An evidenced native ARM inspector run, whether on a physical board or a hosted ARM VM, supplies one narrow reuse result, not native package builds, a supported ARM desktop, M2 compatibility or performance gains. User onboarding, both Air sizes and all other full-goal gates remain owned by their separate tracks. Shared roadmap/acceptance/manifests are unchanged by this documentation task.

## Retained artifact and hosted-VM clarification

Coordinator retained the exact Fish archive at `artifacts/reuse/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.zst`. Follow-up rehash confirmed SHA-256 `05489a9fdbea83423220cc257525dea83a6d3a2ccbab5155dd64a6c68a3678c8`; read-only x86 inspection at that retained path passed again with 12 members/no ELF/no errors and unchanged stdout SHA-256 `f2691de56f9b4a361a37f125cf7dc0701ac1c2dc7abecb44c3689ef63eba0ce0`. The runbook now uses this retained path throughout. It remains ignored local storage, not an artifact available automatically through CI checkout or an invented public download.

Added a clearly marked **NOT RUN** `ubuntu-24.04-arm` hosted-VM alternative, supported by primary GitHub runner documentation and native-ARM availability references. The existing CI worker owns workflow/provider eligibility audit; coordinator owns execution/input transport. The procedure records actual job/setup logs, source/workflow/action revisions, inputs, provider/VM/image context and runtime observations; a runner label or ARM image alone cannot earn native execution. No blanket physical-board prerequisite remains for this software-only reuse gate. A physical board still supplies its own identity/attestation, and all physical Mac/hardware gates remain separate. A second actual run is useful repeatability evidence, not an invented requirement that prevents one reviewed native VM execution from demonstrating component reuse. No hosted job was dispatched by this task.
