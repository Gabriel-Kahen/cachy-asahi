# Setup tooling workstream

October 11, 2026. Assigned portable runtime helper implemented and tested. This is a user configuration tool, separate from research/build scripts. No helper invocation used the real user home, installed packages/services or launched a compositor. Actual Asahi lifecycle/onboarding and M2 results remain **NOT RUN**.

## Frozen source interface for coordinator/package worker

**Canonical, self-contained entry:** `scripts/setup/setup.py`.

**Source frozen after validation:** SHA-256 `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`.

Python 3.11+ stdlib only; MIT/SPDX header, executable shebang. Package as `/usr/bin/cachy-asahi-setup` with no import-module payload. Default trusted template root `/usr/share/cachy-asahi`; fixed template leaves `fish/config.fish`, `zsh/config.zsh`, `hyprland/hyprland.lua`. Packaging worker owns `packages/settings/cachy-asahi-setup`; this worker did not edit it or any recipe. The package worker must compare its local copy byte-for-byte with this canonical source and pin its checksum, including root LICENSE/notice as appropriate. No post-install hook should automatically activate it.

Command interface:

- `cachy-asahi-setup activate --components fish zsh hyprland` previews; add `--apply` to execute.
- `cachy-asahi-setup remove [--components ...]` previews; add `--apply` to execute.
- `cachy-asahi-setup recover [--apply]` inspects/resumes an interrupted transaction.
- Explicit fixtures: `--home`, `--template-root`; optional within-home `--config-home`, `--zdotdir`, `--state-dir`.
- Exit 0 completed, exit 2 preserved conflict/pending preview, exit 1 invalid/unsafe/unavailable path or unresolved interrupted edits. JSON output never includes user config contents.

## Behavior and ownership

Guarded, canonical source blocks are appended after existing Fish/Zsh config; repeated setup is idempotent and removal changes only an exact tracked block. Existing configuration bytes/permissions/group/xattrs and unrelated later edits survive. Existing empty files remain. Edited owned blocks remain with visible conflicts. Templates missing after package removal leave harmless guards. No login-shell switch or prompt/history/system policy is introduced.

Hyprland uses only the separate `CONFIG_HOME/cachy-asahi/hyprland.lua`. Preexisting untracked copies are never adopted; unchanged tool-owned copies can be explicitly refreshed on template upgrade or removed, while edited copies survive. Base Hyprland rc/session files remain unchanged. Guidance preserves the validated base launcher/UWSM and conditionally shows standalone `start-hyprland -- --config`; no wrapper/compositor/session command executes.

Private journal records known deltas and hashes without persisting user config or template contents. Atomic no-clobber/new-file and fsynced replacement/deletion operations, final state commit, idempotent replay and nonblocking per-user lock cover interrupted/repeated execution. Unknown state paths/canonical blocks, symlinks, hardlinks, special files, permissions, external roots and stale templates are rejected. Recovery preserves edits that differ from both planned endpoints and requires reconciliation rather than overwriting them. This safe refusal is an explicit limitation, not a completed removal.

## Actual validation

`python3 -m unittest discover -s scripts/setup -v`: **40 passed** on existing x86_64 development host. Only temporary user/template fixtures were mutated. Coverage:

- Preview writes nothing; explicit component selection; fresh/repeated setup, removal/reinstall and existing empty/nonempty config.
- Byte/permission/xattr preservation; unrelated additions before/after shell blocks; no-newline boundary handling; edited owned files/blocks preserved; untracked identical desktop copy not adopted.
- Template upgrade updates only unchanged owned desktop copies; removal remains usable after packages disappear.
- Interruption before first config write, after first write, during removal and after state commit; repeated replay without duplicate blocks; user edit/stale-template refusal; preparation failure before any new config write; parallel apply rejection.
- Base desktop rc unchanged; mocked process execution forbidden in helper; no secret text in journals/state/reports.
- File/directory/template/state symlink attacks, hardlinks/FIFO/unsafe permissions, root/path escape and tampered state/journal target/block rejection.
- Actual installed Fish and Zsh accepted quoted paths and their guarded blocks, executed only trusted fixtures in temporary HOME/XDG/ZDOTDIR directories, and produced no activation output when fixture templates disappeared.

`python3 -m py_compile scripts/setup/setup.py scripts/setup/test_setup.py`: passed. The static CI workflow now runs the setup suite; GitHub-hosted execution is NOT RUN. Original build/check ownership was not reused for this task: changes are only `scripts/setup/**`, `docs/setup-tooling.md`, this report, and the existing `.github/workflows/static.yml` as authorized.

## Remaining gates / operational limits

- Packaging worker supplies the independently reviewed recipe/local-copy sync check and package artifact results; coordinator reconciles its manifest selection. No native ARM build/install is inferred from these fixture tests.
- Actual supported-base package install → setup → upgrade → remove → reinstall, fresh/existing users, interrupt/recovery and guide-following exercise on both M2 Air sizes remain pending.
- Validate the exact base Hyprland/launcher/UWSM contract and graphics/audio platform preservation on target; runtime guidance and untouched base rc are not hardware evidence.
- Apply only while independent editors are idle; cooperative helper locking does not create filesystem compare-and-swap with unrelated processes. Actual SIGKILL/power-loss/temp-file and filesystem durability behavior require target tests. Unknown private leftover temp files are not auto-deleted.
- External XDG roots, symlink-managed dotfiles, user edits after an interrupted transaction and missing/changed unapplied desktop source are fail-closed/manual-reconciliation cases, documented in `docs/setup-tooling.md`.
- No state/secret backups, signing, package-manager mutation, session registration, default shell changes, compositor launch or system policy changes are included.

## Independent-review correction and refreeze

The initial `c7d4b9...` source freeze is superseded. Root's fixture review reproduced S1 (a coherently edited pending shell journal retargeting its new guarded block to another template root) and S2 (a readable 2 MiB config receiving an oversized appended block, then becoming unmanageable by removal). Both are corrected in the canonical source; no cross-user compromise is inferred from these same-user malformed-state fixtures.

S1: Every new/changed Fish/Zsh record/block is bound to the transaction's approved/current template root, including coherent `new_record`, delta, hash and `new_state` changes. Unchanged carried records from a prior approved root must exactly match existing tracked state. A changed entry cannot reuse an older approval as its new source. Rejections happen before config writes; positive root-switch tests preserve untouched tracked components.

S2: Proposed byte length is checked during planning, across prepared pending deltas before any replay writes, and in the atomic writer before directory creation. The helper cannot create a config/state/journal beyond its own 2 MiB read boundary. Exact-limit copied files and shell outputs remain removable; one-byte-over and at-limit-plus-block inputs, oversized later pending entries and direct writer calls fail safely.

Final local validation after these corrections: **40 setup tests passed**, Python compilation passed. Source refrozen at `a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2`. All tests used temporary fixtures; no real HOME/package/session/hardware execution. Package owner/coordinator must refresh the packaged local copy, PKGBUILD source checksum and recipe lock from this new canonical hash; this worker did not modify their files. Root review report remains reviewer-owned.
