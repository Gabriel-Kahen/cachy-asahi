# Per-user setup and removal tooling

The standalone stdlib helper is `scripts/setup/setup.py`. It is designed for packaging as `/usr/bin/cachy-asahi-setup`; source implementation and temporary-user lifecycle tests are complete, while native package builds, actual Asahi installation and exact-M2 onboarding remain **NOT RUN**. The separate package worker owns the setup recipe. This helper does not install/remove packages, select a login shell, register/launch a session, enable services, or change boot, graphics, audio or system policy.

## Preview, then explicitly apply

Run as the intended non-root user after the selected overlay packages are installed on an accepted base. All invocations preview by default. Select activation components explicitly:

```sh
cachy-asahi-setup activate --components fish zsh hyprland
cachy-asahi-setup activate --components fish zsh hyprland --apply
```

For the source checkout, substitute `python3 scripts/setup/setup.py` for `cachy-asahi-setup`. Selecting a component requires its trusted installed template; there is no download or dependency installation. Components can be activated independently. Preview reports the proposed relative paths and statuses, without writing configuration, state directories or locks, or printing existing configuration contents. Exit 0 means the requested preview/application completed; exit 2 reports preserved existing/edited conflicts or a pending transaction; exit 1 reports an unsafe/unavailable path or invalid operation/state. A conflict is never permission to overwrite the file.

### Fish and Zsh

Fish adds one identifiable interactive/readability-guarded source block to `${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish`, referencing `/usr/share/cachy-asahi/fish/config.fish`. Zsh adds one identifiable interactive/readability-guarded source block after existing initialization in `${ZDOTDIR:-$HOME}/.zshrc`, referencing `/usr/share/cachy-asahi/zsh/config.zsh`. Existing bytes outside the block remain user-owned. Existing permissions, group and extended attributes are retained, or the write fails safely. Existing empty files remain after removal.

Blocks are delimited with `# >>> cachy-asahi setup COMPONENT v1 >>>` and the matching `# <<< ... <<<` line. Repeated setup recognizes its own exact recorded block and adds nothing. An untracked existing marker/block is preserved and reported as a conflict, rather than adopted. An edited tracked block is also preserved. The scripts being sourced already preserve existing functions/completion/theme choices; setup supplies no extra prompt, history or alias policy. It does not choose the account's default shell.

The readability guards let shell startup continue after package templates disappear. Fresh shells pick up package template upgrades. Already-running shells retain functions/completion state until restarted; setup/removal does not execute a shell reset command.

### Optional packaged shell modules

Candidate0.1.0-5 also accepts the six explicit module component names listed in the [package guide](../packages/settings/cachy-asahi-setup/README.md). They enable none by default. Select only installed modules you want, preview, then apply with the same flags above. Setup adds guarded source blocks in deterministic shell order, preserving highlighting before substring search and every user-owned edit. Missing selected modules fail before configuration/state mutation. Module wrappers keep their own runtime, binding and notification policies.

New modules and shared-file journal groups require the new CLI for recovery/removal. Old setup3/4 state and single-entry journals remain supported; old CLIs safely refuse new ownership. Complete recovery/removal before downgrading. See [host validation](validation/setup-shell-modules-host-20261016.md) for tested scope; native setup5 installed upgrade/rollback/removal now passes; actual real-module/target workflows remain pending.

### Explicit Hyprland configuration

Activation copies `/usr/share/cachy-asahi/hyprland/hyprland.lua` to the separate `${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua`. It never creates or replaces the base's `hypr/hyprland.conf`, `hyprland.lua`, launcher configuration or UWSM contract. An existing untracked file at the separate destination is preserved even if its bytes happen to match the template.

After activation, run the configuration parser check separately:

```sh
Hyprland --verify-config --config "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua"
```

This is a parser check, not a compositor launch or hardware acceptance. Select the explicit config through the base's already validated session launcher, using that launcher's documented argument handling. Preserve UWSM on a UWSM-managed base. Only if the accepted base provides the upstream standalone wrapper and validates that route from a logged-out TTY, its forwarding form is:

```sh
start-hyprland -- --config "${XDG_CONFIG_HOME:-$HOME/.config}/cachy-asahi/hyprland.lua"
```

The helper outputs this conditional guidance but never executes it. Do not start another compositor inside an active graphical session. The coordinator must validate launcher/watchdog, portal, authorization-agent and graphics/audio integration before publishing a supported onboarding route.

After a package template upgrade, explicit repeated `activate --components hyprland --apply` updates the user copy only when it still matches the tool's last owned checksum. A user-edited copy is preserved. The tool does not activate that copied config or reload a running compositor automatically.

## Remove, preserve edits, reinstall

Switch back to the prior base session/configuration before removing the copied desktop config. Preview and apply deactivation:

```sh
cachy-asahi-setup remove
cachy-asahi-setup remove --apply
```

Without `--components`, removal considers all tracked components; specify components to limit it. It removes only an unchanged recorded block or unchanged tool-created desktop copy. User additions before/after a shell block remain. A separator is retained when necessary to prevent later user code being joined to an original unterminated line. A shell file created by setup is deleted only if removing the owned block leaves it empty. Existing files are kept even when they become empty. Unknown files, modified owned blocks and modified desktop copies are preserved, reported clearly, and their ownership records retained where relevant. Repeated removal is harmless; repeated activation/reinstall reconstructs only missing owned configuration and never adopts an untracked preexisting copy.

Deactivation works even after templates/packages have disappeared. This is separate from pacman package removal: the helper does not remove dependencies or touch `/usr/share`. The package lifecycle guide must keep both steps explicit. It never stops a running session or removes shell state already loaded in memory.

## State, interruption and recovery

Default private state is `${XDG_STATE_HOME:-$HOME/.local/state}/cachy-asahi/setup/`. `state.json` records known managed block text/source paths, copied-template checksums and ownership metadata. `journal.json` records a pending transaction's known deltas and before/after hashes. Existing user configuration text and copied template contents are **not** stored in the journal/state, backup files or output logs. No credential/configuration contents are printed on errors.

Before any config change, the helper fsyncs a private journal. It prepares every pending delta before new writes, writes/fsyncs a private sibling temporary file, rechecks the current target and atomically publishes each file. New targets use atomic no-clobber creation. It then fsyncs state and removes the journal. This is a recoverable sequence of atomic file operations, not an all-or-nothing multi-file filesystem transaction. A second apply fails while another helper holds its lock.

After an interruption, preview lists each recorded component and relative path as `would-add`, `would-update`, `would-remove` or `already-applied`. It runs the same read-only preparation and conflict checks used by replay, with no configuration, state or lock writes. A changed target or required template stops the preview with exit1 and retains the journal, so conflicts are visible before applying. Preview cannot reserve a file; apply repeats every check. Use the original home/config/ZDOTDIR/state/template-root options:

```sh
cachy-asahi-setup recover
cachy-asahi-setup recover --apply
```

An applied activation/removal also resumes a pending transaction before planning the new request. Already-completed deltas are not repeated, including an interruption after state commit. An unapplied desktop copy requires the same pinned template contents to remain available; a changed/missing template causes safe failure with the journal retained. If a selected file was edited after interruption and differs from both recorded endpoints, recovery preserves it, stops and retains the journal for reconciliation. Do not discard the journal or claim removal completed in this state. The user/maintainer must reconcile the edited path with the pending operation before retrying; automatic rollback does not overwrite user edits.

Only tool invocations cooperate with its lock. Keep unrelated editors idle while applying a change: filesystem rename cannot provide a portable atomic compare-and-swap against an independent editor. The helper compares content/identity immediately before replacement and stops on observed changes. OS kill/power loss during an individual temporary-file write may leave a private sibling `.cachy-asahi-*.tmp`; it never treats an unknown temp file as owned configuration or automatically deletes it. Temporary files contain the intended config and receive no permissions broader than the original; state/journal/lock are private. Actual abrupt-power-loss behavior and filesystem-specific durability still require target testing.

## Path and fixture contract

Home, selected template-root and every directory are opened component-by-component with `O_NOFOLLOW`; targets are opened relative to retained directory descriptors. Symlinks, escaping `..`, control-character paths, hardlinked/special config files, unsafe ownership, group/other writable files/directories and oversized/non-UTF-8 configs are rejected. Existing templates/configs and every proposed output are limited to 2 MiB. Activation preview, transaction planning, pending replay and the atomic writer all enforce the post-write limit; a readable file at the limit cannot receive an oversized appended block. Recovery binds every new/changed shell record and canonical guarded block to the transaction's approved template root; unchanged previously tracked records can retain their already approved root. State/journal must be mode 0600 and their storage directories are created mode 0700. No fallback follows a symlink or writes as root. Dotfile arrangements using symlinks need a separately reviewed workflow; this helper fails closed for them.

`XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `ZDOTDIR` must be within the selected home. External XDG locations are unsupported. Explicit `--config-home`, `--zdotdir` and `--state-dir` must also be absolute paths inside that home. State/config root options must match the original tracked state. For tests, `--home /absolute/temporary-user` ignores the caller's real XDG/ZDOTDIR environment; `--template-root /absolute/trusted-fixture-templates` overrides only the known three template paths. These overrides are explicit and never imply target validation.

Development tests:

```sh
python3 -m unittest discover -s scripts/setup -p 'test_*.py' -v
python3 -m py_compile scripts/setup/setup.py scripts/setup/test_setup.py
```

There are 40 passing temporary-user tests on the development host. Installed Fish/Zsh also parsed and executed generated guarded blocks with quoted fixture paths, and continued cleanly after fixture templates disappeared; all homes/XDG roots were temporary. If those interpreters or extended-attribute support are unavailable, the corresponding tests visibly skip and do not establish their integration result. Static CI includes this suite. Actual package install/upgrade/remove, both M2 Air sizes, base launcher/UWSM selection, real existing-user profiles, filesystem power-loss recovery and an independent complete onboarding exercise remain execution gates.
