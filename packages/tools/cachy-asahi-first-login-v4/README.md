# First user configuration after package installation

The development first-login tool discovers the installed Fish, Zsh and Hyprland
configuration templates and programs, then previews or applies the selected
configuration using `cachy-asahi-setup`. Run it as the intended ordinary user,
without sudo, after the separately reviewed package transaction. It is opt-in;
package installation does not run it.

```sh
cachy-asahi-first-login inspect
cachy-asahi-first-login activate --components fish zsh
cachy-asahi-first-login activate --components fish zsh --apply
```

`inspect` reports available components and the setup helper's ownership/drift
observations. Choose only the components you want. `activate` previews without
writing; `--apply` first repeats that preview and then delegates the actual
configuration change. A missing selected template/program or a preview conflict
blocks the entire selection before the apply call. Setup rechecks ownership and
checks under its apply lock that no journal is pending before starting the
selected changes. If a journal appears after preview, inspect again.

Hyprland is an explicit additional component. Activation creates its separate
user copy; it does not select or launch a session. Validate the configuration and
use the retained, tested base session launcher. Keep the prior session available.
Fresh shells load activated shell settings; running shells retain their state.

If setup has an interrupted transaction, first login reports `recovery-required`
and prints commands for its original configuration roots:

```sh
cachy-asahi-first-login recover
cachy-asahi-first-login recover --apply
```

Use the exact printed commands to keep the original paths and journal ID.
Recovery replays the reviewed transaction with its original components. If
the journal changes, inspect again. Edited or unsafe targets in the journal,
unsafe templates used by them, unsafe ownership state and unreadable journals
block recovery. An unrelated
component can still report an issue while the reviewed transaction is
recoverable. A migration-owned journal is referred to
`cachy-asahi-config-migrate` with its original manifest; setup recovery cannot
resume that operation. Keep the journal and user edits when recovery is blocked.

`HOME`, `XDG_CONFIG_HOME`, `ZDOTDIR` and `XDG_STATE_HOME` follow setup's normal
semantics. Effective paths are captured as explicit options in follow-up commands,
so recovery from another shell uses the same roots. Explicit `--home` ignores
inherited XDG/ZDOTDIR settings unless corresponding options are also supplied.
`--config-home`, `--zdotdir`, `--state-dir` and `--template-root` are forwarded to
setup; it enforces their ownership and path constraints. `--state-dir` denotes
the setup directory itself, not the parent XDG state directory.

The tool emits JSON. Exit `0` means the requested inspection/preview/apply
completed, `2` means attention or explicit recovery is required, and `1` means
missing prerequisites, unsafe state or incompatible helper output. These codes
and component availability describe user configuration, not package signatures,
a working graphical session or installation acceptance. Use the setup helper's
existing `remove` command with the same roots for configuration deactivation.

## Development and delivery

This opt-in 0.1.0-4 recipe requires Python 3.11 or newer and
`cachy-asahi-setup>=0.3.1-2`, the first Setup version with the journal guard.
Fish, Zsh, Hyprland and their matching templates are optional. The installed
entry point runs isolated Python. Helper calls use a fixed system PATH and
locale and explicit configuration roots. Printed follow-ups include `-I -B`.

For source checks with a reviewed Setup helper, use an absolute path:

```sh
python3 -I -B packages/tools/cachy-asahi-first-login-v4/first_login.py inspect \
  --setup-helper /absolute/path/to/cachy-asahi-setup
```

To build a package archive, run `makepkg --cleanbuild --nosign` with the new
Setup dependency installed and Zsh available for checks. The check-only Setup
fixture matches the new Setup recipe's prepared executable. The repository's
`scripts/install/first_login_journal_guard/test_journal_guard.py` exercises both
recipes' temporary staged payloads together.

Package archive build, native AArch64 builds, ALPM installation and upgrade,
graphical first login, and physical M2 qualification are **NOT RUN** for
0.1.0-4. This CLI candidate has no release admission.
