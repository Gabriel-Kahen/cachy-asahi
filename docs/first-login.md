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
serializes its own writes; the preview is not a lock against other writers.

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

Use the exact printed commands when they include path options. Recovery replays
the original setup transaction, including its original selected components; it
does not activate a new selection. Edited files, unsafe state and unreadable
journals block recovery. A migration-owned journal is referred to
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

This tool neither partitions disks nor changes accounts, login shells, packages,
repositories, boot configuration, services or session registration. It does not
establish M2 support or the macOS-to-desktop M8 gate. Complete target installation,
real graphical login, native ARM delivery and both M2 Air journeys remain NOT RUN
for this new tool.

## Development and delivery

The opt-in package lives at `packages/tools/cachy-asahi-first-login`. It requires
Python 3.11 or newer and `cachy-asahi-setup>=0.3.0` with schema-1 status
support (Setup8). Fish, Zsh, Hyprland and their matching project templates are optional
component prerequisites. The standalone implementation has no repository imports.
The installed entry point runs isolated Python and loads its own installed
implementation; it does not depend on the checkout or current working directory.
The corrected 0.1.0-3 candidate also keeps that isolation across the helper and
printed follow-up boundaries: helpers run from `/` with fixed system PATH and
locale, user-site imports disabled and Python safe-path enabled. Ambient
PYTHONPATH/PYTHONHOME and interpreter PATH entries are not forwarded. Effective
HOME/XDG/ZDOTDIR/state roots are captured before this cleanup and passed as
explicit arguments. Printed Python follow-ups include `-I -B`; copy them intact.
An alternate development helper must be a self-contained executable, not rely
on inherited Python imports or the caller's working directory.

From a checkout with the setup package already installed:

```sh
python3 -I scripts/install/first_login.py inspect
```

An explicit absolute `--setup-helper` selects another reviewed executable for
development fixtures. Template discovery is an observation of setup's installed
inputs; it is not an independent package authenticity check.

The new unselected `packages/tools/cachy-asahi-first-login-v3` recipe packages
exactly the maintained code as `0.1.0-3`. The retained `cachy-asahi-first-login`
directory, original `0.1.0-2` archive/provenance, UI02's exact02 dependency and
all frozen fixtures are unchanged. The old four-recipe host rehearsal still
selects retained02 and verifies its local pins; it does not qualify this changed
maintained CLI. The new candidate's checker separately verifies its canonical
source/docs/tests. Rebuild retained02 from its self-contained source copy or
historical tree rather than asserting correspondence with today's maintained
code. Native builds, signed/integrated lifecycle, M2 and release remain open.
