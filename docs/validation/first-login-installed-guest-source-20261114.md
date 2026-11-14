# Installed first-login guest callable: source and local validation

November 14, 2026. **Source implementation and local extracted-payload checks
PASS. Native actor execution remains NOT RUN.** This is a callback adapter for
the native constructor's already-held command runner. It creates no process
supervisor, package installer, network client or acceptance publisher.

The NEW `scripts/integration/first_login_installed_journey.py` exports:

```python
TEMPLATE_CONTENT  # exact selected Fish/Zsh package bytes
run(paths, home, run, uid, gid, label='first-login')
```

The callback contract, agreed with the native constructor owner, is
`run(step, argv, expected=0, cwd=Path) -> bytes`. It supplies combined stdout and
stderr and checks the exact expected exit code, including `2` and `75`. The
owner supplies command/global deadlines, output bounds, process cleanup, a fresh
ordinary-user home and final state cleanup. The helper never invokes subprocess
or another runner itself.

`paths` contains `first_login`, `setup`, `fish`, `zsh`, `python3`, `template_root`
and `template_sha256`. The hash mapping has exactly `fish/config.fish` and
`zsh/config.zsh`; contents must also match the exported actual selected templates.
Native defaults are account `alarm` and template owner UID `0`. Optional `user`,
`template_owner` and `workspace` support explicit local profiles; workspace
otherwise defaults to HOME. Source/template identities are measured before and
after the workflow and must remain unchanged.

The native actor creates/chowns a fresh `0700` HOME to the selected non-root
UID/GID. Template roots/files remain root-owned `0755`/`0644` and readable by that
user. All ancestor directories must permit user traversal. The helper checks
these properties but never chmods/chowns actor paths. Every command is explicitly
prefixed with `/usr/bin/runuser -u alarm -- /usr/bin/env -i` and private
HOME/XDG/ZDOTDIR values. A real user command confirms effective UID/GID before any
configuration operation. All user writes, including the workspace sentinel,
customizations and interrupted setup, happen through that callback as the user.
Root-side module access only validates or observes state.

The 27 ordered user calls preserve the existing shell journey's semantics:
inspect and preview leave the fresh HOME unchanged; actual first-login/Setup8
activation enables Fish `caa_ll`/`caa_mcd` and Zsh completion; repeat preserves
explicit user edits; removal leaves only those user settings; delivered Setup8
is stopped with `os._exit(75)` immediately after its first durable Fish write;
pending activation is refused; explicit recovery completes the real journal;
final deactivation restores the same user-only bytes. No installed source file
is changed for the process-death injection.

The ten actual shell startups are **scripted interactive commands without PTYs**.
The held native runner has no terminal/PTY interface; this adapter never invents
one or credits terminal-emulator/GUI usability. The existing 41-command host
journey included 17 archive-intake commands; installed native intake belongs to
the constructor. This callable adds explicit UID/GID proof and two user-write
commands, yielding 27 installed-workflow calls.

Successful metadata includes schema/status, ordered steps, selected executable
paths/hashes, template pins, user-owned final state, exact preserved user-edit
hashes, final deactivation and recovery observations, and explicit shell/PTY/
recovery scope. Every observed user-state node must be owned by the selected
UID/GID, regular or a directory, and non-writable by group/others. Aliases and
unexpected state are refused; observation is bounded to 512 nodes/8 MiB.
Failures retain partial metadata on `error.first_login_result` for the actor's
own failure report. The actor remains responsible for removing its user state.

## Actual local checks

```sh
python3 -B -Werror::ResourceWarning \
  scripts/integration/first_login_installed_journey_test.py \
  --inputs /absolute/reviewed-four-package-inputs.json \
  --inputs-sha256 REVIEWED_SELECTION_SHA256 -v
```

Three cases pass in 2.1 seconds with zero skips. The positive case consumes the
actual extracted first-login `0.1.0-2` and Setup8 payloads, actual selected Fish/
Zsh templates and host Fish/Zsh programs. It executes all 27 commands and ten
non-PTY shell startups, verifies genuine journal recovery and exact source,
template and user-edit preservation. Negative cases refuse changed templates,
root identity selection and a HOME alias before the first user command.

The local process already runs as an ordinary user. Its test callback verifies
the complete runuser/env prefix and executes the remaining command as that same
UID; it does **not** claim to exercise a privileged root-to-alarm switch. Local
templates explicitly use their actual ordinary owner in the supplied test
profile. Native root-owned fixture traversal, actual root-to-alarm switching,
installed/moved-prefix workflow execution and the constructor's held global
window remain for the native owner to execute. Reinstall smoke is a separate
scope and must not be credited as another full shell/recovery journey.

No frozen recipe, current v3 runtime, native constructor directory, shared
manifest, workflow or system configuration was changed by this adapter work.
Native ARM, M2, graphical login, physical interruption/recovery and release
acceptance remain unqualified by these local checks.
