# cachy-asahi session diagnostics 0.1.0-3

Small opt-in MIT package for the corrected read-only session probe. Run as the
ordinary user inside the affected session:

```sh
cachy-asahi-session-diagnostics --help
cachy-asahi-session-diagnostics
```

JSON goes to stdout. The original probe writes no report itself; use a private
new output file when retaining it. It never changes volume, brightness, services,
inhibitors, lock state or suspend state. Exit 0 means collection completed,
including unknown/unavailable results; it does not mean healthy or hardware
validated. Exit 2 also covers a missing/changed private runtime. All physical
checks remain NOT RUN and speaker protection remains NOT TESTED.

See the installed `session-probe.md` for observations, privacy, fixed query
bounds, exact model/source/baseline options and evidence limits. That byte-held
reference uses repository invocation paths; the installed invocation is the
command above. No checkout, repository root, adjacent project modules, user
PYTHONPATH or copied repository is required. The launcher verifies the exact
private module SHA256 and starts `/usr/bin/python -I -B`. Verification detects
observed corruption, not malicious same-user replacement races or package trust.

Only Python >=3.11 is required. Optional packages provide `hyprctl` (hyprland),
`eglinfo` (mesa-utils), `pw-dump` (pipewire), and `systemctl`, `loginctl`, `busctl`
(systemd). Absent tools/endpoints remain explicit. Optional dependencies are not
an installation plan or a reason to replace the working Asahi platform stack.

Release 0.1.0-3 fixes the socket test's assumption that checkout ancestors
are trusted. A test-only root descriptor anchors a real private `/run/user/UID`
fixture; descendant opens/stats remain real with unchanged ownership, mode,
symlink, hardlink and replacement checks. Production unsafe-ancestry rejection
and the runtime/launcher are byte-held. No Docker-specific writable path is required.

Earlier release 0.1.0-2 corrected child retirement: incompatible SIGCHLD policies skip
launch; default automatic-reaping flags are normalized in this process; group
signals require a verified unreaped leader; ECHILD/lost ownership stays unknown
without fabricated exit0 or further group signals. See `session-probe.md` for
the standalone single-thread policy and unverified-retirement limitation.

The seven owned regular files are:

- `/usr/bin/cachy-asahi-session-diagnostics` (0755)
- `/usr/lib/cachy-asahi-session-diagnostics/session_probe.py` (0644)
- `/usr/share/doc/cachy-asahi-session-diagnostics/README.md` (0644)
- `/usr/share/doc/cachy-asahi-session-diagnostics/session-probe.md` (0644)
- `/usr/share/doc/cachy-asahi-session-diagnostics/source-provenance.json` (0644)
- `/usr/share/licenses/cachy-asahi-session-diagnostics/NOTICE` (0644)
- `/usr/share/licenses/cachy-asahi-session-diagnostics/LICENSE` (0644)

Directories are 0755. Removal removes these package-owned files; user-captured
reports stay where the user put them. No hooks, services, autostarts, global/user
configuration, caches, package trust or platform files are installed or changed.
This is a development recipe with `arch=any`; that declaration is not a native
ARM build or M2 compatibility result. Review before integrating or installing.

```sh
python -B -Werror::ResourceWarning test_session_probe.py
python -B -Werror::ResourceWarning test_package.py
python -B check_package.py --recipe-root .
```

All 35 probe controls remain, including the ten byte-held ownership regressions;
the socket fixture is the sole revised probe test body. The original seven
package controls remain byte-identical. Package controls stage only into
private temporary directories, verify the exact payload/modes, test tamper refusal
and invoke the staged CLI from an unrelated cwd without collecting diagnostics.
An archive-derived headless/live invocation is separate host evidence; no target
installation, ALPM lifecycle, physical M2 or release result follows.
