# Selected desktop application integration

`scripts/workflows/desktop_applications.py` checks selected `.desktop` entries in
an explicitly supplied staged filesystem. It reads metadata and executable bytes;
it never launches an application, sources configuration, invokes a shell, installs
packages or accesses the active session. Its JSON report gives logical paths,
resolved staged paths, symlink targets, SHA256/byte pins and concrete findings.
This is an M6 integration component, not a completed selected-application workflow.

## Run an audit

Use a quiescent staged root whose ancestry you trust. `/` is refused. Every path
inside the environment below is a **logical path within that root**, including
absolute symlink targets. The audit does not inherit the host's PATH, HOME, XDG
settings or locale. Save an explicit JSON environment, for example:

```json
{
  "HOME": "/home/audit",
  "XDG_DATA_HOME": "/home/audit/.local/share",
  "XDG_DATA_DIRS": "/usr/local/share:/usr/share",
  "XDG_CONFIG_HOME": "/home/audit/.config",
  "XDG_CONFIG_DIRS": "/etc/xdg",
  "XDG_CURRENT_DESKTOP": "Hyprland",
  "PATH": "/usr/local/bin:/usr/bin",
  "locale": "C",
  "icon_theme": "hicolor",
  "icon_size": 48,
  "icon_scale": 1,
  "terminal_argv": ["alacritty", "-e"]
}
```

After adoption into the canonical paths, run from the repository root:

```bash
/usr/bin/python3 -B scripts/workflows/desktop_applications.py \
  --root /absolute/staged-root --environment /absolute/audit-environment.json \
  --select Alacritty.desktop --select vim.desktop --select thunar.desktop \
  --mime text/plain --mime inode/directory > /absolute/desktop-audit.json
/usr/bin/python3 -B -m unittest discover -s scripts/workflows -p test_desktop_applications.py
```

Repeat `--select` for desktop IDs from the declared inventory. `--mime` requires
an available explicit default for that exact MIME type; selected entries' declared
types are inspected without automatically requiring defaults for every type.

| Exit | Report status | Meaning |
| ---: | --- | --- |
| 0 | `PASS_STAGED_CHECKS` | No error among the implemented static checks; inspect warnings and limits. |
| 1 | `FAIL_STAGED_CHECKS` | A selected entry or required integration has a concrete fault. |
| 2 | `REFUSED` | Input or staged metadata cannot be safely interpreted within the audit's supported bounds. |

CLI argument errors also exit 2 through argparse. Retain the report together with
the source revision, staged package/archive pins and environment input pin. A
partial three-package stage can legitimately fail because it omits the ELF loader,
theme indexes or configured defaults; do not add host files to disguise omissions.

## What is checked

Desktop IDs follow XDG data-directory precedence: user data first, then each
system data directory in order. Nested filenames map `/` to `-`; ambiguous IDs
within one data directory are refused. The chosen entry records its origin and
shadowed paths. `Hidden=true` is a tombstone that suppresses lower-precedence
copies. `NoDisplay=true` is reported as a handler excluded from menus, not as
uninstalled. `OnlyShowIn` and `NotShowIn` are checked against the declared desktop
names; incompatible predicates or booleans are reported. Main `[Desktop Entry]`
fields are kept separate from desktop action groups.

`Exec` uses the desktop-entry string and command quoting layers, rather than shell
parsing or expansion. The report records no-file-input argv, `%c`, `%i`, `%k`,
literal percent and recognized file/deprecated field codes. Unknown field codes,
unterminated quotes, repeated file placeholders and undefined quoted field-code
uses are refused. `TryExec` and the executable in `Exec` resolve only against the
staged PATH or an absolute staged path. ELF `PT_INTERP`, direct shebang interpreters
and supported `env` interpreter targets are checked recursively. Missing binaries,
missing interpreters and missing executable mode bits remain faults. Mode bits
do not establish credential access, mount `noexec` behavior, shared-library
resolution or successful execution.

`Terminal=true` checks the explicit `terminal_argv` executable and its interpreter
chain. An empty array means unconfigured. The arguments describe the caller's
chosen terminal launch prefix; the checker does not infer a universal terminal
command from the desktop-entry standard or prove that a particular terminal
supports the supplied arguments. D-Bus activation is explicitly unverified; an
available `Exec` fallback does not establish D-Bus launch behavior. Arbitrary
interpreter arguments and shell `-c` payloads do not receive execution acceptance.

Icon selection uses the declared theme, size and scale, theme indexes and
inheritance, hicolor fallback, then unthemed/pixmaps paths. The first theme with a
matching icon wins; size distance chooses within that theme. User icon locations
precede system locations. Absolute icon paths remain inside the staged namespace.
SVG support is assumed for selection; finding bytes is not image decoding or
readable-icon UI evidence.

MIME inspection reads desktop-specific and generic `mimeapps.list` files in XDG
precedence order. It reports default/add/remove references, missing or hidden
handlers, applicable association overrides and the first available explicit
`Exec` fallback. Lower-precedence system association edits do not override a
higher-precedence user desktop entry. `NoDisplay` handlers remain eligible.
Implicit application ranking, MIME subtype inheritance and D-Bus activation are
not inferred, so an unresolved required explicit default remains visible.

## Existing workflow boundaries

The existing
`scripts/ci/desktop-file-manager-workflow/package-inputs.json` pins the Thunar,
GIO/GLib, xfconf and Python inventory. That workflow's private text/plain handler
is a receipt probe, not editor UI. The inventory in
`scripts/ci/desktop-terminal-workflow/package-inputs.json` pins Alacritty, Vim,
GCC and wl-clipboard. Its owned terminal is launched directly with private
configuration; that does not exercise desktop-entry routing. Reuse those inventory
pins as inputs without treating their workflow contracts or previous evidence as
an actual result from this audit.

Native ARM execution, Wayland services, mapped/readable windows, physical input,
both M2 Air sizes, performance, package lifecycle and release acceptance need
their own exact-input results. This checker does not grant any of those results.
`scripts/hardware/session_probe.py` separately observes declared current-session
services with bounded fixed commands and keeps physical checks unverified. This
checker does not call that probe or inherit observations from the active desktop.

Reads use root-relative directory descriptors and interpret symlink targets in
the staged namespace. Literal `/` and filesystem aliases of the active host root
are refused. Application traversal does not follow directory symlinks. Limits
include 10,000 application-directory entries, 128 selected IDs, 512 MIME types,
32 paths per environment list, 32 inherited icon themes, 1,024 directories per
theme, 100,000 staged open attempts and 512 MiB of total file reads. Individual
metadata reads cap at 256 KiB and executable reads at 64 MiB. Budget exhaustion
is a refusal or a concrete selected-entry error, never a passing omission.

## Format references

- [Desktop Entry command quoting and field codes](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html)
- [Desktop Entry value types and escaping](https://specifications.freedesktop.org/desktop-entry/latest/value-types.html)
- [Icon Theme selection](https://specifications.freedesktop.org/icon-theme/latest/)
- [MIME application file precedence](https://specifications.freedesktop.org/mime-apps/latest/file.html)
- [MIME associations](https://specifications.freedesktop.org/mime-apps/latest/associations.html)
- [MIME defaults](https://specifications.freedesktop.org/mime-apps/latest/default.html)
