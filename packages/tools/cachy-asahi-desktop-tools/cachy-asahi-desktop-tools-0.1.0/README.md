# cachy-asahi-desktop-tools 0.1.0

Original MIT development candidate. Offline Python standard-library command;
Python >=3.11 is the sole runtime dependency. Static source is held byte-for-byte
from the project, with a separate versioned CLI. No installation hooks, services,
network access, host PATH resolution, desktop activation or process launching.

The useful first product is staged application integration checking. This is
not a complete dependency solver: ELF shared libraries, credential/mount access,
D-Bus activation, rendered icons, arbitrary interpreter arguments, terminal
argument behavior, implicit MIME ranking and application behavior are unproven.
Root ancestry must be trusted and the staged tree quiescent while inspecting.
Only selected desktop entries and the checker's inspected integration paths are
bound; this is not an inventory of every package/file in an entire root.

Prepare an explicit environment JSON (all paths describe the staged namespace):

```json
{"HOME":"/home/fixture","XDG_DATA_HOME":"/home/fixture/.local/share","XDG_DATA_DIRS":"/usr/local/share:/usr/share","XDG_CONFIG_HOME":"/home/fixture/.config","XDG_CONFIG_DIRS":"/etc/xdg","XDG_CURRENT_DESKTOP":"Hyprland","PATH":"/usr/local/bin:/usr/bin","icon_theme":"hicolor","icon_size":48,"icon_scale":1,"terminal_argv":["terminal","-e"],"locale":"C"}
```

Capture a passing baseline as data, review and retain its exact SHA256:

```bash
cachy-asahi-desktop-tools capture --root /private/staged-root --environment /private/environment.json --select tool.desktop --mime text/plain > /private/inventory.json
sha256sum /private/inventory.json
cachy-asahi-desktop-tools audit --root /private/staged-root --environment /private/environment.json --select tool.desktop --mime text/plain --inventory /private/inventory.json --inventory-sha256 EXACT_LOWERCASE_SHA256
```

Repeat `--select`/`--mime` as needed, in the original order. Capture exits 0 only
on static success; static faults exit 1 and emit the failure report rather than
an inventory. Audit exits 0 on exact passing bindings, 1 on a matching static
fault (normal capture refuses faults), and 2 on inventory drift or unsafe input.
Argument parser failures also exit 2. Check exit status before trusting redirected
output. Failed capture output must never replace a retained reviewed inventory.

Audit checks the inventory byte pin before opening the environment or staged
root. It then binds exact environment bytes, selections, every inspected file
pin, symlink chain/mode and the entire static report except its physical root
path. Paths are logical paths inside the staged namespace. Both installed prefix
and staged root may be moved; the inventory file and environment may be renamed
without changing contents. No claim is made about an untrusted concurrent writer.
Inventories are self-generated snapshots, not signatures or authentication of a
package distributor. Keep the approved digest independently. CLI writes JSON to
stdout only and never modifies its inspected files or the environment JSON.

XDG precedence, Hidden/NoDisplay/show-in rules, Exec/TryExec and freedesktop field
codes, staged shebang/ELF loader chains, explicit terminal prefix, MIME/default
fallback and icon-theme/pixmaps handling are inherited unchanged. The file-input,
runtime and window-lifecycle modules were inspected but are not executable
entrypoints in this package. They remain separate source workflows requiring
existing owned private guest/container/session contracts and unchanged exclusive
wait/signal custody; this package cannot obtain graphical PASS by launching a
.desktop command in the user's session. No packaged `runtime`, `window` or
`launch` operation exists in version 0.1.0.

Build without system mutation:

```bash
makepkg --cleanbuild --force --nodeps
```

Run from the recipe directory beside its pinned source archive. `check()` runs
the unchanged 54 static tests plus package/CLI controls using inert fixtures.
No acquisition or dependency installation occurs in this command. A portable
private layout can also be created without makepkg:

```bash
python3 -I -B cachy-asahi-desktop-tools-0.1.0/assemble.py --destdir /private/new-empty-stage --prefix /usr
/private/new-empty-stage/usr/bin/cachy-asahi-desktop-tools --help
```

The package owns `bin/cachy-asahi-desktop-tools`, two modules beneath
`lib/cachy-asahi-desktop-tools/`, two documents beneath
`share/doc/cachy-asahi-desktop-tools/`, and
`share/licenses/cachy-asahi-desktop-tools/LICENSE`, relative to `/usr`.
The exact six-file/mode inventory is `payload-map.json`. Removal deletes these
package-owned files; there are no hooks, backups, services, caches, state or
user configuration to migrate. Preserve user-created files. Private file
removal tests are not an ALPM transaction. Actual package installation/removal
must be separately exercised in a disposable target environment.

Source provenance is in `PROVENANCE.json`; `source-map.json` seals all finite
source files except itself. `payload-map.json` seals the installable files.
The source archive plus PKGBUILD is the complete offline build input. New
adapter code and fixtures are original MIT; vendored audit/tests and assembler
retain the project's MIT license. No third-party executable or fixture payload
is redistributed. The inert ELF headers are original test data, never binaries
launched by the tests.

Native ARM build, actual ALPM installed lifecycle, native 16K, graphical launch,
owned-window operation, both physical M2 Air sizes: NOT RUN. Performance:
NOT MEASURED. Release admission: NOT ADMITTED. Host checks cannot close these gates.
