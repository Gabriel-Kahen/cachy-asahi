# Owned Thunar copy / GIO rename / text-launch workflow

Source-ready generic ARM slice. Native execution, readable pixels, interactive
rename/editor UI, physical input, managed login and Apple hardware are NOT_RUN.
This worker changed only this artifact directory. Root owns adoption and actuals.

Both existing minimal and shipped-overlay fixtures launch the installed Thunar
4.20.10-1 on their private Wayland/D-Bus session. The lane requires the exact
Thunar D-Bus owner PID, a native mapped/visible PID-owned window titled Files,
and unclipped geometry. Runtime introspection must match each selected method's
argument names and signatures before invoking it. An exact known hyprctl exit-6
read timeout may retry only during the initial 90-second mapping wait; all later
capture queries remain strict. The existing 591-package runtime and generic
4K/software graphics path remain unchanged.

The fresh 0700 guest workspace contains synthetic UTF-8 seed and outside sentinel
files. Thunar DisplayFolder opens its Files directory. Thunar CopyTo creates
Files/created.txt from the seed. The installed `gio move` renames it to
renamed.txt: this is explicitly a native filesystem operation, and supplies no
Thunar rename-dialog acceptance. Thunar LaunchFiles opens that text file through
a private MIME handler. The handler verifies exact content and publishes an
exclusive receipt with path, nonce, UID, PID and content digest. It is a launch
probe, not an editor UI. No shell copy, filesystem setup or receipt is presented
as GUI interaction or physical input.

Thunar uses private XDG config/data/cache directories. A directly owned foreground
xfconfd starts first to avoid activating a settings daemon with the fixture user's
configuration. Existing user configuration is snapshotted and must match after
each phase; seed, outside sentinel and final file bytes must survive. Thunar
must quit with exit 0 and retire its window before compositor exit 0. Every
failure retires and drains owned children, preserving the original exception.
The full workspace disappears with the existing disposable guest disk cleanup.

package-inputs.json records exact versions, archive/signature hashes/sizes,
licenses, providers and sources for the 185-package/719-edge closure of Thunar,
glib2, xfconf and Python from exact574. No additions/replacements are proposed.
check_inputs.py reproduces it using private libalpm metadata; it performs no
package installation, native app execution or network access. source-pins.json
preserves 30 shared prerequisites. The held Thunar service/man/metadata excerpts
in upstream/ informed the CLI/API selection. A read-only ELF64 relocation audit
of the pinned Thunar binary independently recovered the exact selected
GDBusMethodInfo/ArgInfo names and signatures; thunar-dbus-audit.json records
archive/binary hashes. This is source audit only. Live introspection remains mandatory.

After adopting the declared files to scripts/ci/desktop-file-manager-workflow/:

```bash
python3 -B -m unittest discover -s scripts/ci/desktop-file-manager-workflow -p test_workflow.py
python3 -B -m unittest discover -s scripts/ci/desktop-file-manager-workflow/ci -p test_caller.py
python3 -B scripts/ci/desktop-file-manager-workflow/check_inputs.py --source "$PWD"
python3 -B scripts/ci/desktop-file-manager-workflow/prepare.py --source "$PWD" --output /absolute/fresh-file-manager-runner
python3 -B /absolute/fresh-file-manager-runner/test_desktop574_runtime.py
bash -n /absolute/fresh-file-manager-runner/desktop574_fixture.sh
```

Root may use ci/workflow.yml as the manual-only native ARM workflow, with exact
source/workflow SHA equality, the accepted retained-input seed, owned builder
cleanup and bounded closed public export. The standalone invocation is:

```bash
timeout --signal=TERM --kill-after=30s 2050s python3 -B /absolute/fresh-file-manager-runner/desktop574_runtime.py --source "$PWD" --base-dir /absolute/successful574-output --output /absolute/fresh-file-manager-output
```

Success status: PASS_THUNAR_COPY_LAUNCH_GIO_RENAME_GENERIC_ARM_SMOKE. Closed public
retention includes bounded reports/logs and both exact QMP PPMs, excluding guest
disk, input cache, private workspace, executable and arbitrary directory contents.
Metadata acceptance is always PIXELS_PENDING_VISUAL_REVIEW. Root must inspect
both actual images for readable Files location, Thunar content area and the
renamed.txt entry, without modal errors, clipping or transparent/invisible text.
The independent bar/reload opacity/capture limitation remains unresolved; mapped
metadata and successful API calls do not substitute for readable pixels here.

The exact argument contracts are runtime gates, not an assertion that this held
Thunar has already executed them successfully. Unsupported signatures, launch
routing or file operations fail the lane and remain unfinished. No M2, 16K,
accelerated rendering, performance or complete M6 acceptance is claimed.
