# Python candidate plus installed FirstLogin GTK

This is one x86_64 cross-component host diagnostic. It installs the unchanged
source-built Python 3.14.8 candidate in the exact frozen private GTK image,
executes the actual installed FirstLogin window/Preview/Apply through unchanged
PyGObject, then restores the exact original Python provider and complete package
inventory. It never controls the host desktop, installs host packages or invokes
native workflows. UI, backend, package and GI runtime bytes remain unchanged.

The direct-installed GTK driver and package-owner functions are reused read-only
from commit `1bff639be5582559c81a012320f6b3752f259433`. The controller verifies
each borrowed file against that Git object before copying check-only helpers
into its private driver snapshot. No complete UI actor or runtime is forked.
The new owner adds only Python package checks/restoration; the ordinary-user
probe runs the original `installed_gui.py` with `runpy`, without patching it.

## Exact inputs and capacity

- UI archive: `cachy-asahi-first-login-ui-0.1.0-2-any.pkg.tar.zst`, 16,905 bytes,
  SHA-256 `869fb4f1dcf7fc26ff87594398eba8d15d4a8051e6feaf96d4b8fe457ccb4ea4`.
- Python candidate: exact full-Tk second-run `python-3.14.8-1.1-x86_64.pkg.tar.zst`,
  SHA-256 `8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e`.
- Original frozen GTK-image provider: `python-3.14.9-1-x86_64.pkg.tar.zst`,
  SHA-256 `e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55`;
  its original signature SHA-256 is
  `9261278f2a855d6ae8f7b148ef84300030a120d11ddcf66e93835f705656925d`.
  Both are retained in the disposable image and the public signature is
  verified through its Arch keyring before TEST signing.
- FirstLogin/Setup8 and Fish/Zsh template inputs use the unchanged UI actor's
  exact `inputs.json` pins. The bounded reader joins all 24 installed UI/backend
  file hashes/modes to those exact archives and UI source pins. Delivered
  templates are data inputs; no replacement fixture is invented.

At least **8 GiB free workspace capacity** is required both before preparing the
run and immediately before provisioning. Actual measured free bytes are retained
in the report. The already-built UI is reused, with no new makepkg workspace or
copied full-root tree. The only prerequisite transaction is inside the pinned
official Arch image, using the unchanged GTK provisioner's November 9 frozen
repositories, exact DB hashes and Required package signatures.

```sh
python3 -I -B -Werror::ResourceWarning scripts/integration/python314_desktop/test_desktop.py -v
python3 -I -B -Werror::ResourceWarning scripts/integration/python314_desktop/run.py \
  --ui-worktree /home/gabe/Documents/ChatGPT/cachy-asahi-first-login-ui-candidate-20261114 \
  --retained-inputs /tmp/cachy-asahi-first-login-ui-candidate-final-20261114/inputs \
  --ui-archive /tmp/cachy-asahi-first-login-ui-candidate-final-20261114/build/cachy-asahi-first-login-ui-0.1.0-2-any.pkg.tar.zst \
  --python-archive /tmp/cachy-asahi-python314-tk-full-second-20261114/export/python-3.14.8-1.1-x86_64.pkg.tar.zst \
  --output "$PWD/work/python314-desktop-final"
```

Host Python 3.14 supplies the bounded zstd DATA reader. Docker and the pinned
official image must already be installed. Missing capacity/materials/dependencies
or failed source/provider checks stop the run; there is no namespace, provider,
dependency or capability fallback.

## Actual phases and assertions

The existing UI owner TEST-signs/installs the genuine FirstLogin/Setup8 backends,
refuses the unsigned UI, then TEST-signs/installs its exact existing archive. All
24 package payload files, modes/root ownership and complete ALPM ownership are
checked. Python candidate and retained provider copies receive fresh ephemeral
TEST signatures through that same private signer. Python local transactions
require trust, mask hooks and use `--noscriptlet`, with no dependency bypass.
Positive transactions reject ancillary pacman/ldconfig errors even if the exit
status is zero.

The whole original provider payload is verified before replacement. The actual
Python operation is **3.14.9→3.14.8 downgrade**, not the historical 3.14.7 upgrade.
All candidate bytes/modes/UID/GID/links, exact ALPM path ownership, dependencies,
complete inventory and removal of old-only files are checked. The original
PyGObject `_gi.cpython-314-x86_64-linux-gnu.so` hash must remain unchanged.

UID/GID1000 launches a private D-Bus session and Xvfb with software rendering,
no host bus, GPU/input/sound device, physical display or checkout/package-source
mount. Its actual capabilities and bounding set are zero, NNP=1 and seccomp=2.
The unchanged installed driver imports `/usr/lib/cachy-asahi/first-login-ui/gui.py`,
maps its window, checks read-only inspection, emits Preview, emits Apply against
the real installed backends while preserving an edit, and closes without a
worker. There is no moved-prefix or source-loaded UI substitute in this lane.

The wrapper records Python version/executable, actual mapped libpython and its
candidate/provider payload hash, GI extension path/hash and GTK/GLib/Gio identity.
The exact original provider is restored, then the same installed-window driver
runs under 3.14.9 in a second private home. Both caller-home byte/mode/UID/GID/link
maps must survive provider restoration and subsequent removal of all three UI/
backend packages. Removal restores the exact original full package inventory.
This does not claim every shared desktop-cache byte/mtime is restored.

All post-provision owner and ordinary-user operations retain the unchanged UI
journey's network-none, two-CPU/4-GiB/256-PID, default seccomp, NNP and **zero
capability** contract. Driver mounts are private read-only check-only copies;
source material mounts exist only for the separate backend installation actor.
Lifecycle/application actors have no `/inputs` mount or checkout; source archives
retained inside the image are in root-only directories. No runtime services or
namespace workaround are enabled. The 2100-second controller and bounded child
commands are supervised by the existing process-group runner; cancellation
removes only the registered owned containers, volumes and derived images.

## Results and limits

The final run is retained under `work/python314-desktop-final/`, with provider/
inventory receipts in `public/`, actual ordinary-user GTK/identity/home results
in `user/`, and full command/cleanup receipts in `report.json` and `logs/`.
The first development run already passed runtime/UI/restoration; the final run
adds explicit rejection of zero-exit ancillary package errors. Its earlier
candidate/restore logs were independently inspected and contained none.

November 14, 2026: final execution PASS. The measured pre-provision workspace
capacity is 10,358,132,736 bytes, above the 8,589,934,592-byte requirement. Actual
GTK 4.24.1/GLib 2.90.1 and the same installed GI extension run the original four
window controls under 3.14.8 and again under restored 3.14.9; both GUI stderr
logs are empty. Effective/bounding capabilities are zero, NNP=1, seccomp=2 and
source-hidden assertions pass in both processes. Python candidate/provider
payloads cover 3,191/3,198 nodes. Inventory remains 303 packages during provider
replacement/restoration, then the exact 300-package baseline after removal of
the three UI/backend packages. Both private homes remain byte/mode/UID/GID/link
identical. All seven cleanup actions return zero: three containers, two volumes
and two derived images are removed. No ancillary package errors occur.

Four source controls pass under isolated Python 3.12.13 and 3.14.7: insufficient
capacity refusal, recorded capacity threshold, zero-exit ancillary-error refusal
and acceptance of the genuine downgrade warning. No candidate/runtime edits or
capability additions were needed. Actual direct-installed controls establish
only this finite cross-component workload, not arbitrary PyGObject consumers.

The previous core HOLD, full-Tk build, ABI, venv and both Python lifecycle results
remain unchanged. This adds x86_64 cross-component evidence only. Native ARM,
16K, supported Asahi/M2, physical graphical login, production trust, original
source/legal/freshness, full-system acceptance and release gates remain open.
