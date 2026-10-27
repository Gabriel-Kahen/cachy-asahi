# Setup8 finite real-shell composition

This opt-in lane reuses accepted Setup8 **0.3.0-1**, run **40490674681**,
archive SHA256 `8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47`.
The constructor checks all ten archive payload files against the current recipe
source. It reuses the exact accepted `test_delivery.py` driver, including its
real engine SIGKILL checkpoint, pending-journal interlocks and readonly recovery
checks. It does not rerun a sealed producer or modify the production algorithms.

The finite selection is Fish config, Zsh config, fish-bang-bang, fish-autopair,
fish-done, zsh-autosuggestions, zsh-syntax-highlighting, and
zsh-history-substring-search. Every module and its runtime/support files comes
from the real local PKGBUILD `package()` output with declared checksums verified.
Hyprland and platform components are outside this lane.

`construct.py` writes a fresh context containing the accepted archive, package
sources, installed-layout staging tree, driver, and complete byte/mode registry.
It never installs anything. Pin the resulting `context.json` SHA256 in Root's
review/dispatch record; native execution requires this external digest and a
readonly context mount.

```sh
python3 -I -B scripts/ci/setup8-real-shells/construct.py \
  --source /absolute/checkout --accepted /absolute/retained/artifact.zip \
  --output /absolute/fresh/context
python3 -I -B /absolute/fresh/context/trial.py \
  --context /absolute/fresh/context --work /absolute/fresh/private-profiles
python3 -I -B -Werror scripts/ci/setup8-real-shells/test_context.py \
  --context /absolute/fresh/context --work /absolute/private-test-parent -v
```

The host trial requires an ordinary user, Python >=3.11, Fish >=4.9.3, Zsh >=5.9,
Bash, coreutils and xattr-capable local storage. It runs real Fish and Zsh startup
files automatically in bounded PTYs, with a private HOME/XDG/ZDOTDIR and no real
session bus. Fish notification calls reach only a private `notify-send` recorder.
Zsh autosuggestions retain their default asynchronous mode. Source syntax checks
and nine context adversarial checks are separate from the actual shell trial.

Four private profiles cover fresh setup, existing files, managed-block edits,
and a genuine SIGKILL after the first migrated target write. The inherited
delivery lifecycle covers preview/status, repeat activation, outside edits,
managed-edit refusal, wrong recovery refusal, conflict during recovery,
completion, version ledger, setup removal, and exact-new-root reactivation.
The extension verifies exact original user profile bytes, appended outside edits,
mode, xattrs, ownership, and on-disk history across removal. Twelve PTYs and six
noninteractive probes exercise custom functions/prompts/bindings, Fish pairing,
empty-history expansion and notification invocation, default async Zsh history
suggestions, substring selection and actual highlight regions before/after
migration. A separate control explicitly observes preservation/refusal when a
predefined `history-substring-search-up` widget occupies the module namespace.
Use the documented source-before-module-keybindings ordering for full activation.

**Migration scope:** both retained roots contain byte-identical real packaged
payloads. `cachy-asahi-shell-composition` 1.0-1 → 1.0-2 are explicit *fixture
configuration identities*, not installed package release versions. This tests
source-root relocation and all eight owned blocks together. It does not prove a
changed upstream module release migration or a Setup7→Setup8 package upgrade.
The accepted earlier lane retains its separate Setup7 upgrade evidence.

## Native entry for Root

`native.py` is executable only as root PID1 inside a marked disposable native
**aarch64 Docker container**, with an existing ordinary `alarm` account. Root
supplies the already-produced builder image and readonly constructed context.
It is deliberately not a CI dispatcher or image producer.

The image must already contain Python, GnuPG, Fish >=4.9.3, Zsh >=5.9, libnotify,
coreutils and base-devel, with the nine trial packages absent. The script checks
this offline, builds the eight shell packages with `makepkg` as alarm (including
recipe checks), and reuses the accepted Setup8 archive without rebuilding it.
It then performs install → repeat install → removal → reinstall → final removal
using private pacman policy, suppressed scriptlets/hooks and local unsigned test
packages. Ordinary-user probes join every installed payload/mode/root owner and
ALPM version/Qkk result to the constructed package stage. Actual homes are held
across package removal/reinstall; exact initial inventory and protected global
configuration must be restored. It retains logs, package hashes, raw profiles,
snapshots and reports, and checks that no ordinary-user processes remain.

Reviewed entry invocation (inside Root's new disposable container):

```sh
CACHY_SETUP8_REAL_SHELL_CONTAINER=1 python3 -I -B /context/native.py \
  --context /context --context-sha256 REVIEWED_CONTEXT_JSON_SHA256 \
  --output /out/fresh-native
```

The process must be PID1, so invoke Python directly as the container entrypoint,
with the marker passed through the container environment. Give the container
no network, device, host-home, audio, system-bus or privileged mounts. Root owns
container registration, finite external timeout, cleanup and CI publication.
The entry refuses this development host before mutation. Native execution,
native 16K, signed integrated lifecycle, physical M2, desktop notification delivery,
onboarding and release admission remain **NOT RUN** until independently executed.
Host `--verify-reinstall` checks only the readonly post-reinstall protocol and
explicitly does not claim a package transaction.
