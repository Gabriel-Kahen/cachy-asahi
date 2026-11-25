# Qtbase installed 16 KiB trial preflight

This source-only preflight binds a future offline installation of
`cachy-asahi-qt612-gui-server-source-reference 6.12.0-2` to the exact original
Q3 scratch, configure closure, and 356-package inventory. Use a new writable
child of the Q3 scratch. The separate package build and staging guest supplies
the archive and never serves as the install target. The plan records the
expected clean 356 → 357 → 357 → 356 → 357 → 356 inventory.
[Q3 evidence](../../../docs/validation/qtbase612-emulated-arm16k-configure-20261118.md)
· [Packaging handoff](../qt612_full_16k_preflight/PACKAGING.md)

```sh
lane=scripts/integration/qt612_installed_16k_preflight
python3 -I -B "$lane/preflight.py" \
  --q3-terminal "$Q3_TERMINAL" --q3-scratch "$Q3_SCRATCH" \
  --q3-inventory "$Q3_INVENTORY" --nonce "$FRESH_NONCE" > "$PRIVATE_PLAN"
python3 -I -B "$lane/preflight.py" --emit-consumer-cmake > "$PRIVATE_CONSUMER/CMakeLists.txt"
python3 -I -B -Werror::ResourceWarning "$lane/test_preflight.py"
```

Set the consumer's `smoke.cpp` to the exact pinned source shipped with the
GUI-server recipe. The projected CMake consumer discovers Qt 6.12.0 under
`/usr`, checks the actual imported public and private targets and scanner,
and links the same bounded offscreen and local Wayland server API smoke.
It uses an empty private home and runtime directory, standard loader search,
and no build RPATH. Retain the loaded offscreen plugin's actual mapping and
join it to the archive and ALPM ownership. The plan pins both consumer files.
[Reference fixture](../../../packages/port/qt612-gui-server-source-reference/SmokeCMakeLists.txt)

Before invoking a mutation, a future admitted actor must bind the retired
packaging receipt, archive and detached signature, current public TEST
certificate, full primary and signing fingerprints, and original verification
receipts. Use a separate private keyring and the emitted signature-required
pacman configuration inside the disposable guest. The two sibling controls
must exercise normal pacman with a tampered signature and with the selected
key absent, respectively. Both require the precise signature refusal and an
unchanged stopped local-database snapshot. Do not use production trust or copy
secret keys into the guest.
[Public signature verifier](../../port/qt612-gui-native-v1/trust.py)
· [Stopped ALPM database snapshot](../../install/overlay583_trial/trial.py)

At each installed stage, confirm the exact new inventory, database consistency,
all package-owned payload and aliases, and the 40 runtime dependencies.
`qt6-base=6.12.0-2` and the upstream-version consumer must resolve. The exact
official `qt6-base=6.12.0-3` demand must return solely the unsatisfied demand.
Check every Qt SONAME with the regular loader using RTLD_NOW/LOCAL and bind
all actual transitive provider paths and bytes to the selected installed owners.
Check all plugin and tool owners and exercise the ordinary-user offscreen
consumer. Both removals must restore the baseline package database byte map,
configuration checks and original provider runtime. Require the package-owned
leaves to be removed and every new Qt SONAME to stop resolving. The llhttp
guest's existing loader and restore checks illustrate the independent receipts.
[Installed loader and restore example](../llhttp_overlay583/guest.py)

The preflight emits unissued data and consumer source. It performs no ALPM,
signature or VM operations. Package assembly, signed installation, loader
checks and restoration remain unrun. An official Qt provider replacement needs
a separate admitted image, current trusted rollback archive and its own
consumer requirements.

## Guest supervisor callbacks

`worker.py` rederives the selected preflight plan before invoking any
callback. It checks the closed independently pinned selection, the public-only
certificate packets, original detached signature, exact signature-required
configuration, and the proposed guest boundary. It then uses the existing
TEST status parser and normal ALPM commands for the five mutations. It joins
each installed stage to the signed payload and pinned normal-loader provider
closure. It builds the independent consumer once, then reruns that same
consumer after both reinstalls. After each removal it compares the stopped
database and protected observations with the recorded baseline.

The worker has no CLI or default executor. The future guest supervisor supplies
all command, mount-identity, signature-input, installed-state and loader
observations. It must use the existing stopped database reader, capture the
normal loader's actual maps and approved path owners, and retain the raw command
streams. The separate sibling validator takes original ALPM diagnostic and
stopped-database observations from independently retired sibling clones.

```sh
python3 -I -B -Werror::ResourceWarning "$lane/test_worker.py"
```

These controls feed inert fixtures through the actual worker. They exercise
command ordering, protected-configuration preservation, failed or unretired
commands, bad trust and guest boundaries, distinct signature-refusal clones,
and exact inventory, loader and database restoration. Live signatures and
installation remain unrun.
