# Independent GUI18 passive producer projection

This directory selects frozen GUI recipe commit
`b05267833d497ef034576741bf31968019a526c3` as independent DATA. It does not extend
the existing F69 recipe or transport binding. The GUI handoff seal is unavailable
and explicitly `UNBOUND`; `recipe.lock.json` records the commit/tree and whole
file pins taken from that commit. It is not an authority document.

`projection.py` reuses pinned parent `producer.py`, `prepare.py`, `f_intake.py`
and `finish_pair.py` libraries. `parent.lock.json` pins the exact imported code.
Parent files remain unchanged. The retained Qt build contract, module source
contract, checker and notice fixtures are exact frozen recipe bytes; checker
code is passive MIT-licensed parsing code. Qt source licensing remains the
173-notice inventory in the pinned contract, with publication/legal acceptance
outside this source projection.

The separate GUI producer:

- Admits only the exact GUI package/contract, 14 active recipe files, all 13
  source operands, 113 configuration settings and 18 shared modules. The five
  added modules and GUI smoke marker are explicit. F69 admission and its pair
  reader reject this tuple.
- Reuses whole signed base/additional input intake. The normal base349 already
  includes the pinned libdrm, libglvnd, Mesa and Wayland versions, so the proposed
  image remains 356 packages. Normal `pacman -T`, makepkg dependency and check
  behavior remain enabled; actual version/provides transaction verification,
  signature verification and image creation are still `NOT_RUN`.
- Emits separate GUI builder/entry/finisher source. The entry retains raw
  configuration, notices and GUI stage receipts before natural container
  destruction. The finisher projects the parent's strict archive, current-byte
  custody, comparison, package metadata and license checks, adapting GUI smoke,
  private/public modules, plugins, GNU ELF observations and structural 16K data.
  The source checker observes provider names; runtime resolution stays unbound.
- Retains the exact small unissued EXPERIMENTAL resource policy. Generated
  builder main unconditionally refuses with
  `GUI_ROOT_CAPACITY_UNISSUED_NO_ACTOR_ENTRY`. There is no GUI actor adapter,
  capacity issuer or implicit F69 transport fallback.

The Python API exposes `inspect_recipe`, `admit_complete_preparation`,
`dependency_image_plan`, `pair_commands`, `prepare_producer` and
`verify_producer_source`. Projection helpers produce bytes; none starts a
process. `prepare_producer` accepts optional explicit signed provider references
through its Python API. Without them it emits a complete bounded source
namespace with `HOLD_MISSING_QT612_GUI_SIGNED_INPUTS`, rather than claiming a
complete input plan. The output includes the pinned upstream archive in its
private recipe build view; it is not a transport export.

Run the 16 positive MODEL/refusal controls:

```sh
python -I -B scripts/ci/qt612-reference-native-source/gui/test_projection.py
```

Passive source construction, with absolute paths and a fresh output outside
the framework/recipe input trees:

```sh
python -I -B scripts/ci/qt612-reference-native-source/gui/projection.py \
  --framework /ABS/PINNED_FRAMEWORK_TREE \
  --gui-root /ABS/FROZEN_GUI_TREE \
  --archive /ABS/qtbase-everywhere-src-6.12.0.tar.xz \
  --output /ABS/FRESH_GUI_DATA_OUTPUT
```

`evidence/passive-preparation.DATA.json` records the local real-file intake,
static recipe/input-map agreement, source-map verification and namespace
refusals. That is source preparation evidence only. No Qt compilation, native
pair, actual stage, smoke execution, GPG, installation, device backend,
compositor connection, M2 check, performance result or publication occurred.
