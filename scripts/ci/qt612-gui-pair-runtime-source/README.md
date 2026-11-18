# Prepare the public Qt GUI pair runtime Source

Run the constructor with an independently selected helper commit, the sealed
portable-v2 input skeleton and the exact public route plan. It reads the helper
files from local Git objects so working-tree edits do not enter the Source.
Use `--ingress-commit` when the acquisition and input binder are selected from a
separate reviewed commit.

```sh
python3 -I -B scripts/ci/qt612-gui-pair-runtime-source/prepare.py \
  --repo "$REPO" --helper-commit "$HELPER_COMMIT" \
  --portable "$PORTABLE_V2" \
  --portable-selection-sha256 "$PORTABLE_SELECTION_SHA256" \
  --portable-map-sha256 "$PORTABLE_MAP_SHA256" \
  --routes "$PUBLIC_ROUTE_PLAN" --routes-sha256 "$ROUTE_PLAN_SHA256" \
  --output "$FRESH_RUNTIME_SOURCE"
```

The replacement `pipeline.py` is the only changed body in the 214-leaf
portable skeleton. Its file pin, the portable Source map and the pathless
selection are regenerated. The 567-route plan body stays exact. Package
archives are excluded. The optional `--md4c-signature` and
`--md4c-certificate` inputs must be the already selected adjacent 119-byte
signature and 265-byte binary public certificate. The separately issued
`--md4c-authority-path` and `--md4c-authority-sha256` accept only the exact
pathless public R128 projection and require those two inputs.

The runtime Source map contains exactly `kind`, `schema` and `files`. Each
member binds its byte count, SHA-256 and mode. Its mapped
`runtime-inputs.DATA.json` lists external program pins, public input roles,
the entry reference when selected and the separately pinned R128 checkout.
An entry-less construction is unissued. For an entry-ready Source, supply
`--entry-selection` and `--entry-selection-sha256` over a separately selected
document with kind `QT612_GUI_PAIR_ENTRY_SELECTION_V1`, the complete local Git
`commit`, the fixed `entry` path
`scripts/ci/qt612-gui-server-pair-adapter/entry.py`, and a closed `files`
object of relative program paths and whole `bytes` and `sha256` pins.
The workflow independently selects the entry descriptor.

Two unchanged, already public Qt parent lockfiles contain historical local
paths. The public runtime omits their bodies. Its
`scripts/ci/qt612-gui-pair-runtime-source/runtime.py` supplies
`stage_helpers(source=..., map_sha256=..., frozen_locks=..., output=...)`.
Use the independently pinned original lock files beneath a read-only
checkout, and a fresh owned code directory, before importing the acquisition
or binder programs. The actual family input bind separately checks all
current Source bytes. The previously published R128 runtime checkout remains
an independent operand. Its complete historical tree is absent from this
Source.

Run the local controls with
`python3 -I -B -m unittest discover -s scripts/ci/qt612-gui-pair-runtime-source`.
The constructor builds no packages, signs nothing and issues no authority.
