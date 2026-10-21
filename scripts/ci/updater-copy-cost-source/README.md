# Fixed Updater copy-cost diagnostic source

This dedicated factory reproduces exactly the489-file diagnostic source published as
`108eea03755d605e2fec0e5226f8ed38aa56c5bb`, using the complete489-file parent
`5c7e4c9a1b807cfb24542b024bf34af9bb15dba1`. Six readable replacement files
under `payload/` replace exactly six pinned parent leaves;483 remain byte-identical.
It does not change an existing source factory or its defaults.

With an independently obtained immutable parent checkout, run:

```sh
python3 -I -B scripts/ci/updater-copy-cost-source/prepare.py \
  --parent /absolute/path/to/original489 --output /absolute/path/to/fresh-output
```

The output must be absent and disjoint from both the input and this factory. Only
checkout-root `.git` metadata is excluded. Symlinks, hardlinked files, foreign
members, missing members and all byte drift are refused. The complete parent,
whole fixed profile, and all six replacements are checked before output creation.
The final output is checked against the complete expected489 map. The factory uses
only the Python standard library and never imports or executes emitted code.

Run the maintained controls with two independently obtained immutable source
checkouts (the CI workflow pins both commits):

```sh
UPDATER_COPY_PARENT=/absolute/path/to/original489 \
UPDATER_COPY_EXPECTED=/absolute/path/to/diagnostic489 \
  python3 -I -B -Werror scripts/ci/updater-copy-cost-source/test_factory.py
```

The five focused tests cover real isolated factory help/emission and whole-output
equality, parent drift/missing/extras before output, profile/payload drift before
output, path/file alias refusals and stale-atime reads, and the actual generated
cost-hook body inverse with the original1200/1860/600 clocks. The last test imports
only the emitted adapter/contract and generates an owned hook file; it runs no
updater, subprocess actor or package transaction. The scoped read-only CI runs
these controls on Python3.12 and3.14. The tests do not invoke the full native reader.

The diagnostic records at most12 scalar records/3072 bytes in the existing8192-byte
caller stderr. It measures inner copy cost; it is not a deadline cure, observed
speedup, or native-fit result. Full original graph, hashes, capability, mount,
hardlink, lifetime, cleanup and result predicates remain required. Existing
owner3900/copy1200/driver1860/verify600/cleanup60 clocks remain unchanged.
Native fit is **UNQUALIFIED**. SOURCE_ONLY grants no package authentication,
installation, target-composition, release or M2 authority.

The original real-copy/descriptor and complete source controls are separately
retained development evidence at
`artifacts/development/updater604-normal-failure-development-20261021/`
(`cost-final-controls.stderr`, `descriptor-controls.stderr`,
`source-controls.stderr`, `source-finite.stderr`, `source-freeze.json`). They are
not shipped tests and are not claimed to run in this scoped CI. Original source,
receipts, native artifacts and reader4235 remain separate and immutable.
