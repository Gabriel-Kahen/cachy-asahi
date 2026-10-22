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

## Mandatory clocks with optional I/O accounting

The separate `optional_io.py` entry emits exact489 source
`2ef64d460aedeed8f40909d32f4a074e8c3c546b` from complete
`108eea03755d605e2fec0e5226f8ed38aa56c5bb`. Five replacements preserve484
leaves. The default `prepare.py` output remains byte-exact. Run:

```sh
python3 -I -B scripts/ci/updater-copy-cost-source/optional_io.py \
  --parent /absolute/original-diagnostic489 --output /absolute/fresh-source
```

The actual failed run39605033498 retained no copy-cost records. The old helper
incorrectly made mandatory wall/CPU/rusage output conditional on optional proc
I/O accounting. Schema2 preserves the scalar clocks and uses explicit unknown
I/O values when accounting is unavailable; unknown is distinct from observed
zero. All12-record/3072-byte caps, full observations, original exceptions and
1200/1860/3900 native clocks remain unchanged. This is a diagnostic fix;
native39726250527 is pending and no deadline cure or speedup is claimed.

The optional source CI independently checks both immutable489 source checkouts,
exact output, drift/alias refusal and the actual private helper behavior with
missing I/O. It runs no updater, GPG, VM or package transaction.

## Inner copywalk text validation

`copywalk_text.py --parent /absolute/optional-io489 --output /absolute/fresh489`
emits exact489 source `b21a5864d5a4610b9181a1c270ac8821d8448a17` from
`2ef64d460aedeed8f40909d32f4a074e8c3c546b`. Six replacement leaves preserve483
others. Both existing entry points and outputs remain unchanged.

The private descriptor route now uses the source-verified canonical POSIX text
validator with the entire original fallback for uncertain values. Original code
objects perform every fresh filesystem, hash, graph, link, mount, capability and
lifetime check. No filesystem or successful validation result is cached. Native
1200/1860/3900 clocks remain held. Local owned-fixture equivalence/refusal checks
passed; the ARM trial remains pending, with no M2 performance claim.

The separate read-only CI reproduces both complete489 maps, checks drift/alias
refusals and runs all106 emitted source controls through unittest discovery.
No native reader, API, GPG, package installation or VM actor runs in this CI.

Run the portable maintained controls against the two complete immutable checkouts:

```sh
UPDATER_TEXT_PARENT=/absolute/optional-io489 \
UPDATER_TEXT_EXPECTED=/absolute/copywalk-text489 \
  python3 -I -B -Werror scripts/ci/updater-copy-cost-source/test_copywalk_text.py
```

The seven tests cover exact isolated CLI/full489 emission, the6/483 inverse,
checkout metadata exclusion, parent/profile/payload drift before output, source
and file aliases, and unchanged historical profile/optional-output composition.
They then discover and run all106 original controls from the verified emitted
source in a temporary directory, with no development-artifact paths. The original
owned ext4 image controls require `mkfs.ext4` and `debugfs` (e2fsprogs); missing
tools fail explicitly. No original test or assertion is patched or skipped.
