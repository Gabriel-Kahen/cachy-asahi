# Installed Perl capability-name successor

This finite adapter derives a new Source from the exact unused 232-file Source
`71246ca38e58f9f410d1f3eea15f5ddf174bb1bf`. It changes Docker inspect name
comparison for the seven already-declared ALPM capabilities. One optional
`CAP_` prefix is accepted per name; exactly seven distinct raw and semantic names
are required. Extra, missing, repeated, unknown, malformed and differently cased
names refuse. Raw inspect records are unchanged.

Both the core and capsule producer copies change. Eleven other core files,
eighteen other capsule members, original200, actor, package bytes, public trust,
hooks, transaction policy, resource policy and prerequisite review remain exact.
The contract explicitly labels adapter revision v2 and the historical core commit;
it does not claim all twelve old core files remain unchanged. Outer/inner operation
names stay v1. A fresh Source/ref and new external admission are required.

The full 232-file inverse archives small changed metadata and the old producer,
then deterministically reconstructs the old capsule from current members and the
archived producer/inner map. It avoids an extra archived 40 MiB capsule. The existing
original200 inverse is updated to include the new finite additions.

After integration, the existing parent `filesystem.py` is loaded by its exact
SHA256. In an isolated checkout lacking that parent, explicitly select the same
read-only helper with `CACHY_PERL_INSTALLED_V2_FILESYSTEM`; it must hash
`7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7`.
Only verified helper bytes are compiled. No input Source/package code is imported.

```sh
python3 -I -B -m unittest discover \
  -s scripts/ci/perl5423-installed-lifecycle-native/successor_v2 -p 'test_*.py' -v

# Explicit real retained-parent DATA check; no export or runtime role.
python3 -I -B scripts/ci/perl5423-installed-lifecycle-native/successor_v2/check_parent.py \
  --previous-source /absolute/path/to/the/exact232/source-tree

# Print exact proposed Source facts in memory. --output is optional and may only
# be used under a separate, fresh Root DATA space review.
python3 -I -B scripts/ci/perl5423-installed-lifecycle-native/successor_v2/prepare.py \
  --previous-source /absolute/path/to/the/exact232/source-tree
```

The real XS v4 single-capability observation in `data/` establishes the Docker
spelling `CAP_CHOWN`. Seven-capability inspect fixtures are modeled controls,
not an actual installed lifecycle. Every other inspect predicate is retained and
negative-tested. Actor bytes remain frozen: direct kernel checks cover
Eff/Prm `0x800400cb`, Inh/Amb zero and NNP1; Bnd was not directly checked and no
such claim is added. Exact seven-cap Docker inspect/CapDrop policy remains.

No actor, GPG, ALPM, lease, network, actual Reader, compilation or publication was
run. All new Source actual selectors remain null. Root must update the once/Reader
bindings for 241 files, revised map/tree/capsule/core producer and adapter inverse,
without changing the sealed unentered 232 once packet. Source or DATA controls do
not establish native installation, 16K, M2 or release acceptance.
