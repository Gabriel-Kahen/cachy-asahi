# Minimal206 builder metadata DATA CI

This separate lane runs 11 unchanged author controls plus six focused catalog/
resolver/lock controls. It does not download, inspect or execute the 1.47 GB package/
rootfs intake. No native build, GPG, signing, baseline selection or old349 output
admission occurs. The source author's separate native-source variant is outside
this lane and is not reimplemented here.

The only transported fixtures are the exact three public **unsigned catalog
snapshots**, totaling 11,103,582 bytes: core 257,446, extra 10,783,831, alarm 62,305. Their
full pins and primary URLs are recorded in `catalogs.DATA.json` and independently
matched to the original author primary/manifest pins. They were copied from the
existing verified public cache, not fetched from mutable mirror URLs. No package
archive, rootfs, keyring or signature material is copied into this CI family.
Embedded public PGPSIG bytes already present in these metadata indexes are not
signature authentication.

Before importing author code, the driver verifies the whole source lock, exact
15-file source namespace/modes, four maintained engine source pins, bootstrap
metadata pin and 41 original recipe leaves. The source author's code is unchanged.
The driver stages verified operands in a private source tree, using the checker
held in LLHTTP Source95 at its original path.
The catalog directory must contain only three single-link 0644 exact pinned files.
Aliases, missing/extra files and body changes refuse before parsing.

The six added controls require:

1. Genuine complete catalog regeneration to byte-identical 1,189,335-byte builder
   manifest/c5c9f445..., with 206 packages, 869 satisfied edges, 165 reconciled rootfs
   names, seven unselectable catalog records and all 1,236 remaining review holds.
2. Byte-identical 236,589-byte native operand/629ef929... and 4,048-byte expected206
   inventory/303cb32d..., while the distinct old349 metadata remains unchanged.
3. Every selected edge and both explicit provider bindings to satisfy the ORIGINAL
   declared normal requirement; provider declarations are not erased.
4. Missing normal dependencies, declared conflicts and replacements to fail.
5. Wrong version witnesses and an additional selected versioned provider to refuse
   rather than silently choosing an alternative.
6. Catalog namespace/alias/body substitutions to refuse.

The last two resolver adversaries are explicitly MODEL metadata changes used only
to exercise refusal. They are not package bodies, actual Root profiles or accepted
providers. Existing author controls also use a tiny synthetic .PKGINFO archive
and signature-status TEXT; they invoke no GPG or native tool. The unissued
libgit2 project llhttp dependency continues to refuse before entry.

All 17 tests run with processes, sockets, ctypes, custody locks, signals and
post-fence resource setters denied. The source-only metadata process is bounded
to 2 GiB AS, 180 CPU seconds, 16 MiB files and 128 FDs. These are CI bounds, not a native
builder fit measurement. The original planner/resolver limits remain unchanged.
The workflow uses pinned setup actions, read-only contents and Python 3.12/3.14;
all fixture and code inputs come from the checkout, with no acquisition step.

```sh
python -I -B -Werror::ResourceWarning scripts/ci/minimal-native-builder-data/ci.py
```

Metadata graph PASS and manifest reproduction confer no current trust/revocation,
signature authentication, package transaction, build success, new baseline,
Source/native caller selection, runtime compatibility, installation, 16K or M2
acceptance. The complete base-devel graph remains required. Root authentication,
actual project provider, Root selection/native authority and physical fit remain
UNISSUED/UNKNOWN. Review holds are retained, not converted to zero or waived.
