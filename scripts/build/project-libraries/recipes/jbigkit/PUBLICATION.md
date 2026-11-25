# Filtered project jbigkit 2.2-1.1 candidate

This independently written MIT recipe builds a distinct project candidate.
Root must accept its final name/version/provides policy. Declared software
licence remains GPL-2.0-or-later; retained author, translator and permissive
notices retain their original scopes. There is no claim of legal clearance,
ALARM binary equivalence, actual clean ARM build, consumer ABI or M2 acceptance.

The literal fixed source array plus PKGBUILD forms the public rebuild pack.
It contains a deterministic filtered archive with exactly 37 unchanged Source
files and 5 directories. All 13 example/data/generator files are excluded;
the source-filter manifest records their identities/hashes without shipping
their contents. The original official 441,594-byte archive is private audit
custody only. Neither a rebuild nor package staging reads that private archive.
The full author homepage prose is excluded. COPYING, ANNOUNCE, selected Source
notices, the patch licence declaration and project MIT text remain retrievable.

The exact retained 4,481-byte shared-library patch is applied first. A separate
new patch adds prominent 2026-10-13 modification notices to all three Makefiles
and removes external-image/fuzz test targets. No C/header/library source bytes
are changed. Project checks run the GPL-covered libjbig unit tests serially,
then use independently written MIT synthetic P4 fixtures for conversion-tool
roundtrips. Fixtures are formula-generated white/black/checker/stripe patterns,
not transformed copies of excluded images. This reduced and replaced test scope
is explicit; it is not a claim to have run the former image corpus or fuzzing.
Roundtrip comparison checks decoded dimensions and every defined pixel, allowing
header/comment formatting differences. Unused row-padding bits are ignored.
The bounded P4 parser consumes only the mandatory raster delimiter, preserving
binary bytes whose values are whitespace; exact raster length disambiguates CRLF.

The proposed provides entries are jbigkit=2.2, libjbig.so=2.2-64 and
libjbig85.so=2.2-64. Root must inspect actual project ELF SONAMEs/architecture
before admitting that metadata. The recipe has no automatic replaces, hooks,
services, boot/kernel/driver/firmware changes, or host installation. Every
package write stays under pkgdir. Source and licence files are copied from the
checked ordinary startdir files; a final exact public-bundle check follows.

Explicit !staticlibs, !lto and !debug options keep this baseline package from
inheriting unselected static-library, LTO or automatic debug-split policy.
Root must pin and inspect the actual makepkg configuration and retain every
produced artifact, including unexpected extras. These flags make no performance
or reproducibility claim; actual metadata must match the proposed SO-provides.

For a future private build, Root selects and binds a clean native aarch64
container/toolchain, CARCH and CACHY_ASAHI_CONTAINER=1. Epoch1791585070 remains
the exact original Source maximum mtime and filtered metadata epoch. Every
stage verifies fixed public inputs and original/patched Source before upstream
Makefile execution. The author ran only passive Source and own synthetic-data
controls. Private-build dispatch is NOT ADMITTED here; public redistribution is
separate and remains unaccepted pending review and actual provenance/delivery.

R1/A05/A12 next steps: independent patch/filter/recipe review; Root policy and
private build admission; actual two clean ARM builds with serial test logs;
ELF/16K/dependency/consumer inspection; corresponding-source-to-output binding;
reviewed signed publication with same-place retrievable Source and notices.
Complete R1-R5/M5-M9/A01-A15 requirements remain unchanged.
