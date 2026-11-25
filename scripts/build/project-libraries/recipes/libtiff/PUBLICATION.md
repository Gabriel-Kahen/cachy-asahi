# Project libtiff 4.7.2-1.1 — proposed filtered source

This original MIT recipe adds project attribution and an explicit source
projection to upstream commit d01a94be176f5f6a87f7ee1c0b32e65416aa2b4d. It
does not relicense upstream or linked dependencies. Root owns package naming,
version/provider policy, actor admission and publication.

The six literal PKGBUILD source inputs are the filtered project archive,
UPSTREAM-NOTICES.txt, LICENSE.MIT, this file, source-filter.json and
stage-source.py. The original unfiltered upstream archive is a private audit
input outside this copyset. No public rebuild needs that original archive.
The filtered archive includes exact library/tool code, headers, CMake modules,
portability code, source generators and test source, including VERSION,
RELEASE-DATE and libtiff-4.pc.in required by CMake. Every member is allowlisted
by path/size/SHA256. No contrib/docs/fuzz or test/images/test/refs fixture is
included. No upstream code was executed to derive this archive.

Native check() selects exactly ascii_tag, long_tag and short_tag using an
anchored regex, checks CTest discovery contains those three names, and rejects
an empty selection. Their pinned C source writes its own dummy pixels and
tags, then reads those generated TIFF files. long_tag/short_tag use check_tag.c.
They do not read excluded image/reference fixtures. The full upstream suite,
image conversion coverage and private original-archive tests are NOT RUN.
No fixture-specific image grant is inferred from an origin URL or from the
top license alone. test-source-evidence.json and excluded-test-data.json in
the proposal retain the exact source basis and omitted fixture hashes.

Root builds only in the locked native ARM OCI environment with the exact
project jbigkit provider. Guards require CACHY_ASAHI_CONTAINER=1, an ordinary
OCI marker, native Linux/aarch64 and the exact inherited epoch 1782568888.
Markers are assertions, not complete isolation proof. install uses DESTDIR;
no host installation, hooks, services or platform changes are introduced.
The explicit libtiff.so=6-64/libtiffxx.so=6-64 provides remain proposals until
Root measures the actual ELF outputs and checks consumers and 16K behavior.
OpenGL/tiffgt, LERC, contrib and docs remain excluded. The upstream
tiff-deprecated=OFF semantic ambiguity remains disclosed.

package() stages the exact filtered archive, PKGBUILD, notices, manifest and
helper together in usr/share/cachy-asahi-libtiff/corresponding-source/recipe/,
so every literal source[] file is alongside PKGBUILD in its public startdir.
It copies actual generated headers, CMakeCache, compile commands and selected-test
metadata, computing their actual hashes without inventing future expected pins.
No same-package output hash or new unsupported provider environment variable is
required by package(). inventory.json hashes every staged file. Root's locked
image/dependency inputs select the project jbigkit provider during native build.
After both packages exist, Root must join the exact project-jbig binary and
preferred source pack with libtiff binary/source/recipe/dependency provenance in
a separate release index. provider_release_association=NOT_RECORDED and
public_promotion=false are retained until that post-build evidence is closed.
The local delivery mechanism is not proof that corresponding source is complete.

The retained grants support a bounded private compilation experiment without
inventing a new permission/approval requirement. All supplemental grants and
copyrights are preserved. Frank Cringle derivation is explicitly stated to be
with permission in the official source. The historical uvcode generator is
absent: the pinned table and its granted including source are present, but no
claim of complete preferred-source provenance is made for that table.
JBIG's holder states static/dynamic linking creates a GPL-covered combination;
the Berkeley acknowledgment conditions and applicable GPL source-delivery
terms still need a concrete compliant distribution basis. Adding notices or
filtering unknown examples does not alone settle that issue.

No public release is admitted. Actual generated-code/configuration/source and
binary correspondence, native builds, test results, license/source delivery,
signed transactions, lifecycle/recovery and both M2 Air models remain open.
Root can review and admit the bounded private experiment independently of
public redistribution acceptance. Old sealed recipes and results are unchanged.
