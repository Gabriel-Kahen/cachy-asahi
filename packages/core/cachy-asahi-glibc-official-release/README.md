# Unselected official GNU 2.43 build candidate

This is the separate project-owned package
`cachy-asahi-glibc-official-release 2.43.caa1-3`, aarch64. It uses the complete
official GNU 2.43 release archive plus two exact documented patches, not GNU8362 or a reconstruction of
the held binary. Its private prefix is
`/opt/caa/g243a1`.
The older candidate's source lock and the held binary's unresolved recipe gap
remain unchanged. This candidate is not selected for a base, overlay or release.

`source-lock.json` records the exact official archive, detached signature and GNU
publisher keyring bytes/URLs/SHA256; the release-payload tree hash is derived from
that archive and does not claim an upstream Git tree. The uniform archive mtime
1769201640 fixes the build epoch. The mount guard patch is a minimal GNU2.43 adaptation of upstream
8d6fbb22cdd54660056408ca0e9682a8cedbf055 retained with the older recipe; it
does not import the old ALARM patch set. A second project patch removes only
five stale XFAIL annotations from the held-builder test profile. This is an
explicitly patched release baseline; it does not imply later stable-branch fixes or the
old ALARM security patches are included. Security/update suitability remains an
admission prerequisite.

GPG validates the release signature with signing subkey
FD19E6D31B192EE4DC63EAD3DC2B16215ED5412A and primary
35B17DF5752577CA0C541CEB94BFDF4484AD142F from GNU's published keyring. The retained
key is expired now; the signature was made before that expiration. No separate
pretrusted fingerprint authority has been established. The exact GPG status,
expiration and trust limitation must remain visible. Hashes/cryptographic
validation alone do not confer release trust or selection.

The concrete PKGBUILD uses ordinary -O2 -g, no tuning/LTO/PGO. It disables nscd
and Systemtap, and builds candidate C.utf8/gconv data. It runs all applicable GNU
`check` and `check-abi` targets without deleting tests. GD-dependent optional
memusagestat is absent from the accepted builder. Source licenses and notices
travel in full in the exact archive; top-level COPYINGv2, COPYING.LESSERv2 and
LICENSES are also retained here. The recipe/harness is MIT; GNU sources have the
mixed GPL/LGPL and other notices recorded in LICENSES and individual files.

Dependencies: glibc, filesystem, tzdata. Build dependencies: gcc, binutils, make,
bison, gawk, python, perl, texinfo, patch, linux-api-headers; makepkg/fakeroot/xz
must already exist in the accepted owned574 builder. The harness installs no
build dependencies. Native build/test/ABI/runtime/lifecycle/hardware/performance
results are NOT RUN in this preparation.

All runtime/header/tool/data files are under the versioned private prefix;
notices additionally use `/usr/share/licenses/cachy-asahi-glibc-official-release`.
No provides/replaces/conflicts, hooks, install scriptlets, global loader/cache,
locale-gen, services or defaults are changed. Removal would remove its owned
payload/notices; installation/removal behavior still requires a separate real
lifecycle before admission. See the companion `scripts/ci/glibc-official-release`
harness README for materialization and the explicit native lane.


The versioned prefix /opt/caa/g243a1 identifies GNU2.43 candidate1. Gettext catalog
localedir is explicitly /opt/caa/g243a1/l (17ASCII bytes); _nl_default_dirname's
terminating NUL makes its exported object18bytes, as required by the untouched
upstream aarch64 ABI list. configure's localedir feeds config.make, Makeconfig
and intl/Makefile's LOCALEDIR. Compiled C.utf8 data stays under usr/lib/locale
inside the same prefix. No /usr/share/locale lookup or alias outside the prefix
is introduced. Both GNU check-abi and the independent exact OBJECT/TLS-size
comparison remain strict and unmodified.

For actual38898464517, all three failures and five XPASS remain historical
failures. The proposal guards OPEN_TREE macros supplied by newer kernel headers,
uses TIMEOUTFACTOR=5 only for tst-malloc-too-large-malloc-hugetlb2 (100s from its
20s default), and changes five formerly expected-failing tests into required
ordinary PASS/FAIL tests. It does not delete tests, alter allocator assertions,
or permit XPASS/unknown FAIL. A still-slow test or any new XPASS stays fatal.
The source lock records exact patch order/hash/provenance. Patch application is
fuzz-zero and checked. Native compilation/tests/ABI/pairs for this configuration
remain NOT_RUN; no release/security/source-authority admission is implied.


Pkgrel3 disables multiarch through the standard upstream --disable-multi-arch
configure option. Actual38906503054 pkgrel2 completed GNU check/check-abi (both
exit0:6938PASS,13XFAIL,107UNSUPPORTED,zeroFAIL/XPASS/ERROR) and built its first
archive, but strict public ABI comparison failed. Passive inspection confirms
memchr/memcpy/memmove/memset/strlen@@GLIBC_2.17 were IFUNC GLOBAL. The held
baseline requires FUNC, with WEAK binding for memchr/strlen. All other ten
libraries matched; libc retained2777 public symbol tuples but these five differed.
The pinned non-multiarch AArch64 assembly ENTRY macros define ordinary function
types, with weak_alias for memchr/strlen; memcpy.S defines both memcpy/memmove.
This is a baseline build choice, not a symbol-type/binding waiver or a claim
that IFUNC is generally incompatible with AArch64. Those assembly routines may
still use ordinary ARMv8/Advanced SIMD instructions; no performance gain or M2
compatibility is claimed. All GNU/independent ABI checks (including exact
OBJECT/TLS size/default version/binding) and both previous patches stay strict.
The short localedir/prefix and bounded single-test timeout remain unchanged.

The source lock and materializer bind this configuration, pkgrel3 and package
identity into source/runtime receipts. Native pkgrel3 GNU tests, strict ABI,
header/runtime execution and build pair are NOT RUN. Pkgrel2's failed first
static gate prevented candidate runtime execution and the second build. Passing
upstream tests does not establish static/runtime ABI, installability or admission.
