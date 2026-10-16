# Unselected official GNU 2.43 build candidate

This is the separate project-owned package
`cachy-asahi-glibc-official-release 2.43.caa1-1`, aarch64. It uses the complete
unmodified official GNU 2.43 release archive, not GNU8362 or a reconstruction of
the held binary. Its private prefix is
`/opt/cachy-asahi/glibc-official-release/2.43-caa1`.
The older candidate's source lock and the held binary's unresolved recipe gap
remain unchanged. This candidate is not selected for a base, overlay or release.

`source-lock.json` records the exact official archive, detached signature and GNU
publisher keyring bytes/URLs/SHA256; the release-payload tree hash is derived from
that archive and does not claim an upstream Git tree. The uniform archive mtime
1769201640 fixes the build epoch. No old ALARM patches are carried. This gives an
unmodified release baseline; it does not imply later stable-branch fixes or the
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
