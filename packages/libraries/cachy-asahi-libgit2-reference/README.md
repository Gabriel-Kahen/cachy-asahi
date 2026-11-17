# libgit2 original source-provider development candidate

This original recipe builds libgit2 1.9.7 from upstream tag `v1.9.7`, exact commit
`49e408b3208bc3093757a1c2db938d3590f3f412`. `source.json` pins the 7,758,424-byte
primary archive and SHA-256. It is unselected and does not reconstruct the
unrecovered ALARM recipe or establish source correspondence to a foreign binary.
The primary [upstream release](https://github.com/libgit2/libgit2/releases/tag/v1.9.7)
and [llhttp generated release](https://github.com/nodejs/llhttp/releases/tag/release/v9.3.1)
were checked directly. No upstream source signature was verified.

The recipe requests external llhttp 9.3.1, OpenSSL, libssh2, PCRE2 and zlib.
It retains upstream collision-detecting SHA1, bundled xdiff and NTLM, threads,
HTTPS and SSH; it disables GSSAPI and the CLI. No PC/boot/platform assumptions or
x86 tuning flags are added. No package hooks, services or installation scripts
exist. It provides `libgit2=1:1.9.7` and generated `libgit2.so` SONAME metadata,
conflicts with the alternative `libgit2`, and has no automatic replaces. The
candidate name separates project ownership while satisfying the Rust recipe's
unchanged `libgit2` dependency. These metadata promises still require an actual
native ALPM transaction and the unchanged Rust build, not just source inspection.

Runtime dependencies are `glibc openssl libssh2 pcre2 zlib llhttp=9.3.1`.
Build dependencies are the implicit base-devel C toolchain, CMake >=3.25, Ninja,
pkgconf and Python (upstream Clar suite generation occurs during build()).
Build commands are in PKGBUILD. check() requires upstream offline and util suites
with a 600-second per-suite limit, then a dynamic-library API control of exact
version, required features, repository/blob roundtrip and invalid OID rejection.
Online, external SSH/server and invasive upstream suites are not selected.
Failures propagate; no --nodeps, --nocheck or permissive test wrapper is used.

Upstream `COPYING` contains GPLv2-only plus the project's linking exception and
all bundled notices, including LGPL xdiff, MIT SHA1/NTLM, BSD wildmatch and other
third-party sections. `LicenseRef-libgit2` refers to this full unmodified text,
installed with AUTHORS. It does not reinterpret the exception as GCC's exception.
External library license obligations remain those of their separately built
packages. Preserve the exact full upstream source archive, recipes and complete
notices alongside any future project binaries; native source-offer and delivery
review is still required. The original recipes and smoke/validation code are MIT.

## Source validation

Acquire the two URLs from the sibling source.json files outside the builder,
retain their original names, and run offline:

```sh
python -B packages/libraries/cachy-asahi-libgit2-reference/validate_sources.py --cache /absolute/source-cache
python -B packages/libraries/cachy-asahi-libgit2-reference/test_sources.py --cache /absolute/source-cache
```

The validator reads and hashes the complete files before opening archives, checks
member paths/types and required license/build/test sources, confirms llhttp's
generated release version and refuses a generator/npm tree. It extracts nothing.
The sole libgit2 fixture symlink is checked by exact path and `new.txt` target.
Controls corrupt each archive without changing its length and require refusal.
`.SRCINFO` is generated from each real PKGBUILD; normal makepkg source checks and
dependency checks remain separate and mandatory.

## Finite native plan and trust boundary

The failed actual RustSource367 run 44000620180 imported the qualified image and
prepared successfully; unchanged makepkg then exited 8 for missing libgit2.
`native-plan.json` pins the exact observed 350-package inventory and the required
baseline material versions. No existing 350 package may be replaced implicitly.

Reuse `scripts/build/build.py`, `scripts/ci/maintained-native` and the Rust source
lane's existing qualified-image/retained-output adapters. Do not add an operator
or weaken their source/trust/actor checks. The coordinator must supply a separately
reviewed project-source/provider profile: successor_v18 is official-only and
refuses project keys/conflicts, so these candidates are NOT admissible there.
Build two clean llhttp packages first on a qualified disposable ARM builder,
compare archives/payload/PKGINFO/BUILDINFO/MTREE, and inspect architecture, SONAME,
ELF dependencies, pkg-config and installed paths. With explicitly reviewed
project TEST signatures, install that provider only inside disposable builder
images, then repeat the two-build process for libgit2. Retain the exact 350+2
inventory and run the unchanged Rust recipe dependency checks and build.

Provider intake must join exact source archives/checksums/recipes/licenses,
qualified native outputs, complete BUILDINFO, package names/provides/conflicts,
all ELF closure, project TEST signature and separate key fingerprint, and baseline
inventory. It must not authenticate project packages with the ALARM keyring,
relabel foreign archives, widen official signature acceptance, or insert a
project provider into the existing v18 official-only profile. Review install,
remove and reinstall in the disposable image with no protected-platform changes.

Current result: source recipes and host source checks only. Native build pairs,
project TEST signing, actual native package solving/install/lifecycle, successful
Rust continuation, 16K compatibility, both M2 Air sizes and release are NOT RUN.
Host source compilation does not establish any of those gates. No performance
claim is made.

## Actual host validation

Private x86_64 CMake builds and DESTDIR staging passed for both candidates, with
no host installation. Both real package() functions also staged successfully,
including their license notices, into private directories. This is not a
makepkg archive or dependency-solving result. Full upstream CTest offline passed in 150.36 seconds
(2,931 successes, 79 upstream conditional skips), and util passed in 0.41 seconds
(441 successes, six conditional skips); no failure was ignored. All full output
is retained in evidence/ctest-full-output.log. Both focused API checks passed.
The host had CMake 4.3.3 privately installed but no registered pacman CMake;
`pacman -T` correctly refused `cmake>=3.25`. No makepkg package was built.

Installed private staging produced libllhttp.so.9.3 and libgit2.so.1.9 SONAMEs,
headers and pkg-config metadata at `/usr`. libgit2 links to libssl.so.3,
libcrypto.so.3, libllhttp.so.9.3, libpcre2-8.so.0, libssh2.so.1, libz.so.1 and
libc.so.6; the staged libraries have no RPATH/RUNPATH. Build-tree libgit2 had a
private llhttp RUNPATH, so its smoke/test runs used the newly compiled provider.
Host system library versions differ from the pinned native baseline and do not
prove that target ABI closure. Exact tools, binary hashes, paths and logs are in
evidence/host-result.json and the sibling llhttp evidence directory.

Both actual makepkg source checksum checks passed from the populated local cache
using `--verifysource --ignorearch` solely for source verification on x86_64.
The unchanged normal architecture check refuses the host as expected. Native
build execution must use normal aarch64 validation, with no --ignorearch. Exact
argv/environment records are in each evidence/commands.json.
