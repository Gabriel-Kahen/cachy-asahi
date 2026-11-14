# Independent Perl5.42.3 source candidate

This original MIT packaging defines **perl5.42.3-1.2**, an unselected maintained
source candidate. It is separate from the signed historical ALARM5.42.3-1
binary. The missing historical recipe-hash correspondence remains unresolved;
this recipe, its source snapshot and a successful build cannot establish it.
No shared manifest, default selection, native source family or Asahi platform
component is changed.

`source-lock.json` pins the official Perl/perl5 snapshot at
`bc3dab4d4f66de5ea67dda34e5feb5230a54c603` (annotated v5.42.3 tag object
`bfedb80da3c7c928c3acc902747d12b7c910948c`) and both upstream regex cache fixes,
in order: `568e6fd238867bb9e99fa3f47cba3169009239e0` and
`54cf3d44cbbedd17d774e9a37921963e8fd5d0cb`. The22,610,875-byte HTTP source snapshot
has SHA256 `16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725`.
Every patch and local build/check input has an explicit SHA256 in PKGBUILD and
`.SRCINFO`. These are retained immutable repository materials, not an upstream
release-signature verification or a claim about the old ALARM binary.

The `UPSTREAM-README`, `UPSTREAM-Artistic` and `UPSTREAM-Copying` bodies are exact
selected-source notices. Perl offers Artistic-1.0-Perl / GPL-1.0-or-later terms;
individual component notices and source headers retain their own terms. Package
staging copies the root notices and all named source LICENSE/COPYING/Artistic/
NOTICE files, preserving their relative paths. `LICENSE.packaging` covers only
this project's original recipe/check implementation. The separately retained
Arch recipe was inspected for facts and is not reused as packaging source.

## Build and installed layout

Upstream `README`, `INSTALL` and `README.linux` in the pinned snapshot document
Configure, make, the complete test harness and DESTDIR installation. The recipe
uses a shared/threaded64-bit interpreter, explicit conventional distribution
paths, two compiler jobs and two upstream harness jobs. It declares both
aarch64 and x86_64; that declaration proves no ARM build or M2 compatibility.

| Path | Ownership and purpose |
| --- | --- |
| `/usr/bin/perl` | Package-owned interpreter |
| `/usr/bin/core_perl` | Package-owned upstream tools; explicit historical command paths retained |
| `/usr/bin/<core-command>` | 29 package-owned relative symlinks to `core_perl/<core-command>`; no shell PATH hook |
| `/usr/share/perl5/core_perl` | Package-owned architecture-independent core modules |
| `/usr/lib/perl5/5.42/core_perl` | Package-owned Config, C extensions, headers and shared libperl |
| `/usr/share/perl5/vendor_perl`, `/usr/lib/perl5/5.42/vendor_perl` | Configured vendor-module search/install paths; external module packages retain their own files |
| `/usr/local/share/perl5/site_perl`, `/usr/local/lib/perl5/5.42/site_perl` | Operator-owned local modules; no contents or empty directories enter this package |
| `/usr/share/licenses/perl` | Exact upstream and packaging notices |

Runtime dependencies are glibc, gdbm>=1.17, db5.3, libxcrypt/libcrypt.so, bzip2
and zlib. `perl-text-diff` is optional for `ptardiff` archive comparisons; the
upstream tool refuses that function when Text::Diff is absent. GCC, binutils,
make, patch and Python build/check the source; procps-ng
supports upstream tests. Upstream's `BUILD_ZLIB=0` / `BUILD_BZIP2=0` controls and
explicit include/library paths select system compression libraries. Before the
full suite, `readelf` must establish actual DT_NEEDED entries for `libz.so.1`
and `libbz2.so.1.0`; a silently bundled build cannot pass. The full upstream
`TEST_JOBS=2 make test_harness` must succeed. The added
source-built interpreter check independently validates113 core-module provider
claims against its own Module::CoreList5.042003, exact configured paths, threads
and shared libperl, and loads actual DB_File, GDBM_File, Compress::Raw::Zlib,
Compress::Raw::Bzip2 and threads C extensions. A missing optional extension cannot
silently become build credit. Upstream default unsupported/skipped tests must
remain visible in the retained full harness log; no recipe test is excluded.

That source check found a concrete historical metadata discrepancy:
Scalar::List::Utils is1.69 in the selected source, while the old PKGINFO claimed
1.68_01. The candidate therefore provides `perl-scalar-list-utils=1.69`.
Pod::Man's source spelling `v6.0.2` is normalized only to the conventional dotted
package version `6.0.2`. Other provider facts must match the selected source;
historical metadata is not an authority for this recipe.

The requested C optimization flags are `-O2 -g -fstack-protector-strong -fno-plt`;
the linker requests RELRO/NOW, as-needed, and the explicit core-libperl RUNPATH.
LTO/debug-split packaging is disabled. Generic makepkg purging is disabled because
its default `*.pod` target removes runtime data needed by `splain`/`diagnostics`
and documentation needed by `perldoc`. Upstream POD files remain package-owned;
only the upstream package-local `.packlist` ledger is discarded. Upstream Linux
hints add their own flags;
the actual config.sh, command log and eventual BUILDINFO establish effective
flags and inputs. No architecture tuning or performance gain is claimed.

All installation uses `make DESTDIR="$pkgdir" install`. The read-only stage
checker requires the expected ELF architecture and complete essential paths,
and refuses system configuration, ALPM hooks, services, local/site contents,
special files, escaping links, unsafe modes and oversized payloads. It executes
no staged program. There is no install scriptlet or post-transaction hook.

The observed historical package had3,231 paths and one229-byte old-module warning
hook. Its body invokes Perl/find/pacman to inspect old module directories. That
unreviewed historical hook and its helper/profile scripts are not copied. Before
any future adoption, the operator must separately review/rebuild external XS
modules and module-search/PATH changes; shared5.42 paths are not an ABI acceptance
claim. Removing this package removes its package-owned files, while external
vendor packages and operator local/site module contents remain separately owned.
Actual ALPM install/upgrade/remove preservation remains untested for this recipe.

## Controlled validation

Build only in an owned disposable environment with the declared dependencies
already present. No dependency installation, privileged build or host package
installation is part of this route. An explicit opt-in gate prevents accidental
preparation:

```sh
# From an owned recipe copy with the exact source snapshot pre-staged:
env CACHY_ASAHI_PERL_BUILD=1 SOURCE_DATE_EPOCH=1785628800 \
  makepkg --cleanbuild --force --nosign --noconfirm --log

# Independent metadata/layout/refusal controls; no build or installation:
python3 -B packages/port/perl5423-source-candidate/test_recipe.py -v
```

The original controlled host build is recorded separately in `validation.json`
for **5.42.3-1.1/r3**, unchanged. The packaging-only **1.2** result and command
checks are recorded in `command-validation.json`. Host x86_64 results
cannot satisfy native ARM,16K, installed ABI/upgrade/removal, M2 hardware,
performance, historical binary correspondence, production signing/distribution
or release acceptance. The candidate stays unselected.

The retained **1.1/r3** clean host run completed makepkg successfully with both required
system compression libraries: **2,920 files / 1,351,653 tests /411seconds**,
upstream result PASS, with157 reported whole-file skips retained in
`validation.json`. Those include platform/developer/author fixtures, unavailable
optional modules/SSL/locales, isolated networking, and lengthy/4–10GiB tests;
they are not represented as exercised features. The113 provider/five extension
checks and all10 recipe controls pass. A separate read-only staged smoke loaded
its own Config and eight staged C-extension objects as Perl5.42.3; the old Scalar
provider claim was refused.

Retained **1.1/r3** unsigned host archive: **21,843,532bytes**, SHA256
`6f563b2dc3c3fb9c2d3ce5d3c3d304c6cfff29dffc75ef7ce50a2b7ce513e371`.
All54 packaged ELF files are x86_64. The archive has no ALPM hook or install
scriptlet and retains exact dual notices. Earlier failed/changed-composition
outputs remain separate facts in `validation.json`; they are not a reproducible
pair. The host Perl remains5.42.2-2.1; no package was installed on the host.

## Command delivery and packaging-only 1.2 validation

The r3 layout was reproduced with the actual candidate interpreter, its core
modules and shared library mounted at their configured paths in a read-only,
network-isolated bubblewrap overlay. With `PATH=/usr/bin:/bin`, all29 tool names
were unresolved; explicit `/usr/bin/core_perl/prove --version` succeeded using
Perl5.42.3. No historical profile script is needed for the1.2 solution.

`stage_commands.py` validates the complete pinned29-command set and all vacant
destinations before creating `/usr/bin/<name> -> core_perl/<name>`. It refuses
existing files, directories, links and dangling links without replacing them.
The original scripts, explicit paths and `perlbug`/`perlthanks` hardlink remain.
These links are ordinary package payload entries, removed with the package;
there is no profile, install scriptlet or hook. Existing conflicting files
require normal package-manager resolution; the recipe never forces replacement.
Operator `/usr/local/bin` and external `/usr/bin/vendor_perl` commands remain
separately owned. A PATH with vendor tools before core tools must be configured
by its operator; this package does not choose that policy.

Actual invocation also found that default makepkg `*.pod` purging broke
`splain`, although upstream source tests had passed. The1.2 recipe retains
upstream POD runtime/documentation files and stage-checks `perldiag.pod`.
Final archive comparison against r3 finds exactly29 added relative links and
257 added POD files whose bytes match the original source-built tree; all2,973
existing `/usr` entries retain their type, mode, ownership, timestamps, links
and contents. Only `.PKGINFO`, `.BUILDINFO` and `.MTREE` change besides additions.

The new unsigned **1.2** archive is **24,550,858bytes**, SHA256
`c4924603c063963ad92e1935e2f9637d3a7e21cd0e944635a450abe966d4a944`.
It was produced by `makepkg --repackage --force --nosign --noconfirm --log`
from a separate copy of r3's built tree. All11 source pins were checked before
repack. The prepare/build/check function bodies and the11,632-node built-tree
map are unchanged, both before and after repack; the original r3 archive is
unchanged. The upstream suite was not rerun for these packaging-only changes.
The repack log retains upstream installer `libfakeroot.so` preload warnings;
archive root ownership and unchanged existing payload were checked independently.

All13 recipe/staging/refusal controls pass. Actual extracted-archive smoke
resolves and invokes all29 tools through PATH, syntax-checks all29 scripts,
and performs63 child invocations. `prove` runs five assertions about the
candidate interpreter, configured paths and real core XS loading. Functional
checks cover conversions, hashing, archive creation/listing/grep, generators,
`splain` diagnostic expansion and `perldoc -f print`. `ptardiff` resolves and
executes, then correctly refuses archive comparison because optional Text::Diff
is absent; that comparison is **NOT RUN**, and its optional dependency is now
explicit. Version/help checks do not certify the tools' complete behavior.
The known-input JSON conversion passes while `json_pp` retains an upstream
duplicate `v`/`V` option warning; full option semantics are not certified.

```sh
python3 -B packages/port/perl5423-source-candidate/test_staged_commands.py \
  --root /absolute/path/to/extracted-perl-package
```

A separate manifest-owned leaf-removal simulation with the genuine payload
removes all package commands while preserving bytes, modes and inodes of seven
operator/vendor sentinels, including local and vendor commands/modules and an
operator profile. This is **not an ALPM installation or removal result**.
`command-validation.json` pins the private baseline, repack, command and removal
evidence. ABI/external XS acceptance, actual ALPM install/upgrade/remove,
native ARM/16K, both M2 sizes and release acceptance remain unqualified.
