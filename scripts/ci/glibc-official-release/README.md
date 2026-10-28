# Official GNU release native build lane

Prepared, unselected source bundle; native package execution NOT RUN here. This
separately named GNU2.43 candidate does not resolve the held binary/GNU8362 source
gap. The source lock and complete archive are obtainable now, with real detached
signature evidence and explicit current key-expiration/trust limitations.

`acquire.py --output ABS_FRESH_INPUTS` fetches exactly the hash/size-bound official
GNU2.43 tar.gz, detached signature and GNU keyring. Three parallel public-only
requests have 30-second socket/180-second per-file limits. No secret transport or
package/source execution occurs. A changed official object fails its pin.
`materialize.py --recipe ABS_RECIPE --inputs ABS_INPUTS --output ABS_FRESH_BUNDLE`
checks all exact bytes, bounded archive paths/modes/types/contents and the derived
release-payload tree; then public-only gpgv verifies the exact signature subkey,
primary and signing epoch. BADSIG/revocation/invalid signatures fail. Current
KEYEXPIRED/EXPKEYSIG is explicitly retained as an unselected trust limitation.
The output contains the concrete PKGBUILD, full original source/license notices,
signature, publisher keyring, source lock and authentication receipt.

The complete source is 40,287,809 bytes, SHA256
`e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004`.
Its derived payload identity is `97ac10e146c65ecbd22d36e3743eb5b5e9166ae9`,
20,740 files and 267,112,798 payload bytes. This is not an upstream Git revision.
Inspection limits remain 96 MiB compressed, 512 MiB payload, 60,000 members,
64 MiB/file and 180 seconds, with a decoded tar-header/PAX bound as well.

## Native build-pair integration

`run.py` is a separate adaptation of the adopted glibc-owned-rebuild owner.
Inputs retain reviewed bundle/harness manifest SHA256 pins and an explicit
32-character `--owner-token`. The non-executing default validates inputs; only
`--execute` starts native work. The source archive/signature are reverified before
actors. Required other flags are `--bundle`, `--base-dir`, `--source-root`,
`--smoke-dir`, `--smoke-manifest`, and `--output` (absolute simple paths without
symlink parents). Root supplies `--bundle-manifest-sha256` and
`--harness-manifest-sha256` after materialization/review. The manual workflow
performs exactly this sequence using its pinned recipe/source acquisition.

The borrowed base must be the existing accepted owned574 native ARM image,
matching its report/token/immutable image ID and lock
`cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac`.
No image build/commit/removal or package installation occurs in the consumer.
The immutable image is read-only in ordinary offline containers with no
capabilities/new privileges, 4 CPUs, 12 GiB, 1024 PIDs, 8192 descriptors and a
512 MiB tmpfs. A private account overlay preserves getpwuid/getgrgid behavior;
only the consumer's own work/tmp paths are writable. Preflight requires at least
40 GiB measured free space (a reserve, not a disk quota).

Both clean builds use identical `/work` paths and fixed epoch 1769201640. Ordinary
compilation and applicable GNU `check`/`check-abi` must pass; all named statuses
are retained. FAIL, XPASS, ERROR, malformed statuses or nonzero make exits fail.
UNSUPPORTED/XFAIL are reported honestly and cannot prove those features work.
No tests are removed. Concrete `.BUILDINFO` must bind to the actual PKGBUILD.
The resulting archives must reproduce byte-for-byte.

Private extraction validates paths, links and separate package identity. Static
ABI compares the baseline loader plus ten DSOs, including exact public symbol
version/defaultness, type, binding, visibility and OBJECT/TLS size. Candidate C
headers additionally compile with `-nostdinc`, candidate includes, recorded GCC
builtin headers, and a copied bounded kernel-only include tree. The dependency
receipt refuses bootstrap libc header fallback. It is a declared C-header
surface, not complete C++/header ABI acceptance. No candidate executes in this
header check.

The adopted canonical runtime smoke is consumed unchanged at manifest SHA256
`e10336aef200731c7dd4b06546b718e095c1ecf7718e4a25fa57d6bbed6270a6`.
It compiles against recorded bootstrap headers, executes using the explicit
candidate loader/data, and proves mapped/hash identities in parent and child.
The consumer requires its complete native receipt/cases/source identities.
Neither a zero CLI exit nor the header check replaces GNU tests/runtime proof.
The held process runtime remains pinned to
`8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821`;
only a private exact-request descriptor facade adapts 128 to 8192.

Work deadline is 15,000 seconds, each native build 6,300 seconds, each ABI/header/
runtime phase 900 seconds, plus a separate 900-second cleanup reserve. A held
CLOEXEC exclusive consumer lease precedes every actor. Ordered external cleanup
must acquire it before reconciling the five exact token/image-bound container
names; a live owner, foreign object or unknown daemon state preserves the
producer and yields failure. No daemon-wide cleanup occurs.

## Concrete manual workflow

The proposed `.github/workflows/native-arm-glibc-official-release.yml` is manual
only, 360-minute native ARM job limit, source input equal to the workflow and
checkout revision before any secrets. It reuses the exact existing six retained
private input files (their existing 22 chunks), fourteen public input files from
04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd, and the unchanged token-owned574
producer. It introduces no secret or secret upload. Producer cleanup follows
all consumer retirement, including error/cancellation paths. Unknown producer
build/cleanup state fails and remains owned for Root recovery.

Closed public evidence includes the two exact package archives (256 MiB each),
package metadata/SRCINFO, GNU named test summaries, ABI/header/runtime receipts,
bounded diagnostics and complete original GNU source/signature/keyring plus
build scripts/notices. Aggregate cap is 768 MiB. GNU/build logs may have explicit
bounded tails; per-test summary receipts are never silently truncated. No base
cache, private seed log, account overlay, toolchain image or secret enters the
export. Upload is from that closed export only, short retention, after ordered
cleanup. Missing/oversized required evidence fails the receipt and cannot yield
native acceptance.

Tests are inert synthetic archives/statuses/transport facades only. No compiler,
Docker, package, recipe, host installation, CI dispatch or Git actor runs during
preparation. The retained real source inspection and gpgv validation are data and
cryptographic evidence. Root owns adoption, actual native builds and any later
lifecycle/platform/security/trust/admission decisions.


The check-repair revision uses the shorter versioned private prefix
/opt/caa/g243a1 and explicit catalog localedir /opt/caa/g243a1/l. The resulting
17-byte string plus NUL preserves the original18-byte _nl_default_dirname ABI
object without changing an ABI list or ABI comparator. stage.py/run.py and
package identity track pkgrel2 and that exact private root. Source materialization
requires the two exact declared patches as well as the unchanged signed GNU
release inputs and payload identity. The full GNU check/check-abi and collector's
strict FAIL/XPASS/ERROR policy remain. The only timeout scale is one named malloc
variant's standard TIMEOUTFACTOR=5. Five stale expected-failure annotations are
removed, so regressions become FAIL rather than acceptable XFAIL. Native repair
results are NOT_RUN; original actual38898464517 remains failed.


Pkgrel3 baseline multiarch correction: the recipe now explicitly configures
--disable-multi-arch, selecting the pinned standard AArch64 assembly sources
instead of IFUNC-dispatch multiarch wrappers. Actual38906503054 pkgrel2 passed
GNU check/check-abi but failed the independent public-symbol gate for five
FUNC->IFUNC changes; memchr/strlen also changed WEAK->GLOBAL. That actual stays
FAIL, with the second build/header/runtime execution NOT RUN. All eleven-library
static ABI gates and exact symbol binding/type/version/OBJECT/TLS checks remain
unchanged. No .abilist or source assembly is patched. The source lock layout
records multiarch=disabled; configured_features and package_version travel in
bundle and runtime receipts and are checked before actors. PKGBUILD must contain
the concrete option and pkgrel3; contradictory declarations are refused. Staging
and closed retention accept only the exact new -3 archive identity. The source
manifest and manual workflow pins bind the updated harness; native validation
must rerun the complete tests/ABI/headers/runtime and pair. No performance,
16KiB, physical M2, installation or admission credit follows from source audit.
