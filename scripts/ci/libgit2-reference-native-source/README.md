# Original libgit2 native pair preparation

This separate successor reuses the llhttp framework at frozen integration
`7770823e19115eeba2bbb81f1abf5643cc4258c6`. It prepares source and a manual
workflow; native ARM builds, signing, dependency installation, native16K, both
M2 Air sizes and release are **NOT RUN**. Performance is **NOT MEASURED**.
There is no actual Root acceptance, native image or issued Source in this tree.

The original project recipe is pinned at
`7e4d4ce45b19e45b6241af6f4fd787e67a1cdf18`, upstream libgit2 v1.9.7 commit
`49e408b3208bc3093757a1c2db938d3590f3f412`. Its 7,758,424-byte archive SHA256 is
`173c45822177d73bb1a97555d864ad04a3e0486eb0bc3455443a4669a35d8aa2`.
`recipe-pin.json` records every original recipe/evidence file, the complete
15,122-member archive closure including modes and its exact fixture symlink,
and upstream AUTHORS and COPYING. COPYING includes the linking exception and
bundled notices. HTTPS/checksum provenance is not an upstream signature.
The original recipe is not proof of correspondence to an ALARM recipe or binary.

## Required llhttp dependency

The libgit2 recipe retains normal dependencies: glibc, OpenSSL, libssh2, pcre2,
zlib and `llhttp=9.3.1`, with CMake>=3.25, Ninja, pkgconf and Python build tools.
There is no `--nodeps`, `--nocheck` or substitute provider path. The inherited
signed349 bootstrap, all original provider versions and official trust remain
unchanged. Only `cachy-asahi-llhttp-reference 9.3.1-1` may produce inventory350.

Actual dependency operands are **UNBOUND**. Construction requires six explicit
ordinary existing DATA files: the exact original native aarch64 llhttp XZ
package, detached signature, public PROJECT TEST key, native-pair receipt,
offline signing receipt and Root acceptance receipt. The expected descriptor
must contain all six byte pins, the public TEST fingerprint and the fixed
original source/license identity. `project-test.TEMPLATE.json` contains no
usable pins or acceptance. Host unsigned packages, foreign ALARM signer data,
different source/license/version/architecture, missing operands and changed
bytes refuse. No key is generated or signing operation supplied here.

Root must assemble the native receipt join explicitly from the accepted llhttp
pair, exact package pin and original source/license evidence. Its required
top-level `package`, `source` and `license` fields are a separate Root-reviewed
join; the predecessor finisher output does not supply them by itself.

Receipt JSON does not authenticate Root. Before actors, independent Root
runtime and admission documents must bind both the tuple SHA256 and exact Root
receipt byte SHA256. The Source actual selectors stay NULL. A matching DATA
shape alone never grants execution or establishes signature validity.

After admission, a dedicated offline disposable image layer uses a separate
`/project-test-gnupg` keyring, verifies the exact primary public fingerprint and
detached GPG VALIDSIG, and performs normal local pacman `-U` with both
`SigLevel = Required TrustedOnly` and `LocalFileSigLevel = Required TrustedOnly`.
It has no configured repository or network. The TEST key's primary/subkey
fingerprints must be disjoint from every actual official ALARM primary/subkey;
the official349 keyring must remain unchanged. Exact349 before/exact350 after
inventories, full original349 package-owned files and local package-database
bytes, and signature/transaction receipts must join before either of two clean
normal libgit2 makepkg builds. Inventory counts alone are insufficient.
This stage is builder-only PROJECT TEST installation, not Asahi target acceptance.

The comparator retains whole archive, payload, PKGINFO and BUILDINFO equality.
The finisher additionally requires both normal check phases, passed upstream
offline/util suites and smoke markers, exact350 BUILDINFO and retained locks,
distinct clean identities, current archive/member custody, original upstream
COPYING/AUTHORS and the fixed AArch64 shared-library dependency closure including
`libllhttp.so.9.3`. XZ basename/magic and finite decompression gates precede
inspection. ELF page geometry does not establish native16K or M2 runtime results.

## Construction boundary

All inputs are local explicit DATA. Preparation acquires nothing, invokes no
Docker/GPG/pacman/APT actors, and supplies no private key or actual runtime data.
Fresh output must be outside both source checkouts. Construction remains blocked
until the real accepted dependency tuple exists; there is no material fallback.

```sh
python3 -I -B scripts/ci/libgit2-reference-native-source/prepare.py \
  --root /absolute/framework-checkout --recipe-root /absolute/recipe-checkout \
  --archive /absolute/libgit2-1.9.7.tar.gz \
  --dependency-paths /absolute/six-operand-paths.json \
  --dependency-expected /absolute/root-reviewed-tuple-descriptor.json \
  --output /absolute/fresh-libgit2-Source
```

The path JSON has exactly `package`, `signature`, `public_key`, `native_receipt`,
`signing_receipt` and `root_receipt`, each an absolute path. The expected JSON
extends `project_test.DEFAULT_EXPECTED` with `fingerprint` and exact six `pins`.
Root must separately publish/register/read back the closed Source, bind its
whole map, supply fresh independent genuine admission/runtime and once-caller
custody, and perform any authorized dispatch. There is no reserved Source label
or claimed publication in this proposal.

The inherited zero-host-APT policy stays in force: only qualified existing host
tools, zero host package-manager commands/mutations and no bsdtar consumer.
Controller512MiB/1CPU, owner2GiB/1CPU and daemon6GiB/4CPU cgroup limits, swap0,
bounded PIDs and physically allocated12GiB ext4 storage remain required, with
10GiB observed available RAM and14GiB disk minimum. The libgit2 pair allowance is
2400s; each ordinary build allows900s. The controller work/outer scope limits are
2850/2940s. Dedicated socket/storage ownership, PID/starttime/PIDFD, natural reap,
empty twice and retained custody remain required. Uncertain retirement HOLD.
These are proposed admission limits, not measured native completion times.

## Actor-fenced DATA controls

```sh
LIBGIT2_DATA_RECIPE_ROOT=/absolute/original-recipe-checkout \
LIBGIT2_DATA_ARCHIVE=/absolute/libgit2-1.9.7.tar.gz \
LLHTTP_DATA_ARCHIVE=/absolute/llhttp-9.3.1.tar.gz \
python3 -I -B -Werror::ResourceWarning \
  scripts/ci/libgit2-reference-native-source/test_data.py
```

The controls read genuine original recipe/archive/license material and check
finite framework derivation, strict operands, provider inventory preservation,
offline Required-signature plan generation, resources, no-host-APT, XZ, ELF and
finisher refusals. Missing explicit source operands report SKIP. An audit fence
forbids process, fork and network actors, including code imported by the tests.

Positive synthetic key/signature/receipt/package fixtures are named **MODEL**.
They exercise DATA shapes only; cryptography is `NOT RUN`. A temporary MODEL
constructor output checks complete namespace, pins, null actuals and custody,
then is removed. It is never a retained real Source, Root grant, signed package
or native runtime tuple. MODEL postcondition results are not actual build or
dependency-installation acceptance. No model is used to fill production operands.
