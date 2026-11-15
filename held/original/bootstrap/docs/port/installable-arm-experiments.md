# Installable ARM-C01 zlib experiments

These two **unselected development packages** extend the pinned
[ARM-C01 experiment](arm-experiments.md) into a side-by-side installation candidate.
They are not an optimization winner or a replacement for the system zlib.
The accepted [C01 native record](../validation/arm-c01-native-20261015.md) covers
older isolated artifacts; it does not establish these package builds or lifecycle.

| Package | Entire executable/library prefix | One compiler difference |
| --- | --- | --- |
| `cachy-asahi-zlib-baseline` | `/usr/lib/cachy-asahi/experiments/zlib-baseline` | `-fno-lto` |
| `cachy-asahi-zlib-lto` | `/usr/lib/cachy-asahi/experiments/zlib-lto` | `-flto=2`, compile diagnostic `-Werror=lto-type-mismatch` |

Both are version `1.3.2-1`, with runtime dependency `glibc` and build dependencies
`gcc`, `binutils`, `make` (plus the existing makepkg/base-devel builder).
Both preserve the existing `-O2 -g -march=armv8-a -mtune=generic`, hardening,
page-layout flags, two-job limit, fixed epoch, GCC archive wrappers and per-target
random seed from C01. Makepkg's extra build flags, automatic LTO, debug splitting,
and stripping are disabled in each recipe; the job configuration also disables automatic dependency inference. There is no shared
`libz.so`, default search-path integration, pkg-config entry, `/usr/bin` command,
hook, scriptlet, `provides`, `conflicts`, `replaces` or user configuration.
The only paths outside each private prefix are its own package license directory.

The pinned unmodified upstream archive is `https://zlib.net/zlib-1.3.2.tar.gz`,
1,502,830 bytes, SHA256
`bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16`.
Each package carries that complete corresponding source archive, its actual
PKGBUILD, the original project probe and strict decoder sources, and project MIT
notice. The zlib notice is installed separately under
`/usr/share/licenses/<package>/LICENSE.zlib`. The static library and generated
headers remain within the package prefix. The generated Makefile records effective
flags/prefix; configure logs are retained in job evidence rather than packaged,
because their timestamps differ between clean builds. No upstream source patch
or newly invented tuning flag is introduced.

## Functional workload

Each prefix contains `bin/minigzip`, `bin/strict-gzip` and `bin/probe`, linked
explicitly with that build's local `libz.a`. This still dynamically depends on
the recorded glibc/loader. `probe --installed-check` verifies its real executable
path equals its compiled prefix and that header/runtime versions equal 1.3.2.
It checks 21 compression/decompression cases (levels 1/6/9; empty, one-byte,
16 KiB boundaries, 65,537-byte and 1 MiB inputs) and 42 corrupt/truncated stream
checks. `--build-check` runs the same checks before packaging without requiring
an installed path. These are finite functional tests, not throughput measurements.

The job also runs seven public deterministic inputs, three compression levels,
Python independent decompression and all active variants' strict gzip decoders.
For two coexisting variants that is 42 encodes, 84 cross-decodes and six strict
negative checks per phase. The original C01 strict driver rejects corrupt CRC,
missing trailers and trailing bytes with exit 2. Upstream minigzip alone is not
a strict truncation oracle. No private workload, training profile or uncontrolled
random input is used.

## Prepare without installation

`scripts/experiments/package_variants.py audit --root <checkout>` checks source
pins, distinct identity, reviewed flags and package boundaries without evaluating
the recipe. `prepare` copies a finite, checksum-bound offline context:

```sh
python3 -B scripts/experiments/package_variants.py prepare \
  --root /absolute/reviewed/source \
  --source /absolute/retained/zlib-1.3.2.tar.gz \
  --packages /absolute/accepted-341-packages.lock \
  --base-commit <40-hex-source-base> \
  --output /absolute/new-context
```

The complete original builder inventory is pinned to SHA256
`fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25`.
The base commit is a source reference, not a claim that an uncommitted proposal is
in Git. Actual executable source/recipes and both retained archives are bound
by `context.json`'s complete hash map; externally retain its SHA256. After source
integration, regenerate the context from the accepted commit. A changed source,
helper, package lock or recipe invalidates the context. No tool installs packages
in `audit` or `prepare`.

## Disposable native ARM job source

The context includes the standalone helper and all offline recipe inputs. Root's
native job owner provisions a fresh immutable image from the existing accepted
signed 341-package bootstrap, retains that exact image identity and acquisition
records, and supplies this entrypoint **inside a disposable native aarch64 Docker
container**:

```sh
python3 -B /inputs/scripts/experiments/package_variants.py native-job \
  --context /inputs --context-sha256 <externally-held-context-sha256> --output /out
```

The owner binds only the context read-only at `/inputs` and a new evidence directory
at `/out`; uses container root for this local ALPM lifecycle and ordinary `alarm`
for every makepkg invocation; sets `CACHY_ASAHI_DISPOSABLE_ZLIB=1`; disables
networking; and limits the container to two CPUs, 4 GiB, 256 PIDs, private 2 GiB
executable `/tmp`, and an outer 1,250-second timeout. Root filesystem writes stay
inside the disposable container. Do not mount the host root, Docker socket,
keys or unrelated state. Preserve the accepted builder's masked hook directory
`/builder-disabled-hooks`. This is a development-local unsigned transaction:
the temporary ALPM configuration explicitly disables signature requirements only
inside this container; it confers no signed repository/release acceptance.
Do not invoke `native-job` on the workstation or reference Mac.

The entrypoint verifies the complete base inventory before building. Each variant
gets two fresh builds of release 1 at the same canonical path, followed by a
metadata-only `pkgrel=2` build for a real upgrade. It requires complete payload
and archive-byte identity between release-1 rebuilds, retains all six packages,
logs/tool versions and Makefile/configure records, validates AArch64/static-zlib
linkage, 16 KiB ELF layout and the expected LTO sections, then runs:

1. Baseline install and probe/workload.
2. LTO install alongside baseline, checking both and cross-decoding.
3. Upgrade both to release 2 and repeat the transaction.
4. Remove baseline, verify surviving LTO, then remove LTO.
5. Reinstall both release-2 artifacts and finally remove both.

Every phase checks the complete base-plus-experiment package inventory, relevant
prefix/license directory presence or absence, the active installed payload against
the archives, and unchanged system zlib/libc/pacman/config sentinels. Only declared
private-prefix files and package metadata are accepted in an archive; links,
special files, setuid modes, unapproved paths and unexpected ownership fail.
Failures and timeouts fail the job and retain diagnostics. The owner must remove
and independently verify absence of its exact container on success, failure or
cancellation; `result.json` explicitly leaves outer cleanup to that owner.
The 1,200-second inner budget and process-group cleanup do not replace that outer
container cleanup. No workflow or branch is published by this helper.

## Evidence limits

Host checks cover both real makepkg source-verification/metadata paths and a
private host-ISA build of the pinned upstream source/probes with the finite cross
decoder workload. ARM ISA options are deliberately omitted in that host fixture;
its success is host plumbing evidence only. Native package build/rebuild,
installed ALPM behavior, installed generic 16 KiB execution, both physical M2 Air
models, performance/power and release admission remain **NOT RUN** until their
specific jobs execute. An ELF layout check alone gives no 16 KiB runtime credit.
These new executables also cannot inherit the older C01 artifacts' runtime result.
No performance timing or winner-selection logic exists here.
