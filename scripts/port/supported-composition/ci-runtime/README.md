# Reviewed libalpm host test runtime

This finite x86_64 CI runtime runs the supported-composition and maintenance
controls with genuine libalpm 16.0.1. The existing Ubuntu/libalpm 13 controls can
continue separately. No old engine or ABI gate is changed, and no resolver is
modeled or skipped. This is neither a native ARM builder nor a target image.

The official Arch base manifest is pinned to
`sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae`
(official image source revision 457808cdaf8ca50c14692f1099c2efd63049bd00).
Its actual `pacman --version` reports libalpm 16.0.1. The Dockerfile checks the
official 2026/11/09 core DB pin, 131666 bytes, SHA-256
`aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae`,
and uses only that fixed snapshot to add Python 3.14.9-1 and mpdecimal 4.0.1-3.
Pacman's package signature requirement stays enabled under the pinned image's
Arch keyring. Only these two packages were added in the actual local build.
All other runtime packages originate in the exact base image. The resulting
`/opt/composition-runtime-packages.txt` records their installed versions.

## Exact host acquisition and offline installation

The foundation shard previously made its first archive connection inside the
image build. PR485/486/487 each stopped there with curl28 after60 seconds, before
the DB hash, package installation or composition tests. Acquisition now runs on
the host, outside that build bridge, and prepares the complete immutable input
set before the image build starts.

`inputs.lock` pins the same131666-byte core DB and both package archives by exact
filename, size and SHA256. Package sizes/hashes and the two detached signature
packets are independently joined to that DB's `FILENAME`, `CSIZE`, `SHA256SUM`
and `PGPSIG` records. The signature packets are decoded from the whole-pinned DB;
they are not new keys or trust decisions. No archive/signature bytes are vendored.
The package DB reports PSF-2.0 for Python and BSD-2-Clause for mpdecimal.

Sources are the fixed [2026/11/09 core DB](https://archive.archlinux.org/repos/2026/11/09/core/os/x86_64/core.db),
[Python3.14.9-1](https://archive.archlinux.org/packages/p/python/python-3.14.9-1-x86_64.pkg.tar.zst)
and [mpdecimal4.0.1-3](https://archive.archlinux.org/packages/m/mpdecimal/mpdecimal-4.0.1-3-x86_64.pkg.tar.zst).
These are exact official archive objects, with no moving mirror/version fallback.
Pacman's documented [local file repository](https://man.archlinux.org/man/pacman.conf.5.en)
provides the same `-S` transaction from the staged files. `SigLevel = Required
DatabaseOptional`, the pinned image keyring, explicit package versions and
libalpm16.0.1 assertion remain. The image verifies the whole input-lock checksum
and every file's size/SHA again, installs with `RUN --network=none`, and asserts
both installed package versions. Missing dependencies fail offline.

The helper makes at most three attempts per public transfer, with10-second
connect and60-second request caps, an explicit process timeout and one180-second
deadline across the entire acquisition. Only transient transport/HTTP failures
retry. Hash/length errors, certificate errors, malformed DB joins and unsafe
cache operands fail closed. Partial downloads never enter the cache/context.

The workflow restores/saves only these five exact input files, using an exact
key bound to the input lock and Dockerfile with no restore-key fallback. Every
hit is reverified; a missing or corrupt ordinary file is reacquired from its
same pinned URL, and signatures are rederived without another request. Save
follows successful complete verification, before image/tests, so later failures
do not prevent verified inputs from being retained. A warm verified cache needs
no archive network. The existing APT `.deb` cache and prerequisite/attr setup are
unchanged. Cache-service restore/save failures are optional optimization failures;
the exact-input acquisition, verification, image build and suites remain required.
The fixed base image still requires its ordinary registry pull when
not locally retained; this repair does not claim to cache or qualify that pull.

From the checkout root (the build context must be fresh):

```sh
composition_work=$(mktemp -d)
python3 -I -B -Werror::ResourceWarning scripts/port/supported-composition/ci-runtime/test_acquire.py
python3 -I -B scripts/port/supported-composition/ci-runtime/acquire.py \
  --cache "$composition_work/cache" --context "$composition_work/context"
docker build --pull=false \
  --file scripts/port/supported-composition/ci-runtime/Dockerfile \
  --tag cachy-asahi-supported-composition-tests \
  "$composition_work/context"
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=128 --memory=512m \
  --tmpfs /tmp:rw,nodev,nosuid,noexec,size=256m,mode=1777 \
  --mount "type=bind,src=$PWD,dst=/work,readonly" \
  cachy-asahi-supported-composition-tests
```

Host acquisition and a missing base image require their respective HTTPS
sources. Package installation occurs only in the disposable image, offline;
the test invocation also retains `--network=none`. No host network-mode,
package installation or system configuration change is required. BuildKit is
required for the Dockerfile's per-RUN network restriction.

Deterministic MODEL controls cover cold/warm and partial/corrupt caches, exact
DB/signature joins, changed input locks, unsafe links/paths, interrupted requests,
retry exhaustion and total deadlines without network or package/image tools.
Actual public acquisition receipts separately retain all five whole-file pins.
Acquisition does not perform GPG signature verification or execute packages;
the unchanged required-signature transaction does that in the pinned image.
An acquisition/control PASS is not a Docker build or composition-suite PASS.

## Runtime boundary and earlier retained validation

The retained image/test results below predate this acquisition repair. No new
Docker build was run for it; the new offline image install and suites still need
the separately owned hosted check.

The image defaults to UID/GID 65534. `run.py` refuses root and any libalpm version
other than 16.0.1, prints the runtime identity and scope, and runs the
composition, maintenance, staged archive mapping, signed operand assembly,
signed addition source indexing, signed recipe history, maintenance archive
joins, and passive guest staging. Each suite uses a 120-second timeout and
`-I -B -Werror::ResourceWarning`. The passive guest suite uses a small image
fixture with an injected free-space measurement so it runs in the CI tmpfs.
The runner reads the bind-mounted checkout and writes
only disposable user state under container `/tmp` and `/dev/shm`. Linux shared
memory tmpfs supplies the real read-induced-atime regression even when host
`/tmp` has noatime. No checkout content or host state is modified.

The first actual isolated run exposed a false DATA-change refusal: comparing
complete `stat_result` values included atime advanced by the read itself. The
new-directory Reader now preserves device/inode/mode/nlink/UID/GID/size and
mtime_ns/ctime_ns checks plus exact SHA, while excluding atime. Regression
controls force a real atime update and still refuse actual content replacement
and inode replacement during reads. No frozen platform module changed.

After that correction, the actual isolated runtime passes all 16 composition
and eight maintenance controls. It retains real dependency/provider/conflict
preparation under the frozen engine and reports native ARM/hardware NOT RUN.
These synthetic-metadata host controls do not accept the real 626 transaction,
source/license closure, upstream freshness, production trust or hardware.

The actual local build/test logs, installed package list and scoped receipt are
retained under `work/supported-composition-ci-runtime-20261114/`; no image was
published. `run.py` takes no arguments and returns the first failed suite exit
(or 0 when all suites pass), so CI should propagate its Docker exit directly.
