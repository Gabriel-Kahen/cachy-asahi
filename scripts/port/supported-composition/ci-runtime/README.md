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

From the checkout root:

```sh
docker build --pull=false \
  --file scripts/port/supported-composition/ci-runtime/Dockerfile \
  --tag cachy-asahi-supported-composition-tests \
  scripts/port/supported-composition/ci-runtime
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --pids-limit=128 --memory=512m \
  --tmpfs /tmp:rw,nodev,nosuid,noexec,size=256m,mode=1777 \
  --mount "type=bind,src=$PWD,dst=/work,readonly" \
  cachy-asahi-supported-composition-tests
```

The build requires HTTPS access to the fixed official image and archive; it
installs prerequisites only in disposable image layers. Local rootless bridge
networking timed out during the actual build. Adding `--network=host` to the
build command succeeded here; the test invocation still used `--network=none`.
CI may use its ordinary build network if available. No host package install or
host configuration change is part of either command.

The image defaults to UID/GID 65534. `run.py` refuses root and any libalpm version
other than 16.0.1, prints actual runtime identity/scope, and runs only
`test_compose.py` and `test_maintenance.py`, each with a 120-second timeout and
`-I -B -Werror::ResourceWarning`. It reads the bind-mounted checkout and writes
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
(or0 after both suites), so CI should propagate its Docker exit directly.
