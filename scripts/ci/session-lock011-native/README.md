# SessionLock 0.1.1-1 native qualification

This opt-in lane targets `cachy-asahi-session-lock` **0.1.1-1**, source
`d721a0eac52b348c2370ff4c536f624923752c57`. Idle watching requires an explicit
action and timeout. The 0.1.0-1 helper and Settings 0.1.1-1 coupled native
drafts retain their original pins and scope.

## Native build pair

Use an ordinary user and a local native AArch64 Linux Docker daemon. Obtain a
reviewed immutable `sha256:` image ID for the signed ALARM 349-package builder
used by the earlier component routes. The fresh image and its authenticated
bootstrap provenance are operator inputs. The
[exact package inventory](../session-lock-settings-native-source-v2/fixtures/expected349.lock)
has SHA-256 `579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453`.
It supplies Python 3.14.8-1, Swaylock 1.8.6-1, systemd 262-1 and coreutils
9.12-2. Swayidle is optional. The build's idle controls substitute inert
watcher and locker programs and execute the fixed printf callback locally.

```sh
scripts/ci/session-lock011-native/build-pair.sh \
  "$REVIEWED_ARM64_IMAGE_ID" /absolute/private-parent/fresh-session-lock011
```

The wrapper reuses `native_arm.py probe`, `build.py` and `compare.py`. It uses
two fresh resource-limited non-root containers, an offline network namespace,
normal dependency checking, and `SOURCE_DATE_EPOCH=1794667200`. The reviewed
input set pins all ten helper recipe files. Both makepkg logs must show the
24 manual, 16 idle and two package controls. Byte comparison and the exact
five-file archive payload check must pass. Retain `runner`, `a`, `b`,
`compare.json` and `payload.json` together with the authenticated image record.
The runner receipt records the observed page size.

## Coupled Settings verification

The separate [idle pair profile](../../integration/profiles/desktop-session-lock011-idle.json)
pins Settings 0.1.1-1 source `76385030c78e67e17616229555843746a3da492b` and the
corrected helper 0.1.1-1. Use the two recipes' actual `package()` functions to
assemble a fresh private prefix as an ordinary user, or supply the 14 payload
files copied from an independently verified disposable ALPM transaction. The
`--prefix` input contains exactly those files and their parent directories.

```sh
python3 -I -B scripts/integration/desktop_session_lock.py \
  --profile scripts/integration/profiles/desktop-session-lock011-idle.json \
  --profile-sha256 faac805487cb2b6c58a03a844631f5848a7002363d2495364ca368b0927427e0 \
  --settings-package "$SETTINGS_ARCHIVE" --settings-sha256 "$SETTINGS_SHA256" \
  --session-lock-package "$HELPER_ARCHIVE" --session-lock-sha256 "$HELPER_SHA256" \
  --prefix "$PRIVATE_PAYLOAD_PREFIX"
```

Use the actual archive digests from reviewed build receipts. The verifier
checks archive identity, complete metadata and payload, and the precise Lua
binding delta. It accepts bounded XZ and Zstandard package archives. It
performs offline byte checks only.

The successor's disposable signed lifecycle remains open. A coupled run needs
an updated source-bound ALPM owner and reader before using the older draft's
transaction sequence. The 349-package base would reach 350 with the exact
helper installed for Settings' dependency-enabled build, and 351 with both
packages installed. Verify Required/Required TEST trust, wrong-key and tamper
refusal, all 14 ALPM-owned files, removal, reinstall, and restoration of the
full baseline including protected user files. Capture the restored inventory
and verify helper fixtures against the installed and moved bytes. Any activated
desktop or suspend test belongs to a separate physical session journey.

## Host results and remaining inputs

Actual fresh unsigned x86_64 `makepkg --nodeps --cleanbuild --clean
--noconfirm --log` runs passed under Python 3.14.7. Dependency resolution was
skipped. The helper passed all 42 tests and its archive passed the static
package audit and shared builder metadata binding. Settings passed 5+2
controls using Lua and Hyprland 0.56.2 in config-verification mode only. The
offline verifier passed all 32 controls and accepted both actual staged
prefixes (historical pair 13 files, successor pair 14 files).

| Host archive | Bytes | SHA-256 |
| --- | ---: | --- |
| `cachy-asahi-session-lock-0.1.1-1-any.pkg.tar.zst` | 22,231 | `5de3fd5f8ed40ede0f8037308b6d6ad006c319e9eb75d79278ba9052acba1091` |
| `cachy-asahi-hyprland-settings-0.1.1-1-any.pkg.tar.zst` | 24,740 | `af95068ae09a53ed3d1f7affa02057c0a70a07edbb9adbc0fe5af864bc06fb57` |

The build wrapper refused the local x86_64 host and daemon before starting any
build. Native 4K/16K build receipts, version-exact native Settings builds and
signed installed lifecycle remain pending. The optional historical ALARM
Swayidle 1.9.0-1 pin and detached signature are recorded in the
[574-package input lock](../maintained-desktop574-inputs.json). Its recorded
mirror returned HTTP 404 for both on 2026-11-25. Native fixture checks use the
349-package builder. Testing the actual optional actor requires recovering the
signed original or reviewing a new provider capture with its dependencies.

Physical 13-inch and 15-inch M2 Air checks require supported Asahi installs and
recovery access. Check real idle protocol and inhibitors, rearming after unlock,
duplicate locker refusal, Swaylock PAM, and explicit lock/suspend/resume with
the base's lid policy intact. These checks, performance, and release admission
remain pending.
