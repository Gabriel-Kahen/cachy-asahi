# Hyprland 0.1.1 candidate: ordered session locking

The separate recipe
[`packages/desktop/cachy-asahi-hyprland-settings011/PKGBUILD`](../../packages/desktop/cachy-asahi-hyprland-settings011/PKGBUILD)
builds an opt-in `cachy-asahi-hyprland-settings` 0.1.1-1 successor. The existing
0.1.0-3 recipe directory and all earlier native evidence remain unchanged.
This candidate is not selected for development or release by this lane.

Its only Lua behavior changes are:

| Binding | 0.1.0-3 | 0.1.1-1 |
| --- | --- | --- |
| `SUPER + L` | `swaylock --color 000000` | `cachy-asahi-session-lock lock` |
| `SUPER + SHIFT + L` | Unassigned | `cachy-asahi-session-lock suspend` |

The new dependency is bounded to `cachy-asahi-session-lock>=0.1.0` and `<0.2.0`.
The [helper behavior and limits](session-lock.md) remain authoritative: readiness
precedes requesting suspend, errors/cancellation preserve the locker, normal
authorization/inhibitors apply, and queued sleep versus subsequent unlock is
not atomic. There is no automatic lid/idle policy or session activation.

All other keyboard/mouse bindings, display/input/audio configuration and optional
startup behavior are unchanged. Screenshot helper, Waybar JSON/CSS, Mako config,
license and notice are byte-identical to the old source. The upstream Hyprland
API reference remains 0.56.2 commit
`efb50993780079460b0cbed1363e2166a2de1d9f`, bounded to `>=0.56.2`, `<0.57.0`.
Original MIT sources, previous recipe/configuration hashes and unchanged-source
hashes are recorded in the installed `source-provenance.json`; every recipe
input has a fixed SHA256 and generated `.SRCINFO` entry.

The [README](../../packages/desktop/cachy-asahi-hyprland-settings011/README.md)
uses a new user-owned `hyprland-0.1.1.lua` copy, preserves the earlier user copy,
and documents activation, rollback and removal of helper-dependent bindings.
Installing the package does not rewrite user configuration. Both versions have
the same package name and paths, so this is an explicitly installed upgrade or
downgrade alternative, not a parallel-installable package. The settings package
does not duplicate ownership of the separately packaged lock helper.

## Actual local checks, 2026-11-14

On the existing x86_64 host with Python 3.14.7 and Hyprland 0.56.2 at the exact
API reference commit:

| Check | Actual result |
| --- | --- |
| `python -I -B -Werror::ResourceWarning test_settings.py` | PASS, 5 tests |
| Lua dispatcher-stub execution | 36 baseline and 37 successor unique bindings; all prior semantics except the declared lock command match |
| `luac -p` and real `Hyprland --verify-config` | PASS for default and optional screenshot/Waybar/Mako configuration; `config ok`, no session launch |
| Screenshot source/staged `--help` | PASS; full/region CLI retained; no capture |
| `python -I -B -Werror::ResourceWarning test_package.py` | PASS, 2 tests: exact source metadata/dependency bounds and actual `package()` staging |
| `bash -n PKGBUILD` | PASS |
| Actual `makepkg --nodeps --noconfirm` in a fresh temporary copy | PASS, including real 5+2-test `check()` and `package()`; dependency resolution deliberately skipped |
| Recipe static audit / literal metadata consistency | `static-pass` / `MATCH_MODELED_LITERAL_DECLARATIONS`, no errors |
| Final package static audit and exact source-byte comparison | `artifact-static-pass`; exactly nine root-owned regular payload files, no install hook or ELF |
| Existing recipe directory comparison | No tracked changes |

Final host archive: `cachy-asahi-hyprland-settings-0.1.1-1-any.pkg.tar.zst`,
24747 bytes, SHA256
`a2e7f87f952bfbee67c717e4611dd97a6447f548e56d0c079b5de44aeccd0931`.
Temporary host archive, `build.log` and `host-result.json` are under
`/tmp/cachy-asahi-settings011-release-source-host-ncv_fn0e/`. These are local
development outputs, not published or durable release evidence. Builds used
`SOURCE_DATE_EPOCH=1794667200`; no byte-reproducibility claim is made across
different source states or host directories.

The existing installed desktop verifier and frozen native component inputs
target the selected old eight-file payload. This successor adds the provenance
document as a ninth file and requires a matching reviewed integration lock and
verifier before any later native qualification; those shared tools are unchanged.
Clean native ARM4K/16K builds, dependency/install/upgrade/remove transactions,
actual helper/compositor/PAM behavior, screenshot capture, bar/notification
runtime, lock/suspend/resume and both M2 Air sizes remain **NOT RUN**. Earlier
0.1.0-3 native results do not qualify this version. M6/R4 remains incomplete.
