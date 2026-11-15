# Original opt-in Fish helpers

This is an original, minimal development alternative to the blocked CachyOS Fish
config. It does not reproduce CachyOS's prompt, plugins, aliases, or notifications.
No upstream configuration is redistributed. Original material is MIT-licensed;
`LICENSE` copies the root project grant and is installed with the package.
Upstream CachyOS license gaps remain because that configuration is excluded.

Runtime dependencies: `fish` and `coreutils`, whose official aarch64 package pages
were present on October 11, 2026. See `arm-dependency-audit.json`; the chosen Asahi
base snapshot and actual dependency resolution remain unverified. The recursive
package-declared runtime names/providers and license metadata are recorded in
`runtime-dependency-observation.json`; signatures and version constraints were
not validated. Build uses
standard Arch `base-devel` tools and Fish for syntax checking. No compiled payload,
16K-page binary check, plugin, font, additional service, or package hook is involved.

## Package ownership and opting in

The package owns only these files:

- `/usr/share/cachy-asahi/fish/config.fish`
- `/usr/share/licenses/cachy-asahi-fish-config/NOTICE`
- `/usr/share/licenses/cachy-asahi-fish-config/LICENSE`

It owns no `/etc/skel` or user file. It does not select a login shell, change the
prompt, set universal variables, enable services, or run commands at login.
After the package is reviewed and built for the selected base, a user
may add this guarded block to their existing `~/.config/fish/config.fish`:

```fish
if test -r /usr/share/cachy-asahi/fish/config.fish
    source /usr/share/cachy-asahi/fish/config.fish
end
```

Interactive shells gain `caa_ll` (detailed file listing) and `caa_mcd DIRECTORY`
(create one directory, then enter it). Relative targets resolve from the current
directory even when `CDPATH` contains another match; the helper preserves `CDPATH`.
Existing functions with those names win.
These commands only act when invoked. Noninteractive sourcing returns immediately.

Removal through pacman deletes the three package files. The user-authored guarded
block stays harmless when the file is absent. New shells no longer gain helpers;
functions in an already-running shell remain until that shell exits. A user may
remove their guarded block manually; no package uninstall hook rewrites it.
Reinstall provides the same helpers through the existing block. Actual package
installation/removal on Asahi remains NOT RUN.

## Development verification

Current source revision **0.1.0-2** fixes `caa_mcd` entering a different existing
`CDPATH` match after creating a directory locally. Real Fish 4.9.3 controls pass
for colliding relative targets, spaces, leading dashes, a literal `-`, absolute
paths, unchanged `CDPATH` and original mkdir failures. `check()` now runs both
Fish syntax validation and the checksummed `check-config.py`; Python>=3.11 is a
check dependency only. Runtime dependencies and the three installed paths are
unchanged.

A normal host build passed with dependency checks enabled:
`SOURCE_DATE_EPOCH=1791748800 LC_ALL=C makepkg --cleanbuild --nosign --noconfirm`.
The [build log](evidence/host-0.1.0-2.log) records all four source checksum checks
and the actual semantic check. The unsigned any archive is 13,606 bytes, SHA256
`11fc855397e900e7b3e847ac2f72e02160ce2f5a79884d4b88f37761189f61f9`.
Static archive inspection confirmed exactly the three 0644 package files above;
Python and the test helper are not runtime payloads. No host package was installed.

A [negative build](evidence/host-0.1.0-2-old-config-negative.log) with the original
0.1.0-1 config and its matching checksum passed source validation, then failed
this same semantic `check()` before packaging (exit 4, no archive). This private
fixture changes only the config/checksum to expose the original CDPATH bug.

Current 0.1.0-2 native ARM, installation and hardware qualification are NOT RUN.
The older retained build records below, `host-validation.json` and native evidence
belong to 0.1.0-1 and remain unchanged.

Run from this recipe directory, without any installation or dependency-sync flag:

```sh
bash -n PKGBUILD
fish --no-config --no-execute config.fish
python check-config.py
makepkg --config /etc/makepkg.conf --noconfirm
```

All passed on the x86_64 development host with Fish 4.9.3 and makepkg 7.1.0.
`check-config.py` uses temporary homes and checks noninteractive behavior,
preexisting helpers, repeated sourcing, spaces/dash-prefixed paths, invalid
arguments, absent privileged aliases, and absent universal-variable writes.

Two builds in separate temporary work directories produced identical installed
payload checksums. Archive bytes differed; build metadata was not normalized.
These were the same host environment, not independent clean native ARM builds.
`host-validation.json` records actual commands, archive checksums, file lists,
temporary artifact paths, and retained logs under `evidence/`. No package was
installed. Current 0.1.0-2 native aarch64 build/rebuild, dependency resolution on
the chosen target snapshot, user configuration lifecycle on target, and M2 Air
testing remain pending. The inventory retains the separate 0.1.0-1 native evidence.

The recipe checksums pin its original local configuration, notice and MIT grant. Upstream
revision and archive hashes are audit evidence in `upstream-audit.json`, not build
inputs. See `../../../docs/audits/tools-defaults.md` for the full upstream decision.
