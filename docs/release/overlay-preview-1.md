# Cachy-Asahi Overlay Preview 1

This preview provides four shell and setup packages plus an optional desktop
template for an existing Arch Linux ARM or Asahi Arch Linux ARM installation.
All five archives are architecture-independent `any` packages built on hosted
AArch64 runners. They contain original MIT-licensed project material. Physical
M2 validation and production repository enrollment are pending.

## Download and verify

Download the five package archives and the corresponding source archive from
the [GitHub prerelease](https://github.com/Gabriel-Kahen/cachy-asahi/releases/tag/overlay-preview-1).
The [checksum list](overlay-preview-1/SHA256SUMS) is also tracked in this tag.
In a new directory, with GitHub CLI installed:

```sh
gh release download overlay-preview-1 --repo Gabriel-Kahen/cachy-asahi \
  --pattern '*.pkg.tar.*' --pattern '*-sources.tar.gz' --pattern SHA256SUMS
sha256sum --strict --check SHA256SUMS
```

Compare the downloaded checksum list with the tagged copy. The preview archives
are unsigned local files. Keep the system's pacman signature policy in force.
If it requires signed local packages, use the source bundle for inspection
and wait for the signed repository before installing on that system.

## Install and activate the shell overlay

Use a disposable test system with `fish`, `zsh`, `coreutils`, `gnupg`, `pacman`
and Python 3.11 or newer already installed. From the download directory in Bash,
preview the transaction. It should list only the four requested packages.

```bash
packages=(
  cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz
  cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz
  cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz
  cachy-asahi-first-login-0.1.0-3-any.pkg.tar.xz
)
pacman -U --print-format '%n %v' -- "${packages[@]}"
sudo pacman -U -- "${packages[@]}"
```

As the intended ordinary user, inspect and preview the configuration. Apply
only the components you want, then start fresh shells. Fish gains `caa_ll`
and `caa_mcd`. Zsh gains built-in completion.

```sh
cachy-asahi-first-login inspect
cachy-asahi-first-login activate --components fish zsh
cachy-asahi-first-login activate --components fish zsh --apply
```

### Optional Hyprland template

Use this package only with an existing Hyprland version from 0.56.2 through
the end of the 0.56 series. Its dependencies also include Alacritty, Wofi,
Swaylock, WirePlumber, `brightnessctl` and Python. Check the base's versions
and preview the transaction before installing the single archive.

```sh
pacman -U --print-format '%n %v' -- cachy-asahi-hyprland-settings-0.1.0-3-any.pkg.tar.zst
sudo pacman -U -- cachy-asahi-hyprland-settings-0.1.0-3-any.pkg.tar.zst
cachy-asahi-first-login activate --components hyprland
cachy-asahi-first-login activate --components hyprland --apply
```

This creates a separate user configuration. Keep the existing session and
validate the new file before using the base's session launcher. See the
[Hyprland configuration guide](../../packages/desktop/cachy-asahi-hyprland-settings/README.md).

## Remove and recover

If you tried the desktop template, return to the original session first.
With setup still installed, preview and apply deactivation as the original
ordinary user. Keep any files reported as edited. If setup reports an interrupted
transaction, follow its printed recovery commands before removal.

```sh
cachy-asahi-setup remove
cachy-asahi-setup remove --apply
```

Preview the package removal, then remove the preview packages that you installed.
Add `cachy-asahi-hyprland-settings` to both commands if you installed it.

```bash
packages=(cachy-asahi-first-login cachy-asahi-setup cachy-asahi-fish-config cachy-asahi-zsh-config)
pacman -R --print-format '%n %v' -- "${packages[@]}"
sudo pacman -R -- "${packages[@]}"
```

Start fresh shells to unload the settings. A future package update can use the
same verified local-file transaction. Keep the previous verified archive if you
need to restore that version. For setup-journal recovery, use the original path
options shown by the tool. See [first-login recovery](../first-login.md).

## Build provenance and validation

The source bundle contains the exact PKGBUILD and declared source files for
each archive. All five recipe digests match their archives' `.BUILDINFO`, and
all declared source files passed `makepkg --verifysource`.

The four shell archives passed a combined transaction on disposable Arch
Linux x86_64. Pacman previewed, installed, removed and reinstalled them. Both
shells loaded the activated settings, deactivation preserved edits made after
activation, and final removal restored the exact starting package inventory.
Separately, the release CLI staged all five archives against the historical
574-package generic ARM inventory and verified the signed staging bundle from
a public-key-only keyring. That local rehearsal used a disposable TEST key.

| Package | Build source | Validation |
| --- | --- | --- |
| Fish config `0.1.0-2` | [19dea1cc](https://github.com/Gabriel-Kahen/cachy-asahi/tree/19dea1cca35659ad7ab307dfea09c30a77362640/held-source32/scripts/ci/fish-config02-native-source/recipe) | [Native build pair and emulated 16 KiB upgrade and rollback](../validation/native-fish-md4c-reproducibility-20261118.md) |
| Zsh config `0.1.0-1` | [3c008d73](https://github.com/Gabriel-Kahen/cachy-asahi/tree/3c008d738bd0ae4f6e7e405f4a6c68f72cc9ac75/packages/shells/cachy-asahi-zsh-config) | [Native run](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/40535391856) and [emulated Overlay583 lifecycle](../validation/offline-overlay583-emulated-install-20261117.md) |
| Setup `0.3.0-1` | [5d0f5ae6](https://github.com/Gabriel-Kahen/cachy-asahi/tree/5d0f5ae6331807704a8ebafc7922972629e0b96f/packages/tools/cachy-asahi-setup8) | [Native build pair and installed migration checks](../validation/setup8-migration-native-20261027.md) |
| First Login `0.1.0-3` | [f21f8f9e](https://github.com/Gabriel-Kahen/cachy-asahi/tree/f21f8f9e3a84006b13ee1106351c27dca21f5fc3/packages/tools/cachy-asahi-first-login-v3) | [Native build pair and emulated 16 KiB shell lifecycle](../validation/first-login-v3-native-arm4k-20261118.md) |
| Hyprland settings `0.1.0-3` | [990b3bd5](https://github.com/Gabriel-Kahen/cachy-asahi/blob/990b3bd5635851ff6383e5316f36cd61f9800005/native/build-tools-sources-v2.tar) | [Native build pair and isolated install and removal](../validation/hyprland03-native-20261108.md) |
