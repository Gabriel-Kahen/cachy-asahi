# Tools and defaults audit

October 11, 2026. Upstream candidates are **source-audited, not built or installed**.
Original opt-in shell alternatives have development-host evidence documented below;
clean native aarch64 builds, selected-base installation, M2 validation, and stable
release gates remain pending. No system defaults are selected by this workstream.

## Inputs and scope

All three packaging recipes were inspected at CachyOS-PKGBUILDS commit
`c7cf5b4f2c70f28ed50601b3f75b19da93ba663f`. These are observed audit inputs, not
claims that a moving branch will remain at these revisions.

| Candidate | Recipe version | Resolved source commit | Proposed decision |
| --- | --- | --- | --- |
| cachyos-fish-config | 16-1, tag v16 | `cc78c7f7a8a7a623aaaa9283994b64ce4fc50d6a` | Defer upstream reuse; license and ARM dependency gaps, platform aliases |
| cachyos-zsh-config | 1.0.3-1, tag v1.0.3 | `79c20770964110b873a4c0429c2a560fd28d33ac` | Defer upstream reuse; license and ARM dependency gaps, broad shell overrides |
| cachyos-settings | 1:1.4.1-1, tag 1.4.1 | `764693fe2863bc2b00db6ad6f4c1d57cded739f2` | Defer bundle; select no system defaults |

Pins were resolved through GitHub's commit/ref/tag APIs, and full source trees and
pinned raw recipes were retrieved over HTTPS into temporary audit directories.
Checksums and dependency observations are stored beside the owned packages. These
hashes pin inspected bytes; they do not establish signer trust. Zsh/settings tag
verification reported by GitHub is separate from local trusted-key verification,
which was NOT RUN. Neither upstream signed Git-source checksum was verified with
makepkg because the upstream packages were not built.

## Fish candidate

Primary inputs: [recipe](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-fish-config/PKGBUILD),
[main config](https://raw.githubusercontent.com/CachyOS/cachyos-fish-config/cc78c7f7a8a7a623aaaa9283994b64ce4fc50d6a/cachyos-config.fish),
[pinned full tree](https://github.com/CachyOS/cachyos-fish-config/tree/cc78c7f7a8a7a623aaaa9283994b64ce4fc50d6a).
The v16 tag archive SHA256 matched the recipe's
`97a0b603f393be3422465ff9e18f2d03ccfc33657b672de6ba89b3a3ac3b473d`.
The commit archive, with a different archive root name, has SHA256
`3d92eb0fe806528a5ef048cf006a49beabdf49535783363b227399ae09ff3ce1`.
See [machine-readable audit](../../packages/shells/cachy-asahi-fish-config/upstream-audit.json).

The tree contains README.md, config.fish, cachyos-config.fish and conf.d/done.fish.
The recipe declares MIT, but the main configuration has no explicit license grant
and the tree has no license file. The dependency declaration alone does not clear
redistribution of the main configuration. No upstream code is copied into our recipe.

The embedded `done.fish` is version 1.19.1 and includes the complete MIT notice for
Francisco Lourenço and Daniel Wehner (2016). The main configuration credits
`oh-my-fish/plugin-bang-bang` for copied history functions but does not carry its
copyright/license notice. [The plugin license at inspected commit ec991b8](https://raw.githubusercontent.com/oh-my-fish/plugin-bang-bang/ec991b80ba7d4dda7a962167b036efc5c2d79419/LICENSE)
is MIT, credited to Aerys Bat and Derek Stavis (2015). A future derivative must
resolve the main file's grant and retain applicable source notices. The plugin's
inspected license commit is evidence for the grant, not proof of the revision from
which CachyOS originally copied the functions. Neither component is bundled here.

| Declared runtime dependency | Official aarch64 observation | Declared license metadata |
| --- | --- | --- |
| bat | 0.26.1-3 | Apache-2.0 OR MIT |
| expac | 10-13 | GPL |
| eza | 0.23.5-2 | EUPL-1.2 |
| fastfetch | 2.69.0-1 | MIT |
| fish | 4.9.3-1 | GPL-2.0-only AND BSD-3-Clause AND ISC AND MIT AND PSF-2.0 |
| fish-autopair | Package page not found | Upstream source/license unresolved for this candidate |
| fish-pure-prompt | Package page not found | Upstream source/license unresolved for this candidate |
| fisher | 4.4.8-1 | MIT |
| fzf | 0.74.5-1 | MIT |
| pkgfile | 26-1 | MIT |
| tealdeer | 1.9.0-1 | MIT, Apache-2.0 |
| ttf-fantasque-nerd | 3.5.1-2 | OFL-1.1-no-RFN |

The [dependency observation](../../packages/shells/cachy-asahi-fish-config/arm-dependency-audit.json)
records URLs and response hashes. For example, [Fish's ARM package page](https://archlinuxarm.org/packages/aarch64/fish)
confirms a published aarch64 entry. Page availability and declared licenses are not
a pinned dependency solution or source-license clearance. The two missing module
pages and missing CachyOS-PKGBUILDS recipes at this revision leave their package
sources, pins and notices unresolved; they are omitted from the original alternative.
A 404 does not prove absence from all repositories. Build dependency: git, besides
standard Arch packaging tools. Source package declares an unrelated
`kwin-scripts-window-colors` conflict; it is not retained.

Installed files upstream: `/usr/share/cachyos-fish-config/cachyos-config.fish`,
`/usr/share/cachyos-fish-config/conf.d/done.fish`, and
`/etc/skel/.config/fish/config.fish`. The recipe includes a hook source without
setting `install=`, so that file is not registered as an installation hook by this
PKGBUILD. The hook's text only prints upgrade advice; it does not migrate existing
users. Skeleton ownership affects future homes, while existing users must opt in.
Removal would not erase copies or source lines already created in user homes.

The main config unconditionally sources done, which exits a noninteractive shell;
defines a fastfetch greeting; sets universal done variables; sources `.fish_profile`;
adds PATH entries; changes history/bindings and replaces common commands. It exposes
`grubup`, pacman lock deletion, destructive orphan cleanup, and CachyOS mirror/update
aliases. GRUB and mirror commands conflict with preserving the chosen Asahi base.
Other undeclared command consumers include coreutils, util-linux `col`, hwinfo,
CachyOS mirror tools, netcat, grep, procps and journalctl. Notification code probes
Hyprland/X11/desktop tools and executes notification helpers after long commands;
a declared optional capability is not proof of integration on the selected desktop.
Defer notifications, plugins, global replacements, fonts and prompt until separately
licensed and justified; reject bootloader/mirror/lock-removal aliases for this overlay.

## Zsh candidate

Primary inputs: [recipe](https://raw.githubusercontent.com/CachyOS/CachyOS-PKGBUILDS/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-zsh-config/PKGBUILD),
[pinned config](https://raw.githubusercontent.com/CachyOS/cachyos-zsh-config/79c20770964110b873a4c0429c2a560fd28d33ac/cachyos-config.zsh).
Annotated tag object `bb4e4e0cce4a332e164148b3e692d10ed4360971` resolves to the
source commit above. The three-file source tree consists of README.md,
cachyos-config.zsh and zshrc; there is no license file or explicit grant despite
recipe metadata `GPL-1.0-only`. No upstream configuration is copied.

Upstream owns `/usr/share/cachyos-zsh-config/cachyos-config.zsh` and
`/etc/skel/.zshrc`; no package install/remove hook is declared. Existing user files
are not migrated. User copies/source lines survive package removal. Config sources
Oh My Zsh, Powerlevel10k, completions and plugins; changes history and keybindings;
overrides make/ninja parallelism; defines broad aliases; and queries pacman's orphan
list at source time. Lock deletion and destructive package-removal aliases are not
suitable defaults. Build parallelism needs workload/memory/thermal evidence on the
fanless reference machine rather than an unbounded CPU-count policy.

Declared dependencies: fzf, oh-my-zsh-git, pkgfile, powerline-fonts, vim, zsh,
zsh-autosuggestions, zsh-completions, zsh-history-substring-search,
zsh-syntax-highlighting, zsh-theme-powerlevel10k. Build dependency: git plus
standard Arch packaging tools. [ARM dependency evidence](../../packages/shells/cachy-asahi-zsh-config/dependency-observation.json)
records core/extra database hashes, package/license metadata and the original
alternative's runtime closure. Oh My Zsh Git and Powerlevel10k packages were not
present in those observed databases; no base availability claim is made for them.
[Excluded-source license observations](../../packages/shells/cachy-asahi-zsh-config/excluded-source-license-observation.json)
record primary plugin/theme notices. They are inspected external dependencies,
not bundled assets or a licensed upstream Zsh config derivative. The missing upstream grant
and unavailable dependencies block wholesale reuse.

## Settings candidate: individually assessed

The [full settings audit](../../packages/settings/AUDIT.md) covers all 49 installed
files and each sysctl default, source licenses, dependency observations, installation
hooks, service/configuration effects, conflicts, and restoration gates. The
[49-file inventory](../../packages/settings/upstream-inventory.json) pins their bytes
and distinguishes Git executable bits, archive modes and extracted modes.

The root license contains GPLv3 text while the recipe declares GPL-1.0-only.
Vendored regulatory tooling includes ISC notices; other asset/grant questions and
the unaudited CachyOS ananicy rule dependency remain explicit. The installation hook
enables ananicy-cpp, resolved and oomd (and the regulatory path when applicable),
without recording or restoring prior service state. The package mixes AMD/NVIDIA,
PC watchdog/audio/storage/EFI assumptions, DNS changes, audio limits, OOM policy,
zram, sysctl and THP policy. Removal deletes files without restoring live settings,
service state, deleted dumps or user preferences.

Initial proposal: select none. Reject PC hardware/boot defaults, automatic
location-from-timezone regulatory changes, blanket timeout shortening, and the
unmodified THP shrinker constant. Defer architecture-neutral tuning one variable at
a time until the target baseline, actual offered controls, restoration procedure,
and measured acceptance rule exist. A source comment based on 512 PTEs is not
justification for a 16K-page Asahi kernel. Optional diagnostics/Zink wrappers need
separate license/dependency/platform review before recipes. No settings installer,
system mutation, service change or performance claim is delivered.

## Concrete original alternatives and package lifecycle

Development recipes:

- [cachy-asahi-fish-config](../../packages/shells/cachy-asahi-fish-config/README.md):
  only namespaced file-list/create-and-enter helpers; runtime fish + coreutils.
- [cachy-asahi-zsh-config](../../packages/shells/cachy-asahi-zsh-config/README.md):
  opt-in completion setup and separately opted-in plain prompt; runtime zsh.

These are original minimal alternatives, **not CachyOS config derivatives** and
not feature-equivalent replacements. Local files and notices are pinned by recipe
SHA256 checksums; upstream revisions are audit inputs only. Each owns its config
under `/usr/share/cachy-asahi/` and a license-state notice under `/usr/share/licenses/`;
Zsh also owns a usage README beside its config; both install the complete MIT grant
beside the notice.
No skeleton, global shell rc, user-owned file, executable, hook, service, font or
binary is installed. Existing shell/customization state wins where documented.
Users add guarded source blocks themselves; package removal leaves their authored
blocks harmless when package files disappear. Already-running shells retain loaded
functions/state until exit. Exact behavior, opting out and reinstall are documented
per recipe. No login shell is selected automatically.

Both original packages are MIT-licensed, copy the coordinator-selected root
project LICENSE into the package, and checksum that grant as a local source.
The upstream licensing blockers apply only to excluded third-party configurations.
No original project license blocker remains after the coordinator selection. Published official ARM metadata
can resolve the minimal runtime names/providers, with version/signature/source-license
and chosen-snapshot checks still pending. No baseline package binaries are bundled.

## Evidence and manifest proposal

Fish: Bash/Fish syntax checks and isolated-home behavioral tests PASS. Two actual
`makepkg --config /etc/makepkg.conf --noconfirm` builds in separate temporary work
directories PASS on x86_64, Fish 4.9.3, makepkg 7.1.0. Package file lists contained
only the config/notice/MIT grant and archive metadata; no `.INSTALL` or protected-stack path.
Installed payload hashes match between builds, archive bytes differ because build
metadata was not normalized. See [host record](../../packages/shells/cachy-asahi-fish-config/host-validation.json)
and retained logs. This is same-environment assembly, not the M1 clean native ARM gate.
Zsh: Bash/Zsh syntax, recipe metadata and isolated-home checks PASS. Two
`makepkg --nodeps --nocheck` builds PASS on the same x86_64 host. Those flags
skip dependency resolution and recipe check(); syntax/runtime checks ran separately.
All four installed payload hashes match, archive bytes differ. Its
[host record](../../packages/shells/cachy-asahi-zsh-config/host-validation.json)
and retained logs distinguish these results from clean ARM builds or installation.

Coordinator-only manifest proposal (this worker does not edit the manifest):

| Entry | Proposed state | Next gate |
| --- | --- | --- |
| cachyos-fish-config | deferred, source-audited; attach full commit and audit path | Main-source grant/notices, module recipes and base dependency solution, platform-safe derivative review |
| cachyos-zsh-config | deferred, source-audited; attach full commit and audit path | Main-source grant, missing theme/framework recipes, narrowed customization review |
| cachyos-settings | deferred, source-audited; attach full commit and audit path | License correction, baseline/conflict inventory, individual measured experiment/restoration gates |
| cachy-asahi-fish-config 0.1.0-1 | proposed-development, host-packaged | Coordinator integration review; clean aarch64 builds/rebuild; target config lifecycle |
| cachy-asahi-zsh-config 0.1.0-1 | proposed-development, host-packaged | Coordinator integration review; clean aarch64 builds/rebuild; target config lifecycle |

If the project's manifest vocabulary only permits candidate/deferred/built, keep
original alternatives candidate and record the x86_64 build evidence separately.
No worker proposes marking M0 or M1 complete: selected-base resolution, coordinator
integration review and clean ARM evidence remain open. Installed,
hardware-tested, release/update-tested and measured-performance states are all
NOT RUN. Keep kernel-manager/chwd deferred; this work adds no recipes for them.
