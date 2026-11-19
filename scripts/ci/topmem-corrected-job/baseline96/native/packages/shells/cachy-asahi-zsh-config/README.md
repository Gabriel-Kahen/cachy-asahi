# Original, opt-in Zsh configuration

Status: **source-audited, MIT-licensed and host-packaged; release validation pending**. This is an
original alternative to `cachyos-zsh-config`, not a repackaging of its unlicensed
configuration. It provides built-in completion and an optional plain prompt.
It does not reproduce the CachyOS theme/plugin experience. Runtime dependency:
`zsh`; no third-party assets are bundled.

## Pins and upstream audit

Audited October 11, 2026:

- [CachyOS recipe at c7cf5b4f2c70f28ed50601b3f75b19da93ba663f](https://github.com/CachyOS/CachyOS-PKGBUILDS/blob/c7cf5b4f2c70f28ed50601b3f75b19da93ba663f/cachyos-zsh-config/PKGBUILD): version 1.0.3-1, architecture `any`, declared GPL-1.0-only.
- [Configuration commit 79c20770964110b873a4c0429c2a560fd28d33ac](https://github.com/CachyOS/cachyos-zsh-config/tree/79c20770964110b873a4c0429c2a560fd28d33ac): the full tree has only `README.md`, `cachyos-config.zsh` and `zshrc`. There is no license file or explicit grant in those files. The recipe's declaration is insufficient to clear reuse.
- Annotated tag `v1.0.3`, object `bb4e4e0cce4a332e164148b3e692d10ed4360971`, points to that commit. GitHub reports its signature valid; local GPG verification was **not run**. The recipe names key `B1B70BB1CD56047DEF31DE2EB62C3D10C54D5DA9`.
- [upstream-audit.json](upstream-audit.json) records SHA-256 values for the recipe and every upstream configuration file. They were fetched for audit and are not included in the package.

The upstream recipe installs `/usr/share/cachyos-zsh-config/cachyos-config.zsh`
and `/etc/skel/.zshrc`. It has no `install=` script or custom transaction hook;
its dependency packages can bring their own behavior. The skeleton file
activates the configuration for subsequently created users; it can conflict
with other owners of that path.

The configuration reads the Powerlevel10k instant-prompt cache and user
`~/.p10k.zsh`; sources Oh My Zsh and default `git`, `fzf`, `extract` plugins;
loads Powerlevel10k, highlighting, autosuggestions, history substring search,
and pkgfile's command-not-found handler. Dependency-provided completion/theme
code and caches are therefore part of its execution surface. It overrides
parallel `make`/`ninja` behavior and package-management commands, including
aliases for deleting a pacman lock and removing orphan packages. The orphan
query and `nproc` substitutions execute during sourcing even when the aliases
are unused. That configuration is excluded entirely; it is not installed in
an inactive directory as a licensing workaround.

## Dependency and transitive-license observations

The upstream recipe requires `fzf`, `oh-my-zsh-git`, `pkgfile`,
`powerline-fonts`, `vim`, `zsh`, `zsh-autosuggestions`, `zsh-completions`,
`zsh-history-substring-search`, `zsh-syntax-highlighting`, and
`zsh-theme-powerlevel10k`; build dependency `git`.

[dependency-observation.json](dependency-observation.json) records exact
versions, architectures, package checksums, dependencies and declared licenses
observed in the Arch Linux ARM aarch64 core/extra databases. Nine of the eleven
runtime candidates appear there; `oh-my-zsh-git` and
`zsh-theme-powerlevel10k` do not. Absence from those two databases is not a
claim that no other repository or source build can supply them. The first
`mirror.archlinuxarm.org` HTTPS attempt failed certificate hostname validation;
the named official mirror `fl.us.mirror.archlinuxarm.org` was used with normal
TLS verification instead. Database signatures were not checked. These records
are availability evidence, not the chosen Asahi release snapshot.

[excluded-source-license-observation.json](excluded-source-license-observation.json)
pins separate current dependency-source observations and hashes discovered
license files. They are **not pins for a proposed upstream package build**.
Oh My Zsh, fzf, autosuggestions, pkgfile and Powerline carry MIT-style notices;
history search has a BSD three-clause header, syntax highlighting a BSD notice,
and Vim its custom Vim license plus separately licensed bundled components.
Zsh completions' root notice identifies Zsh copyright and grants redistribution;
individual completion notices still need review before any bundled reuse.
Powerlevel10k has a root permissive notice **and a GPLv3 gitstatus license**.
Oh My Zsh and Vim also contain additional license files. A top-level license
label does not settle bundled/transitive licensing. Full licensing and artifact
closure of the excluded upstream configuration remains **blocked/deferred**,
rather than marked cleared from this file-discovery audit.

The selected original alternative depends only on the base's `zsh`.
The observation records the recursive package-declared Zsh dependency graph,
including virtual providers. All observed names have providers, but constraints
and signatures are not installation-tested. Zsh itself is declared `custom`;
its transitive dependencies retain the base distribution's licenses. This
package distributes none of their code, binaries, themes, fonts or license
material. Original project material is licensed under MIT. The local `LICENSE` is copied
byte-for-byte from the project root MIT text, including its copyright notice,
and installed alongside NOTICE. This clears the original-project licensing
blocker; it grants no additional rights over excluded upstream material.

## Recipe, ownership and lifecycle

Local `config.zsh`, `NOTICE`, `usage.md` and `LICENSE` assets are pinned by SHA-256 in the
PKGBUILD. Source acquisition needs no moving upstream revision, network access
or Git. Build tooling is the ordinary Arch `makepkg`/base-devel environment;
there is no compilation and no build-time package installation.

The package contains exactly four regular payload files:

- `/usr/share/cachy-asahi/zsh/config.zsh`
- `/usr/share/cachy-asahi/zsh/README.md`
- `/usr/share/licenses/cachy-asahi-zsh-config/NOTICE`
- `/usr/share/licenses/cachy-asahi-zsh-config/LICENSE`

There are no `/etc`, `/boot`, user-home, systemd, pacman-hook or shell-selection
files, no binaries, and no install script. 16K-page binary compatibility is not
introduced by this data-only package; compatibility of base Zsh remains the
base's separate validation requirement. No Asahi platform components change.

[usage.md](usage.md) supplies explicit session/persistent opt-in and removal
instructions. Installing does not activate anything or replace existing user
configuration. Only interactive sessions initialize completion. Existing
completion, prompt and aliases survive; the prompt has a separate opt-in.
Repeated sourcing is a no-op. Completion performs Zsh's permission audit,
skips insecure directories and disables its dump file. Package removal leaves
user configuration untouched; a guarded source line becomes a no-op, and a new
session drops the old process's completion state.

## Actual local validation and remaining gates

The MIT change refreshed NOTICE, headers, usage, source checksums and `.SRCINFO`;
the installed LICENSE was checked against the actual root license. A local
`.gitignore` makes retained evidence logs visible despite root exclusions.

Host: x86_64 Linux, Zsh 5.9.2, makepkg 7.1.0. Commands run:

```sh
bash -n PKGBUILD
makepkg --printsrcinfo
python check-config.py
makepkg --nodeps --nocheck
```

The first `--printsrcinfo -p` attempt from the repository root failed because
makepkg requires the recipe in its current directory; running inside this
package directory succeeded. `.SRCINFO` is generated from this recipe.

Two builds copied the recipe/assets into separate temporary directories and
ran the exact final build command, without `-i`, `-s`, root access or host
package installation. `--nodeps` explicitly skips dependency resolution, and
`--nocheck` skips the recipe check; syntax/runtime checks ran separately.
[evidence/](evidence/) retains both command logs and build metadata;
[host-validation.json](host-validation.json) records return codes, package
file lists, SHA-256 values and the runtime output. Both builds passed and all
four payload hashes matched. Archive hashes differ because generated package
metadata differs. Temporary archives were not retained for release.

The isolated-HOME checks passed: noninteractive no-op; completion initialization;
preserved prompt/history path/alias; completion opt-out; reuse of existing
completion; prompt opt-in; repeated source; guarded removal; unchanged user
files and no created files/directories. These checks source the local config,
not a host installation, and do not certify actual pacman upgrade/removal.

Pending: a selected/versioned Asahi base and dependency trust
snapshot; independent recipe review; two clean native aarch64 builds and
retrievable artifacts; package-manager install/upgrade/remove/reinstall tests;
interactive behavior on both exact M2 Air sizes. No hardware or performance
claim follows from these host checks.

Manifest proposal: keep `cachyos-zsh-config` deferred for its missing upstream
license grant and unresolved imported dependency closure. Add
`cachy-asahi-zsh-config` as an original, opt-in candidate with status
`host-packaged-validation-pending`; runtime `zsh`; license `MIT`; native build,
package lifecycle and hardware gates pending. The coordinator alone selects or edits the
shared manifest.
